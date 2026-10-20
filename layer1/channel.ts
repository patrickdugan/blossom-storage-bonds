// Pay per proof over a real Bitcoin payment channel, behind the same Payee/Payer interfaces as the
// Lightning stub. This is a Spilman-style one-way channel on regtest (bsb-bond chan-*), not Lightning. The
// client funds a 2-of-2 output with a refund to itself after t_refund. Each payment is a new state, signed
// by the client, that pays the provider more. The provider keeps the latest one and closes with it.
//
// An invoice still carries a hash. The provider releases the preimage once it holds a valid client
// signature for the new total, so a paid receipt proves the same thing as before: the payee acknowledged
// that payment. As in any one-way channel, the provider can take a signature and refuse the preimage.
// That costs the client one epoch, and the client stops paying.

import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { sha256 } from "../model/schnorr.ts";
import { fail, json, readBody } from "./blossom.ts";
import type { BondTool } from "./bondtool.ts";
import { preimageMatches, type Invoice, type Payee, type Payer } from "./lightning.ts";

const PREFIX = "bsbch1";

export function decodeChannelInvoice(pr: string): Invoice & { payUrl: string } {
  if (!pr.startsWith(PREFIX)) throw new Error("not a bsb channel invoice");
  const v = JSON.parse(Buffer.from(pr.slice(PREFIX.length), "base64url").toString("utf8"));
  if (typeof v.h !== "string" || !Number.isSafeInteger(v.a) || typeof v.p !== "string" || typeof v.u !== "string") throw new Error("malformed invoice");
  return { paymentRequest: pr, paymentHash: v.h, amountMsat: v.a, payee: v.p, memo: String(v.m ?? ""), expiresAt: Number(v.x), payUrl: v.u };
}

export interface ChannelFile { provider_x: string; client_x: string; capacity_sats: number; t_refund: number; funding_txid?: string; funding_vout?: number }

/** The provider's side. It lives in the provider process and serves POST /channel/open and /channel/pay. */
export class ChannelPayee implements Payee {
  readonly nodeId: string;
  private readonly tool: BondTool;
  private readonly dir: string;
  private payUrl = "";
  private readonly pending = new Map<string, { inv: Invoice; preimage: string; paid: boolean }>();
  /** Per client: the channel file and the latest state the client has signed. */
  readonly channels = new Map<string, { path: string; paid: number; sig?: string }>();

  constructor(providerX: string, tool: BondTool, dir: string) {
    this.nodeId = `bsbch:${providerX}`; this.tool = tool; this.dir = dir;
  }
  setBaseUrl(url: string) { this.payUrl = `${url}/channel/pay`; }

  async createInvoice(amountMsat: number, memo: string, ttlSec = 600): Promise<Invoice> {
    if (!Number.isSafeInteger(amountMsat) || amountMsat <= 0 || amountMsat % 1000 !== 0) throw new Error("amount must be whole sats");
    const preimage = randomBytes(32).toString("hex");
    const h = sha256(Buffer.from(preimage, "hex")).toString("hex");
    const pr = PREFIX + Buffer.from(JSON.stringify({ h, a: amountMsat, p: this.nodeId, m: memo, x: Math.floor(Date.now() / 1000) + ttlSec, u: this.payUrl })).toString("base64url");
    const inv = decodeChannelInvoice(pr);
    this.pending.set(h, { inv, preimage, paid: false });
    return inv;
  }

  /** Routes for the provider's server. */
  async route(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
    if (req.method !== "POST" || (url.pathname !== "/channel/open" && url.pathname !== "/channel/pay")) return false;
    let body: any;
    try { body = JSON.parse(String(await readBody(req, 1 << 16))); } catch { fail(res, 400, "body must be JSON"); return true; }
    try {
      if (url.pathname === "/channel/open") {
        const ch = body as ChannelFile;
        if (ch.provider_x !== this.nodeId.slice(6)) throw new Error("channel names another provider");
        const path = `${this.dir}/channel-${ch.client_x.slice(0, 16)}.json`;
        writeFileSync(path, JSON.stringify(ch));
        const check = await this.tool.run("chan-check", path);
        this.channels.set(ch.client_x, { path, paid: 0 });
        json(res, 200, check);
      } else {
        const { paymentRequest, client_x, paid, sig } = body as { paymentRequest: string; client_x: string; paid: number; sig: string };
        const inv = decodeChannelInvoice(String(paymentRequest));
        const p = this.pending.get(inv.paymentHash);
        if (!p || p.inv.paymentRequest !== paymentRequest) throw new Error("unknown invoice");
        if (p.paid) throw new Error("invoice already paid");
        const ch = this.channels.get(client_x);
        if (!ch) throw new Error("no channel with this client");
        if (paid !== ch.paid + p.inv.amountMsat / 1000) throw new Error(`state pays ${paid} sats, expected ${ch.paid + p.inv.amountMsat / 1000}`);
        await this.tool.run("chan-verify", ch.path, String(paid), String(sig));
        ch.paid = paid; ch.sig = sig; p.paid = true;
        json(res, 200, { preimage: p.preimage });
      }
    } catch (e) { fail(res, 402, (e as Error).message); }
    return true;
  }

  /** Close a client's channel on chain with the latest state. */
  close(clientX: string): Promise<Record<string, any>> {
    const ch = this.channels.get(clientX);
    if (!ch?.sig) return Promise.reject(new Error("nothing to close"));
    return this.tool.run("chan-close", ch.path, String(ch.paid), ch.sig);
  }
}

/** The client's side: one channel per provider, opened with open(). */
export class ChannelPayer implements Payer {
  readonly nodeId: string;
  private readonly tool: BondTool;
  private readonly clientX: string;
  private readonly chans = new Map<string, { path: string; paid: number }>();

  constructor(clientX: string, tool: BondTool) { this.nodeId = `bsbch:${clientX}`; this.clientX = clientX; this.tool = tool; }

  /** Fund the channel on chain (the caller mines and then tells the provider). */
  async open(path: string, ch: ChannelFile): Promise<ChannelFile> {
    writeFileSync(path, JSON.stringify(ch));
    const v = (await this.tool.run("chan-open", path)) as ChannelFile;
    this.chans.set(`bsbch:${ch.provider_x}`, { path, paid: 0 });
    return v;
  }
  paidTo(payee: string): number { return this.chans.get(payee)?.paid ?? 0; }

  decode(pr: string): Invoice { return decodeChannelInvoice(pr); }

  async pay(pr: string, maxMsat: number): Promise<{ preimage: string }> {
    const inv = decodeChannelInvoice(pr);
    if (inv.amountMsat > maxMsat) throw new Error("invoice amount over max");
    const ch = this.chans.get(inv.payee);
    if (!ch) throw new Error("no channel to this payee");
    const paid = ch.paid + inv.amountMsat / 1000;
    const { sig } = await this.tool.run("chan-sign", ch.path, String(paid));
    const r = await fetch(inv.payUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paymentRequest: pr, client_x: this.clientX, paid, sig }) });
    if (r.status !== 200) throw new Error(`payee refused: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
    const { preimage } = (await r.json()) as { preimage: string };
    if (!preimageMatches(inv.paymentHash, preimage)) throw new Error("payee returned a wrong preimage");
    ch.paid = paid;
    return { preimage };
  }
}
