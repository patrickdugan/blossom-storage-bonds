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
import { existsSync, readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { sha256 } from "../model/schnorr.ts";
import { fail, json, readBody } from "./blossom.ts";
import type { BondTool } from "./bondtool.ts";
import { preimageMatches, type Invoice, type Payee, type Payer } from "./lightning.ts";
import { Ledger, writeFileDurable } from "./ledger.ts";

const PREFIX = "bsbch1";

export function decodeChannelInvoice(pr: string): Invoice & { payUrl: string } {
  if (!pr.startsWith(PREFIX)) throw new Error("not a bsb channel invoice");
  const v = JSON.parse(Buffer.from(pr.slice(PREFIX.length), "base64url").toString("utf8"));
  if (typeof v.h !== "string" || !/^[0-9a-f]{64}$/i.test(v.h) ||
      !Number.isSafeInteger(v.a) || v.a <= 0 || v.a % 1000 !== 0 ||
      typeof v.p !== "string" || !/^bsbch:[0-9a-f]{64}$/i.test(v.p) ||
      typeof v.u !== "string" || !/^https?:\/\//i.test(v.u) ||
      !Number.isSafeInteger(v.x) || v.x < 1) throw new Error("malformed invoice");
  return { paymentRequest: pr, paymentHash: v.h, amountMsat: v.a, payee: v.p, memo: String(v.m ?? ""), expiresAt: v.x, payUrl: v.u };
}

export interface ChannelFile { provider_x: string; client_x: string; capacity_sats: number; t_refund: number; funding_txid?: string; funding_vout?: number }

/** The provider's side. It lives in the provider process and serves POST /channel/open and /channel/pay. */
export class ChannelPayee implements Payee {
  readonly nodeId: string;
  private readonly tool: BondTool;
  private readonly dir: string;
  private payUrl = "";
  private readonly pending = new Map<string, { inv: Invoice; preimage: string; paid: boolean }>();
  private readonly inFlightChannelClients = new Set<string>();
  /** Per client: the channel file and the latest state the client has signed. */
  readonly channels = new Map<string, { path: string; paid: number; sig?: string }>();
  /** Phase 7C: what was paid by whom, so an exact retry after a lost reply gets the same preimage. */
  private readonly paidBy = new Map<string, { client_x: string; paid: number; sig: string }>();
  private readonly ledger?: Ledger;

  /** With `ledgerPath`, invoices, channel opens and accepted payments are written ahead and replayed on
   *  restart. Without one, state is in memory only (the phase 2 behaviour, kept for the model tests). */
  constructor(providerX: string, tool: BondTool, dir: string, ledgerPath?: string) {
    this.nodeId = `bsbch:${providerX}`; this.tool = tool; this.dir = dir;
    if (ledgerPath) {
      this.ledger = new Ledger(ledgerPath);
      for (const r of this.ledger.replay()) {
        if (r.t === "invoice") {
          const inv = decodeChannelInvoice(String(r.pr));
          this.pending.set(inv.paymentHash, { inv, preimage: String(r.preimage), paid: false });
        } else if (r.t === "open") {
          // The ledger holds the channel's terms, so a channel file lost in a crash is rebuilt.
          if (r.ch && !existsSync(String(r.path))) writeFileDurable(String(r.path), String(r.ch));
          this.channels.set(String(r.client_x), { path: String(r.path), paid: 0 });
        } else if (r.t === "paid") {
          const ch = this.channels.get(String(r.client_x));
          const p = this.pending.get(String(r.h));
          if (!ch || !p) throw new Error(`${ledgerPath}: payment for an unknown channel or invoice`);
          if (Number(r.paid) <= ch.paid) throw new Error(`${ledgerPath}: payments must increase`);
          ch.paid = Number(r.paid); ch.sig = String(r.sig); p.paid = true;
          this.paidBy.set(String(r.h), { client_x: String(r.client_x), paid: Number(r.paid), sig: String(r.sig) });
        }
      }
    }
  }
  setBaseUrl(url: string) { this.payUrl = `${url}/channel/pay`; }

  async createInvoice(amountMsat: number, memo: string, ttlSec = 600): Promise<Invoice> {
    if (!Number.isSafeInteger(amountMsat) || amountMsat <= 0 || amountMsat % 1000 !== 0) throw new Error("amount must be whole sats");
    if (!Number.isSafeInteger(ttlSec) || ttlSec < 1) throw new Error("invoice TTL must be positive seconds");
    const preimage = randomBytes(32).toString("hex");
    const h = sha256(Buffer.from(preimage, "hex")).toString("hex");
    const pr = PREFIX + Buffer.from(JSON.stringify({ h, a: amountMsat, p: this.nodeId, m: memo, x: Math.floor(Date.now() / 1000) + ttlSec, u: this.payUrl })).toString("base64url");
    const inv = decodeChannelInvoice(pr);
    this.ledger?.append({ t: "invoice", h, pr, preimage });
    this.pending.set(h, { inv, preimage, paid: false });
    return inv;
  }

  /** Routes for the provider's server. */
  async route(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
    if (req.method !== "POST" || (url.pathname !== "/channel/open" && url.pathname !== "/channel/pay" && url.pathname !== "/channel/state")) return false;
    let body: any;
    try { body = JSON.parse(String(await readBody(req, 1 << 16))); } catch { fail(res, 400, "body must be JSON"); return true; }
    try {
      if (url.pathname === "/channel/state") {
        // The total this provider holds a client signature for. The client uses it only within bounds
        // it already knows (ChannelPayer.reconcile), so a lie can only cost the provider.
        const ch = this.channels.get(String(body.client_x));
        if (!ch) throw new Error("no channel with this client");
        json(res, 200, { paid: ch.paid });
      } else if (url.pathname === "/channel/open") {
        const ch = body as ChannelFile;
        if (ch.provider_x !== this.nodeId.slice(6)) throw new Error("channel names another provider");
        const path = `${this.dir}/channel-${ch.client_x.slice(0, 16)}.json`;
        writeFileDurable(path, JSON.stringify(ch));
        const check = await this.tool.run("chan-check", path);
        if (!this.channels.has(ch.client_x)) {
          this.ledger?.append({ t: "open", client_x: ch.client_x, path, ch: readFileSync(path, "utf8") });
          this.channels.set(ch.client_x, { path, paid: 0 });
        }
        json(res, 200, check);
      } else {
        const { paymentRequest, client_x, paid, sig } = body as { paymentRequest: string; client_x: string; paid: number; sig: string };
        const inv = decodeChannelInvoice(String(paymentRequest));
        const p = this.pending.get(inv.paymentHash);
        if (!p || p.inv.paymentRequest !== paymentRequest) throw new Error("unknown invoice");
        if (p.paid) {
          // An exact retry (same client, total and signature) after a lost reply: return the same
          // preimage, count nothing twice. Anything else for a paid invoice is a replay.
          const prior = this.paidBy.get(inv.paymentHash);
          if (prior && prior.client_x === client_x && prior.paid === paid && prior.sig === sig) { json(res, 200, { preimage: p.preimage, retry: true }); return true; }
          throw new Error("invoice already paid");
        }
        if (Math.floor(Date.now() / 1000) >= p.inv.expiresAt) throw new Error("invoice expired");
        const ch = this.channels.get(client_x);
        if (!ch) throw new Error("no channel with this client");
        if (this.inFlightChannelClients.has(client_x)) throw new Error("channel verification already in flight");
        this.inFlightChannelClients.add(client_x);
        try {
          const expectedPaid = ch.paid + p.inv.amountMsat / 1000;
          if (!Number.isSafeInteger(expectedPaid) || paid !== expectedPaid)
            throw new Error(`state pays ${paid} sats, expected ${expectedPaid}`);
          await this.tool.run("chan-verify", ch.path, String(paid), String(sig));
          // Write ahead: the payment is on disk before the preimage leaves.
          this.ledger?.append({ t: "paid", h: inv.paymentHash, client_x, paid, sig: String(sig) });
          ch.paid = paid; ch.sig = sig; p.paid = true;
          this.paidBy.set(inv.paymentHash, { client_x, paid, sig: String(sig) });
          json(res, 200, { preimage: p.preimage });
        } finally {
          this.inFlightChannelClients.delete(client_x);
        }
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
  private readonly chans = new Map<string, { path: string; paid: number; done: number }>();
  private readonly paidInvoiceHashes = new Set<string>();
  private readonly inFlightChannels = new Set<string>();
  private readonly ledger?: Ledger;
  /** Signed states handed out but not yet acknowledged (a crash or lost reply interrupted them). */
  readonly unsettled = new Map<string, { pr: string; payee: string; paid: number; sig: string }>();

  /** With `ledgerPath`, every signed state is written ahead. After a restart the client counts each
   *  as possibly delivered (so it never signs a lower total or pays an invoice twice), and `resume()`
   *  completes the interrupted ones. */
  constructor(clientX: string, tool: BondTool, ledgerPath?: string) {
    this.nodeId = `bsbch:${clientX}`; this.clientX = clientX; this.tool = tool;
    if (ledgerPath) {
      this.ledger = new Ledger(ledgerPath);
      for (const r of this.ledger.replay()) {
        if (r.t === "open") {
          if (r.ch && !existsSync(String(r.path))) writeFileDurable(String(r.path), String(r.ch));
          this.chans.set(String(r.payee), { path: String(r.path), paid: 0, done: 0 });
        }
        else if (r.t === "intent") {
          const ch = this.chans.get(String(r.payee));
          if (!ch) throw new Error(`${ledgerPath}: payment on an unknown channel`);
          ch.paid = Math.max(ch.paid, Number(r.paid));
          this.paidInvoiceHashes.add(String(r.h));
          this.unsettled.set(String(r.h), { pr: String(r.pr), payee: String(r.payee), paid: Number(r.paid), sig: String(r.sig) });
        } else if (r.t === "done") {
          const u = this.unsettled.get(String(r.h));
          if (u) { const ch = this.chans.get(u.payee); if (ch) ch.done = Math.max(ch.done, u.paid); }
          this.unsettled.delete(String(r.h));
        } else if (r.t === "reconciled") {
          const ch = this.chans.get(String(r.payee));
          if (ch) { ch.paid = Number(r.paid); ch.done = Number(r.paid); }
          for (const [h, u] of [...this.unsettled]) if (u.payee === r.payee && u.paid > Number(r.paid)) this.unsettled.delete(h);
        }
      }
    }
  }

  /** Re-send each interrupted payment exactly as signed. The provider counts an exact retry once. */
  async resume(): Promise<{ resumed: string[]; failed: { h: string; why: string }[] }> {
    const resumed: string[] = [], failed: { h: string; why: string }[] = [];
    for (const [h, u] of [...this.unsettled]) {
      try {
        const inv = decodeChannelInvoice(u.pr);
        const r = await fetch(inv.payUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paymentRequest: u.pr, client_x: this.clientX, paid: u.paid, sig: u.sig }) });
        if (r.status !== 200) throw new Error(`payee refused: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
        const { preimage } = (await r.json()) as { preimage: string };
        if (!preimageMatches(inv.paymentHash, preimage)) throw new Error("payee returned a wrong preimage");
        this.ledger?.append({ t: "done", h, preimage });
        this.unsettled.delete(h);
        resumed.push(h);
      } catch (e) { failed.push({ h, why: (e as Error).message }); }
    }
    return { resumed, failed };
  }

  /** After a resume the provider refused (say, the invoice expired before the client came back), ask
   *  the provider which total it holds. Accept it only between the last acknowledged total and the
   *  highest total this client signed. Below that range the provider would be claiming less than it
   *  acknowledged; above it, more than was ever signed. Either way the answer is refused. Within it, a
   *  lie only costs the provider: the client never signs below a total the provider could be holding. */
  async reconcile(payee: string, stateUrl: string): Promise<number> {
    const ch = this.chans.get(payee);
    if (!ch) throw new Error("no channel to this payee");
    const r = await fetch(stateUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_x: this.clientX }) });
    if (r.status !== 200) throw new Error(`payee refused: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
    const { paid } = (await r.json()) as { paid: number };
    if (!Number.isSafeInteger(paid) || paid < ch.done || paid > ch.paid) throw new Error(`provider claims ${paid} sats, outside [${ch.done}, ${ch.paid}]`);
    this.ledger?.append({ t: "reconciled", payee, paid });
    ch.paid = paid; ch.done = paid;
    for (const [h, u] of [...this.unsettled]) if (u.payee === payee && u.paid > paid) this.unsettled.delete(h);
    return paid;
  }

  /** Fund the channel on chain (the caller mines and then tells the provider). */
  async open(path: string, ch: ChannelFile): Promise<ChannelFile> {
    writeFileDurable(path, JSON.stringify(ch));
    const v = (await this.tool.run("chan-open", path)) as ChannelFile;
    this.ledger?.append({ t: "open", payee: `bsbch:${ch.provider_x}`, path, ch: readFileSync(path, "utf8") });
    this.chans.set(`bsbch:${ch.provider_x}`, { path, paid: 0, done: 0 });
    return v;
  }
  paidTo(payee: string): number { return this.chans.get(payee)?.paid ?? 0; }

  decode(pr: string): Invoice { return decodeChannelInvoice(pr); }

  async pay(pr: string, maxMsat: number): Promise<{ preimage: string }> {
    const inv = decodeChannelInvoice(pr);
    if (Math.floor(Date.now() / 1000) >= inv.expiresAt) throw new Error("invoice expired");
    if (inv.amountMsat > maxMsat) throw new Error("invoice amount over max");
    const ch = this.chans.get(inv.payee);
    if (!ch) throw new Error("no channel to this payee");
    if (this.paidInvoiceHashes.has(inv.paymentHash)) throw new Error("invoice already paid");
    if (this.inFlightChannels.has(inv.payee)) throw new Error("channel payment already in flight");
    this.inFlightChannels.add(inv.payee);
    try {
      const paid = ch.paid + inv.amountMsat / 1000;
      if (!Number.isSafeInteger(paid) || paid <= ch.paid) throw new Error("channel payment total overflow");
      const { sig } = await this.tool.run("chan-sign", ch.path, String(paid));
      // Write ahead: from here the provider may hold this state, so the client counts it as paid.
      this.ledger?.append({ t: "intent", h: inv.paymentHash, pr, payee: inv.payee, paid, sig: String(sig) });
      ch.paid = paid;
      this.paidInvoiceHashes.add(inv.paymentHash);
      this.unsettled.set(inv.paymentHash, { pr, payee: inv.payee, paid, sig: String(sig) });
      const r = await fetch(inv.payUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paymentRequest: pr, client_x: this.clientX, paid, sig }) });
      if (r.status !== 200) throw new Error(`payee refused: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
      const { preimage } = (await r.json()) as { preimage: string };
      if (!preimageMatches(inv.paymentHash, preimage)) throw new Error("payee returned a wrong preimage");
      this.ledger?.append({ t: "done", h: inv.paymentHash, preimage });
      this.unsettled.delete(inv.paymentHash);
      ch.done = Math.max(ch.done, paid);
      return { preimage };
    } finally {
      this.inFlightChannels.delete(inv.payee);
    }
  }
}
