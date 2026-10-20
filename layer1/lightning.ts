// Lightning, behind an interface. THIS IS A STUB: no Lightning node runs in phase 1b. StubNetwork is an
// in-memory ledger that keeps the one property pay per proof needs, a hash lock. The payee makes an
// invoice for SHA-256(preimage), the payer pays it once, and only then learns the preimage, which is its
// proof of payment. Invoices are "lnstub1…" strings, not BOLT11. A real backend (an LND or CLN REST
// client, or NWC over Nostr) has to implement Payee and Payer and nothing else changes.

import { randomBytes } from "node:crypto";
import { sha256 } from "../model/schnorr.ts";

export interface Invoice {
  readonly paymentRequest: string;
  readonly paymentHash: string;   // hex SHA-256 of the preimage
  readonly amountMsat: number;
  readonly payee: string;         // node id
  readonly memo: string;
  readonly expiresAt: number;     // unix seconds
}

export interface Payee {
  readonly nodeId: string;
  createInvoice(amountMsat: number, memo: string, ttlSec?: number): Promise<Invoice>;
}

export interface Payer {
  readonly nodeId: string;
  /** Parse without paying, so the caller can check amount and payee first. */
  decode(paymentRequest: string): Invoice;
  /** Pay at most maxMsat. Resolves with the preimage, which the caller should check against the hash.
   *  The on-chain backend (layer1/onchain.ts) has no hash lock: it resolves with an empty preimage and
   *  the txid, and its proof of payment is a receipt built once the transaction confirms. */
  pay(paymentRequest: string, maxMsat: number): Promise<{ preimage: string; txid?: string }>;
}

export const preimageMatches = (paymentHash: string, preimage: string): boolean =>
  /^[0-9a-f]{64}$/.test(preimage) && sha256(Buffer.from(preimage, "hex")).toString("hex") === paymentHash;

const PREFIX = "lnstub1";

function decodeStub(pr: string): Invoice {
  if (!pr.startsWith(PREFIX)) throw new Error("not an lnstub invoice");
  const v = JSON.parse(Buffer.from(pr.slice(PREFIX.length), "base64url").toString("utf8"));
  if (typeof v.h !== "string" || !Number.isSafeInteger(v.a) || typeof v.p !== "string") throw new Error("malformed invoice");
  return { paymentRequest: pr, paymentHash: v.h, amountMsat: v.a, payee: v.p, memo: String(v.m ?? ""), expiresAt: Number(v.x) };
}

interface Pending { invoice: Invoice; preimage: string; paid: boolean }

/** One shared ledger. Nodes start with a balance; a payment moves msat from payer to payee and settles
 *  instantly. No routing, fees, channels or failures beyond "unknown", "expired", "already paid",
 *  "over max" and "insufficient balance". */
export class StubNetwork {
  private readonly invoices = new Map<string, Pending>();
  readonly balances = new Map<string, number>();

  node(nodeId: string, balanceMsat = 0): Payee & Payer {
    if (!this.balances.has(nodeId)) this.balances.set(nodeId, balanceMsat);
    const net = this;
    return {
      nodeId,
      async createInvoice(amountMsat: number, memo: string, ttlSec = 600): Promise<Invoice> {
        if (!Number.isSafeInteger(amountMsat) || amountMsat <= 0) throw new Error("amount must be a positive integer msat");
        const preimage = randomBytes(32).toString("hex");
        const h = sha256(Buffer.from(preimage, "hex")).toString("hex");
        const x = Math.floor(Date.now() / 1000) + ttlSec;
        const pr = PREFIX + Buffer.from(JSON.stringify({ h, a: amountMsat, p: nodeId, m: memo, x })).toString("base64url");
        const invoice = decodeStub(pr);
        net.invoices.set(h, { invoice, preimage, paid: false });
        return invoice;
      },
      decode: decodeStub,
      async pay(paymentRequest: string, maxMsat: number): Promise<{ preimage: string }> {
        const inv = decodeStub(paymentRequest);
        const p = net.invoices.get(inv.paymentHash);
        // The request is attacker-supplied, so trust only the ledger's own copy of the invoice.
        if (!p || p.invoice.paymentRequest !== paymentRequest) throw new Error("unknown invoice");
        if (p.paid) throw new Error("invoice already paid");
        if (p.invoice.expiresAt < Date.now() / 1000) throw new Error("invoice expired");
        if (p.invoice.amountMsat > maxMsat) throw new Error("invoice amount over max");
        const bal = net.balances.get(nodeId) ?? 0;
        if (bal < p.invoice.amountMsat) throw new Error("insufficient balance");
        net.balances.set(nodeId, bal - p.invoice.amountMsat);
        net.balances.set(p.invoice.payee, (net.balances.get(p.invoice.payee) ?? 0) + p.invoice.amountMsat);
        p.paid = true;
        return { preimage: p.preimage };
      },
    };
  }
}
