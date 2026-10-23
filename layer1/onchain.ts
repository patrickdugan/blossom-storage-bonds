// Pay per proof with plain on-chain Bitcoin payments, behind the same Payee/Payer interfaces as the
// stub, the one-way channel and LND, and a receipt that anyone can check without a node.
//
// The invoice. The provider signs it with its Nostr key: a random 32-byte payment hash, the amount, the
// memo (which names the epoch), an expiry, and an x-only "pay key" P that it holds the secret for.
//
// The payment. The client pays to a taproot output whose key commits to the payment hashes it settles
// (pay to contract): Q = P + t·G with t = H_TapTweak(P ‖ m) and m = H_bsb/pay(h_1 ‖ … ‖ h_n). This is
// BIP341's tweak with m in place of a script-tree root, so the provider spends Q on the key path with
// d + t, and to anyone without the invoices Q is an ordinary P2TR output. One transaction can pay many
// epochs and many providers: one output per provider, each committing to the hashes of every invoice it
// pays and holding at least their sum. No OP_RETURN is needed, and none is used.
//
// The receipt is the txid plus an inclusion proof: the transaction, the invoices each output pays, the
// block header, the transaction's Merkle branch to the header's root, and the coinbase with its branch
// (all leaves sit at one depth, so a real coinbase at leaf 0 pins the depth). verifyReceipt() checks it
// against a header chain, block hash by height (layer1/headerchain.ts: the stand-in for a ZeroSync-style
// proof of that chain). The check needs no node and no trust in whoever built the receipt.
//
// Where this differs from Lightning's hash lock:
// - Nothing is atomic. On Lightning the payee can claim the money only by revealing the preimage of the
//   payment hash, so payment and proof of payment are one event. Here the hash is only a tag the output
//   commits to; nobody ever learns or needs a preimage, so pay() resolves with an empty one, and the
//   proof of payment is the receipt, which exists once the transaction confirms.
// - The proof is public and needs no cooperation from the payee: once the transaction is in a block
//   under enough work, the payee cannot deny it and the payer cannot fake it. A preimage proves only to
//   someone who trusts the invoice it opens, and it is private to the payer until published.
// - It is not final at once: a confirmation is minutes away and can be reorganised, so a verifier asks
//   for depth (1 block on regtest; 3 to 6 on mainnet), where Lightning settles in seconds.
// - It costs a share of a transaction (docs/design.md §4.5): about 43 vB per provider output, plus about
//   111 vB per transaction for one taproot input, the change and the overhead.
// - Paying an expired or wrong invoice cannot fail safe: the coins move anyway. The payer checks the
//   invoice before paying, and the receipt records the block time so a verifier can see lateness.
// - It proves the payment happened, not that it did not. Showing an epoch went unpaid means showing that
//   no output in any block since the invoice commits to its hash, which only the payee can even
//   recognise; see the design doc.

import { randomBytes } from "node:crypto";
import { G, N, add, be32, int, liftX, mul, schnorrSign, schnorrVerify, sha256, taggedHash, type Key } from "../model/schnorr.ts";
import { fromDisplay, parseHeader, sha256d, toDisplay, type HeaderSource } from "./headerchain.ts";
import type { Invoice, Payee, Payer } from "./lightning.ts";
import { Ledger } from "./ledger.ts";

// ── transactions ──

export interface TxIn { readonly txid: string; readonly vout: number; readonly script: Buffer; readonly sequence: number }
export interface TxOut { readonly value: bigint; readonly script: Buffer }
export interface Tx {
  readonly version: number;
  readonly inputs: TxIn[];
  readonly outputs: TxOut[];
  readonly locktime: number;
  /** The serialization without witness data, which the txid hashes. */
  readonly stripped: Buffer;
  readonly txid: string;
}

function reader(b: Buffer) {
  let o = 0;
  const need = (n: number) => { if (o + n > b.length) throw new Error("transaction truncated"); };
  const r = {
    get offset() { return o; },
    bytes(n: number): Buffer { need(n); const s = b.subarray(o, o + n); o += n; return Buffer.from(s); },
    u8(): number { need(1); return b[o++]; },
    u32(): number { need(4); const v = b.readUInt32LE(o); o += 4; return v; },
    u64(): bigint { need(8); const v = b.readBigUInt64LE(o); o += 8; return v; },
    /** Core's ReadCompactSize: non-canonical encodings are rejected. */
    varint(): number {
      const f = r.u8();
      if (f < 0xfd) return f;
      let v: number;
      if (f === 0xfd) { need(2); v = b.readUInt16LE(o); o += 2; if (v < 0xfd) throw new Error("non-canonical varint"); return v; }
      if (f === 0xfe) { v = r.u32(); if (v <= 0xffff) throw new Error("non-canonical varint"); return v; }
      throw new Error("varint too large");
    },
  };
  return r;
}
const varint = (n: number): Buffer => {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b;
};

export function parseTx(raw: Uint8Array): Tx {
  const b = Buffer.from(raw);
  const r = reader(b);
  const version = r.u32();
  let nIn = r.varint();
  let segwit = false;
  if (nIn === 0) {
    if (r.u8() !== 1) throw new Error("bad segwit flag");
    segwit = true;
    nIn = r.varint();
  }
  const inStart = r.offset - varint(nIn).length;
  const inputs: TxIn[] = [];
  for (let i = 0; i < nIn; i++) {
    const txid = toDisplay(r.bytes(32)), vout = r.u32(), script = r.bytes(r.varint()), sequence = r.u32();
    inputs.push({ txid, vout, script, sequence });
  }
  const nOut = r.varint();
  const outputs: TxOut[] = [];
  for (let i = 0; i < nOut; i++) outputs.push({ value: r.u64(), script: r.bytes(r.varint()) });
  const ioEnd = r.offset;
  if (segwit) for (let i = 0; i < nIn; i++) { const n = r.varint(); for (let k = 0; k < n; k++) r.bytes(r.varint()); }
  const locktime = r.u32();
  if (r.offset !== b.length) throw new Error("trailing bytes after the transaction");
  if (nIn === 0 || nOut === 0) throw new Error("a transaction needs inputs and outputs");
  const stripped = Buffer.concat([b.subarray(0, 4), b.subarray(inStart, ioEnd), b.subarray(b.length - 4)]);
  return { version, inputs, outputs, locktime, stripped, txid: toDisplay(sha256d(stripped)) };
}

export const isCoinbase = (t: Tx): boolean =>
  t.inputs.length === 1 && t.inputs[0].txid === "0".repeat(64) && t.inputs[0].vout === 0xffffffff;

// ── Merkle trees, Core's way (an odd last node pairs with itself) ──

/** Leaves and results in internal byte order. */
export function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) throw new Error("no leaves");
  let level = leaves;
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1] ?? level[i]])));
    level = next;
  }
  return level[0];
}
export function merkleBranch(leaves: Buffer[], index: number): Buffer[] {
  const out: Buffer[] = [];
  let level = leaves, i = index;
  while (level.length > 1) {
    out.push(level[i ^ 1] ?? level[i]);
    const next: Buffer[] = [];
    for (let k = 0; k < level.length; k += 2) next.push(sha256d(Buffer.concat([level[k], level[k + 1] ?? level[k]])));
    level = next; i >>= 1;
  }
  return out;
}
export function rootFromBranch(leaf: Buffer, index: number, branch: Buffer[]): Buffer {
  let h = leaf;
  for (const [d, s] of branch.entries()) h = sha256d((index >> d) & 1 ? Buffer.concat([s, h]) : Buffer.concat([h, s]));
  return h;
}

// ── pay to contract ──

const mod = (a: bigint, m = N) => ((a % m) + m) % m;
const h32 = (h: string) => { if (!/^[0-9a-f]{64}$/.test(h)) throw new Error("not a 32-byte hex hash"); return Buffer.from(h, "hex"); };

export const paymentCommitment = (hashes: string[]): Buffer => {
  if (hashes.length === 0) throw new Error("an output commits to at least one payment hash");
  return taggedHash("bsb/pay", ...hashes.map(h32));
};
/** BIP341's key tweak: Q = P + H_TapTweak(P ‖ m)·G, with m the commitment (or nothing, for BIP86). */
export function tweakKey(internalX: string, m?: Buffer): { outputKey: string; tweak: bigint; oddY: boolean } {
  const P = liftX(int(h32(internalX)));
  if (!P) throw new Error("internal key is not on the curve");
  const t = int(taggedHash("TapTweak", h32(internalX), ...(m ? [m] : [])));
  if (t >= N) throw new Error("tweak out of range");
  const Q = add(P, mul(t, G));
  if (!Q) throw new Error("tweaked key is infinity");
  return { outputKey: be32(Q.x).toString("hex"), tweak: t, oddY: (Q.y & 1n) === 1n };
}
export const payToContract = (payKeyX: string, hashes: string[]) => tweakKey(payKeyX, paymentCommitment(hashes));
export const p2trScript = (outputKey: string): Buffer => Buffer.concat([Buffer.from([0x51, 0x20]), h32(outputKey)]);
/** The secret that spends the output: the pay key's (even-y) secret plus the tweak. */
export const payToContractSecret = (payKey: Key, hashes: string[]): bigint => mod(payKey.d + payToContract(payKey.x, hashes).tweak);

// ── encodings Core wants: bech32m addresses and WIF keys ──

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
const hrpExpand = (hrp: string) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
function toWords(bytes: Buffer): number[] {
  const out: number[] = [];
  let acc = 0, bits = 0;
  for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out.push((acc >> bits) & 31); } }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
}
export const HRP: Record<string, string> = { mainnet: "bc", regtest: "bcrt", signet: "tb" };
/** A witness v1 (taproot) address, BIP350 bech32m. */
export function taprootAddress(outputKey: string, network: string): string {
  const hrp = HRP[network];
  if (!hrp) throw new Error(`no address prefix for ${network}`);
  const data = [1, ...toWords(h32(outputKey))];
  const pm = polymod(hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ 0x2bc830a3;
  const chk = Array.from({ length: 6 }, (_, i) => (pm >>> (5 * (5 - i))) & 31);
  return hrp + "1" + data.concat(chk).map((d) => CHARSET[d]).join("");
}
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58check(payload: Buffer): string {
  const b = Buffer.concat([payload, sha256d(payload).subarray(0, 4)]);
  let n = int(b), s = "";
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x !== 0) break; s = "1" + s; }
  return s;
}
/** A compressed-key WIF for Core's rawtr() descriptor. */
export const wif = (d: bigint, network: string): string =>
  base58check(Buffer.concat([Buffer.from([network === "mainnet" ? 0x80 : 0xef]), be32(d), Buffer.from([1])]));

// ── invoices ──

export interface OnchainInvoice extends Invoice {
  /** x-only key the paying output is tweaked from. */
  readonly payKey: string;
  readonly network: string;
}

const PREFIX = "bsbonchain1";
const invoiceDigest = (v: { h: string; a: number; p: string; k: string; n: string; m: string; x: number }) =>
  sha256("bsb/onchain-invoice|", JSON.stringify([v.h, v.a, v.p, v.k, v.n, v.m, v.x]));

/** Parse and check the payee's signature. Throws on anything malformed or forged. */
export function decodeOnchainInvoice(pr: string): OnchainInvoice {
  if (!pr.startsWith(PREFIX)) throw new Error("not an on-chain invoice");
  const v = JSON.parse(Buffer.from(pr.slice(PREFIX.length), "base64url").toString("utf8"));
  const hex = (s: unknown, n: number) => typeof s === "string" && new RegExp(`^[0-9a-f]{${n}}$`).test(s);
  if (!hex(v.h, 64) || !hex(v.p, 64) || !hex(v.k, 64) || !hex(v.s, 128) || typeof v.n !== "string" || typeof v.m !== "string") throw new Error("malformed invoice");
  if (!Number.isSafeInteger(v.a) || v.a <= 0 || v.a % 1000 !== 0) throw new Error("amount must be whole sats");
  if (!Number.isSafeInteger(v.x)) throw new Error("malformed expiry");
  if (!schnorrVerify(invoiceDigest(v), Buffer.from(v.p, "hex"), Buffer.from(v.s, "hex"))) throw new Error("invoice signature does not verify");
  return { paymentRequest: pr, paymentHash: v.h, amountMsat: v.a, payee: v.p, payKey: v.k, network: v.n, memo: v.m, expiresAt: v.x };
}

/** The provider's side: invoices signed with its Nostr key, payable to outputs only it can spend. */
export class OnchainPayee implements Payee {
  readonly nodeId: string;
  readonly payKey: Key;
  readonly network: string;
  private readonly key: Key;
  readonly issued = new Map<string, OnchainInvoice>();
  private readonly ledger?: Ledger;
  /** Phase 7C: with `ledgerPath`, every invoice is written ahead, so a restarted provider can still
   *  derive the key for, and sweep, payments made to invoices it issued before the crash. */
  constructor(nostrKey: Key, payKey: Key, network: string, ledgerPath?: string) {
    this.key = nostrKey; this.payKey = payKey; this.network = network; this.nodeId = nostrKey.x;
    if (ledgerPath) {
      this.ledger = new Ledger(ledgerPath);
      for (const r of this.ledger.replay()) if (r.t === "invoice") {
        const inv = decodeOnchainInvoice(String(r.pr));
        if (inv.payee !== this.key.x || inv.payKey !== this.payKey.x) throw new Error(`${ledgerPath}: invoice of another payee`);
        this.issued.set(inv.paymentHash, inv);
      }
    }
  }
  async createInvoice(amountMsat: number, memo: string, ttlSec = 3600): Promise<OnchainInvoice> {
    if (!Number.isSafeInteger(amountMsat) || amountMsat <= 0 || amountMsat % 1000 !== 0) throw new Error("amount must be a positive whole number of sats");
    // A tag, not a hash lock: nobody ever needs its preimage.
    const v = { h: sha256(randomBytes(32)).toString("hex"), a: amountMsat, p: this.key.x, k: this.payKey.x, n: this.network, m: memo, x: Math.floor(Date.now() / 1000) + ttlSec };
    const s = schnorrSign(invoiceDigest(v), this.key.d, randomBytes(32)).toString("hex");
    const inv = decodeOnchainInvoice(PREFIX + Buffer.from(JSON.stringify({ ...v, s })).toString("base64url"));
    this.ledger?.append({ t: "invoice", pr: inv.paymentRequest });
    this.issued.set(inv.paymentHash, inv);
    return inv;
  }
  /** The secret for an output paying `hashes`, if they are all this payee's own invoices. */
  secretFor(hashes: string[]): bigint {
    for (const h of hashes) if (!this.issued.has(h)) throw new Error(`not our invoice: ${h.slice(0, 16)}…`);
    return payToContractSecret(this.payKey, hashes);
  }

  /** Spend what the receipts paid this payee: import each output's key, d + t, into a Core wallet of
   *  its own as rawtr(), let the wallet find the coins, and send them all to `to`. Shows the payments
   *  are the payee's to spend, by a path nobody else has the key for. */
  async sweep(node: Rpc, wallet: Rpc, walletName: string, receipts: PaymentReceipt[], to: string, feeRate: number) {
    // A long-lived node keeps the wallet from an earlier sweep but does not load it after a restart.
    try { await node("createwallet", [walletName, false, true]); }
    catch (e) {
      if (!/already exists/.test((e as Error).message)) throw e;
      try { await node("loadwallet", [walletName]); } catch (l) { if (!/already loaded/.test((l as Error).message)) throw l; }
    }
    const outs: { txid: string; vout: number; sats: number }[] = [];
    const descs: { desc: string; timestamp: number }[] = [];
    for (const r of receipts) for (const o of r.outputs) {
      const invs = o.invoices.map(decodeOnchainInvoice);
      if (invs[0]?.payee !== this.nodeId) continue;
      const raw = `rawtr(${wif(this.secretFor(invs.map((i) => i.paymentHash)), this.network)})`;
      descs.push({ desc: `${raw}#${(await node("getdescriptorinfo", [raw])).checksum}`, timestamp: 0 });
      outs.push({ txid: r.txid, vout: o.vout, sats: invs.reduce((s, i) => s + i.amountMsat / 1000, 0) });
    }
    if (outs.length === 0) throw new Error("no payments to sweep");
    const imp = await wallet("importdescriptors", [descs]);
    if (!imp.every((x: any) => x.success)) throw new Error(`importdescriptors: ${JSON.stringify(imp)}`);
    const have = new Set((await wallet("listunspent", [0]) as any[]).map((u) => `${u.txid}:${u.vout}`));
    const missing = outs.filter((o) => !have.has(`${o.txid}:${o.vout}`));
    if (missing.length) throw new Error(`wallet does not see ${missing.map((m) => `${m.txid.slice(0, 12)}…:${m.vout}`).join(", ")}`);
    // Spending a taproot output costs 57.5 vB, so at 5 sat/vB one 512-sat payment is worth less than
    // its own spend (111 vB alone, 555 sats). Then sweep at Core's 1 sat/vB relay floor, and say so.
    // Core says so in one of two ways: the fee is more than the coins ("too low"), or what is left is
    // below the dust limit (at 2 sat/vB, 512 - 222 = 290 sats; seen on a private signet, 2026-10-23).
    let used = feeRate, s: any;
    try { s = await wallet("sendall", [[to], null, "unset", feeRate]); }
    catch (e) {
      if (!/too low|dust/.test((e as Error).message) || feeRate <= 1) throw e;
      used = 1;
      s = await wallet("sendall", [[to], null, "unset", used]);
    }
    if (!s.complete) throw new Error("sendall did not complete");
    return { txid: s.txid as string, outputs: outs, sats: outs.reduce((a, o) => a + o.sats, 0), feeRate: used, ...(used !== feeRate ? { uneconomicAt: feeRate } : {}) };
  }
}

/** Placeholder kind, not registered in the NIPs: a payment receipt, content = PaymentReceipt. */
export const KIND_PAYMENT_RECEIPT = 4247;

/** Tags: p for each payee, x for the txid, e (epoch) for each memo's epoch height. */
export function receiptTags(r: PaymentReceipt): string[][] {
  const tags: string[][] = [["x", r.txid]];
  for (const o of r.outputs) for (const pr of o.invoices) {
    const i = decodeOnchainInvoice(pr);
    if (!tags.some((t) => t[0] === "p" && t[1] === i.payee)) tags.push(["p", i.payee]);
    const m = /^bsb zk epoch (\d+)$/.exec(i.memo);
    if (m) tags.push(["epoch", m[1]]);
  }
  return tags;
}

// ── the payer: a Bitcoin Core descriptor wallet ──

type Rpc = (method: string, params?: unknown[]) => Promise<any>;
const btc = (sats: bigint | number) => (Number(sats) / 1e8).toFixed(8);
const sats = (v: number) => BigInt(Math.round(v * 1e8));

export interface PaidOutput { vout: number; payee: string; payKey: string; invoices: string[]; hashes: string[]; sats: number }
export interface BatchPayment { txid: string; hex: string; vsize: number; feeSats: number; feeRate: number; outputs: PaidOutput[] }

export class OnchainPayer implements Payer {
  readonly nodeId: string;
  readonly network: string;
  /** sat/vB, or a function asked before each payment (net.ts feeRate off regtest). */
  readonly feeRate: number | (() => Promise<number>);
  private readonly rpc: Rpc;
  private readonly paid = new Set<string>();
  private readonly paidTo = new Map<string, number>();
  private readonly ledger?: Ledger;
  /** Signed payments written ahead, by txid: rebroadcast after a restart, never re-paid. */
  readonly sent = new Map<string, string>();
  /** `rpc` talks to the payer's wallet (…/wallet/<name>); `feeRate` is in sat/vB. With `ledgerPath`,
   *  each signed payment is written ahead before it is broadcast (phase 7C), so a restarted client
   *  never pays an invoice twice and can rebroadcast a payment the node may not have relayed. */
  constructor(rpc: Rpc, network: string, feeRate: number | (() => Promise<number>) = 5, nodeId = "onchain-wallet", ledgerPath?: string) {
    this.rpc = rpc; this.network = network; this.feeRate = feeRate; this.nodeId = nodeId;
    if (ledgerPath) {
      this.ledger = new Ledger(ledgerPath);
      for (const r of this.ledger.replay()) if (r.t === "send") {
        for (const o of r.outputs as { payee: string; hashes: string[]; sats: number }[]) {
          for (const h of o.hashes) this.paid.add(h);
          this.paidTo.set(o.payee, (this.paidTo.get(o.payee) ?? 0) + o.sats * 1000);
        }
        this.sent.set(String(r.txid), String(r.hex));
      }
    }
  }

  /** Re-send every written-ahead payment. Idempotent: a confirmed or known transaction is fine. */
  async rebroadcast(): Promise<{ txid: string; ok: boolean; why?: string }[]> {
    const out: { txid: string; ok: boolean; why?: string }[] = [];
    for (const [txid, hex] of this.sent) {
      try { await this.rpc("sendrawtransaction", [hex]); out.push({ txid, ok: true }); }
      catch (e) {
        const why = (e as Error).message;
        out.push({ txid, ok: /already|known|in chain|txn-already/i.test(why), why });
      }
    }
    return out;
  }
  decode(pr: string): OnchainInvoice { return decodeOnchainInvoice(pr); }

  /** One invoice, one transaction. There is no preimage to return; the proof is the receipt. */
  async pay(pr: string, maxMsat: number): Promise<{ preimage: string; txid: string }> {
    const b = await this.payBatch([{ paymentRequest: pr, maxMsat }]);
    return { preimage: "", txid: b.txid };
  }

  /** Pay many invoices in one transaction: one output per payee key, committing to its hashes in
   *  the order given. Every invoice is checked first; any failure pays nothing. */
  async payBatch(items: { paymentRequest: string; maxMsat: number }[]): Promise<BatchPayment> {
    const now = Date.now() / 1000;
    const groups = new Map<string, { payee: string; payKey: string; invs: OnchainInvoice[] }>();
    const seen = new Set<string>();
    for (const it of items) {
      const inv = this.decode(it.paymentRequest);
      if (inv.network !== this.network) throw new Error(`invoice is for ${inv.network}`);
      if (inv.expiresAt < now) throw new Error("invoice expired");
      if (inv.amountMsat > it.maxMsat) throw new Error("invoice amount over max");
      if (this.paid.has(inv.paymentHash) || seen.has(inv.paymentHash)) throw new Error("invoice already paid");
      seen.add(inv.paymentHash);
      const k = `${inv.payee}|${inv.payKey}`;
      if (!groups.has(k)) groups.set(k, { payee: inv.payee, payKey: inv.payKey, invs: [] });
      groups.get(k)!.invs.push(inv);
    }
    if (groups.size === 0) throw new Error("nothing to pay");
    const plan = [...groups.values()].map((g) => {
      const hashes = g.invs.map((i) => i.paymentHash);
      const q = payToContract(g.payKey, hashes).outputKey;
      return { ...g, hashes, script: p2trScript(q).toString("hex"), address: taprootAddress(q, this.network), sats: g.invs.reduce((s, i) => s + i.amountMsat / 1000, 0) };
    });
    for (const p of plan) if (p.sats < 330) throw new Error(`output of ${p.sats} sats is below the taproot dust limit`);
    const rate = typeof this.feeRate === "number" ? this.feeRate : await this.feeRate();
    const f = await this.rpc("walletcreatefundedpsbt", [[], plan.map((p) => ({ [p.address]: btc(p.sats) })), 0,
      { fee_rate: rate, change_type: "bech32m", replaceable: true }]);
    const signed = await this.rpc("walletprocesspsbt", [f.psbt, true, "DEFAULT", true, true]);
    if (!signed.complete || !signed.hex) throw new Error("wallet could not sign the payment");
    const tx = parseTx(Buffer.from(signed.hex, "hex"));
    const outputs: PaidOutput[] = plan.map((p) => {
      const vout = tx.outputs.findIndex((o) => o.script.toString("hex") === p.script);
      if (vout < 0 || tx.outputs[vout].value !== BigInt(p.sats)) throw new Error("funded transaction lost an output");
      return { vout, payee: p.payee, payKey: p.payKey, invoices: p.invs.map((i) => i.paymentRequest), hashes: p.hashes, sats: p.sats };
    });
    // Write ahead: once this record is on disk, these invoices count as paid even if the broadcast
    // or this process fails, and a restart rebroadcasts the same transaction instead of paying again.
    this.ledger?.append({ t: "send", txid: tx.txid, hex: signed.hex, outputs: outputs.map((o) => ({ payee: o.payee, hashes: o.hashes, sats: o.sats })) });
    for (const p of plan) {
      for (const h of p.hashes) this.paid.add(h);
      this.paidTo.set(p.payee, (this.paidTo.get(p.payee) ?? 0) + p.sats * 1000);
    }
    this.sent.set(tx.txid, signed.hex);
    const txid: string = await this.rpc("sendrawtransaction", [signed.hex]);
    if (txid !== tx.txid) throw new Error("node reports a different txid");
    const d = await this.rpc("decoderawtransaction", [signed.hex]);
    const feeSats = Math.round(f.fee * 1e8);
    return { txid, hex: signed.hex, vsize: d.vsize, feeSats, feeRate: feeSats / d.vsize, outputs };
  }

  paidMsatTo(payee: string): number { return this.paidTo.get(payee) ?? 0; }
}

// ── receipts ──

export interface PaymentReceipt {
  v: 1;
  network: string;
  txid: string;
  tx: string;
  block: { height: number; header: string; time: number; index: number; branch: string[]; coinbase: string; coinbaseBranch: string[] };
  outputs: { vout: number; invoices: string[] }[];
  /** How the verifier learns the chain. Here, a header chain from genesis from any mirror. */
  chain: { kind: "headers-standin"; mirror?: string } | { kind: "stark-chain-segment"; proofs: string };
}

/** Build a receipt from a node that has the transaction confirmed (txindex). This side trusts its node;
 *  the verifier trusts nothing it is handed. */
export async function buildReceipt(rpc: Rpc, network: string, txid: string, outputs: { vout: number; invoices: string[] }[], chain: PaymentReceipt["chain"]): Promise<PaymentReceipt> {
  const t = await rpc("getrawtransaction", [txid, 1]);
  if (!t.blockhash) throw new Error(`${txid} is not confirmed`);
  const block = await rpc("getblock", [t.blockhash, 1]);
  const leaves = (block.tx as string[]).map(fromDisplay);
  const index = (block.tx as string[]).indexOf(txid);
  const coinbase = await rpc("getrawtransaction", [block.tx[0], 0, t.blockhash]);
  return {
    v: 1, network, txid, tx: t.hex,
    block: {
      height: block.height, header: await rpc("getblockheader", [t.blockhash, false]), time: block.time, index,
      branch: merkleBranch(leaves, index).map((b) => b.toString("hex")), coinbase, coinbaseBranch: merkleBranch(leaves, 0).map((b) => b.toString("hex")),
    },
    outputs, chain,
  };
}

export interface ReceiptPayment { vout: number; payee: string; paymentHash: string; amountMsat: number; memo: string; expiresAt: number; late: boolean }
export type ReceiptCheck =
  | { ok: true; txid: string; height: number; blockHash: string; confirmations: number; payments: ReceiptPayment[]; bytes: number }
  | { ok: false; why: string };

/**
 * Check a receipt against a header chain. True means: the transaction is in the block at that height
 * of `chain`, at least `minConf` deep, and each listed output pays the payee's committed key at least
 * the sum of the invoices it commits to, each invoice signed by its payee. Nothing here asks a node.
 */
export function verifyReceipt(r: PaymentReceipt, chain: HeaderSource, opts: { network: string; minConf?: number }): ReceiptCheck {
  const fail = (why: string): ReceiptCheck => ({ ok: false, why });
  try {
    if (r.v !== 1 || r.network !== opts.network) return fail("wrong receipt version or network");
    const tx = parseTx(Buffer.from(r.tx, "hex"));
    const cb = parseTx(Buffer.from(r.block.coinbase, "hex"));
    if (tx.txid !== r.txid) return fail("transaction does not hash to the txid");
    // A 64-byte transaction can pose as an inner Merkle node (CVE-2017-12842).
    if (tx.stripped.length === 64 || cb.stripped.length === 64) return fail("64-byte transaction");
    if (!isCoinbase(cb)) return fail("the coinbase is not a coinbase");
    if (isCoinbase(tx)) return fail("the payment is a coinbase");
    const header = parseHeader(Buffer.from(r.block.header, "hex"));
    const { height, index, branch, coinbaseBranch } = r.block;
    if (header.time !== r.block.time) return fail("block time differs from the header");
    if (chain.hashAt(height) !== header.hash) return fail(`block ${height} of the chain is not this header`);
    const confirmations = chain.height - height + 1;
    if (confirmations < (opts.minConf ?? 1)) return fail(`${confirmations} confirmations, need ${opts.minConf ?? 1}`);
    if (branch.length !== coinbaseBranch.length) return fail("branch depth differs from the coinbase's");
    if (!Number.isSafeInteger(index) || index <= 0 || index >= 2 ** branch.length) return fail("index out of range");
    const bs = (a: string[]) => a.map((h) => h32(h));
    if (!rootFromBranch(fromDisplay(tx.txid), index, bs(branch)).equals(header.merkleRoot)) return fail("Merkle branch does not reach the header's root");
    if (!rootFromBranch(fromDisplay(cb.txid), 0, bs(coinbaseBranch)).equals(header.merkleRoot)) return fail("coinbase branch does not reach the header's root");

    const payments: ReceiptPayment[] = [];
    const hashes = new Set<string>(), vouts = new Set<number>();
    for (const o of r.outputs) {
      if (vouts.has(o.vout)) return fail(`output ${o.vout} listed twice`);
      vouts.add(o.vout);
      const out = tx.outputs[o.vout];
      if (!out) return fail(`no output ${o.vout}`);
      const invs = o.invoices.map(decodeOnchainInvoice);
      if (invs.length === 0) return fail(`output ${o.vout} lists no invoices`);
      const { payee, payKey } = invs[0];
      for (const i of invs) {
        if (i.payee !== payee || i.payKey !== payKey) return fail(`output ${o.vout} mixes payees`);
        if (i.network !== opts.network) return fail("invoice for another network");
        if (hashes.has(i.paymentHash)) return fail("a payment hash appears twice");
        hashes.add(i.paymentHash);
      }
      const q = payToContract(payKey, invs.map((i) => i.paymentHash)).outputKey;
      if (!out.script.equals(p2trScript(q))) return fail(`output ${o.vout} does not commit to its invoices`);
      const owed = invs.reduce((s, i) => s + BigInt(i.amountMsat / 1000), 0n);
      if (out.value < owed) return fail(`output ${o.vout} holds ${out.value} sats, the invoices ask ${owed}`);
      for (const i of invs) payments.push({ vout: o.vout, payee, paymentHash: i.paymentHash, amountMsat: i.amountMsat, memo: i.memo, expiresAt: i.expiresAt, late: header.time > i.expiresAt });
    }
    if (payments.length === 0) return fail("no outputs");
    return { ok: true, txid: tx.txid, height, blockHash: header.hash, confirmations, payments, bytes: Buffer.byteLength(JSON.stringify(r)) };
  } catch (e) {
    return fail((e as Error).message);
  }
}

/** The vsize model for a batch: one taproot key-path input, n taproot outputs and taproot change. */
export const batchVsize = (outputs: number, inputs = 1): number => 10.5 + 57.5 * inputs + 43 * (outputs + 1);
