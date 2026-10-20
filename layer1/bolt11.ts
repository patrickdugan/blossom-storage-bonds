// BOLT 11 invoice decoding, with the payee's node id recovered from the signature. A receipt carries
// the invoice and the preimage, so anyone holding the receipt can check, with no node and no network,
// that the preimage opens the hash the payee signed for that amount. The client also checks the payee
// before it pays.
//
// Reader rules followed (BOLT 11 "A reader"): Bech32 checksum without the 90-character limit; the
// amount and multiplier, with no sub-millisatoshi `p` amounts; exactly one `p` and one `s`, both 52
// words; exactly one of `d` or `h`; `n` must be 53 words, and if present the signature must verify
// against it and be low-S; otherwise the key is recovered (high-S allowed); unknown even feature bits
// fail. Fields the market does not use (`f`, `r`, `m`, `c`) are skipped. Not constant time, which is
// fine: decoding handles only public data.

import { G, N, add, int, liftX, mul, sha256, type Point } from "../model/schnorr.ts";
import type { Invoice } from "./lightning.ts";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
const hrpExpand = (hrp: string) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));

/** Bech32 (not bech32m), with no length limit, as BOLT 11 requires. */
export function bech32Decode(s: string): { hrp: string; words: number[] } {
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error("mixed case");
  s = s.toLowerCase();
  const sep = s.lastIndexOf("1");
  if (sep < 1 || sep + 7 > s.length) throw new Error("no separator or too short");
  const hrp = s.slice(0, sep);
  for (const c of hrp) if (c.charCodeAt(0) < 33 || c.charCodeAt(0) > 126) throw new Error("bad hrp character");
  const data = [...s.slice(sep + 1)].map((c) => { const v = CHARSET.indexOf(c); if (v < 0) throw new Error("bad data character"); return v; });
  if (polymod(hrpExpand(hrp).concat(data)) !== 1) throw new Error("bad checksum");
  return { hrp, words: data.slice(0, -6) };
}

/** 5-bit words to bytes, zero-padding the last byte (used for signing data and for field values). */
function toBytes(words: number[], pad: boolean): Buffer {
  const out: number[] = [];
  let acc = 0, bits = 0;
  for (const w of words) {
    acc = (acc << 5) | w; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
    acc &= (1 << bits) - 1;
  }
  if (pad && bits > 0) out.push((acc << (8 - bits)) & 0xff);
  return Buffer.from(out);
}
const wordsInt = (words: number[]) => words.reduce((a, w) => a * 32 + w, 0);

const modN = (a: bigint) => ((a % N) + N) % N;
function invN(a: bigint): bigint {
  let [x, y, r0, r1] = [1n, 0n, modN(a), N];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [x, y] = [y, x - q * y]; }
  return modN(x);
}
const P_FIELD = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const compress = (p: NonNullable<Point>) => (p.y & 1n ? "03" : "02") + p.x.toString(16).padStart(64, "0");
function decompress(hex: string): Point {
  const b = Buffer.from(hex, "hex");
  if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3)) return null;
  const p = liftX(int(b.subarray(1)));
  if (!p) return null;
  return (p.y & 1n) === BigInt(b[0] & 1) ? p : { x: p.x, y: P_FIELD - p.y };
}

/** ECDSA public-key recovery: Q = r⁻¹(sR − eG). */
function recover(e: bigint, r: bigint, s: bigint, recid: number): Point {
  if (r <= 0n || r >= N || s <= 0n || s >= N || recid < 0 || recid > 3) return null;
  const R0 = liftX(recid & 2 ? r + N : r);
  if (!R0) return null;
  const R = (R0.y & 1n) === BigInt(recid & 1) ? R0 : { x: R0.x, y: P_FIELD - R0.y };
  const eG = mul(modN(-e), G);
  return mul(invN(r), add(mul(s, R), eG));
}
function verify(e: bigint, r: bigint, s: bigint, Q: Point): boolean {
  if (!Q || r <= 0n || r >= N || s <= 0n || s >= N) return false;
  const w = invN(s);
  const X = add(mul(modN(e * w), G), mul(modN(r * w), Q));
  return X !== null && modN(X.x) === r;
}

const MULT: Record<string, bigint> = { m: 1_000_000_000n, u: 1_000_000n, n: 1_000n, p: 1n };   // in pico-BTC per unit
// Feature bits the market's invoices may set: var_onion (8/9), payment_secret (14/15), basic_mpp
// (16/17), route blinding (24/25), payment_metadata (48/49). Unknown odd bits are fine; unknown even fail.
const KNOWN_FEATURES = new Set([8, 9, 14, 15, 16, 17, 24, 25, 48, 49]);

export interface Bolt11 extends Invoice {
  readonly network: string;          // hrp currency: bc, tb, tbs, bcrt, ...
  readonly timestamp: number;
  readonly paymentSecret: string;
  readonly descriptionHash?: string;
  readonly minFinalCltvDelta: number;
  readonly features: number[];
}

export function decodeBolt11(pr: string): Bolt11 {
  const { hrp, words } = bech32Decode(pr);
  const m = /^ln([a-z]+?)(?:(\d+)([munp]?))?$/.exec(hrp);
  if (!m) throw new Error("not a lightning invoice");
  const network = m[1];
  if (!["bc", "tb", "tbs", "bcrt", "sb"].includes(network)) throw new Error(`unknown currency ${network}`);
  // No amount is legal (a donation invoice); amountMsat is then 0 and payers here refuse it.
  let msat = 0n;
  if (m[2] !== undefined) {
    if (m[2].startsWith("0")) throw new Error("amount has a leading zero");
    if (m[3] === "p" && !m[2].endsWith("0")) throw new Error("sub-millisatoshi amount");
    const pico = BigInt(m[2]) * (m[3] ? MULT[m[3]] : 1_000_000_000_000n);
    if (pico % 10n !== 0n) throw new Error("sub-millisatoshi amount");
    msat = pico / 10n;
    if (msat <= 0n || msat > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("amount out of range");
  }

  if (words.length < 7 + 104) throw new Error("too short");
  const sigWords = words.slice(-104), body = words.slice(0, -104);
  const timestamp = wordsInt(body.slice(0, 7));
  const fields = new Map<number, number[][]>();
  for (let i = 7; i < body.length;) {
    if (i + 3 > body.length) throw new Error("truncated field");
    const type = body[i], len = body[i + 1] * 32 + body[i + 2];
    if (i + 3 + len > body.length) throw new Error("field overruns data");
    const v = body.slice(i + 3, i + 3 + len);
    fields.set(type, [...(fields.get(type) ?? []), v]);
    i += 3 + len;
  }
  const one = (type: number, name: string, len?: number): number[] | undefined => {
    const vs = fields.get(type);
    if (!vs) return undefined;
    if (vs.length !== 1) throw new Error(`more than one ${name} field`);
    if (len !== undefined && vs[0].length !== len) throw new Error(`${name} field has length ${vs[0].length}, not ${len}`);
    return vs[0];
  };
  const p = one(1, "p", 52), s = one(16, "s", 52), d = one(13, "d"), h = one(23, "h", 52), n = one(19, "n", 53);
  const x = one(6, "x"), c = one(24, "c"), f9 = one(5, "9");
  if (!p) throw new Error("no payment hash");
  if (!s) throw new Error("no payment secret");
  if ((d === undefined) === (h === undefined)) throw new Error("need exactly one of d and h");
  for (const [v, name] of [[x, "x"], [c, "c"], [f9, "9"]] as const) if (v && v.length > 0 && v[0] === 0) throw new Error(`${name} field is not minimal`);
  let memo = "";
  if (d) {
    memo = new TextDecoder("utf-8", { fatal: true }).decode(toBytes(d, false));
  }
  const features: number[] = [];
  if (f9) for (let i = 0; i < f9.length; i++) for (let b = 0; b < 5; b++) if ((f9[f9.length - 1 - i] >> b) & 1) features.push(i * 5 + b);
  for (const bit of features) if (bit % 2 === 0 && !KNOWN_FEATURES.has(bit)) throw new Error(`unknown required feature ${bit}`);

  const sig = toBytes(sigWords, false);
  if (sig.length !== 65) throw new Error("bad signature length");
  const e = int(sha256(Buffer.from(hrp, "utf8"), toBytes(body, true)));
  const r = int(sig.subarray(0, 32)), sv = int(sig.subarray(32, 64)), recid = sig[64];
  let payee: string;
  if (n) {
    const key = toBytes(n, false).toString("hex");
    if (sv > N / 2n) throw new Error("high-S signature with an n field");
    if (!verify(e, r, sv, decompress(key))) throw new Error("signature does not verify against n");
    payee = key;
  } else {
    const Q = recover(e, r, sv, recid);
    if (!Q || !verify(e, r, sv, Q)) throw new Error("signature is not recoverable");
    payee = compress(Q);
  }
  const expiry = x ? wordsInt(x) : 3600;
  return {
    paymentRequest: pr, paymentHash: toBytes(p, false).toString("hex"), amountMsat: Number(msat), payee, memo,
    expiresAt: timestamp + expiry, network, timestamp, paymentSecret: toBytes(s, false).toString("hex"),
    descriptionHash: h ? toBytes(h, false).toString("hex") : undefined, minFinalCltvDelta: c ? wordsInt(c) : 18, features,
  };
}
