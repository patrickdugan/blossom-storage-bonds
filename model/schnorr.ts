// BIP340 Schnorr over secp256k1 in plain bigint arithmetic. Enough for the model: keys, sign, verify,
// tagged hashes. Not constant time; never use it for real keys.

import { createHash } from "node:crypto";

export const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export const sha256 = (...parts: Array<Uint8Array | string>): Buffer => {
  const h = createHash("sha256");
  for (const p of parts) h.update(typeof p === "string" ? Buffer.from(p, "utf8") : p);
  return h.digest();
};
export const taggedHash = (tag: string, ...parts: Uint8Array[]): Buffer => {
  const t = sha256(tag);
  return sha256(t, t, ...parts);
};

const mod = (a: bigint, m = P): bigint => ((a % m) + m) % m;
function inv(a: bigint, m = P): bigint {
  let [x, y, r0, r1] = [1n, 0n, mod(a, m), m];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [x, y] = [y, x - q * y]; }
  return mod(x, m);
}
function powMod(b: bigint, e: bigint, m = P): bigint {
  let r = 1n; b = mod(b, m);
  for (; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m;
  return r;
}

export type Point = { x: bigint; y: bigint } | null;
export const G: Point = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};
export function add(a: Point, b: Point): Point {
  if (!a) return b; if (!b) return a;
  if (a.x === b.x && mod(a.y + b.y) === 0n) return null;
  const l = a.x === b.x ? mod(3n * a.x * a.x * inv(2n * a.y)) : mod((b.y - a.y) * inv(b.x - a.x));
  const x = mod(l * l - a.x - b.x);
  return { x, y: mod(l * (a.x - x) - a.y) };
}
export function mul(k: bigint, p: Point): Point {
  let r: Point = null;
  for (k = mod(k, N); k > 0n; k >>= 1n, p = add(p, p)) if (k & 1n) r = add(r, p);
  return r;
}
export function liftX(x: bigint): Point {
  if (x >= P) return null;
  const c = mod(x ** 3n + 7n);
  const y = powMod(c, (P + 1n) / 4n);
  if (mod(y * y) !== c) return null;
  return { x, y: y & 1n ? P - y : y };
}

export const be32 = (n: bigint): Buffer => Buffer.from(n.toString(16).padStart(64, "0"), "hex");
export const int = (b: Uint8Array): bigint => (b.length === 0 ? 0n : BigInt("0x" + Buffer.from(b).toString("hex")));

/** d is normalised so that d·G has an even y, as BIP340 x-only keys require. */
export interface Key { readonly d: bigint; readonly x: string }
export function keyFrom(d0: bigint): Key {
  const Q = mul(d0, G)!;
  return { d: Q.y & 1n ? N - d0 : d0, x: be32(Q.x).toString("hex") };
}
export const keyFromSeed = (seed: string): Key => keyFrom(mod(int(sha256("bsb-fixture-key|", seed)), N) || 1n);

export function schnorrSign(m: Uint8Array, d: bigint, aux: Uint8Array = Buffer.alloc(32)): Buffer {
  const Px = be32(mul(d, G)!.x);
  const t = be32(d ^ int(taggedHash("BIP0340/aux", aux)));
  const k0 = mod(int(taggedHash("BIP0340/nonce", t, Px, m)), N);
  if (k0 === 0n) throw new Error("nonce is zero");
  const R = mul(k0, G)!;
  const k = R.y & 1n ? N - k0 : k0;
  const e = mod(int(taggedHash("BIP0340/challenge", be32(R.x), Px, m)), N);
  return Buffer.concat([be32(R.x), be32(mod(k + e * d, N))]);
}

export function schnorrVerify(m: Uint8Array, pubx: Uint8Array, sig: Uint8Array): boolean {
  if (pubx.length !== 32 || sig.length !== 64) return false;
  const Pk = liftX(int(pubx));
  const r = int(sig.subarray(0, 32)), s = int(sig.subarray(32, 64));
  if (!Pk || r >= P || s >= N) return false;
  const e = mod(int(taggedHash("BIP0340/challenge", sig.subarray(0, 32), pubx, m)), N);
  const R = add(mul(s, G), mul(N - e, Pk));
  return R !== null && (R.y & 1n) === 0n && R.x === r;
}
