// NIP-44 v2 encrypted payloads: secp256k1 ECDH, HKDF-SHA256, ChaCha20, HMAC-SHA256, and the NIP's
// power-of-two padding. Checked against the official vectors (layer1/nip44.test.ts). Uses only
// node:crypto plus the model's curve arithmetic.

import { createCipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { N, be32, int, liftX, mul } from "../model/schnorr.ts";

const SALT = Buffer.from("nip44-v2");
const hmac = (key: Uint8Array, ...parts: Uint8Array[]): Buffer => {
  const h = createHmac("sha256", key);
  for (const p of parts) h.update(p);
  return h.digest();
};

/** HKDF-extract(IKM = shared x, salt = "nip44-v2"). Symmetric: conv(a, B) = conv(b, A). */
export function conversationKey(secret: Uint8Array | bigint, pubX: string | Uint8Array): Buffer {
  const d = typeof secret === "bigint" ? secret : int(secret);
  if (d <= 0n || d >= N) throw new Error("invalid secret key");
  const P = liftX(int(typeof pubX === "string" ? Buffer.from(pubX, "hex") : pubX));
  if (!P) throw new Error("invalid public key");
  const S = mul(d, P);
  if (!S) throw new Error("invalid shared point");
  return hmac(SALT, be32(S.x));
}

/** HKDF-expand(conversation key, info = nonce, 76) → chacha key, chacha nonce, hmac key. */
export function messageKeys(convKey: Uint8Array, nonce: Uint8Array): { chachaKey: Buffer; chachaNonce: Buffer; hmacKey: Buffer } {
  if (convKey.length !== 32 || nonce.length !== 32) throw new Error("conversation key and nonce must be 32 bytes");
  const t1 = hmac(convKey, nonce, Buffer.from([1]));
  const t2 = hmac(convKey, t1, nonce, Buffer.from([2]));
  const t3 = hmac(convKey, t2, nonce, Buffer.from([3]));
  const okm = Buffer.concat([t1, t2, t3]).subarray(0, 76);
  return { chachaKey: okm.subarray(0, 32), chachaNonce: okm.subarray(32, 44), hmacKey: okm.subarray(44, 76) };
}

export function paddedLen(len: number): number {
  if (len <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

const chacha = (key: Buffer, nonce12: Buffer, data: Buffer): Buffer => {
  const c = createCipheriv("chacha20", key, Buffer.concat([Buffer.alloc(4), nonce12]));
  return Buffer.concat([c.update(data), c.final()]);
};

export function encrypt(plaintext: string, convKey: Uint8Array, nonce: Uint8Array = randomBytes(32)): string {
  const pt = Buffer.from(plaintext, "utf8");
  if (pt.length < 1 || pt.length > 65535) throw new Error("plaintext must be 1..65535 bytes");
  const k = messageKeys(convKey, nonce);
  const padded = Buffer.alloc(2 + paddedLen(pt.length));
  padded.writeUInt16BE(pt.length, 0);
  pt.copy(padded, 2);
  const ct = chacha(k.chachaKey, k.chachaNonce, padded);
  const mac = hmac(k.hmacKey, nonce, ct);
  return Buffer.concat([Buffer.from([2]), Buffer.from(nonce), ct, mac]).toString("base64");
}

export function decrypt(payload: string, convKey: Uint8Array): string {
  if (payload.length === 0 || payload[0] === "#") throw new Error("unknown encryption version");
  if (payload.length < 132 || payload.length > 87472) throw new Error("invalid payload size");
  const raw = Buffer.from(payload, "base64");
  if (raw.toString("base64") !== payload) throw new Error("invalid base64");
  if (raw.length < 99 || raw.length > 65603) throw new Error("invalid data size");
  if (raw[0] !== 2) throw new Error("unknown encryption version");
  const nonce = raw.subarray(1, 33), ct = raw.subarray(33, raw.length - 32), mac = raw.subarray(raw.length - 32);
  const k = messageKeys(convKey, nonce);
  if (!timingSafeEqual(hmac(k.hmacKey, nonce, ct), mac)) throw new Error("invalid MAC");
  const padded = chacha(k.chachaKey, k.chachaNonce, ct);
  const len = padded.readUInt16BE(0);
  if (len < 1 || padded.length !== 2 + paddedLen(len)) throw new Error("invalid padding");
  if (padded.subarray(2 + len).some((b) => b !== 0)) throw new Error("invalid padding");
  return padded.subarray(2, 2 + len).toString("utf8");
}
