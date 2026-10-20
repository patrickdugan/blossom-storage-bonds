// BLAKE2s-256 (RFC 7693) with an 8-byte personalization, which node's built-in blake2s256 does not
// expose. Used by the Blake2s variant of the aggregated storage proof (model/zk_pdp.ts); checked
// against node's blake2s256 and the RFC's "abc" vector in zk_pdp.test.ts.

const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const rotr = (x: number, n: number): number => ((x >>> n) | (x << (32 - n))) >>> 0;

function compress(h: Uint32Array, m: Uint32Array, t: number, last: boolean): void {
  const v = new Uint32Array(16);
  v.set(h); v.set(IV, 8);
  v[12] ^= t >>> 0; v[13] ^= Math.floor(t / 2 ** 32);
  if (last) v[14] = ~v[14] >>> 0;
  const g = (a: number, b: number, c: number, d: number, x: number, y: number): void => {
    v[a] = (v[a] + v[b] + x) >>> 0; v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr(v[b] ^ v[c], 12);
    v[a] = (v[a] + v[b] + y) >>> 0; v[d] = rotr(v[d] ^ v[a], 8);
    v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr(v[b] ^ v[c], 7);
  };
  for (const s of SIGMA) {
    g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

/** The initial state for a 32-byte, unkeyed digest with personalization `personal` (8 bytes). */
export function blake2sIV(personal: Uint8Array = new Uint8Array(8)): Uint32Array {
  if (personal.length !== 8) throw new Error("personalization is 8 bytes");
  const h = Uint32Array.from(IV);
  h[0] ^= 0x01010020;
  const p = Buffer.from(personal);
  h[6] ^= p.readUInt32LE(0); h[7] ^= p.readUInt32LE(4);
  return h;
}

export function blake2s(data: Uint8Array, personal?: Uint8Array): Buffer {
  const h = blake2sIV(personal);
  const d = Buffer.from(data);
  const blocks = Math.max(1, Math.ceil(d.length / 64));
  for (let i = 0; i < blocks; i++) {
    const block = Buffer.alloc(64);
    d.copy(block, 0, 64 * i, Math.min(64 * (i + 1), d.length));
    const m = new Uint32Array(16);
    for (let j = 0; j < 16; j++) m[j] = block.readUInt32LE(4 * j);
    const last = i === blocks - 1;
    compress(h, m, last ? d.length : 64 * (i + 1), last);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) out.writeUInt32LE(h[i], 4 * i);
  return out;
}
