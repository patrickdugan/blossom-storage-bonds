// Aggregated storage proof (phase 3a): the statement zk/cairo proves, and its witness.
//
// One provider, one epoch, every deal at once. Public: a challenge seed (later a Bitcoin block
// hash), q, and the deal list (chunk-tree root R_i and chunk count n_i per deal). The provider
// shows q chunks per deal at indices it cannot choose:
//
//   nonce_i = H("bsb/zk-pdp/deal|" ‖ seed ‖ R_i)
//   idx_ij  = u64le(H("bsb/zk-pdp/chal|" ‖ nonce_i ‖ u32le(j))[0..8]) mod n_i,  j < q
//
// The Cairo program recomputes the indices, hashes each 4 KiB chunk into its leaf, climbs its
// Merkle path to R_i, and outputs (seed, q, number of deals, D), with D a digest of the deal
// list. A verifier who knows the deals it cares about recomputes D and needs nothing else: the
// chunks stay private and the proof is about the same size for any number of deals.
//
// Two backends. "sha" is the protocol's tree (storage_bonds.ts: SHA-256, prefix bytes 0/1/2,
// root binds n) with 16-byte tags that keep the challenge preimages word-aligned. "blake" is the
// same shape with Blake2s-256 and domain separation by personalization (zk/cairo/src/
// blake_tree.cairo), which stwo-cairo proves with a native opcode; it exists to measure what the
// hash choice costs. This is layer 1's epoch (storage_bonds.ts epochIndices) with each deal's
// nonce derived from one public seed instead of sent by each client.
//
// Mode 1 (holdings, phase 3b) draws the q challenges across all of the provider's chunks at once,
// so a proof's cost depends on q and not on the number of deals:
//
//   nonce = H_hold(seed ‖ D),  g_j = u64le(H("bsb/zk-pdp/chal|" ‖ nonce ‖ u32le(j))[0..8]) mod N,
//   N = Σ n_i, and g_j names deal k and index g_j − (n_0 + … + n_(k-1)).
//
// A provider that dropped a fraction f of all its chunks passes with probability (1 − f)^q, the
// same as one deal of the same total size. The trade-off: a small deal is sampled only in
// proportion to its size, so q per epoch no longer guarantees q looks at every deal.

import { createCipheriv } from "node:crypto";
import { sha256 } from "./schnorr.ts";
import { blake2s } from "./blake2s.ts";
import { CHUNK, leafHash, merkleProof, treeFromLeaves } from "./storage_bonds.ts";

export type Backend = "sha" | "blake";

const u32le = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64le = (n: number): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u64be = (n: number): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const P = (s: string): Buffer => Buffer.from(`bsb-${s}`);   // 8-byte Blake2s personalizations

interface Hashes {
  leaf(chunk: Buffer): Buffer;
  node(l: Buffer, r: Buffer): Buffer;
  root(n: number, top: Buffer): Buffer;
  nonce(seed: Buffer, root: Buffer): Buffer;
  chal(nonce: Buffer, j: number): Buffer;
  dset(deals: DealRef[]): Buffer;
  hold(seed: Buffer, dset: Buffer): Buffer;
  /** 32-bit words of a byte string, in the order the Cairo backend reads them. */
  words(b: Buffer): number[];
}

const be = (b: Buffer): number[] => Array.from({ length: b.length / 4 }, (_, i) => b.readUInt32BE(4 * i));
const le = (b: Buffer): number[] => Array.from({ length: b.length / 4 }, (_, i) => b.readUInt32LE(4 * i));

const HASHES: Record<Backend, Hashes> = {
  sha: {
    leaf: leafHash,
    node: (l, r) => sha256(Buffer.from([1]), l, r),
    root: (n, top) => sha256(Buffer.from([2]), u64le(n), top),
    nonce: (seed, root) => sha256("bsb/zk-pdp/deal|", seed, root),
    chal: (nonce, j) => sha256("bsb/zk-pdp/chal|", nonce, u32le(j)),
    dset: (deals) => sha256("bsb/zk-pdp/dset|", ...deals.flatMap((d) => [d.root, u64be(d.n)])),
    hold: (seed, dset) => sha256("bsb/zk-pdp/hold|", seed, dset),
    words: be,
  },
  blake: {
    leaf: (c) => blake2s(c, P("leaf")),
    node: (l, r) => blake2s(Buffer.concat([l, r]), P("node")),
    root: (n, top) => blake2s(Buffer.concat([u64le(n), top]), P("root")),
    nonce: (seed, root) => blake2s(Buffer.concat([seed, root]), P("deal")),
    chal: (nonce, j) => blake2s(Buffer.concat([nonce, u32le(j)]), P("chal")),
    dset: (deals) => blake2s(Buffer.concat(deals.flatMap((d) => [d.root, u64le(d.n)])), P("dset")),
    hold: (seed, dset) => blake2s(Buffer.concat([seed, dset]), P("hold")),
    words: le,
  },
};

export interface DealRef { readonly root: Buffer; readonly n: number }
export interface Tree { readonly n: number; readonly levels: Buffer[][]; readonly root: Buffer }

/** The chunk tree from its leaves. For "sha" this is storage_bonds.ts treeFromLeaves itself. */
export function treeOf(backend: Backend, leaves: Buffer[]): Tree {
  if (backend === "sha") return treeFromLeaves(leaves);
  const H = HASHES[backend];
  const levels: Buffer[][] = [leaves];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next: Buffer[] = [];
    for (let i = 0; i < prev.length; i += 2) next.push(H.node(prev[i], prev[i + 1] ?? prev[i]));
    levels.push(next);
  }
  return { n: leaves.length, levels, root: H.root(leaves.length, levels[levels.length - 1][0]) };
}

/** One chunk's leaf hash in this backend's tree. */
export const leafOf = (backend: Backend, chunk: Buffer): Buffer => HASHES[backend].leaf(chunk);

export function challengeIndices(backend: Backend, seed: Buffer, d: DealRef, q: number): number[] {
  const H = HASHES[backend];
  const nonce = H.nonce(seed, d.root);
  return Array.from({ length: q }, (_, j) => Number(H.chal(nonce, j).readBigUInt64LE(0) % BigInt(d.n)));
}

export const dealsDigest = (backend: Backend, deals: DealRef[]): Buffer => HASHES[backend].dset(deals);

export type Mode = 0 | 1;

/** Holdings mode: the q challenges over all deals' chunks, as (deal, index within the deal). */
export function holdingsChallenges(backend: Backend, seed: Buffer, deals: DealRef[], q: number): { deal: number; idx: number }[] {
  const H = HASHES[backend];
  const total = deals.reduce((a, d) => a + d.n, 0);
  if (total >= 2 ** 32) throw new Error("over 2^32 chunks");
  const nonce = H.hold(seed, H.dset(deals));
  return Array.from({ length: q }, (_, j) => {
    let g = Number(H.chal(nonce, j).readBigUInt64LE(0) % BigInt(total));
    let k = 0;
    while (g >= deals[k].n) { g -= deals[k].n; k++; }
    return { deal: k, idx: g };
  });
}

const hex = (n: number | bigint): string => "0x" + n.toString(16);

/** The program's public output, felt by felt: seed (8 words), q, mode, deal count, D (8 words). */
export function statementOutput(backend: Backend, seed: Buffer, q: number, deals: DealRef[], mode: Mode = 0): string[] {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const H = HASHES[backend];
  return [...H.words(seed), q, mode, deals.length, ...H.words(H.dset(deals))].map(hex);
}

/** The RISC Zero guest's journal (zk/risc0, phase 6): statementOutput's 19 felts, each as a
 *  big-endian u32, 76 bytes. For "sha" the seed and D come out as their raw bytes, so the journal
 *  is seed ‖ u32be(q) ‖ u32be(mode) ‖ u32be(deal count) ‖ D. */
export function journalBytes(seed: Buffer, q: number, deals: DealRef[], mode: Mode = 1): Buffer {
  return Buffer.concat(statementOutput("sha", seed, q, deals, mode).map((h) => {
    const b = Buffer.alloc(4); b.writeUInt32BE(Number(h)); return b;
  }));
}

/** The RISC Zero holdings guest's input stream (zk/risc0/methods/guest/src/bin/hold.rs): seed,
 *  u32le q, u32le deal count, per deal (root, u32le n), then per challenge j (u32le deal, the
 *  4 KiB chunk, u32le path length, path). Mode 1 and "sha" only. Like witnessFelts, it throws on a
 *  missing chunk unless `substitute` supplies bytes to send in its place. */
export function risc0Witness(seed: Buffer, q: number, deals: HeldDeal[],
  substitute?: (deal: number, idx: number) => Buffer): Buffer {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const refs = deals.map((d) => ({ root: d.tree.root, n: d.tree.n }));
  const parts: Buffer[] = [seed, u32le(q), u32le(deals.length)];
  for (const r of refs) parts.push(r.root, u32le(r.n));
  for (const c of holdingsChallenges("sha", seed, refs, q)) {
    let chunk = deals[c.deal].chunk(c.idx);
    if (!chunk) {
      if (!substitute) throw new Error(`deal ${c.deal}: challenged chunk ${c.idx} is not held`);
      chunk = substitute(c.deal, c.idx);
    }
    if (chunk.length !== CHUNK) throw new Error("chunk size");
    const path = merkleProof(deals[c.deal].tree, c.idx);
    parts.push(u32le(c.deal), chunk, u32le(path.length), ...path);
  }
  return Buffer.concat(parts);
}

/** One deal as the provider holds it: the tree, and whatever chunks it still has. */
export interface HeldDeal { readonly tree: Tree; readonly chunk: (i: number) => Buffer | undefined }

/** Cairo Serde of the witness (zk/cairo/src/lib.cairo, `Args`). Throws if a challenged chunk is
 *  missing, unless `substitute` supplies bytes to send in its place (which the program rejects). */
export function witnessFelts(backend: Backend, seed: Buffer, q: number, deals: HeldDeal[],
  substitute?: (deal: number, idx: number) => Buffer, mode: Mode = 0): string[] {
  const H = HASHES[backend];
  const f: (number | bigint)[] = [...H.words(seed), q, mode, deals.length];
  const opening = (di: number, idx: number) => {
    const d = deals[di];
    let c = d.chunk(idx);
    if (!c) {
      if (!substitute) throw new Error(`deal ${di}: challenged chunk ${idx} is not held`);
      c = substitute(di, idx);
    }
    if (c.length !== CHUNK) throw new Error("chunk size");
    if (backend === "sha") {
      const msg = Buffer.concat([Buffer.from([0]), c]);   // leaf preimage, 4097 bytes
      f.push(1024, ...be(msg.subarray(0, 4096)), msg[4096]);
    } else {
      f.push(1024, ...le(c), 0);
    }
    const path = merkleProof(d.tree, idx);
    f.push(path.length, ...path.flatMap(H.words));
  };
  const refs = deals.map((d) => ({ root: d.tree.root, n: d.tree.n }));
  deals.forEach((d, di) => {
    f.push(...H.words(d.tree.root), d.tree.n, mode === 0 ? q : 0);
    if (mode === 0) for (const idx of challengeIndices(backend, seed, refs[di], q)) opening(di, idx);
  });
  if (mode === 0) {
    f.push(0);
  } else {
    const cs = holdingsChallenges(backend, seed, refs, q);
    f.push(cs.length);
    for (const c of cs) { f.push(c.deal); opening(c.deal, c.idx); }
  }
  return f.map(hex);
}

/** The verifier's check natively, without a proof: every challenged chunk opens to its root. */
export function verifyNatively(backend: Backend, seed: Buffer, q: number, deals: HeldDeal[], mode: Mode = 0): boolean {
  const H = HASHES[backend];
  const opens = (d: HeldDeal, i: number) => {
    const c = d.chunk(i);
    if (!c) return false;
    let h = H.leaf(c);
    merkleProof(d.tree, i).forEach((sib, lvl) => {
      h = (i >> lvl) & 1 ? H.node(sib, h) : H.node(h, sib);
    });
    return H.root(d.tree.n, h).equals(d.tree.root);
  };
  const refs = deals.map((d) => ({ root: d.tree.root, n: d.tree.n }));
  if (mode === 1) return holdingsChallenges(backend, seed, refs, q).every((c) => opens(deals[c.deal], c.idx));
  return deals.every((d, di) => challengeIndices(backend, seed, refs[di], q).every((i) => opens(d, i)));
}

/** A synthetic deal of n chunks: AES-256-CTR keystream under a per-deal key, so a 1 GiB deal is
 *  cheap to regenerate chunk by chunk and never needs to sit in memory (like a replica). */
export function syntheticDeal(backend: Backend, label: string, n: number): HeldDeal {
  const key = sha256("bsb/zk-pdp/synthetic|", label);
  const chunk = (i: number): Buffer => {
    const iv = Buffer.alloc(16);
    iv.writeBigUInt64BE(BigInt(i) * BigInt(CHUNK / 16), 8);
    return createCipheriv("aes-256-ctr", key, iv).update(Buffer.alloc(CHUNK));
  };
  const leaves = Array.from({ length: n }, (_, i) => HASHES[backend].leaf(chunk(i)));
  return { tree: treeOf(backend, leaves), chunk };
}
