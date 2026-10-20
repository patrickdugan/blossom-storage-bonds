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
    words: be,
  },
  blake: {
    leaf: (c) => blake2s(c, P("leaf")),
    node: (l, r) => blake2s(Buffer.concat([l, r]), P("node")),
    root: (n, top) => blake2s(Buffer.concat([u64le(n), top]), P("root")),
    nonce: (seed, root) => blake2s(Buffer.concat([seed, root]), P("deal")),
    chal: (nonce, j) => blake2s(Buffer.concat([nonce, u32le(j)]), P("chal")),
    dset: (deals) => blake2s(Buffer.concat(deals.flatMap((d) => [d.root, u64le(d.n)])), P("dset")),
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

export function challengeIndices(backend: Backend, seed: Buffer, d: DealRef, q: number): number[] {
  const H = HASHES[backend];
  const nonce = H.nonce(seed, d.root);
  return Array.from({ length: q }, (_, j) => Number(H.chal(nonce, j).readBigUInt64LE(0) % BigInt(d.n)));
}

export const dealsDigest = (backend: Backend, deals: DealRef[]): Buffer => HASHES[backend].dset(deals);

const hex = (n: number | bigint): string => "0x" + n.toString(16);

/** The program's public output, felt by felt: seed (8 words), q, deal count, D (8 words). */
export function statementOutput(backend: Backend, seed: Buffer, q: number, deals: DealRef[]): string[] {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const H = HASHES[backend];
  return [...H.words(seed), q, deals.length, ...H.words(H.dset(deals))].map(hex);
}

/** One deal as the provider holds it: the tree, and whatever chunks it still has. */
export interface HeldDeal { readonly tree: Tree; readonly chunk: (i: number) => Buffer | undefined }

/** Cairo Serde of the witness (zk/cairo/src/lib.cairo, `Args`). Throws if a challenged chunk is
 *  missing, unless `substitute` supplies bytes to send in its place (which the program rejects). */
export function witnessFelts(backend: Backend, seed: Buffer, q: number, deals: HeldDeal[],
  substitute?: (deal: number, idx: number) => Buffer): string[] {
  const H = HASHES[backend];
  const f: (number | bigint)[] = [...H.words(seed), q, deals.length];
  deals.forEach((d, di) => {
    f.push(...H.words(d.tree.root), d.tree.n, q);
    for (const idx of challengeIndices(backend, seed, { root: d.tree.root, n: d.tree.n }, q)) {
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
    }
  });
  return f.map(hex);
}

/** The verifier's check natively, without a proof: every challenged chunk opens to its root. */
export function verifyNatively(backend: Backend, seed: Buffer, q: number, deals: HeldDeal[]): boolean {
  const H = HASHES[backend];
  return deals.every((d) => challengeIndices(backend, seed, { root: d.tree.root, n: d.tree.n }, q).every((i) => {
    const c = d.chunk(i);
    if (!c) return false;
    let h = H.leaf(c);
    merkleProof(d.tree, i).forEach((sib, lvl) => {
      h = (i >> lvl) & 1 ? H.node(sib, h) : H.node(h, sib);
    });
    return H.root(d.tree.n, h).equals(d.tree.root);
  }));
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
