// Blossom storage bonds: Filecoin's storage-proof job rebuilt from Nostr, Blossom, Lightning and plain
// tapscript. Executable companion to docs/design.md; regtest/ runs the same chain as real transactions.
//
// Two layers, and only the second touches the chain:
//
//   1. Pay per proof (off-chain). Each epoch the client sends a fresh nonce over Nostr, the provider
//      answers with Merkle paths for the chunks the nonce selects, the client checks them against the
//      root R it computed at upload, and pays the epoch over Lightning. The client is the verifier, so
//      the client's own randomness is the challenge. No block hash, no oracle, no BitVM.
//   2. Sentinel bond (on-chain, enforceable). The provider locks collateral in a taproot output whose
//      leaves are a chain of precommitted salted-hash challenges (Juels–Kaliski sentinels). To
//      challenge, the client reveals a 16-byte secret r_i in a presigned transaction; the provider must
//      answer within Δ blocks with the 80-byte preimage r_i ‖ window[idx(r_i)], which OP_SHA256 checks
//      against h_i. A miss forfeits the bond. This runs on mainnet today: no OP_CAT, no covenant, no
//      committee. 80 bytes is the largest tapscript stack item Core relays
//      (MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE); consensus would take 520, but a 520-byte answer is
//      rejected as bad-witness-nonstandard (found on regtest, see regtest/).
//
// Each provider stores its own ciphertext of the blob (AES-256-CTR under a per-replica key), so its
// sentinels can only be answered from a copy of that ciphertext. That is the cheap substitute for
// Filecoin's PoRep sealing: it works because the data owner defines the replicas.
//
// What is real: the scripts are real tapscript bytes with real opcodes, the leaf and branch hashes are
// BIP341 tagged hashes, signatures are BIP340 (model/schnorr.ts), the Merkle trees and sentinels hash
// with SHA-256, and replica encryption is node's AES-256-CTR. What is not, here: signatures sign a
// stand-in digest, not a BIP341 sighash; the internal key stands in for a MuSig2 aggregate; the
// interpreter runs only the opcodes these leaves use; transaction sizes are summed from parts. The
// regtest harness does all of that for real and its measured sizes match these to the byte.

import { createCipheriv } from "node:crypto";
import { sha256, taggedHash, schnorrSign, schnorrVerify, type Key } from "./schnorr.ts";

// ───────────────────────────── constants ─────────────────────────────

export const MAX_ELEMENT = 520;            // MAX_SCRIPT_ELEMENT_SIZE: consensus, script/script.h
export const MAX_STANDARD_ITEM = 80;       // MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE: relay policy, policy/policy.h
export const SALT = 16;                    // r: a 128-bit secret
export const WINDOW = MAX_STANDARD_ITEM - SALT;   // 64 bytes: r ‖ window is one standard stack item
export const CHUNK = 4096;                 // Merkle leaf for pay per proof
export const WINDOWS_PER_CHUNK = CHUNK / WINDOW;  // 64
export const TAPLEAF_VERSION = 0xc0;

const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n: number): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const indexFrom = (digest: Uint8Array, n: number): number => Number(Buffer.from(digest).readBigUInt64LE(0) % BigInt(n));

// ───────────────────────────── replicas and chunks ─────────────────────────────

/** Per-replica key. The blob id is in the key, so CTR never reuses a keystream across blobs. */
export const replicaKey = (clientSecret: Uint8Array, blobId: string, providerId: string): Buffer =>
  sha256("bsb/replica-key|", Buffer.from(clientSecret), `|${blobId}|${providerId}`);

export function encryptReplica(plain: Uint8Array, key: Uint8Array): Buffer {
  const c = createCipheriv("aes-256-ctr", key, Buffer.alloc(16));
  return Buffer.concat([c.update(plain), c.final()]);
}

/** Split into CHUNK-byte chunks, zero-padding the last. The deal records the true length. */
export function chunk(data: Uint8Array): Buffer[] {
  const out: Buffer[] = [];
  for (let o = 0; o < Math.max(1, data.length); o += CHUNK) {
    const c = Buffer.alloc(CHUNK);
    Buffer.from(data).copy(c, 0, o, Math.min(o + CHUNK, data.length));
    out.push(c);
  }
  return out;
}

// ───────────────────────────── Merkle commitment ─────────────────────────────
//
// Blossom names a blob by the SHA-256 of the whole file, which cannot open one chunk. The client computes
// a chunk tree at upload and both sides sign R in the deal. Leaves and nodes are domain-separated and
// the root binds n, so duplicating the last node at odd levels cannot be used to forge a second tree.

const leafHash = (c: Uint8Array): Buffer => sha256(Buffer.from([0]), c);
const nodeHash = (l: Uint8Array, r: Uint8Array): Buffer => sha256(Buffer.from([1]), l, r);

export interface Tree { readonly n: number; readonly levels: Buffer[][]; readonly root: Buffer }

export function buildTree(chunks: Buffer[]): Tree {
  const levels: Buffer[][] = [chunks.map(leafHash)];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next: Buffer[] = [];
    for (let i = 0; i < prev.length; i += 2) next.push(nodeHash(prev[i], prev[i + 1] ?? prev[i]));
    levels.push(next);
  }
  const top = levels[levels.length - 1][0];
  return { n: chunks.length, levels, root: sha256(Buffer.from([2]), u64(chunks.length), top) };
}

export function merkleProof(t: Tree, idx: number): Buffer[] {
  const path: Buffer[] = [];
  for (let lvl = 0, i = idx; lvl < t.levels.length - 1; lvl++, i >>= 1) {
    const row = t.levels[lvl];
    path.push(row[i ^ 1] ?? row[i]);
  }
  return path;
}

export function merkleVerify(root: Uint8Array, n: number, idx: number, c: Uint8Array, path: Buffer[]): boolean {
  if (idx < 0 || idx >= n) return false;
  let depth = 0;
  for (let w = n; w > 1; w = Math.ceil(w / 2)) depth++;
  if (path.length !== depth) return false;
  let h = leafHash(c);
  path.forEach((sib, lvl) => { h = (idx >> lvl) & 1 ? nodeHash(sib, h) : nodeHash(h, sib); });
  return sha256(Buffer.from([2]), u64(n), h).equals(Buffer.from(root));
}

// ───────────────────────────── layer 1: pay per proof ─────────────────────────────

export const epochIndices = (nonce: Uint8Array, n: number, q: number): number[] =>
  Array.from({ length: q }, (_, j) => indexFrom(sha256("bsb/epoch|", Buffer.from(nonce), u32(j)), n));

export interface EpochProof { readonly chunks: Buffer[]; readonly paths: Buffer[][] }

/** The provider answers from whatever it still holds; a missing chunk is an empty buffer. */
export function proveEpoch(held: Map<number, Buffer>, t: Tree, nonce: Uint8Array, q: number): EpochProof {
  const idx = epochIndices(nonce, t.n, q);
  return { chunks: idx.map((i) => held.get(i) ?? Buffer.alloc(0)), paths: idx.map((i) => merkleProof(t, i)) };
}

export function verifyEpoch(root: Uint8Array, n: number, nonce: Uint8Array, q: number, p: EpochProof): boolean {
  const idx = epochIndices(nonce, n, q);
  return idx.every((i, j) => p.chunks[j].length === CHUNK && merkleVerify(root, n, i, p.chunks[j], [...p.paths[j]]));
}

/** A provider that keeps a fraction f of chunks passes an epoch with probability f^q (indices drawn with
 *  replacement). Its gain from deleting, per epoch, against storing everything. */
export const epochPass = (f: number, q: number): number => f ** q;
export const deletionGain = (f: number, q: number, price: number, cost: number): number =>
  (epochPass(f, q) * price - f * cost) - (price - cost);

// ───────────────────────────── layer 2: sentinels ─────────────────────────────

export interface Sentinel {
  readonly r: Buffer;      // client secret until the challenge reveals it
  readonly s: Buffer;      // SHA256(r): goes in the bond's challenge leaf
  readonly idx: number;    // which 64-byte window, derived from r so it stays hidden until the reveal
  readonly h: Buffer;      // SHA256(r ‖ window[idx]): goes in the response leaf
}

export const sentinelSecret = (seed: Uint8Array, replicaRoot: Uint8Array, i: number): Buffer =>
  sha256("bsb/sentinel|", Buffer.from(seed), Buffer.from(replicaRoot), u32(i)).subarray(0, SALT);
/** The window index over all n·64 windows of an n-chunk replica. */
export const sentinelIndex = (r: Uint8Array, nChunks: number): number =>
  indexFrom(sha256("bsb/idx|", Buffer.from(r)), nChunks * WINDOWS_PER_CHUNK);
export const windowOf = (c: Buffer, idx: number): Buffer =>
  c.subarray((idx % WINDOWS_PER_CHUNK) * WINDOW, (idx % WINDOWS_PER_CHUNK + 1) * WINDOW);

export function makeSentinel(seed: Uint8Array, t: Tree, chunks: Buffer[], i: number): Sentinel {
  const r = sentinelSecret(seed, t.root, i);
  const idx = sentinelIndex(r, t.n);
  return { r, s: sha256(r), idx, h: sha256(r, windowOf(chunks[Math.floor(idx / WINDOWS_PER_CHUNK)], idx)) };
}

/** What the provider must put on chain once r is revealed: one 80-byte item, or null if it no longer
 *  holds the chunk that contains the window. */
export function sentinelResponse(r: Uint8Array, nChunks: number, held: Map<number, Buffer>): Buffer | null {
  const idx = sentinelIndex(r, nChunks);
  const c = held.get(Math.floor(idx / WINDOWS_PER_CHUNK));
  return c ? Buffer.concat([Buffer.from(r), windowOf(c, idx)]) : null;
}

/** The provider cannot check h_i at setup without learning idx_i, so a client could plant a bad h_i,
 *  challenge it, and take a bond the provider could never save. Cut and choose: the client commits to M
 *  sentinels, the provider opens M − k of its choice, and the bond uses the other k. With b bad sentinels
 *  the chance that none is opened is C(M−b, k)/C(M, k). One bad sentinel is all a thief needs. */
export function cutAndChooseSurvives(M: number, k: number, b: number): number {
  let p = 1;
  for (let j = 0; j < b; j++) p *= (k - j) / (M - j);
  return Math.max(0, p);
}

/** A client that plants one bad sentinel wins the forfeited share α·B if it survives and loses its
 *  setup cost otherwise. The theft is unprofitable when (k/M)·α·B < setupCost. Burning (1−α) of a
 *  forfeit is how to make it unprofitable without a huge M; the zk alternative is in the note. */
export const theftEv = (M: number, k: number, alpha: number, bond: number, setupCost: number): number =>
  cutAndChooseSurvives(M, k, 1) * alpha * bond - (1 - cutAndChooseSurvives(M, k, 1)) * setupCost;

/** Smallest M at which one planted sentinel has negative expected value for the client. Opening costs
 *  the provider one 80-byte SHA-256 per sentinel and the client 64 bytes of commitment, so M in the
 *  tens of thousands is cheap. */
export function minCutAndChoose(k: number, alpha: number, bond: number, setupCost: number): number {
  let M = k + 1;
  while (theftEv(M, k, alpha, bond, setupCost) >= 0) M = Math.ceil(M * 1.01) + 1;
  let lo = Math.max(k + 1, Math.floor(M / 1.01) - 2), hi = M;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (theftEv(mid, k, alpha, bond, setupCost) < 0) hi = mid; else lo = mid + 1; }
  return lo;
}

// ───────────────────────────── tapscript ─────────────────────────────

export const OP = {
  DROP: 0x75, EQUAL: 0x87, EQUALVERIFY: 0x88, SHA256: 0xa8,
  CHECKSIG: 0xac, CHECKSIGVERIFY: 0xad, CLTV: 0xb1, CSV: 0xb2,
} as const;

/** Minimal CScriptNum encoding. */
export function scriptNum(n: number): Buffer {
  if (n === 0) return Buffer.alloc(0);
  const out: number[] = [];
  let a = Math.abs(n);
  while (a > 0) { out.push(a & 0xff); a = Math.floor(a / 256); }
  if (out[out.length - 1] & 0x80) out.push(n < 0 ? 0x80 : 0);
  else if (n < 0) out[out.length - 1] |= 0x80;
  return Buffer.from(out);
}
const decodeNum = (b: Buffer): number => {
  if (b.length === 0) return 0;
  let v = 0;
  for (let i = 0; i < b.length; i++) v += (i === b.length - 1 ? b[i] & 0x7f : b[i]) * 256 ** i;
  return b[b.length - 1] & 0x80 ? -v : v;
};

const push = (d: Uint8Array): Buffer => {
  if (d.length > 75) throw new Error("model pushes at most 75 bytes");
  return Buffer.concat([Buffer.from([d.length]), Buffer.from(d)]);
};
const script = (...parts: Array<number | Uint8Array>): Buffer =>
  Buffer.concat(parts.map((p) => (typeof p === "number" ? Buffer.from([p]) : push(p))));
const xonly = (k: Key): Buffer => Buffer.from(k.x, "hex");
/** A number as MINIMALDATA policy wants it: OP_1..OP_16 for 1..16, else a minimal CScriptNum push. */
const num = (n: number): number | Buffer => (n >= 1 && n <= 16 ? 0x50 + n : scriptNum(n));

/** Bond_i, challenge: the client cosigns the presigned Challenge_i and reveals r_i. */
export const challengeLeaf = (C: Key, P: Key, s: Uint8Array): Buffer =>
  script(xonly(C), OP.CHECKSIGVERIFY, xonly(P), OP.CHECKSIGVERIFY, OP.SHA256, s, OP.EQUAL);
/** Bond_i, refund: the provider alone after the term ends. */
export const refundLeaf = (P: Key, termEnd: number): Buffer =>
  script(num(termEnd), OP.CLTV, OP.DROP, xonly(P), OP.CHECKSIG);
/** Challenged_i, respond: the provider shows r_i ‖ chunk; the client's presignature sends the bond on
 *  to Bond_{i+1}. */
export const respondLeaf = (P: Key, C: Key, h: Uint8Array): Buffer =>
  script(xonly(P), OP.CHECKSIGVERIFY, xonly(C), OP.CHECKSIGVERIFY, OP.SHA256, h, OP.EQUAL);
/** Challenged_i, forfeit: the client after Δ blocks of silence. */
export const forfeitLeaf = (C: Key, delta: number): Buffer =>
  script(num(delta), OP.CSV, OP.DROP, xonly(C), OP.CHECKSIG);

const compactSize = (n: number): Buffer =>
  n < 0xfd ? Buffer.from([n]) : Buffer.concat([Buffer.from([0xfd]), Buffer.from([n & 0xff, n >> 8])]);

export const tapLeafHash = (s: Uint8Array): Buffer =>
  taggedHash("TapLeaf", Buffer.from([TAPLEAF_VERSION]), compactSize(s.length), Buffer.from(s));
export const tapBranch = (a: Uint8Array, b: Uint8Array): Buffer =>
  Buffer.compare(Buffer.from(a), Buffer.from(b)) < 0 ? taggedHash("TapBranch", a, b) : taggedHash("TapBranch", b, a);

/** Every state in the chain is a two-leaf tree: depth 1, a 65-byte control block. */
export const twoLeafRoot = (a: Uint8Array, b: Uint8Array): Buffer => tapBranch(tapLeafHash(a), tapLeafHash(b));

// ───────────────────────────── interpreter (the opcodes above, and OP_1..OP_16) ─────────────────────────────

export interface SpendCtx {
  /** BIP340 check against the stand-in digest of the spending transaction. */
  readonly digest: Buffer;
  readonly lockTime: number;     // nLockTime of the spending tx (block heights only)
  readonly age: number;          // confirmations of the spent output (for CSV)
}

export type ScriptResult = { ok: true } | { ok: false; why: string };

/** Relay policy, not consensus: Core's IsWitnessStandard rejects any tapscript stack item (other than
 *  the script and control block) over 80 bytes, as bad-witness-nonstandard. */
export const isStandardTapscriptStack = (stack: Buffer[]): boolean => stack.every((w) => w.length <= MAX_STANDARD_ITEM);

/** BIP342 rules that matter here: every initial stack element ≤ 520 bytes; a non-empty invalid
 *  signature fails the script; CHECKSIG with an empty signature pushes false; exactly one true element
 *  must remain (clean stack is consensus in tapscript). */
export function runTapscript(s: Buffer, witness: Buffer[], ctx: SpendCtx): ScriptResult {
  if (witness.some((w) => w.length > MAX_ELEMENT)) return { ok: false, why: "stack element over 520 bytes" };
  const st = [...witness];
  const truthy = (b: Buffer | undefined) => b !== undefined && b.some((x, i) => x !== 0 && !(i === b.length - 1 && x === 0x80));
  for (let pc = 0; pc < s.length; ) {
    const op = s[pc++];
    if (op >= 1 && op <= 75) { st.push(s.subarray(pc, pc + op)); pc += op; continue; }
    if (op >= 0x51 && op <= 0x60) { st.push(Buffer.from([op - 0x50])); continue; }
    switch (op) {
      case OP.DROP: if (!st.pop()) return { ok: false, why: "DROP on empty stack" }; break;
      case OP.SHA256: { const a = st.pop(); if (!a) return { ok: false, why: "SHA256 on empty stack" }; st.push(sha256(a)); break; }
      case OP.EQUAL: case OP.EQUALVERIFY: {
        const b = st.pop(), a = st.pop();
        if (!a || !b) return { ok: false, why: "EQUAL on short stack" };
        const eq = a.equals(b);
        if (op === OP.EQUALVERIFY) { if (!eq) return { ok: false, why: "EQUALVERIFY failed" }; }
        else st.push(eq ? Buffer.from([1]) : Buffer.alloc(0));
        break;
      }
      case OP.CHECKSIG: case OP.CHECKSIGVERIFY: {
        const pub = st.pop(), sig = st.pop();
        if (!pub || sig === undefined) return { ok: false, why: "CHECKSIG on short stack" };
        let good = false;
        if (sig.length > 0) {
          if (!schnorrVerify(ctx.digest, pub, sig)) return { ok: false, why: "invalid signature" };
          good = true;
        }
        if (op === OP.CHECKSIGVERIFY) { if (!good) return { ok: false, why: "CHECKSIGVERIFY with empty signature" }; }
        else st.push(good ? Buffer.from([1]) : Buffer.alloc(0));
        break;
      }
      case OP.CLTV: {
        const t = st[st.length - 1];
        if (!t) return { ok: false, why: "CLTV on empty stack" };
        if (ctx.lockTime < decodeNum(t)) return { ok: false, why: "CLTV: locktime not reached" };
        break;
      }
      case OP.CSV: {
        const t = st[st.length - 1];
        if (!t) return { ok: false, why: "CSV on empty stack" };
        if (ctx.age < decodeNum(t)) return { ok: false, why: "CSV: relative lock not reached" };
        break;
      }
      default: return { ok: false, why: `opcode 0x${op.toString(16)} not in this model` };
    }
  }
  if (st.length !== 1) return { ok: false, why: "stack not clean" };
  return truthy(st[0]) ? { ok: true } : { ok: false, why: "false on top" };
}

/** Stand-in for a BIP341 sighash: the label of the presigned transaction. */
export const digest = (label: string): Buffer => sha256("bsb/stand-in-sighash|", label);
export const sign = (k: Key, label: string): Buffer => schnorrSign(digest(label), k.d);

// ───────────────────────────── transaction sizes ─────────────────────────────
//
// Weight from the parts: non-witness bytes ×4, witness bytes ×1. Every presigned transaction is a TRUC
// (v3) parent with one P2TR output and a P2A anchor, bumped by a 1-in-1-out child.

const P2TR_OUT = 8 + 1 + 34;
const P2A_OUT = 8 + 1 + 4;
const INPUT = 36 + 1 + 4;
const TX_OVERHEAD = 4 + 1 + 1 + 4;   // version, vin count, vout count, locktime
const KEYPATH_WITNESS = 1 + 1 + 64;

export const witnessBytes = (items: number[]): number => 2 /* marker+flag */ + compactSize(items.length).length +
  items.reduce((a, n) => a + compactSize(n).length + n, 0);
export const vsize = (nonWitness: number, witness: number): number => Math.ceil((nonWitness * 4 + witness) / 4);

/** A one-input script-path spend to one P2TR output plus a P2A anchor. */
export function scriptPathVsize(stack: number[], leaf: number, depth: number): number {
  return vsize(TX_OVERHEAD + INPUT + P2TR_OUT + P2A_OUT, witnessBytes([...stack, leaf, 33 + 32 * depth]));
}

export const TX = {
  /** The provider funds the bond: one keypath input, bond and change outputs. */
  fund: vsize(TX_OVERHEAD + INPUT + 2 * P2TR_OUT, witnessBytes([64])),
  /** Cooperative close by MuSig2 keypath: one input, provider and client outputs. */
  coopClose: vsize(TX_OVERHEAD + INPUT + 2 * P2TR_OUT, witnessBytes([64])),
  /** The CPFP child: the anchor (empty witness) plus one keypath fee input, one output. */
  child: vsize(TX_OVERHEAD + 2 * INPUT + P2TR_OUT, 2 + 1 + KEYPATH_WITNESS),
} as const;

/** On-chain vbytes per deal. Happy path: fund and close. Each challenge the client actually issues adds
 *  a Challenge_i and either a Respond_i or a Forfeit_i, each with its CPFP child. */
export function dealVbytes(challenges: number, leaves: { challenge: number; respond: number }): number {
  const challengeTx = scriptPathVsize([SALT, 64, 64], leaves.challenge, 1);
  const respondTx = scriptPathVsize([MAX_STANDARD_ITEM, 64, 64], leaves.respond, 1);
  return TX.fund + TX.coopClose + challenges * (challengeTx + respondTx + 2 * TX.child);
}
