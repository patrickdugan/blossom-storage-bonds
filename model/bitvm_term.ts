// Canonical public statement for the storage term proved in zk/risc0/methods/term.
// These are setup terms, not values to trust from the party asserting a proof. A storage
// dispute graph must pin them and bind its Winternitz public-input commitment to this result.
// This module computes that binding; it is not a Bitcoin-script verifier or a chain-work check.
import { createHash } from "node:crypto";

export interface StorageTerm {
  holdId: Uint8Array;
  headerChainId: Uint8Array;
  q: number;
  dealCount: number;
  dealsDigest: Uint8Array;
  firstHeight: number;
  step: number;
  epochs: number;
  depth: number;
}

export interface TermChainClaim {
  tipHeight: number;
  /** Internal Bitcoin hash byte order, as committed by the header-chain guest. */
  tipHash: Uint8Array;
  totalWork: bigint;
}

export interface WrapConstants {
  controlRoot: Uint8Array;
  /** The term guest's image ID, not the holdings guest's image ID. */
  termId: Uint8Array;
  postState: Uint8Array;
  bn254ControlId: Uint8Array;
}

const DOMAIN = Buffer.from("bsb/r0-term|v1");
export const TERM_PREIMAGE_BYTES = 202;
const sha = (bytes: Uint8Array): Buffer => createHash("sha256").update(bytes).digest();
function bytes32(bytes: Uint8Array, field: string): Buffer {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error(`${field}: expected 32 bytes`);
  return Buffer.from(bytes);
}
function u32(value: number, field: string, positive = false): Buffer {
  if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0) || value > 0xffff_ffff) {
    throw new Error(`${field}: expected ${positive ? "positive " : ""}u32`);
  }
  const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes;
}

/** Exact guest layout. Image IDs retain their raw digest bytes; integers are big-endian. */
export function termPreimage(term: StorageTerm, claim: TermChainClaim): Buffer {
  const fields = [
    DOMAIN, bytes32(term.holdId, "holdId"), bytes32(term.headerChainId, "headerChainId"),
    u32(term.q, "q", true), u32(term.dealCount, "dealCount", true), bytes32(term.dealsDigest, "dealsDigest"),
    u32(term.firstHeight, "firstHeight"), u32(term.step, "step", true), u32(term.epochs, "epochs", true),
    u32(term.depth, "depth", true), u32(claim.tipHeight, "tipHeight"), bytes32(claim.tipHash, "tipHash"),
  ];
  const last = BigInt(term.firstHeight) + BigInt(term.epochs - 1) * BigInt(term.step);
  if (last > 0xffff_ffffn || last + BigInt(term.depth) > BigInt(claim.tipHeight)) {
    throw new Error("term schedule exceeds the proven tip and depth");
  }
  if (typeof claim.totalWork !== "bigint" || claim.totalWork <= 0n || claim.totalWork >= (1n << 256n)) {
    throw new Error("totalWork: expected positive u256");
  }
  fields.push(Buffer.from(claim.totalWork.toString(16).padStart(64, "0"), "hex"));
  return Buffer.concat(fields);
}

export const termJournal = (term: StorageTerm, claim: TermChainClaim): Buffer => sha(termPreimage(term, claim));

/** risc0-to-bitvm2 verify_for_guest.circom's fixed claim prefix, matching host/src/wrap.rs. */
export function wrapConstantsDigest(constants: WrapConstants): Buffer {
  const root = bytes32(constants.controlRoot, "controlRoot");
  const reversed = root.map((byte) => {
    let out = 0; for (let bit = 0; bit < 8; bit++) out |= ((byte >>> bit) & 1) << (7 - bit);
    return out;
  });
  return sha(Buffer.concat([
    reversed, bytes32(constants.termId, "termId"), bytes32(constants.postState, "postState"),
    bytes32(constants.bn254ControlId, "bn254ControlId"),
  ]));
}

// BLAKE3 restricted to one block. The wrapper hashes exactly 64 bytes: constants digest || journal.
// CHUNK_START | CHUNK_END | ROOT, counter zero; this is not a general-purpose BLAKE3 API.
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
export function blake3Block(input: Uint8Array): Buffer {
  if (input.length > 64) throw new Error("BLAKE3 binding supports at most one 64-byte block");
  const block = Buffer.alloc(64); block.set(input);
  let m = Array.from({ length: 16 }, (_, i) => block.readUInt32LE(4 * i));
  const v = [...IV, ...IV.slice(0, 4), 0, 0, input.length, 1 | 2 | 8];
  const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;
  const g = (a: number, b: number, c: number, d: number, x: number, y: number) => {
    v[a] = (v[a] + v[b] + x) >>> 0; v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr(v[b] ^ v[c], 12);
    v[a] = (v[a] + v[b] + y) >>> 0; v[d] = rotr(v[d] ^ v[a], 8);
    v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr(v[b] ^ v[c], 7);
  };
  for (let round = 0; round < 7; round++) {
    g(0, 4, 8, 12, m[0], m[1]); g(1, 5, 9, 13, m[2], m[3]); g(2, 6, 10, 14, m[4], m[5]); g(3, 7, 11, 15, m[6], m[7]);
    g(0, 5, 10, 15, m[8], m[9]); g(1, 6, 11, 12, m[10], m[11]); g(2, 7, 8, 13, m[12], m[13]); g(3, 4, 9, 14, m[14], m[15]);
    m = PERM.map((i) => m[i]);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) out.writeUInt32LE((v[i] ^ v[i + 8]) >>> 0, 4 * i);
  return out;
}

/** 248-bit big-endian integer; deliberately no BN254 modular reduction. */
export function termPublicInput(term: StorageTerm, claim: TermChainClaim, constants: WrapConstants): bigint {
  const bytes = blake3Block(Buffer.concat([wrapConstantsDigest(constants), termJournal(term, claim)])).subarray(0, 31);
  return BigInt("0x" + bytes.toString("hex"));
}

/** Reject non-canonical encodings and field aliases before comparing an asserted public input. */
export function matchesTermPublicInput(asserted: string, term: StorageTerm, claim: TermChainClaim, constants: WrapConstants): boolean {
  if (!/^(0|[1-9][0-9]*)$/.test(asserted) || asserted.length > 75) return false;
  const value = BigInt(asserted);
  return value < (1n << 248n) && value === termPublicInput(term, claim, constants);
}
