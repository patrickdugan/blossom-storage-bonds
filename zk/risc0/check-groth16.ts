// Recomputes the Groth16 proof's one public input from public data, without RISC Zero or the
// prover, and compares it with public.json.
//
//   node zk/risc0/check-groth16.ts <groth16.json> <term.json> <statement.json> <hashes.json>
//
// groth16.json and term.json are bsb-r0's groth16 and prove-term output lines; statement.json is
// witness.ts's (seed per epoch aside, every epoch shares q and the deal list); hashes.json is
// headers.ts's. The chain is regtest, so the tip's total work is 2 per block (MAX / (target + 1)
// for bits 0x207fffff).
//
//   preimage  = "bsb/r0-term|v1" ‖ hold_id ‖ header_chain_id ‖ u32be(q, deals) ‖ D
//               ‖ u32be(first, step, epochs, depth, tip) ‖ tip hash (internal order) ‖ u256be(work)
//   journal   = SHA256(preimage)
//   constants = SHA256(bitrev(control_root) ‖ term image ID ‖ post_state ‖ BN254 identity control ID)
//   public    = BLAKE3(constants ‖ journal)[0..31], as a big-endian integer

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dealsDigest } from "../../model/zk_pdp.ts";

/** A JSON file, or the last line of a file whose earlier lines are guest output. */
const json = (f: string) => { const t = readFileSync(f, "utf8").trim(); try { return JSON.parse(t); } catch { return JSON.parse(t.split("\n").pop()!); } };
const [g16Path, termPath, statementPath, hashesPath] = process.argv.slice(2);
const g = json(g16Path), term = json(termPath), st = json(statementPath), hashes = json(hashesPath).hashes as string[];
const sha = (...b: Buffer[]) => createHash("sha256").update(Buffer.concat(b)).digest();
const u32be = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };

// BLAKE3 of one block of at most 64 bytes: a single compression with CHUNK_START | CHUNK_END | ROOT.
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
function blake3Block(input: Buffer): Buffer {
  if (input.length > 64) throw new Error("one block only");
  const block = Buffer.alloc(64); input.copy(block);
  let m = Array.from({ length: 16 }, (_, i) => block.readUInt32LE(4 * i));
  const v = [...IV, ...IV.slice(0, 4), 0, 0, input.length, 1 | 2 | 8];
  const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;
  const G = (a: number, b: number, c: number, d: number, x: number, y: number) => {
    v[a] = (v[a] + v[b] + x) >>> 0; v[d] = rotr(v[d] ^ v[a], 16); v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr(v[b] ^ v[c], 12);
    v[a] = (v[a] + v[b] + y) >>> 0; v[d] = rotr(v[d] ^ v[a], 8); v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr(v[b] ^ v[c], 7);
  };
  for (let r = 0; r < 7; r++) {
    G(0, 4, 8, 12, m[0], m[1]); G(1, 5, 9, 13, m[2], m[3]); G(2, 6, 10, 14, m[4], m[5]); G(3, 7, 11, 15, m[6], m[7]);
    G(0, 5, 10, 15, m[8], m[9]); G(1, 6, 11, 12, m[10], m[11]); G(2, 7, 8, 13, m[12], m[13]); G(3, 4, 9, 14, m[14], m[15]);
    m = PERM.map((i) => m[i]);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) out.writeUInt32LE((v[i] ^ v[i + 8]) >>> 0, 4 * i);
  return out;
}

const [first, step, epochs, depth] = [term.first, term.step, term.epochs, term.depth];
const tip = hashes.length - 1;
const deals = st.deals.map((d: { root: string; n: number }) => ({ root: Buffer.from(d.root, "hex"), n: d.n }));
const work = Buffer.from(BigInt(2 * (tip + 1)).toString(16).padStart(64, "0"), "hex");
const preimage = Buffer.concat([
  Buffer.from("bsb/r0-term|v1"), Buffer.from(term.hold_id, "hex"), Buffer.from(term.header_chain_id, "hex"),
  u32be(st.q), u32be(deals.length), dealsDigest("sha", deals),
  u32be(first), u32be(step), u32be(epochs), u32be(depth), u32be(tip),
  Buffer.from(hashes[tip], "hex").reverse(), work,
]);
const journal = sha(preimage);
const bitrev = (b: number) => { let r = 0; for (let i = 0; i < 8; i++) r |= ((b >> i) & 1) << (7 - i); return r; };
const constants = sha(
  Buffer.from(Buffer.from(g.control_root, "hex").map(bitrev)), Buffer.from(g.pre_state, "hex"),
  Buffer.from(g.post_state, "hex"), Buffer.from(g.bn254_control_id, "hex"),
);
const pub = blake3Block(Buffer.concat([constants, journal])).subarray(0, 31);
const pubDec = BigInt("0x" + pub.toString("hex")).toString();
const result = {
  preimage_matches: preimage.toString("hex") === term.preimage,
  journal_matches: journal.toString("hex") === g.journal,
  constants_match: constants.toString("hex") === g.constants_digest,
  public_matches: pubDec === g.public_output_dec,
  public_input: pubDec,
};
console.log(JSON.stringify(result));
process.exit(Object.values(result).every((v) => v !== false) ? 0 : 1);
