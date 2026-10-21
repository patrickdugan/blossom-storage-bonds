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
import { dealsDigest } from "../../model/zk_pdp.ts";
import { termJournal, termPreimage, termPublicInput, wrapConstantsDigest } from "../../model/bitvm_term.ts";

/** A JSON file, or the last line of a file whose earlier lines are guest output. */
const json = (f: string) => { const t = readFileSync(f, "utf8").trim(); try { return JSON.parse(t); } catch { return JSON.parse(t.split("\n").pop()!); } };
const [g16Path, termPath, statementPath, hashesPath] = process.argv.slice(2);
const g = json(g16Path), term = json(termPath), st = json(statementPath), hashes = json(hashesPath).hashes as string[];

const [first, step, epochs, depth] = [term.first, term.step, term.epochs, term.depth];
const tip = hashes.length - 1;
const deals = st.deals.map((d: { root: string; n: number }) => ({ root: Buffer.from(d.root, "hex"), n: d.n }));
const work = Buffer.from(BigInt(2 * (tip + 1)).toString(16).padStart(64, "0"), "hex");
const setup = {
  holdId: Buffer.from(term.hold_id, "hex"), headerChainId: Buffer.from(term.header_chain_id, "hex"),
  q: st.q, dealCount: deals.length, dealsDigest: dealsDigest("sha", deals),
  firstHeight: first, step, epochs, depth,
};
const claim = { tipHeight: tip, tipHash: Buffer.from(hashes[tip], "hex").reverse(), totalWork: BigInt("0x" + work.toString("hex")) };
const wrap = {
  controlRoot: Buffer.from(g.control_root, "hex"), termId: Buffer.from(g.pre_state, "hex"),
  postState: Buffer.from(g.post_state, "hex"), bn254ControlId: Buffer.from(g.bn254_control_id, "hex"),
};
const preimage = termPreimage(setup, claim);
const journal = termJournal(setup, claim);
const constants = wrapConstantsDigest(wrap);
const pubDec = termPublicInput(setup, claim, wrap).toString();
const result = {
  preimage_matches: preimage.toString("hex") === term.preimage,
  journal_matches: journal.toString("hex") === g.journal,
  constants_match: constants.toString("hex") === g.constants_digest,
  public_matches: pubDec === g.public_output_dec,
  public_input: pubDec,
};
console.log(JSON.stringify(result));
process.exit(Object.values(result).every((v) => v !== false) ? 0 : 1);
