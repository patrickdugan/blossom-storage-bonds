import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { blake3Block, matchesTermPublicInput, termJournal, termPreimage, termPublicInput, TERM_PREIMAGE_BYTES, wrapConstantsDigest, type StorageTerm, type TermChainClaim, type WrapConstants } from "./bitvm_term.ts";

const fixture = JSON.parse(readFileSync(new URL("../results/bitvm2-spike.json", import.meta.url), "utf8"));
const hex = (value: string) => Buffer.from(value, "hex");
const recorded = fixture.m2.term;
const groth = fixture.m3.groth16;
const term: StorageTerm = {
  holdId: hex(recorded.hold_id), headerChainId: hex(recorded.header_chain_id),
  q: fixture.m2.holds[0].q ?? hex(fixture.m2.holds[0].journal).readUInt32BE(32),
  dealCount: hex(fixture.m2.holds[0].journal).readUInt32BE(40),
  dealsDigest: hex(fixture.m2.holds[0].journal).subarray(44),
  firstHeight: recorded.first, step: recorded.step, epochs: recorded.epochs, depth: recorded.depth,
};
const chain: TermChainClaim = {
  tipHeight: fixture.m2.header_chain.tip_height,
  tipHash: hex(fixture.m2.header_chain.tip_hash).reverse(),
  totalWork: BigInt("0x" + fixture.m2.header_chain.total_work),
};
const constants: WrapConstants = {
  controlRoot: hex(groth.control_root), termId: hex(groth.pre_state),
  postState: hex(groth.post_state), bn254ControlId: hex(groth.bn254_control_id),
};
const changed = (bytes: Uint8Array) => { const result = Buffer.from(bytes); result[0] ^= 1; return result; };

test("BitVM term: reconstructs the actual phase-6 guest journal and Groth16 public input", () => {
  const preimage = termPreimage(term, chain);
  assert.equal(preimage.length, TERM_PREIMAGE_BYTES);
  assert.equal(preimage.toString("hex"), recorded.preimage);
  assert.equal(termJournal(term, chain).toString("hex"), recorded.journal);
  assert.equal(wrapConstantsDigest(constants).toString("hex"), groth.constants_digest);
  assert.equal(termPublicInput(term, chain, constants).toString(), groth.public_output_dec);
  const actualPublic = JSON.parse(readFileSync(new URL("../results/bitvm2-spike-groth16/public.json", import.meta.url), "utf8"));
  assert.equal(actualPublic.length, 1);
  assert.equal(actualPublic[0], termPublicInput(term, chain, constants).toString());
});

test("BitVM term: every setup term and dynamic chain claim is bound to the public input", () => {
  const publicInput = groth.public_output_dec;
  const alteredTerms: Partial<StorageTerm>[] = [
    { holdId: changed(term.holdId) }, { headerChainId: changed(term.headerChainId) },
    { q: term.q + 1 }, { dealCount: term.dealCount + 1 }, { dealsDigest: changed(term.dealsDigest) },
    { firstHeight: term.firstHeight + 1 }, { step: term.step + 1 }, { epochs: term.epochs - 1 }, { depth: term.depth + 1 },
  ];
  for (const change of alteredTerms) assert.equal(matchesTermPublicInput(publicInput, { ...term, ...change }, chain, constants), false, JSON.stringify(Object.keys(change)));
  for (const change of [{ tipHeight: chain.tipHeight + 1 }, { tipHash: changed(chain.tipHash) }, { totalWork: chain.totalWork + 1n }]) {
    assert.equal(matchesTermPublicInput(publicInput, term, { ...chain, ...change }, constants), false);
  }
  for (const field of ["controlRoot", "termId", "postState", "bn254ControlId"] as const) {
    assert.equal(matchesTermPublicInput(publicInput, term, chain, { ...constants, [field]: changed(constants[field]) }), false, field);
  }
  assert.equal(matchesTermPublicInput(publicInput, term, { ...chain, tipHash: Buffer.from(chain.tipHash).reverse() }, constants), false, "RPC hash order is not guest hash order");
});

test("BitVM term: rejects vacuous schedules, invalid encodings, shallow tips and integer overflow", () => {
  for (const field of ["q", "dealCount", "step", "epochs", "depth"] as const) {
    for (const value of [0, -1, 0.5, NaN, Infinity, 0x1_0000_0000]) {
      assert.throws(() => termPreimage({ ...term, [field]: value }, chain), new RegExp(field));
    }
  }
  assert.throws(() => termPreimage({ ...term, epochs: 0xffff_ffff, step: 0xffff_ffff }, chain), /schedule/);
  assert.throws(() => termPreimage(term, { ...chain, tipHeight: 195 }), /schedule/);
  for (const work of [0n, -1n, 1n << 256n]) assert.throws(() => termPreimage(term, { ...chain, totalWork: work }), /totalWork/);
  assert.throws(() => termPreimage({ ...term, holdId: new Uint8Array(31) }, chain), /holdId/);
  assert.throws(() => wrapConstantsDigest({ ...constants, termId: new Uint8Array(33) }), /termId/);
  for (const value of ["", "-1", "+1", "01", " 1", "1e3", (1n << 248n).toString(), "9".repeat(1000)]) {
    assert.equal(matchesTermPublicInput(value, term, chain, constants), false);
  }
  const scalarModulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  assert.equal(matchesTermPublicInput((BigInt(groth.public_output_dec) + scalarModulus).toString(), term, chain, constants), false, "a field-equivalent integer is not the canonical 248-bit commitment");
});

test("BitVM binding BLAKE3 matches independent empty and abc vectors, and rejects multiblock input", () => {
  assert.equal(blake3Block(Buffer.alloc(0)).toString("hex"), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
  assert.equal(blake3Block(Buffer.from("abc")).toString("hex"), "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
  assert.throws(() => blake3Block(Buffer.alloc(65)), /one 64-byte block/);
});
