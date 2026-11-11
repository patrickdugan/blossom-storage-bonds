// Offline: the Nova term checks against nova-bitvm3's proven testnet4 statement (guest A, heights 0-4)
// and the M16-shaped statement for the same chain. m13-verify runs only when BSB_M13_VERIFY and
// BSB_NOVA_WRAP are set; the other wrap tests use a stand-in verifier that reports what it was asked.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { GUEST_A_BYTES, NovaRefused, WRAP_PINS, bindSeeds, checkNovaTermDir, checkProviderPaid, checkPins, decodeStatement, matchPayment, verifyWrap, type Term } from "./nova-term.ts";

const fx = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "nova-term");
const A = readFileSync(join(fx, "testnet4-0-4", "statement.bin"));
const M16 = readFileSync(join(fx, "testnet4-0-4-pay1", "statement.bin"));
const headers = readFileSync(join(fx, "testnet4-0-4", "headers.hex"), "utf8").split(/\s+/).filter(Boolean).map((h) => Buffer.from(h, "hex"));
const term = JSON.parse(readFileSync(join(fx, "testnet4-0-4-pay1", "term.json"), "utf8")) as Term;
const refused = (re: RegExp) => (e: unknown) => e instanceof NovaRefused && re.test(e.message);
const flip = (b: Buffer, at: number) => { const c = Buffer.from(b); c[at] ^= 1; return c; };
const ZN = 12 + 17 * 32;

test("guest A's proven testnet4 statement decodes and meets both pins", () => {
  assert.equal(createHash("sha256").update(A).digest("hex"), "d3b478b0ed0055bbd43a59775729c990a33d1df07bd0a66ee728a3573c832fa0");
  const s = decodeStatement(A);
  assert.equal(s.magic, "NHT4"); assert.equal(s.k, 1); assert.equal(s.steps, 4); assert.equal(s.tipHeight, 4);
  assert.equal(s.tipHash, "000000008f5794caa45c418a0184303e848e9d6756e4d77234c9aada983b4265");
  assert.equal(s.chainwork, 0x500050005n);
  assert.equal(s.pay, undefined);
  checkPins(s, "testnet4");
  assert.equal(bindSeeds(s, headers, term.seeds), 3);
});

test("pins refuse another network, fold width, genesis, key or step count", () => {
  assert.throws(() => checkPins(decodeStatement(A), "mainnet"), refused(/is for NHT4, not mainnet/));
  assert.throws(() => checkPins(decodeStatement(A), "signet"), refused(/no Nova pins/));
  const nhc1 = Buffer.from(A); nhc1.write("NHC1", 0, "latin1");
  assert.throws(() => checkPins(decodeStatement(nhc1), "mainnet"), refused(/z0 is not mainnet's genesis state/));
  const k2 = Buffer.from(A); k2.writeUInt32LE(2, 4);
  assert.throws(() => checkPins(decodeStatement(k2), "testnet4"), refused(/fold width 2/));
  assert.throws(() => checkPins(decodeStatement(flip(A, 12 + 32)), "testnet4"), refused(/genesis state/));   // z0's tip hash
  assert.throws(() => checkPins(decodeStatement(flip(A, 12 + 2 * 17 * 32)), "testnet4"), refused(/key digest/));
  const steps = Buffer.from(A); steps.writeUInt32LE(5, 8);
  assert.throws(() => checkPins(decodeStatement(steps), "testnet4"), refused(/steps 5 differ/));
  assert.throws(() => decodeStatement(A.subarray(0, GUEST_A_BYTES - 1)), refused(/1163 bytes/));
  assert.throws(() => decodeStatement(flip(A, ZN + 32 + 20)), refused(/tip hash half exceeds/));
});

test("seeds bind only through headers that end at the proven tip", () => {
  const s = decodeStatement(A);
  assert.equal(bindSeeds(s, headers.slice(2), term.seeds), 3);          // headers from the lowest seed suffice
  assert.throws(() => bindSeeds(s, headers.slice(3), term.seeds), refused(/below the headers given/));
  assert.throws(() => bindSeeds(s, headers.slice(0, 4), term.seeds), refused(/not the proven tip/));
  assert.throws(() => bindSeeds(s, [headers[0], headers[1], headers[3], headers[4]], term.seeds), refused(/do not link/));
  assert.throws(() => bindSeeds(s, [flip(headers[0], 70), ...headers.slice(1)], term.seeds), refused(/do not link at position 1/));
  assert.throws(() => bindSeeds(s, headers, [{ height: 5, hash: term.seeds[0].hash }]), refused(/above the proven tip/));
  assert.throws(() => bindSeeds(s, headers, [{ height: 3, hash: term.seeds[0].hash }]), refused(/not the proven chain's block/));
  assert.throws(() => bindSeeds(s, [], term.seeds), refused(/no headers/));
});

test("the M16 payment record must be one of the term's payments, deep enough, ending at the tip", () => {
  const s = decodeStatement(M16);
  checkPins(s, "testnet4");
  assert.deepEqual({ ...s.pay, value: String(s.pay!.value) }, { segments: 1, heightB: 1, hashB: "0000000012982b6d5f621229286b880e909984df669c2afabb102ce311b13f28", confirmations: 4,
    txid: term.payments[0].txid, vout: 0, value: "5000000000", scriptLen: 25, scriptSha: createHash("sha256").update(Buffer.from(term.payments[0].script, "hex")).digest("hex") });
  assert.equal(matchPayment(s, term.payments, 3).txid, term.payments[0].txid);
  assert.throws(() => matchPayment(s, term.payments, 5), refused(/4 confirmations, fewer than 5/));
  assert.throws(() => matchPayment(decodeStatement(A), term.payments, 1), refused(/no payment record/));
  assert.throws(() => matchPayment(s, [{ ...term.payments[0], vout: 1 }], 1), refused(/not one of the term's payments/));
  assert.throws(() => matchPayment(s, [{ ...term.payments[0], sats: 4999999999 }], 1), refused(/proven value/));
  assert.throws(() => matchPayment(s, [{ ...term.payments[0], script: "0014" + "00".repeat(20) }], 1), refused(/scriptPubKey/));
  const P = GUEST_A_BYTES;
  const shifted = Buffer.from(M16); shifted.writeUInt32LE(2, P + 8);   // height_B no longer tip - (n - 1)
  assert.throws(() => matchPayment(decodeStatement(shifted), term.payments, 1), refused(/do not end at the proven tip/));
  const tag = Buffer.from(M16); tag.write("PAY2", P, "latin1");
  assert.throws(() => decodeStatement(tag), refused(/PAY1 tag/));
});

/** A stand-in m13-verify: records its expectation file, exits as told. */
function fakeVerifier(exit: number): { cmd: string; seen: () => Record<string, unknown> } {
  const dir = mkdtempSync(join(tmpdir(), "bsb-fake-m13-"));
  const script = join(dir, "m13.mjs"), seen = join(dir, "seen.json");
  writeFileSync(script, `import { copyFileSync } from "node:fs"; copyFileSync(process.argv[4], ${JSON.stringify(seen)});
${exit === 0 ? `console.log(JSON.stringify({ status: "verified" }));` : `console.error("Error: refused: different committed statement");`} process.exit(${exit});\n`);
  return { cmd: `${process.execPath} ${script}`, seen: () => JSON.parse(readFileSync(seen, "utf8")) };
}

test("the wrap check pins every expectation field and carry the M16 key for PAY1 statements", () => {
  const ok = fakeVerifier(0);
  assert.equal(verifyWrap(A, "wrap.bin", ok.cmd).status, "verified");
  assert.deepEqual(ok.seen(), { committed_values_sha256: createHash("sha256").update(A).digest("hex"), exit_code: 0, is_complete: 1,
    program_vk_digest: WRAP_PINS.programs.guestA, recursion_vk_root: WRAP_PINS.recursionVkRoot, wrap_vk_sha256: WRAP_PINS.wrapVkSha256 });
  assert.throws(() => verifyWrap(A, "wrap.bin", fakeVerifier(1).cmd), refused(/m13-verify refused: Error: refused: different committed statement/));
  assert.equal(verifyWrap(M16, "wrap.bin", ok.cmd).programKey, WRAP_PINS.programs.m16);
  assert.equal(ok.seen().program_vk_digest, WRAP_PINS.programs.m16);
});

test("a term directory: fixture term replaces the run's own, and a run's tip must carry the node's chainwork", () => {
  const r = checkNovaTermDir(join(fx, "testnet4-0-4-pay1"), { network: "regtest", seeds: [], payments: [], minConfs: 1 }, { verifier: "" });
  assert.equal(r.term, "fixture"); assert.equal(r.seedsBound, 3); assert.deepEqual(r.payment, { txid: term.payments[0].txid, vout: 0, confirmations: 4 });
  const own = mkdtempSync(join(tmpdir(), "bsb-nova-own-"));
  cpSync(join(fx, "testnet4-0-4", "statement.bin"), join(own, "statement.bin"));
  cpSync(join(fx, "testnet4-0-4", "headers.hex"), join(own, "headers.hex"));
  const run: Term = { network: "testnet4", seeds: term.seeds, payments: [], minConfs: 3 };
  assert.equal(checkNovaTermDir(own, run, { knownChainwork: () => 0x500050005n }).chainwork, "equal to the node's");
  assert.throws(() => checkNovaTermDir(own, run, { knownChainwork: () => 0x600060006n }), refused(/differs from the node's/));
  assert.throws(() => checkNovaTermDir(own, { ...run, network: "regtest" }), refused(/no Nova pins for network regtest/));
});

test("m13-verify accepts guest A's real wrap proof through the term check", { skip: !(process.env.BSB_M13_VERIFY && process.env.BSB_NOVA_WRAP) }, () => {
  const r = checkNovaTermDir(join(fx, "testnet4-0-4"), { network: "testnet4", seeds: [], payments: [], minConfs: 1 });
  assert.equal(r.proof, "verified");
  const bad = mkdtempSync(join(tmpdir(), "bsb-nova-bad-"));
  for (const f of ["headers.hex", "term.json"]) cpSync(join(fx, "testnet4-0-4", f), join(bad, f));
  writeFileSync(join(bad, "statement.bin"), (() => { const b = Buffer.from(A); b.writeUInt32LE(b.readUInt32LE(ZN + 32 * 5) ^ 1, ZN + 32 * 5); return b; })());   // zn's block time
  assert.throws(() => checkNovaTermDir(bad, { network: "testnet4", seeds: [], payments: [], minConfs: 1 }), refused(/m13-verify refused/));
});

// --- M16 mode: the real mainnet payment proof (nova-bitvm3 m16, tip 975,072, payment in block 975,067) ---
const MD = join(fx, "mainnet-m16");
const MB = readFileSync(join(MD, "statement.bin"));
const MJ = JSON.parse(readFileSync(join(MD, "statement.json"), "utf8"));
const MT = JSON.parse(readFileSync(join(MD, "term.json"), "utf8")) as Term;
const REQ = MT.provider!;
const MP = GUEST_A_BYTES;   // PAY1 record offset
const WRAP = join(MD, "wrap.bin");
const REAL = process.env.BSB_M13_VERIFY ? { cmd: process.env.BSB_M13_VERIFY, real: true } : undefined;
/** The real m13-verify when BSB_M13_VERIFY is set, otherwise a stand-in that accepts (the refusals below
 *  that depend on the proof itself then run only against the real verifier). */
const verifierFor = () => REAL?.cmd ?? fakeVerifier(0).cmd;
const paid = (bytes: Buffer, over: Partial<typeof REQ> = {}, net = "mainnet", sj: typeof MJ | undefined = undefined) =>
  checkProviderPaid(bytes, WRAP, verifierFor(), net, { ...REQ, ...over }, sj);

test("M16 statement: mainnet pins, the PAY1 record, and the program key", () => {
  assert.equal(createHash("sha256").update(MB).digest("hex"), "cae6068f7ad8c4891cb3220702a88b0bc3df54013f45e65df11a9ced531bc869");
  assert.equal(MJ.program_vk_digest, "dfc68a5d579b86244a60ba0baee7852348cf0d2a3bb13910ebb95a3e625fcb60");
  assert.equal(WRAP_PINS.programs.m16, MJ.program_vk_digest);
  const s = decodeStatement(MB);
  assert.equal(s.magic, "NHC1"); assert.equal(s.tipHeight, 975072);
  checkPins(s, "mainnet");
  assert.deepEqual({ ...s.pay, value: String(s.pay!.value) }, { segments: s.pay!.segments, heightB: 975067, hashB: s.pay!.hashB, confirmations: 6,
    txid: "a652ab0cf381413ae854a86bb7e4784811b2d4158a65f26ff64a69eb3eb20045", vout: 0, value: "940000", scriptLen: 22, scriptSha: REQ.scriptSha256 });
});

test("M16 accepts the real mainnet proof as 'the client paid the provider'", () => {
  const r = paid(MB, {}, "mainnet", MJ);
  assert.equal(r.proof, "verified"); assert.equal(r.payment.sats, "940000"); assert.equal(r.payment.confirmations, 6);
  assert.equal(paid(MB, { owedSats: 1 }).proof, "verified");           // value above the amount owed
  assert.equal(paid(MB, { minConfs: 1 }).proof, "verified");
  const dir = checkNovaTermDir(MD, { network: "regtest", seeds: [], payments: [], minConfs: 1 }, { verifier: verifierFor() });
  assert.equal(dir.proof, "verified"); assert.equal(dir.providerPaid?.payment.txid, "a652ab0cf381413ae854a86bb7e4784811b2d4158a65f26ff64a69eb3eb20045");
});

test("M16 refuses each of: tampered public bytes, wrong program key, wrong script, low value, few confirmations, wrong z0, testnet4 magic", () => {
  // tampered public bytes: the statement file's digest no longer matches (and the real verifier refuses the proof)
  const tampered = Buffer.from(MB); tampered[GUEST_A_BYTES - 1] ^= 1;            // proofs digest
  assert.throws(() => paid(tampered, {}, "mainnet", MJ), refused(/do not match the statement's committed-values digest/));
  if (REAL) assert.throws(() => paid(tampered), refused(/m13-verify refused/));
  // wrong program key
  assert.throws(() => paid(MB, {}, "mainnet", { ...MJ, program_vk_digest: WRAP_PINS.programs.guestA }), refused(/is not the pinned M16 key/));
  const k = fakeVerifier(0); 
  assert.equal(WRAP_PINS.programs.m16, MJ.program_vk_digest);
  checkProviderPaid(MB, WRAP, k.cmd, "mainnet", REQ); assert.equal(k.seen().program_vk_digest, WRAP_PINS.programs.m16);
  // wrong script
  assert.throws(() => paid(MB, { scriptSha256: "00".repeat(32) }), refused(/not the provider's registered script/));
  // value too low
  assert.throws(() => paid(MB, { owedSats: 940001 }), refused(/below the 940001 owed/));
  // too few confirmations
  assert.throws(() => paid(MB, { minConfs: 7 }), refused(/6 confirmations, fewer than 7/));
  // wrong z0
  assert.throws(() => paid(flip(MB, 12 + 32)), refused(/z0 is not mainnet's genesis state/));
  // testnet4 magic under mainnet pins
  const t4 = Buffer.from(MB); t4.write("NHT4", 0, "latin1");
  assert.throws(() => paid(t4), refused(/statement is for NHT4, not mainnet/));
  // a guest A statement carries no payment
  assert.throws(() => paid(MB.subarray(0, MP)), refused(/no payment record/));
  // the term directory in M16 mode will not skip the proof unless told to
  assert.throws(() => checkNovaTermDir(MD, { network: "regtest", seeds: [], payments: [], minConfs: 1 }, { verifier: "" }), refused(/needs a wrap proof and BSB_M13_VERIFY/));
  assert.match(String(checkNovaTermDir(MD, { network: "regtest", seeds: [], payments: [], minConfs: 1 }, { verifier: "", allowUnverified: true }).proof), /^not checked/);
});

test("M16 proof check: a stand-in verifier that refuses stops an otherwise valid statement", () => {
  assert.throws(() => checkProviderPaid(MB, WRAP, fakeVerifier(1).cmd, "mainnet", REQ), refused(/m13-verify refused/));
});
