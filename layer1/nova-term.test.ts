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
import { GUEST_A_BYTES, NovaRefused, WRAP_PINS, bindSeeds, checkNovaTermDir, checkPins, decodeStatement, matchPayment, verifyWrap, type Term } from "./nova-term.ts";

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
  assert.throws(() => checkPins(decodeStatement(nhc1), "mainnet"), refused(/no genesis state pinned for mainnet/));
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

test("the wrap check pins every expectation field and refuses a PAY1 proof until the M16 key is pinned", () => {
  const ok = fakeVerifier(0);
  assert.equal(verifyWrap(A, "wrap.bin", ok.cmd).status, "verified");
  assert.deepEqual(ok.seen(), { committed_values_sha256: createHash("sha256").update(A).digest("hex"), exit_code: 0, is_complete: 1,
    program_vk_digest: WRAP_PINS.programs.guestA, recursion_vk_root: WRAP_PINS.recursionVkRoot, wrap_vk_sha256: WRAP_PINS.wrapVkSha256 });
  assert.throws(() => verifyWrap(A, "wrap.bin", fakeVerifier(1).cmd), refused(/m13-verify refused: Error: refused: different committed statement/));
  assert.throws(() => verifyWrap(M16, "wrap.bin", ok.cmd), refused(/no M16 program key pinned/));
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
