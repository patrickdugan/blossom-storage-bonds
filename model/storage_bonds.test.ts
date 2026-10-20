import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { keyFromSeed } from "./schnorr.ts";
import {
  CHUNK, MAX_ELEMENT, MAX_STANDARD_ITEM, SALT, TX, WINDOW, isStandardTapscriptStack, buildTree, digest, challengeLeaf, chunk, cutAndChooseSurvives, dealVbytes, minCutAndChoose, deletionGain,
  encryptReplica, epochIndices, epochPass, forfeitLeaf, makeSentinel, merkleProof, merkleVerify, proveEpoch,
  refundLeaf, replicaKey, respondLeaf, runTapscript, sentinelResponses, sentinelSurvival, scriptNum, scriptPathVsize, sentinelResponse, sign, theftEv,
  twoLeafRoot, verifyEpoch, type SpendCtx,
} from "./storage_bonds.ts";

// NOTE: signatures sign a stand-in digest, not a BIP341 sighash, and no transaction is serialized.

const P = keyFromSeed("provider");
const C = keyFromSeed("client");
const SECRET = Buffer.from("client master secret, 32 bytes!!");
const BLOB = Buffer.from(Array.from({ length: 200_000 }, (_, i) => (i * 131 + (i >> 9)) & 0xff));
const BLOB_ID = "sha256:" + "ab".repeat(32);

const replica = (provider: string) => {
  const chunks = chunk(encryptReplica(BLOB, replicaKey(SECRET, BLOB_ID, provider)));
  return { chunks, tree: buildTree(chunks) };
};
const allHeld = (chunks: Buffer[]) => new Map(chunks.map((c, i) => [i, c] as const));

test("geometry: r ‖ window is one 80-byte standard item; a 4 KiB chunk holds 64 windows", () => {
  assert.equal(SALT + WINDOW, MAX_STANDARD_ITEM);
  assert.equal(CHUNK % WINDOW, 0);
  assert.equal(chunk(Buffer.alloc(10_000)).length, 3);
  assert.equal(chunk(Buffer.alloc(10_000))[2].length, CHUNK);
});

test("Merkle: every leaf opens; a wrong chunk, index or path length does not", () => {
  const { chunks, tree } = replica("p1");
  for (const i of [0, 1, 7, tree.n - 2, tree.n - 1]) {
    assert.ok(merkleVerify(tree.root, tree.n, i, chunks[i], merkleProof(tree, i)), `leaf ${i}`);
  }
  assert.ok(!merkleVerify(tree.root, tree.n, 5, chunks[6], merkleProof(tree, 5)));
  assert.ok(!merkleVerify(tree.root, tree.n, 6, chunks[5], merkleProof(tree, 5)));
  assert.ok(!merkleVerify(tree.root, tree.n, 5, chunks[5], merkleProof(tree, 5).slice(1)));
  assert.ok(!merkleVerify(tree.root, tree.n + 1, 5, chunks[5], merkleProof(tree, 5)), "the root binds n");
});

test("replicas: two providers hold unrelated ciphertexts, so one cannot answer from the other's copy", () => {
  const a = replica("p1"), b = replica("p2");
  assert.ok(!a.tree.root.equals(b.tree.root));
  const nonce = randomBytes(32);
  assert.ok(verifyEpoch(a.tree.root, a.tree.n, nonce, 16, proveEpoch(allHeld(a.chunks), a.tree, nonce, 16)));
  // p1 deleted its copy and fetches p2's chunks instead, with p2's paths: it fails against p1's root.
  assert.ok(!verifyEpoch(a.tree.root, a.tree.n, nonce, 16, proveEpoch(allHeld(b.chunks), b.tree, nonce, 16)));
});

test("pay per proof: a provider that dropped chunks fails the epochs that hit them", () => {
  const { chunks, tree } = replica("p1");
  const held = allHeld(chunks);
  for (let i = 0; i < tree.n; i += 2) held.delete(i);          // keeps about half
  const f = held.size / tree.n;
  let passes = 0;
  const epochs = 400, q = 4;
  for (let e = 0; e < epochs; e++) {
    const nonce = randomBytes(32);
    if (verifyEpoch(tree.root, tree.n, nonce, q, proveEpoch(held, tree, nonce, q))) passes++;
  }
  const expect = epochPass(f, q) * epochs;                       // about 23
  assert.ok(Math.abs(passes - expect) < 4 * Math.sqrt(expect), `${passes} passes, expected about ${expect}`);
  assert.ok(new Set(epochIndices(Buffer.alloc(32), tree.n, 64)).size > 25, "indices spread over the blob");
});

test("pay per proof: deleting never pays while price ≥ cost, for any q ≥ 1: the threat is outsourcing, not deletion", () => {
  for (const q of [1, 2, 8, 32]) {
    for (let f = 0; f < 1; f += 0.01) assert.ok(deletionGain(f, q, 1, 1) <= 1e-12, `q=${q} f=${f}`);
  }
  // With q = 1 and a price at twice cost the provider is indifferent at the margin: loss is linear in f.
  assert.ok(Math.abs(deletionGain(0.9, 1, 2, 1) - (-0.1)) < 1e-12);
  // q = 20: keeping 99% of the blob loses 18% of revenue to save 1% of cost.
  assert.ok(Math.abs(1 - epochPass(0.99, 20) - 0.182) < 1e-3);
});

// ───────────────────────────── the bond chain ─────────────────────────────

const TERM_END = 960_000;
const DELTA = 144;
const ctx = (label: string, lockTime = 0, age = 0): SpendCtx => ({ digest: digest(label), lockTime, age });

function bondState(i: number) {
  const { chunks, tree } = replica("p1");
  const sen = makeSentinel(SECRET, tree, chunks, i);
  return {
    chunks, tree, sen,
    challenge: challengeLeaf(C, P, sen.s), refund: refundLeaf(P, TERM_END),
    respond: respondLeaf(P, C, sen.h), forfeit: forfeitLeaf(C, DELTA),
  };
}

test("challenge leaf: needs both signatures and the right r", () => {
  const b = bondState(0);
  const L = `challenge-0`;
  const w = (r: Buffer) => [r, sign(P, L), sign(C, L)];
  assert.deepEqual(runTapscript(b.challenge, w(b.sen.r), ctx(L)), { ok: true });
  assert.equal(runTapscript(b.challenge, w(randomBytes(32)), ctx(L)).ok, false, "wrong r");
  assert.equal(runTapscript(b.challenge, [b.sen.r, sign(P, L), Buffer.alloc(0)], ctx(L)).ok, false, "no client signature");
  assert.equal(runTapscript(b.challenge, [b.sen.r, sign(P, "challenge-1"), sign(C, L)], ctx(L)).ok, false,
    "the provider's presignature is for one transaction only");
});

test("respond leaf: the provider that holds the chunk saves the bond with one 80-byte item", () => {
  const b = bondState(0);
  const L = "respond-0";
  const pre = sentinelResponse(b.sen.r, b.tree.n, allHeld(b.chunks))!;
  assert.equal(pre.length, MAX_STANDARD_ITEM);
  assert.ok(isStandardTapscriptStack([pre]));
  assert.deepEqual(runTapscript(b.respond, [pre, sign(C, L), sign(P, L)], ctx(L)), { ok: true });
});

test("respond leaf: a provider that dropped the sentinel's chunk has nothing that hashes to h", () => {
  const b = bondState(0);
  const held = allHeld(b.chunks);
  held.delete(Math.floor(b.sen.idx / 64));
  assert.equal(sentinelResponse(b.sen.r, b.tree.n, held), null);
  const L = "respond-0";
  // Best try: the same window offset in a neighbouring chunk.
  const c = Math.floor(b.sen.idx / 64);
  const fake = Buffer.concat([b.sen.r, b.chunks[(c + 1) % b.tree.n].subarray((b.sen.idx % 64) * WINDOW, (b.sen.idx % 64 + 1) * WINDOW)]);
  assert.equal(runTapscript(b.respond, [fake, sign(C, L), sign(P, L)], ctx(L)).ok, false);
  // 81 bytes is non-standard (relay); 521 bytes is invalid (consensus), whatever it hashes to.
  assert.ok(!isStandardTapscriptStack([Buffer.alloc(81)]));
  assert.match((runTapscript(b.respond, [Buffer.alloc(521), sign(C, L), sign(P, L)], ctx(L)) as { why: string }).why, /520/);
});

test("forfeit leaf: the client takes the bond only after Δ blocks of silence", () => {
  const b = bondState(0);
  const L = "forfeit-0";
  assert.equal(runTapscript(b.forfeit, [sign(C, L)], ctx(L, 0, DELTA - 1)).ok, false);
  assert.deepEqual(runTapscript(b.forfeit, [sign(C, L)], ctx(L, 0, DELTA)), { ok: true });
  assert.equal(runTapscript(b.forfeit, [sign(P, L)], ctx(L, 0, DELTA)).ok, false, "only the client");
});

test("refund leaf: the provider alone, only from the term's end", () => {
  const b = bondState(0);
  const L = "refund";
  assert.equal(runTapscript(b.refund, [sign(P, L)], ctx(L, TERM_END - 1)).ok, false);
  assert.deepEqual(runTapscript(b.refund, [sign(P, L)], ctx(L, TERM_END)), { ok: true });
});

test("sentinels: the index comes from r, so the leaves reveal nothing about which chunks to keep", () => {
  const { chunks, tree } = replica("p1");
  const sens = Array.from({ length: 64 }, (_, i) => makeSentinel(SECRET, tree, chunks, i));
  assert.ok(new Set(sens.map((s) => s.idx)).size > 60, "distinct windows");
  // A different replica root gives different secrets, so one provider's reveals say nothing about another's.
  const other = replica("p2");
  assert.ok(!makeSentinel(SECRET, other.tree, other.chunks, 0).r.equals(sens[0].r));
  // Two-leaf trees: the state roots differ per sentinel.
  const s0 = bondState(0), s1 = bondState(1);
  assert.ok(!twoLeafRoot(s0.challenge, s0.refund).equals(twoLeafRoot(s1.challenge, s1.refund)));
});

test("multi-window sentinel: one r opens m windows, the leaf checks all m, and one missing chunk loses the bond", () => {
  const { chunks, tree } = replica("p1");
  const m = 16;
  const sen = makeSentinel(SECRET, tree, chunks, 0, m);
  assert.equal(sen.hs.length, m);
  assert.ok(sen.h.equals(makeSentinel(SECRET, tree, chunks, 0).h), "window 0 is the one-window sentinel");
  const leaf = respondLeaf(P, C, sen.hs);
  assert.equal(leaf.length, 68 + 35 * m, "two keyed CHECKSIGVERIFYs, then 35 bytes per window");
  const L = "respond-multi";
  const items = sentinelResponses(sen.r, tree.n, allHeld(chunks), m)!;
  assert.ok(items.every((x) => x.length === MAX_STANDARD_ITEM) && isStandardTapscriptStack(items));
  assert.deepEqual(runTapscript(leaf, [...items].reverse().concat([sign(C, L), sign(P, L)]), ctx(L)), { ok: true });
  // Zero the chunk under window 7 only: the provider still has 15 of 16 answers, and that is not enough.
  const held = allHeld(chunks);
  const c7 = Math.floor(sen.idxs[7] / 64);
  held.set(c7, Buffer.alloc(chunks[c7].length));
  const lossy = sentinelResponses(sen.r, tree.n, held, m)!;
  assert.equal(runTapscript(leaf, [...lossy].reverse().concat([sign(C, L), sign(P, L)]), ctx(L)).ok, false);
  // Detection: a 10% deleter survives one 16-window challenge 18.5% of the time, four of them 0.12%.
  assert.ok(Math.abs(sentinelSurvival(0.9, 16) - 0.1853) < 1e-4);
  assert.ok(Math.abs(sentinelSurvival(0.9, 16, 4) - 0.00118) < 1e-5);
  assert.ok(Math.abs(sentinelSurvival(0.9, 1, 4) - 0.6561) < 1e-12, "one window per challenge: 66% survive four");
});

test("script numbers are minimal", () => {
  assert.equal(scriptNum(144).toString("hex"), "9000");
  assert.equal(scriptNum(127).toString("hex"), "7f");
  assert.equal(scriptNum(TERM_END).toString("hex"), "00a60e");
});

test("cut and choose: one planted bad sentinel survives with probability k/M", () => {
  assert.equal(cutAndChooseSurvives(100, 10, 1), 0.1);
  assert.ok(Math.abs(cutAndChooseSurvives(100, 10, 2) - (10 / 100) * (9 / 99)) < 1e-15);
  assert.equal(cutAndChooseSurvives(100, 10, 11), 0);
  // Theft pays at M = 100, k = 10 if the whole bond goes to the client; burning 90% of a forfeit stops it
  // only when the bond is under 100× the client's setup cost.
  assert.ok(theftEv(100, 10, 1, 1_000_000, 2_000) > 0);
  assert.ok(theftEv(100, 10, 0.1, 1_000_000, 2_000) > 0);
  assert.ok(theftEv(100, 10, 0.1, 100_000, 2_000) < 0);
  // The fix is a large M, not a large burn: theft stops at about M = k·(1 + αB/setup).
  const M = minCutAndChoose(10, 1, 1_000_000, 1_540);
  assert.ok(theftEv(M, 10, 1, 1_000_000, 1_540) < 0 && theftEv(M - 1, 10, 1, 1_000_000, 1_540) >= 0);
  assert.ok(Math.abs(M - 10 * (1 + 1_000_000 / 1_540)) < 2, `M = ${M}`);
});

test("sizes: what a deal costs on chain", () => {
  const b = bondState(0);
  assert.equal(b.challenge.length, 103);
  assert.equal(b.respond.length, 103);
  assert.equal(TX.fund, 154);
  assert.equal(TX.child, 153);
  const ch = scriptPathVsize([SALT, 64, 64], b.challenge.length, 1);
  const rs = scriptPathVsize([MAX_STANDARD_ITEM, 64, 64], b.respond.length, 1);
  assert.equal(ch, 187, "428 WU non-witness + 320 WU witness");
  assert.equal(rs, 203, "the 80-byte item is 20 vB of it");
  // The 32-byte-r, 520-byte-element version measured 191 and 314 on regtest, but does not relay.
  assert.equal(scriptPathVsize([32, 64, 64], b.challenge.length, 1), 191);
  assert.equal(scriptPathVsize([MAX_ELEMENT, 64, 64], b.respond.length, 1), 314);
  const leaves = { challenge: b.challenge.length, respond: b.respond.length };
  assert.equal(dealVbytes(0, leaves), 308, "happy path: fund and cooperative close");
  assert.equal(dealVbytes(1, leaves), 308 + 187 + 203 + 2 * 153);
});
