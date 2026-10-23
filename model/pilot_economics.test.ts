// Phase 7C: the pilot's parameter arithmetic, checked against the runs it came from.
import { test } from "node:test";
import assert from "node:assert/strict";
import { bondFloor, detectPerEpoch, enforceCost, escapeOver, lateRespondBid, minQ, onchainFeeShare, VSIZE } from "./pilot_economics.ts";

test("EC01: the demo's q = 16 detects a 10% deleter 81.5% per epoch, as full-stack recorded", () => {
  assert.ok(Math.abs(detectPerEpoch(0.1, 16) - 0.8146979811148158) < 1e-12);
});

test("EC02: the escape the phase 7b Lightning rehearsal saw (two epochs at q = 16) has probability 3.4%", () => {
  assert.ok(Math.abs(escapeOver(0.1, 16, 2) - 0.0343) < 0.0005);
});

test("EC03: q = 64 (the Blake2s per-proof maximum) lets a 5% deleter escape 3 epochs less than 1 time in 10,000", () => {
  assert.ok(escapeOver(0.05, 64, 3) < 1.1e-4);
  assert.equal(minQ(0.05, 3, 1e-4), 60);
  assert.equal(minQ(0.01, 3, 1e-4), null, "a 1% deleter needs more than q = 256 over 3 epochs");
  assert.ok(escapeOver(0.01, 64, 30) < 1e-8, "but 30 daily epochs at q = 64 catch it");
});

test("EC04: enforcing one sentinel costs 478 vB; at 100 sat/vB that is 47,800 sats", () => {
  assert.equal(VSIZE.challenge + VSIZE.cpfpChild + VSIZE.forfeit, 478);
  assert.equal(enforceCost(100), 47_800);
});

test("EC05: a late responder must outbid the forfeit; the harness's 25 sat/vB beat a 1,000-sat forfeit", () => {
  // Harness S1: Forfeit_1 paid 1,000 sats (7.2 sat/vB over 138 vB); the 2 sat/vB late answer lost,
  // the 25 sat/vB one replaced it.
  assert.ok(lateRespondBid(1_000 / VSIZE.forfeit) < 25 * (VSIZE.respond + VSIZE.cpfpChild));
  assert.ok(lateRespondBid(1_000 / VSIZE.forfeit) > 2 * (VSIZE.respond + VSIZE.cpfpChild));
});

test("EC06: the bond floor for a 1 GB pilot deal is set by enforceability, not by deterrence", () => {
  // Deleting 10% of 1 GB for 30 days saves about 0.1 GB-month of storage: under 10 sats at
  // commodity prices. Deterrence alone would allow a tiny bond, but the client must be able to
  // afford enforcement through a 100 sat/vB spike, plus a bidding war against a late responder.
  const b = bondFloor({ savedSats: 10, pCaught: 1 - escapeOver(0.1, 64, 30), pForfeitGivenChallenge: 1 - 0.9 ** 16, stressRate: 100 });
  assert.ok(b.deter < 100);
  assert.equal(b.floor, b.enforce);
  assert.ok(b.floor > 80_000 && b.floor < 90_000, `floor ${b.floor}`);
});

test("EC07: on-chain pay per proof only pays off when batched; Lightning has no such floor", () => {
  assert.ok(onchainFeeShare(5, 512) > 0.75, "one 512-sat epoch at 5 sat/vB loses over 75% to fees");
  assert.ok(onchainFeeShare(5, 512, 3, 30) < 0.03, "30 epochs per payment: under 3%");
});
