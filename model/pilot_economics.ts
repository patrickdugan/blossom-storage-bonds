// Phase 7C: pilot economics. Sampling, bond floors and per-epoch costs, from the sizes and timings
// the regtest and signet runs measured. Every input is a named parameter, so a pilot can redo the
// arithmetic for its own fee rate, storage price and term.

/** Measured transaction sizes in vB: regtest harness and full-stack runs. */
export const VSIZE = {
  fund: 154, close: 154, challenge: 187, respond: 203, cpfpChild: 153, forfeit: 138, refund: 138,
  /** One batched on-chain pay-per-proof transaction with 3 payee outputs (full-stack --pay onchain). */
  payBatch3: 240,
} as const;

/** Probability that q samples (with replacement) hit at least one of a fraction f of deleted chunks. */
export const detectPerEpoch = (f: number, q: number): number => 1 - (1 - f) ** q;

/** Probability a deleter of fraction f escapes every one of e sampled epochs. */
export const escapeOver = (f: number, q: number, e: number): number => (1 - detectPerEpoch(f, q)) ** e;

/** The smallest q (≤ qMax) such that a deleter of fraction f escapes e epochs with probability ≤ eps,
 *  or null if no q up to qMax does. */
export function minQ(f: number, e: number, eps: number, qMax = 256): number | null {
  for (let q = 1; q <= qMax; q++) if (escapeOver(f, q, e) <= eps) return q;
  return null;
}

/** On-chain cost, in sats, for the client to enforce one sentinel: challenge + CPFP child, then the
 *  forfeit, at `rate` sat/vB. Paid by the client, recovered from the bond. */
export const enforceCost = (rate: number): number => (VSIZE.challenge + VSIZE.cpfpChild + VSIZE.forfeit) * rate;

/** The provider's own on-chain cost to bond a deal and get the bond back (fund + refund). */
export const bondOverhead = (rate: number): number => (VSIZE.fund + VSIZE.refund) * rate;

/** What a late provider must pay to replace a forfeit with its answer (package RBF, harness S1):
 *  more than the forfeit's fee, at a rate above it, over respond + child. */
export const lateRespondBid = (forfeitRate: number, incrementalRate = 1): number =>
  Math.max(VSIZE.forfeit * forfeitRate + 1, (VSIZE.respond + VSIZE.cpfpChild) * (forfeitRate + incrementalRate));

export interface BondInputs {
  /** sats the provider saves over the term by deleting a fraction f (storage it no longer pays for). */
  savedSats: number;
  /** Probability the deletion is caught (and challenged) before the term ends. */
  pCaught: number;
  /** Probability one on-chain sentinel challenge forfeits a caught deleter (m windows). */
  pForfeitGivenChallenge: number;
  /** sat/vB the client must be able to pay to enforce, e.g. a fee spike it must survive. */
  stressRate: number;
}

/** The smallest bond, in sats, that makes deletion irrational and enforcement worth doing:
 *  - deterrence: pCaught · pForfeit · B > savedSats;
 *  - enforceability: B > the client's enforcement cost at the stress fee rate, or a cheat is too
 *    cheap to punish;
 *  - and B must leave headroom above a late provider's RBF bid, since a client in a bidding war
 *    may spend up to B. */
export function bondFloor(x: BondInputs): { deter: number; enforce: number; floor: number } {
  const deter = Math.ceil(x.savedSats / Math.max(1e-12, x.pCaught * x.pForfeitGivenChallenge));
  const enforce = Math.ceil(enforceCost(x.stressRate) + lateRespondBid(x.stressRate));
  return { deter, enforce, floor: Math.max(deter, enforce) };
}

/** Fee share of a pay-per-proof payment on chain: batch fee per payee output over the amount paid. */
export const onchainFeeShare = (rate: number, sats: number, payeesInBatch = 3, epochsBatched = 1): number =>
  (VSIZE.payBatch3 * rate / payeesInBatch) / (sats * epochsBatched);
