/**
 * Binohash admission research model, deliberately NOT a Bitcoin/BitVM verifier.
 *
 * Threat model: grant the provider an IDEAL binding of chosen signed transaction
 * fields to the journal-root it asserts. This is stronger than an implemented
 * Binohash script. Show that even this ideal binding cannot establish journal
 * COMPLETENESS or rule out a refund bypass.
 *
 * Certificate 'work' values are assumed to have been independently verified by
 * a separate exact chain-work verifier. This test makes no proof-validity claim.
 */
import { createHash } from 'node:crypto';

export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonical = (x) => JSON.stringify(x);

export function certificate(id, work, blockHeight, valid = true, answered = false) {
  if (!Number.isSafeInteger(blockHeight) || blockHeight < 0) throw new Error('invalid height');
  if (typeof work !== 'bigint' || work < 0n) throw new Error('work must be nonnegative bigint');
  return Object.freeze({id, work, blockHeight, valid, answered});
}
export function timelyValid(journal, admissionEnd) {
  // blockHeight and validity are supplied by a trusted fixture in this MODEL.
  // Bitcoin Script does not have this collection or consensus observation.
  return journal.filter(c => c.valid && c.blockHeight <= admissionEnd);
}
export function maxWorkCertificate(journal, admissionEnd) {
  const candidates = timelyValid(journal, admissionEnd);
  return [...candidates].sort((a,b) => a.work === b.work
    ? a.id.localeCompare(b.id) : (a.work > b.work ? -1 : 1))[0] ?? null;
}
export function journalRoot(journal) {
  const encoded = journal.map(c => [c.id, c.work.toString(), c.blockHeight, c.valid ? 1 : 0]);
  // Domain-separated canonical commitment to an explicitly supplied collection.
  // Represents neither on-chain publication nor a Merkle nonmembership proof.
  return sha256('BSB/JOURNAL-SUBSET/TEST-ONLY\0' + canonical(encoded));
}
export function makeRefundClaim({chosenJournal, sourceTxFields, payout = 'provider', statedBestId = null}) {
  const root = journalRoot(chosenJournal);
  const fields = { ...sourceTxFields, root, payout, statedBestId };
  return Object.freeze({fields, root, txCommitment: idealTxFieldBinding(fields)});
}
export function idealTxFieldBinding(fields) {
  // IDEALIZATION: fixed, pinned, signed transaction fields have a unique digest.
  // This deliberately grants Binohash an unrealistically strong property.
  return sha256('BSB/IDEAL-FIELD-BINDING/TEST-ONLY\0' + canonical(fields));
}
export function unsafeRefundCheck(claim, presentedSubset) {
  // UNSAFE illustrative design: verifies the spend's claim to the provider's
  // own selected journal subset, but never authenticates completeness.
  return claim.txCommitment === idealTxFieldBinding(claim.fields) &&
    claim.root === journalRoot(presentedSubset) &&
    claim.fields.payout === 'provider';
}
export function specificationRefundCheck({claim, completeJournal, admissionEnd, nowHeight}) {
  // A *specification oracle*, NOT an implementable Bitcoin Script. The caller
  // magically supplies a complete journal and verifies all certificates.
  if (nowHeight <= admissionEnd) return false;
  if (claim.root !== journalRoot(timelyValid(completeJournal, admissionEnd))) return false;
  const best = maxWorkCertificate(completeJournal, admissionEnd);
  if (best && (!best.answered || claim.fields.statedBestId !== best.id)) return false;
  return claim.txCommitment === idealTxFieldBinding(claim.fields);
}
export function carrierProperties(carrier) {
  const table = {
    'taproot-witness': {witnessCommitment: false, preservesTxidWhenWitnessChanges: true, bareLegacy: false, defaultRelay: true},
    'legacy-binohash': {witnessCommitment: false, preservesTxidWhenWitnessChanges: false, bareLegacy: true, defaultRelay: false},
    'ideal-binohash': {witnessCommitment: false, preservesTxidWhenWitnessChanges: false, bareLegacy: true, defaultRelay: false},
  };
  if (!(carrier in table)) throw new Error(`Unknown carrier ${carrier}`);
  return table[carrier];
}
export function witnessBlindFieldCommitment(tx) {
  // Toy hash projection demonstrating the distinction between fields in a
  // signature digest and arbitrary witness/scriptSig contents. NOT a txid.
  return idealTxFieldBinding(tx.signedFields);
}

export function naiveFirstChallengerGate(challenges) {
  // UNSAFE gate: first admitted challenge consumes the shared challenge UTXO.
  const chronological = [...challenges].sort((a,b) => a.blockHeight - b.blockHeight);
  return { admitted: chronological.slice(0,1), blocked: chronological.slice(1) };
}
export function unguardedRefundPath({binohashCheckedOnNewPath, originalRefundLeafStillExists}) {
  // Model independent spending branch: protecting a new branch cannot constrain
  // a provider-controlled old branch spending the same UTXO.
  return Boolean(binohashCheckedOnNewPath && originalRefundLeafStillExists);
}
