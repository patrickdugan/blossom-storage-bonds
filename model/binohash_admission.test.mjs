import test from 'node:test';
import assert from 'node:assert/strict';
import {
  certificate, timelyValid, maxWorkCertificate, journalRoot, makeRefundClaim,
  unsafeRefundCheck, specificationRefundCheck, carrierProperties,
  witnessBlindFieldCommitment
} from './binohash_admission.mjs';
const LOW = certificate('fork-100', 100n, 10, true, true);
const HIGH = certificate('fork-151', 151n, 19, true, false);
const WEAKER = certificate('fork-090', 90n, 18, true, true);
const END = 20;
const tx = {version:2, input:'bond-outpoint', lockTime:40, output:'provider-refund'};
function claim(journal, bestId = journal.at(-1)?.id ?? null) {
  return makeRefundClaim({chosenJournal: journal, sourceTxFields:tx, statedBestId:bestId});
}

// These passing tests are documented ATTACKS against unsafe designs.
test('A01: omitted 151-work fork: ideal transaction binding still accepts provider refund', () => {
  const reported = claim([LOW], LOW.id);
  assert.equal(unsafeRefundCheck(reported,[LOW]), true);
  assert.equal(specificationRefundCheck({claim:reported,completeJournal:[LOW,HIGH],admissionEnd:END,nowHeight:45}),false);
});
test('A02: an earlier weak challenge cannot extinguish the stronger timely challenger', () => {
  assert.equal(maxWorkCertificate([LOW,HIGH],END).id,HIGH.id);
  assert.equal(maxWorkCertificate([HIGH,LOW],END).id,HIGH.id);
});
test('A03: provider-selectable journal root is no authenticated completeness proof', () => {
  assert.notEqual(journalRoot([LOW]), journalRoot([LOW,HIGH]));
  assert.equal(unsafeRefundCheck(claim([LOW],LOW.id),[LOW]),true);
});
test('A04: even a later correct settlement commitment fails while strongest claim unresolved', () => {
  const c = claim([LOW,HIGH],HIGH.id);
  assert.equal(unsafeRefundCheck(c,[LOW,HIGH]),true);
  assert.equal(specificationRefundCheck({claim:c,completeJournal:[LOW,HIGH],admissionEnd:END,nowHeight:45}),false);
});
test('A05: challenge admitted just before cutoff must survive the refund window', () => {
  const late = certificate('just-in-time',200n,END,true,false);
  assert.equal(maxWorkCertificate([LOW,late],END).id,'just-in-time');
  assert.equal(specificationRefundCheck({claim:claim([LOW],LOW.id),completeJournal:[LOW,late],admissionEnd:END,nowHeight:21}),false);
});
test('A06: challenges after the admission cutoff cannot retroactively steal the bond', () => {
  const late = certificate('too-late',500n,END+1,true,false);
  assert.deepEqual(timelyValid([LOW,late],END),[LOW]);
  assert.equal(maxWorkCertificate([LOW,late],END).id,LOW.id);
});
test('A07: a weaker challenger cannot displace stronger cumulative-work evidence', () => {
  assert.equal(maxWorkCertificate([LOW,HIGH,WEAKER],END).id,HIGH.id);
});
test('A08: invalid higher-work evidence cannot displace a valid certificate', () => {
  const invalid = certificate('invalid-500',500n,END-1,false,false);
  assert.equal(maxWorkCertificate([LOW,invalid],END).id,LOW.id);
});
test('A09: a certificate committed in arbitrary witness data is absent from signed-field binding', () => {
  const original={signedFields:tx,witness:{certificate:'fork-100'}};
  const altered={signedFields:tx,witness:{certificate:'fork-151'}};
  assert.equal(witnessBlindFieldCommitment(original),witnessBlindFieldCommitment(altered));
});
test('A10: Binohash as published is a legacy bare-script, nonstandard-relay candidate', () => {
  const props = carrierProperties('legacy-binohash');
  assert.equal(props.bareLegacy,true);
  assert.equal(props.defaultRelay,false);
});
test('A11: replacing an asserted transaction root with itself is a tautological check', () => {
  const old=claim([LOW],LOW.id), current=claim([LOW,HIGH],HIGH.id);
  assert.equal(unsafeRefundCheck(old,[LOW]),true);
  assert.equal(unsafeRefundCheck(current,[LOW,HIGH]),true);
  assert.notEqual(old.txCommitment,current.txCommitment);
});
test('A12: an admitted answered strongest certificate can satisfy the IDEAL policy oracle', () => {
  const answered=certificate('fork-151',151n,19,true,true);
  const log=[LOW,answered];
  const c=claim(log,answered.id);
  assert.equal(specificationRefundCheck({claim:c,completeJournal:log,admissionEnd:END,nowHeight:45}),true);
});
test('A13: provider refund before admission closes is ruled out by ideal policy', () => {
  const c=claim([],null);
  assert.equal(specificationRefundCheck({claim:c,completeJournal:[],admissionEnd:END,nowHeight:END}),false);
});
test('A14: challenge order does not determine exact-work winner', () => {
  const x=[LOW,HIGH,WEAKER], y=[WEAKER,LOW,HIGH];
  assert.equal(maxWorkCertificate(x,END).id,maxWorkCertificate(y,END).id);
});
test('A15: the reference policy check itself depends on omniscient journal access', () => {
  const submitted=claim([LOW],LOW.id);
  const viewA=specificationRefundCheck({claim:submitted,completeJournal:[LOW],admissionEnd:END,nowHeight:45});
  const viewB=specificationRefundCheck({claim:submitted,completeJournal:[LOW,HIGH],admissionEnd:END,nowHeight:45});
  assert.equal(viewA,true);
  assert.equal(viewB,false);
});

test('A16: first-challenger gate censors the stronger later certificate', async () => {
  const {naiveFirstChallengerGate} = await import('./binohash_admission.mjs');
  const gate = naiveFirstChallengerGate([LOW,HIGH]);
  assert.equal(gate.admitted[0].id,LOW.id);
  assert.equal(gate.blocked[0].id,HIGH.id);
});
test('A17: protecting a Binohash branch leaves an independent old refund leaf spendable', async () => {
  const {unguardedRefundPath} = await import('./binohash_admission.mjs');
  assert.equal(unguardedRefundPath({binohashCheckedOnNewPath:true,originalRefundLeafStillExists:true}),true);
  assert.equal(unguardedRefundPath({binohashCheckedOnNewPath:true,originalRefundLeafStillExists:false}),false);
});