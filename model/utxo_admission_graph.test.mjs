import test from 'node:test';
import assert from 'node:assert/strict';
import {transactionId, witnessTransactionId, signedDescendant, descendantReferencesParent} from './txid_admission.mjs';
import {
  TopologyLedger, makeTransaction, spendOf, fundingFixture,
  directProviderRefund, independentChallenge, contestChallenge,
  legacyCarrierMutation, witnessCarrierMutation, checkUnsignedRefundLeaves,
  puzzleCommitment
} from './utxo_admission_graph.mjs';

const at = (ledger,tx,height=200) => ledger.apply(tx,{height,authorized:true});

test('G01: unrelated certificate transaction leaves provider refund spendable', () => {
  const {ledger,bond,independentUTXO} = fundingFixture();
  at(ledger,independentChallenge(independentUTXO,'151-header'));
  assert.equal(ledger.has(bond),true);
  assert.doesNotThrow(()=>at(ledger,directProviderRefund(bond)));
});
test('G02: external certificate cannot change refund transaction identifier', () => {
  const a=fundingFixture(), b=fundingFixture();
  at(a.ledger, independentChallenge(a.independentUTXO,'100-header'));
  at(b.ledger, independentChallenge(b.independentUTXO,'151-header'));
  assert.equal(transactionId(directProviderRefund(a.bond)),transactionId(directProviderRefund(b.bond)));
});
test('G03: replacing a competing bond outpoint prevents old provider refund', () => {
  const {ledger,bond}=fundingFixture();
  const challenge=contestChallenge(bond,'weak-100');
  at(ledger,challenge,10);
  assert.throws(()=>at(ledger,directProviderRefund(bond),200),/missing or spent prevout/);
});
test('G04: independent later challenger cannot spend original output consumed by first', () => {
  const {ledger,bond}=fundingFixture();
  at(ledger,contestChallenge(bond,'weak-100'),10);
  assert.throws(()=>at(ledger,contestChallenge(bond,'strong-151'),20),/missing or spent prevout/);
});
test('G05: successor can be spent by later challenger only under assumed Script policy', () => {
  const {ledger,bond}=fundingFixture();
  const first=contestChallenge(bond,'weak-100');
  at(ledger,first,10);
  const second=contestChallenge(spendOf(first),'strong-151');
  assert.doesNotThrow(()=>at(ledger,second,20));
});
test('G06: refusing assumed script authorization blocks the successor transition', () => {
  const {ledger,bond}=fundingFixture();
  assert.throws(()=>ledger.apply(contestChallenge(bond,'weak-100'), {height:10,authorized:false}),/script authorization unverified/);
});
test('G07: changed parent output commitment changes child prevout', () => {
  const {bond}=fundingFixture();
  const weak=contestChallenge(bond,'weak-100'), strong=contestChallenge(bond,'strong-151');
  assert.notEqual(transactionId(weak),transactionId(strong));
  const preSignedChild=signedDescendant(transactionId(weak));
  assert.equal(descendantReferencesParent(preSignedChild,weak),true);
  assert.equal(descendantReferencesParent(preSignedChild,strong),false);
});
test('G08: modifying legacy unlocking data breaks pre-signed successor', () => {
  const {bond}=fundingFixture();
  const fixed=contestChallenge(bond,'weak-100');
  const child=signedDescendant(transactionId(fixed));
  const changed=legacyCarrierMutation(fixed,'0101');
  assert.equal(descendantReferencesParent(child,changed),false);
});
test('G09: witness-only mutation preserves txid but changes wtxid', () => {
  const {bond}=fundingFixture();
  const fixed=contestChallenge(bond,'weak-100');
  const changed=witnessCarrierMutation(fixed,['cafe']);
  assert.equal(transactionId(fixed),transactionId(changed));
  assert.notEqual(witnessTransactionId(fixed),witnessTransactionId(changed));
});
test('G10: a signed child still points at witness-mutated parent', () => {
  const {bond}=fundingFixture();
  const first=contestChallenge(bond,'weak-100');
  const child=signedDescendant(transactionId(first));
  assert.equal(descendantReferencesParent(child,witnessCarrierMutation(first,['151'])) ,true);
});
test('G11: real legacy scriptSig variant and witness variant have distinct txids', () => {
  const {bond}=fundingFixture();
  const a=contestChallenge(bond,'weak-100');
  const x=legacyCarrierMutation(a,'0101');
  assert.notEqual(transactionId(a),transactionId(x));
  const y=witnessCarrierMutation(a,['0101']);
  assert.equal(transactionId(a),transactionId(y));
});
test('G12: provider timelocked refund requires block strictly after nLockTime', () => {
  const {ledger,bond}=fundingFixture();
  assert.throws(()=>at(ledger,directProviderRefund(bond),150),/not final/);
  assert.doesNotThrow(()=>at(ledger,directProviderRefund(bond),151));
});
test('G13: settlement refund is still spendable after an unanswered unrelated challenge', () => {
  const {ledger,bond,independentUTXO}=fundingFixture();
  at(ledger,independentChallenge(independentUTXO,'strong-151'),20);
  assert.doesNotThrow(()=>at(ledger,directProviderRefund(bond),151));
});
test('G14: duplicate spend of consumed bond UTXO fails', () => {
  const {ledger,bond}=fundingFixture();
  at(ledger, directProviderRefund(bond),151);
  assert.throws(()=>at(ledger,contestChallenge(bond,'strong-151'),152),/missing or spent prevout/);
});
test('G15: output value cannot exceed input value in ledger', () => {
  const {ledger,bond}=fundingFixture();
  const steal=makeTransaction({source:bond,outputScripts:['51'],amounts:[150000n]});
  assert.throws(()=>at(ledger,steal),/creates value/);
});
test('G16: fee and outpoint identities are derived from transaction bytes', () => {
  const {ledger,bond}=fundingFixture();
  const tx=contestChallenge(bond,'weak-100');
  const result=at(ledger,tx);
  assert.equal(result.fee,1000n);
  assert.equal(result.created[0],`${transactionId(tx)}:0`);
});
test('G17: a metadata-only policy marks old direct refund as bypass', () => {
  const paths=[
    {id:'provider-refund-CLTV',payout:'provider',signers:['provider'],mustConsumeContestState:false},
    {id:'bitvm-rebuttal',payout:'provider',signers:['provider'],mustConsumeContestState:true},
    {id:'joint-cooperative-close',payout:'provider',signers:['provider','client'],mustConsumeContestState:false},
  ];
  assert.deepEqual(checkUnsignedRefundLeaves(paths).riskyPaths,['provider-refund-CLTV']);
});
test('G18: toggling only the new Binohash branch leaves old refund bypass', () => {
  const paths=[
    {id:'binohash-checked',payout:'provider',signers:['provider'],mustConsumeContestState:true},
    {id:'old-refund',payout:'provider',signers:['provider'],mustConsumeContestState:false},
  ];
  assert.deepEqual(checkUnsignedRefundLeaves(paths).riskyPaths,['old-refund']);
});
test('G19: test-only scriptPubKey commits to the candidate identity', () => {
  assert.equal(puzzleCommitment('contest/weak-100').length,68);
  assert.notEqual(puzzleCommitment('contest/weak-100'),puzzleCommitment('contest/strong-151'));
});
test('G20: two independent journals conflict only when spending same bond UTXO', () => {
  const a=fundingFixture();
  const cert=independentChallenge(a.independentUTXO,'strong-151');
  at(a.ledger,cert,20);
  assert.equal(a.ledger.has(a.bond),true);
  at(a.ledger,contestChallenge(a.bond,'strong-151'),20);
  assert.equal(a.ledger.has(a.bond),false);
});
test('G21: duplicate signed prevout within transaction rejected by ledger', () => {
  const {ledger,bond}=fundingFixture();
  const tx=contestChallenge(bond,'weak-100');
  tx.vin.push({...tx.vin[0]});
  assert.throws(()=>at(ledger,tx),/double-input/);
});
test('G22: unsigned or unverified successor is refused at authorization boundary', () => {
  const {ledger,bond}=fundingFixture();
  assert.throws(()=>ledger.apply(contestChallenge(bond,'strong-151'),{height:20}),/script authorization unverified/);
});
test('G23: refund without an active input fails regardless of valid locktime', () => {
  const {ledger,bond}=fundingFixture();
  at(ledger,contestChallenge(bond,'weak-100'),20);
  assert.throws(()=>at(ledger,directProviderRefund(bond),151),/missing or spent prevout/);
});
test('G24: a stronger challenge can be appended only to the output created by weaker challenge',()=>{
  const {ledger,bond}=fundingFixture();
  const first=contestChallenge(bond,'weak-100');
  at(ledger,first,10);
  const next=contestChallenge(spendOf(first),'strong-151');
  assert.equal(ledger.has(spendOf(first)),true);
  at(ledger,next,20);
  assert.equal(ledger.has(spendOf(first)),false);
  assert.equal(ledger.has(spendOf(next)),true);
});
