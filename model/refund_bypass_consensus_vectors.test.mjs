import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {
  REFUND_BOND,REFUND_FEE_INPUT,INDEPENDENT_JOURNAL_FUND,PROVIDER_REFUND_SCRIPT,
  providerRefundSamples,refundBypassConsensusVectors
} from './refund_bypass_consensus_vectors.mjs';
import {p2wshScriptPubKey} from './witness_anchor.mjs';
import {TopologyLedger} from './utxo_admission_graph.mjs';
import {cursorGenesis,cursorUpdate} from './journal_cursor.mjs';
import {ContestSpecification} from './contest_spec.mjs';
import {transactionId,witnessTransactionId} from './txid_admission.mjs';

let f,rows,samples;
before(()=>{
  f=refundBypassConsensusVectors();
  rows=new Map(f.cases.map(c=>[c.name,c]));
  samples=providerRefundSamples();
});
const row=name=>rows.get(name);
const at=(ledger,tx,height)=>ledger.apply(tx,{height,authorized:true});

test('RB01: two supplied Script inputs include the independent provider refund and P2WSH carrier',()=>{
  assert.equal(f.checks.length,2);
  assert.equal(f.checks[0].script_pub_key,PROVIDER_REFUND_SCRIPT);
  assert.equal(f.checks[1].script_pub_key,p2wshScriptPubKey);
  assert.equal(PROVIDER_REFUND_SCRIPT.slice(0,10),'029600b175');
});
test('RB02: weak and stronger certificate tags produce identical refund txid',()=>{
  assert.equal(f.facts.weakTxid,f.facts.strongerTxid);
  assert.equal(transactionId(samples.weak),transactionId(samples.strong));
  assert.notEqual(witnessTransactionId(samples.weak),witnessTransactionId(samples.strong));
});
test('RB03: provider signature is reused without modification after witness-only change',()=>{
  assert.equal(f.facts.providerSignatureUnchanged,true);
  assert.equal(samples.weak.vin[0].scriptSig,samples.strong.vin[0].scriptSig);
  assert.equal(row('provider-refund-strong-151-certificate-tag').expected_valid,true);
});
test('RB04: Bitcoin Script has no input referring to independent journal funding',()=>{
  assert.equal(f.facts.noJournalCursorInput,true);
  assert.equal(samples.strong.vin.length,2);
  assert.equal(samples.strong.vin[0].prevTxid,REFUND_BOND.txid);
  assert.equal(samples.strong.vin[1].prevTxid,REFUND_FEE_INPUT.txid);
});
test('RB05: external journal context does not change the raw refund transaction',()=>{
  assert.equal(row('provider-refund-strong-151-certificate-tag').tx_hex,
    row('provider-refund-after-external-weak-to-strong-journal').tx_hex);
  assert.equal(row('provider-refund-after-external-weak-to-strong-journal').expected_valid,true);
});
test('RB06: SIGHASH_ALL protects refund amount and recipient even with ANYONECANPAY',()=>{
  for(const name of ['provider-refund-redirected-payout','provider-refund-devalued-payout']){
    assert.deepEqual(row(name).expected_inputs.map(x=>x.expected_valid),[false,true]);
  }
});
test('RB07: ANYONECANPAY allows replacement fee input without provider re-signing',()=>{
  assert.equal(row('provider-refund-swapped-fee-input').expected_valid,true);
  assert.equal(f.facts.sighashType,0x81);
});
test('RB08: CLTV enforces refund locktime and non-final sequence at Script level',()=>{
  for(const name of ['provider-refund-re-signed-under-CLTV','provider-refund-re-signed-with-final-sequence']){
    assert.deepEqual(row(name).expected_inputs.map(x=>x.expected_valid),[false,true]);
  }
  assert.equal(f.facts.expectedEarliestConfirmationHeight,151);
});
test('RB09: provider key and bond outpoint still have cryptographic signature checks',()=>{
  for(const name of ['provider-refund-without-provider-signature','provider-refund-changed-bond-prevout']){
    assert.equal(row(name).expected_valid,false);
  }
});
test('RB10: 520-byte witness tag can vary without altering protected legacy refund fields',()=>{
  assert.equal(samples.huge.vin[1].witness[0].length,1040);
  assert.equal(transactionId(samples.weak),transactionId(samples.huge));
  assert.notEqual(witnessTransactionId(samples.weak),witnessTransactionId(samples.huge));
  assert.equal(row('provider-refund-max-size-witness-tag').expected_valid,true);
});
test('RB11: real UTXO topology still allows provider to refund after two externally authorized updates',()=>{
  // This ledger checks topology and finality with an explicit authorization
  // oracle; the CI Core harness independently checks these SAME refund bytes
  // under the provider's representative CLTV locking script.
  const ledger=new TopologyLedger([
    {txid:REFUND_BOND.txid,vout:0,amount:REFUND_BOND.amount,scriptPubKey:PROVIDER_REFUND_SCRIPT},
    {txid:REFUND_FEE_INPUT.txid,vout:0,amount:REFUND_FEE_INPUT.amount,scriptPubKey:p2wshScriptPubKey},
    {txid:INDEPENDENT_JOURNAL_FUND.txid,vout:0,amount:INDEPENDENT_JOURNAL_FUND.amount,scriptPubKey:'51'}
  ]);
  const genesis=cursorGenesis({source:INDEPENDENT_JOURNAL_FUND,sourceValue:INDEPENDENT_JOURNAL_FUND.amount});
  at(ledger,genesis.tx,2);
  const weak=cursorUpdate({cursor:genesis,certificateId:'weak-100',work:100n,validatedWork:true});
  at(ledger,weak.tx,10);
  const strong=cursorUpdate({cursor:weak,certificateId:'strong-151-tag',work:151n,validatedWork:true});
  at(ledger,strong.tx,20);
  assert.equal(ledger.has(strong.ref),true);
  assert.equal(ledger.has(REFUND_BOND),true);
  assert.throws(()=>at(ledger,samples.strong,150),/not final/);
  assert.doesNotThrow(()=>at(ledger,samples.strong,151));
  assert.equal(ledger.has(REFUND_BOND),false);
  assert.equal(ledger.has(strong.ref),true);
});
test('RB12: the desired oracle forfeits an unanswered stronger challenge that this graph bypasses',()=>{
  const spec=new ContestSpecification({admissionEnd:20,responseBlocks:5});
  spec.submit({id:'weak-100',headerRoot:'aa'.repeat(32),work:100n,height:10},
    {confirmedHeight:10,verifiedExactWork:true});
  spec.submit({id:'strong-151-tag',headerRoot:'bb'.repeat(32),work:151n,height:20},
    {confirmedHeight:20,verifiedExactWork:true});
  const frozen=spec.freeze(21);
  assert.equal(frozen.required.length,1);
  assert.equal(spec.payout(151),'forfeit');
  assert.equal(row('provider-refund-after-external-weak-to-strong-journal').expected_valid,true);
});
test('RB13: every consensus test spells out expected result for BOTH inputs',()=>{
  assert.equal(f.cases.length,11);
  for(const c of f.cases) {
    assert.deepEqual(c.expected_inputs.map(x=>x.input_index),[0,1]);
    assert.equal(c.expected_valid,c.expected_inputs.every(x=>x.expected_valid));
    assert.equal(typeof c.tx_hex,'string');
  }
});