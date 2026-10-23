import test from 'node:test';
import assert from 'node:assert/strict';
import {
  csvScriptHeightOk,bip68HeightFinal,forfeitContextOk,cltvScriptHeightOk,
  absoluteHeightFinal,refundContextOk,SEQUENCE_DISABLE_FLAG,SEQUENCE_TYPE_FLAG,
  SEQUENCE_FINAL
} from './contextual_finality.mjs';

const challenge={version:2,sequence:144,delay:144,outpointHeight:500};
const refund={contractEndHeight:960000,nLockTime:960000,sequence:0xfffffffe};

test('CF01: correct 144-block CSV Script accepts while BIP68 rejects one block early',()=>{
  assert.equal(csvScriptHeightOk(challenge),true);
  assert.equal(forfeitContextOk({...challenge,candidateHeight:643}),false);
  assert.equal(forfeitContextOk({...challenge,candidateHeight:644}),true);
});
test('CF02: a longer signed sequence raises the BIP68 height requirement',()=>{
  const altered={...challenge,sequence:200};
  assert.equal(csvScriptHeightOk(altered),true);
  assert.equal(forfeitContextOk({...altered,candidateHeight:644}),false);
  assert.equal(forfeitContextOk({...altered,candidateHeight:699}),false);
  assert.equal(forfeitContextOk({...altered,candidateHeight:700}),true);
});
test('CF03: disabled flag and transaction version 1 invalidate CSV',()=>{
  assert.equal(csvScriptHeightOk({...challenge,version:1}),false);
  assert.equal(csvScriptHeightOk({...challenge,sequence:SEQUENCE_DISABLE_FLAG|144}),false);
  // BIP68 itself does not impose a relative lock on disabled sequences.
  assert.equal(bip68HeightFinal({...challenge,sequence:(SEQUENCE_DISABLE_FLAG|144)>>>0,candidateHeight:500}),true);
});
test('CF04: time-based sequence cannot be judged without MTP data',()=>{
  const seq=SEQUENCE_TYPE_FLAG|144;
  assert.equal(csvScriptHeightOk({...challenge,sequence:seq}),false);
  assert.throws(()=>bip68HeightFinal({...challenge,sequence:seq,candidateHeight:700}),
    /median-time-past/);
});
test('CF05: CLTV Script can pass even when nLockTime is not block-final',()=>{
  assert.equal(cltvScriptHeightOk(refund),true);
  assert.equal(refundContextOk({...refund,candidateHeight:960000}),false);
  assert.equal(absoluteHeightFinal({nLockTime:960000,candidateHeight:960000}),false);
  assert.equal(refundContextOk({...refund,candidateHeight:960001}),true);
});
test('CF06: new signature cannot replace the promised CLTV time with earlier one',()=>{
  assert.equal(cltvScriptHeightOk({...refund,nLockTime:959999}),false);
  assert.equal(refundContextOk({...refund,nLockTime:959999,candidateHeight:960001}),false);
  assert.equal(cltvScriptHeightOk({...refund,sequence:SEQUENCE_FINAL}),false);
});
test('CF07: invalid sequences, heights and insufficient CSV values fail closed',()=>{
  for(const sequence of [-1,0xffffffff+1,143,1.5]){
    assert.equal(csvScriptHeightOk({...challenge,sequence}),false);
  }
  assert.equal(forfeitContextOk({...challenge,candidateHeight:-1}),false);
  assert.equal(forfeitContextOk({...challenge,candidateHeight:500_000_000}),false);
  assert.equal(forfeitContextOk({...challenge,outpointHeight:500_000_000,candidateHeight:644}),false);
  assert.equal(refundContextOk({...refund,candidateHeight:500_000_000}),false);
});
test('CF08: protocol termination/cutoff still requires a miner inclusion policy',()=>{
  // The Script itself exposes NO upper height at which a valid challenge
  // stops being eligible, even after the refund is mature.
  const challengeHeight=960002;
  assert.equal(refundContextOk({...refund,candidateHeight:challengeHeight}),true);
  assert.equal(challengeHeight>refund.contractEndHeight,true);
  // This test only captures coexistence of two Script-eligible spends.
  // UTXO exclusivity depends on which conflicting transaction confirms.
});
