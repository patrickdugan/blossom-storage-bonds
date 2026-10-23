import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {witnessStableChainVectors} from './witness_stable_chain_vectors.mjs';
import {witnessChallengeTx,certificateSha256,syntheticWitnessBlock,verifySyntheticWitnessAnchor} from './witness_anchor.mjs';
import {decodeLegacyTransaction} from './legacy_sighash.mjs';
import {transactionId,witnessTransactionId} from './txid_admission.mjs';

let f,lookup;
before(()=>{f=witnessStableChainVectors();lookup=new Map(f.cases.map(x=>[x.name,x]));});
const get=n=>lookup.get(n);
test('WS01: the parent txid remains fixed across different witness certificates',()=>{
  assert.equal(f.facts.parentTxid,f.facts.parentAltTxid);
  assert.notEqual(f.facts.parentWtxid,f.facts.parentAltWtxid);
});
test('WS02: the pre-signed second generation references the parent txid and output 1',()=>{
  assert.equal(f.facts.childPrevout,f.facts.parentTxid);
  assert.equal(f.facts.childVout,1);
});
test('WS03: the signed child remains usable after either first-generation witness variant',()=>{
  assert.equal(f.facts.witnessOnlyAlternateHasSameAuthorization,true);
  assert.equal(get('generation-1-certificate-B').expected_valid,true);
});
test('WS04: changing second-generation witness likewise preserves its txid',()=>{
  assert.equal(f.facts.childTxid,f.facts.childAltTxid);
  assert.notEqual(f.facts.childWtxid,f.facts.childAltWtxid);
});
test('WS05: authorizing witness C instead of witness A requires separate certificate-binding verification',()=>{
  assert.notEqual(f.facts.parentCommittedHash,f.facts.parentAltCertificateHash);
  assert.equal(get('generation-0-witness-only-C').expected_valid,true);
});
test('WS06: authorizing witness D instead of witness B also requires external binding',()=>{
  assert.notEqual(f.facts.childCommittedHash,f.facts.childAltCertificateHash);
  assert.equal(get('generation-1-witness-only-D').expected_valid,true);
});
test('WS07: second-generation wrong prevout breaks presignature and Binohash',()=>{
  const v=get('generation-1-with-wrong-prevout');
  assert.equal(v.expected_valid,false);
  assert.deepEqual(v.expected_inputs.map(x=>x.expected_valid),[true,false,false]);
});
test('WS08: regrinding Binohash for successor burn does not save pre-signed guardian',()=>{
  const v=get('generation-1-regrind-for-burn');
  assert.equal(v.expected_valid,false);
  assert.deepEqual(v.expected_inputs.map(x=>x.expected_valid),[true,false,true]);
});
test('WS09: both generations carry a P2WSH witness certificate in input 0',()=>{
  for(const name of ['generation-0-certificate-A','generation-1-certificate-B']){
    const v=get(name);
    assert.equal(v.tx_hex.slice(8,12),'0001');
    assert.notEqual(v.tx_hex,v.stripped_tx_hex);
  }
});
test('WS10: a mutated witness produces a new synthetic BIP141 inclusion proof',()=>{
  const c=witnessChallengeTx('aa'.repeat(32)),d=witnessChallengeTx('bb'.repeat(32));
  const a=syntheticWitnessBlock(c),b=syntheticWitnessBlock(d);
  const verify=(tx,block)=>verifySyntheticWitnessAnchor({challenge:tx,block,expectedCertificateDigest:certificateSha256(tx)});
  assert.equal(verify(c,a),true);
  assert.equal(verify(d,a),false);
  assert.equal(verify(d,b),true);
});
test('WS11: both stages retain a fixed number of pre-signed slots',()=>{
  assert.equal(f.cases.filter(x=>x.name.includes('generation-0-')).length,2);
  assert.equal(f.cases.filter(x=>x.name.includes('generation-1-')).length,4);
  assert.equal(f.facts.childVout,1);
});
test('WS12: no stage can validate cumulative work from the witness automatically',()=>{
  const good=get('generation-0-certificate-A'),altered=get('generation-0-witness-only-C');
  assert.equal(good.expected_valid,true);
  assert.equal(altered.expected_valid,true);
  assert.equal(good.txid,altered.txid);
  assert.notEqual(good.wtxid,altered.wtxid);
});
