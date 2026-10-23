import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {transactionId,witnessTransactionId} from './txid_admission.mjs';
import {BINOLOCK} from './composite_cursor_consensus_vectors.mjs';
import {verifyToyScript} from './binohash_finddelete_poc.mjs';
import {fixedCertificateGateSamples,fixedCertificateGateVectors} from './fixed_certificate_gate_vectors.mjs';

let f,rows,sample;
before(()=>{
  f=fixedCertificateGateVectors();
  rows=new Map(f.cases.map(x=>[x.name,x]));
  sample=fixedCertificateGateSamples();
});
const result=n=>rows.get(n);
const checks=n=>result(n).expected_inputs.map(x=>x.expected_valid);
const hashHex=hex=>createHash('sha256').update(Buffer.from(hex,'hex')).digest('hex');

test('FG01: fixed witness verifier hashes certificate A and has a matching P2WSH program',()=>{
  const digest=hashHex(sample.certificate);
  assert.equal(sample.script,'a820'+digest+'87');
  assert.equal(sample.witnessProgram,'0020'+hashHex(sample.script));
  assert.equal(f.checks[0].script_pub_key,sample.witnessProgram);
});
test('FG02: the output-0 digest exactly commits to fixed witness certificate A',()=>{
  assert.equal(sample.good.vout[0].scriptPubKey,'6a20'+hashHex(sample.certificate));
  assert.equal(f.facts.commitmentScript,sample.good.vout[0].scriptPubKey);
  assert.equal(f.facts.fixedCertificateSha256,hashHex(sample.certificate));
});
test('FG03: the protecting guardian uses ALL|ANYONECANPAY rather than SINGLE|ANYONECANPAY',()=>{
  assert.equal(f.facts.guardianSighashType,0x81);
  assert.equal(result('static-certificate-A-binds-witness-output-and-successor').expected_valid,true);
});
test('FG04: certificate substitution leaves txid unchanged but Core must reject P2WSH input',()=>{
  assert.equal(f.facts.originalTxid,f.facts.substitutedWitnessTxid);
  assert.notEqual(f.facts.originalWtxid,f.facts.substitutedWitnessWtxid);
  assert.deepEqual(checks('static-gate-rejects-witness-certificate-C'),[false,true,true]);
});
test('FG05: switching the witness verifier to one for C changes P2WSH hash and is rejected',()=>{
  assert.deepEqual(checks('static-gate-rejects-new-witness-script'),[false,true,true]);
  assert.notEqual(f.facts.fixedCertificateSha256,f.facts.secondCertificateSha256);
});
test('FG06: a fresh Binohash for changed OP_RETURN cannot beat the ALL guardian',()=>{
  assert.deepEqual(checks('static-commitment-mutation-reground'),[true,false,true]);
  assert.deepEqual(checks('static-commitment-mutation-unreground'),[true,false,false]);
});
test('FG07: a fresh Binohash for burnt or shaved successor cannot beat guardian',()=>{
  assert.deepEqual(checks('static-successor-script-mutation-reground'),[true,false,true]);
  assert.deepEqual(checks('static-successor-value-mutation-reground'),[true,false,true]);
  assert.equal(f.facts.protectedSuccessorAmount,'40000');
});
test('FG08: changing both cert and OP_RETURN still fails certificate and guardian checks',()=>{
  assert.deepEqual(checks('static-mutate-both-certificate-and-commitment'),[false,false,true]);
});
test('FG09: fee sponsor flexibility still requires a newly solved Binohash',()=>{
  assert.deepEqual(checks('static-change-fee-prevout-without-regrind'),[true,true,false]);
  assert.deepEqual(checks('static-change-fee-prevout-and-regrind'),[true,true,true]);
});
test('FG10: the actual toy Binohash checker accepts the regenerated mutation',()=>{
  assert.equal(verifyToyScript(sample.good,BINOLOCK,{inputIndex:2}).valid,true);
  const v=result('static-change-fee-prevout-and-regrind');
  assert.equal(v.expected_inputs[2].expected_valid,true);
});
test('FG11: every case has all three expected consensus Script input results',()=>{
  assert.equal(f.cases.length,10);
  for(const v of f.cases){
    assert.deepEqual(v.expected_inputs.map(i=>i.input_index),[0,1,2]);
    assert.equal(v.expected_valid,v.expected_inputs.every(i=>i.expected_valid));
  }
});
test('FG12: fixed hash can authorize only the setup-selected certificate in this construction',()=>{
  assert.equal(sample.good.vin[0].witness[0],sample.certificate);
  assert.equal(transactionId(sample.good),f.facts.originalTxid);
  assert.equal(witnessTransactionId(sample.good),f.facts.originalWtxid);
  assert.equal(f.cases.filter(c=>c.expected_valid===true).length,2);
});