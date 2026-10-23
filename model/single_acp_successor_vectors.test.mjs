import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {signedSingleSuccessorVectors,P2PK} from './single_acp_successor_vectors.mjs';
import {decodeLegacyTransaction,legacySignatureHash} from './legacy_sighash.mjs';
import {parseBitcoinSignature,parsePubkey,displayHashToZ,verifyECDSA} from './secp256k1_legacy_demo.mjs';
import {transactionId} from './txid_admission.mjs';

let fixture,byName;
before(()=>{fixture=signedSingleSuccessorVectors();byName=new Map(fixture.cases.map(c=>[c.name,c]));});
const vec=n=>byName.get(n);
function validSignatureFor(name) {
  const tx=decodeLegacyTransaction(vec(name).tx_hex);
  const sig=parseBitcoinSignature(tx.vin[1].scriptSig.slice(2));
  const z=displayHashToZ(legacySignatureHash(tx,1,P2PK,sig.hashType));
  return verifyECDSA({z,r:sig.r,s:sig.s,publicKey:parsePubkey(P2PK.slice(2,-2))});
}
test('SC01: legacy bare P2PK script uses known published test key',()=>{
  assert.equal(P2PK.slice(0,2),'21');
  assert.equal(P2PK.slice(-2),'ac');
});
test('SC02: signature is SIGHASH_SINGLE | ANYONECANPAY',()=>{
  const sig=parseBitcoinSignature(decodeLegacyTransaction(vec('signed-successor-template-A').tx_hex).vin[1].scriptSig.slice(2));
  assert.equal(sig.hashType,0x83);
});
test('SC03: signature verifies over pre-signed successor A',()=>{
  assert.equal(validSignatureFor('signed-successor-template-A'),true);
});
test('SC04: signed output survives certificate substitution in a different output slot',()=>{
  assert.equal(validSignatureFor('change-certificate-output-zero'),true);
  assert.notEqual(fixture.relationships.certificateA,fixture.relationships.certificateB);
});
test('SC05: sponsor input can be replaced without invalidating pre-signed successor',()=>{
  assert.equal(validSignatureFor('replace-unrelated-sponsor-input'),true);
});
test('SC06: unrelated sponsor change output may be edited',()=>{
  assert.equal(validSignatureFor('change-unprotected-output-two'),true);
});
test('SC07: protected successor script cannot be redirected without new signature',()=>{
  assert.equal(validSignatureFor('redirect-protected-successor-output-one'),false);
});
test('SC08: protected successor amount cannot be changed without new signature',()=>{
  assert.equal(validSignatureFor('steal-protected-successor-amount'),false);
});
test('SC09: protected current cursor prevout cannot be changed without new signature',()=>{
  assert.equal(validSignatureFor('replace-protected-current-cursor-input'),false);
});
test('SC10: next-generation template signed for exact parent A validates',()=>{
  assert.equal(validSignatureFor('presigned-next-generation-for-parent-A'),true);
  assert.equal(fixture.relationships.childAPrevout,fixture.relationships.parentA);
});
test('SC11: same next-generation signature fails when parent certificate differs',()=>{
  assert.notEqual(fixture.relationships.parentA,fixture.relationships.parentB);
  assert.equal(validSignatureFor('stale-next-generation-signature-on-parent-B'),false);
});
test('SC12: new authorized signature for parent B validates, but requires signing its new prevout',()=>{
  assert.equal(validSignatureFor('freshly-signed-next-generation-for-parent-B'),true);
  assert.equal(fixture.relationships.childBPrevout,fixture.relationships.parentB);
});
test('SC13: both initial variants preserve same script and amount in protected successor output',()=>{
  assert.equal(fixture.relationships.aSuccessorScript,fixture.relationships.bSuccessorScript);
  assert.equal(fixture.relationships.aSuccessorValue,'40000');
  assert.equal(fixture.relationships.aSuccessorValue,fixture.relationships.bSuccessorValue);
});
test('SC14: deterministic signed transaction bytes preserve txid identity',()=>{
  for(const v of fixture.cases){
    const tx=decodeLegacyTransaction(v.tx_hex);
    assert.equal(transactionId(tx),v.txid);
  }
});
