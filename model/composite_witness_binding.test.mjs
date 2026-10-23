import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {transactionId,witnessTransactionId} from './txid_admission.mjs';
import {compositeAnchoringSamples,BINOLOCK} from './composite_cursor_consensus_vectors.mjs';
import {verifyToyScript} from './binohash_finddelete_poc.mjs';
import {syntheticWitnessBlock,verifySyntheticWitnessAnchor,certificateSha256,p2wshScriptPubKey} from './witness_anchor.mjs';

/**
 * A dynamic certificate can be carried in a genuine SegWit witness while the
 * same transaction also uses a legacy Binohash carrier to authenticate a
 * 32-byte OP_RETURN commitment to that certificate. Actual Bitcoin blocks
 * bind wtxids via BIP141. This file uses synthetic commitment trees only.
 *
 * Crucially the verifier must CHECK that SHA256(witness certificate) equals
 * OP_RETURN; neither the P2WSH OP_DROP script nor the Binohash signature
 * (which covers only the OP_RETURN) enforces that equality by itself.
 */
let a,b,blockA,blockB;
before(()=>{
  ({a,b}=compositeAnchoringSamples());
  blockA=syntheticWitnessBlock(a);blockB=syntheticWitnessBlock(b);
});
const committed=tx=>tx.vout[0].scriptPubKey==='6a20'+certificateSha256(tx);
const anchor=(tx,block)=>verifySyntheticWitnessAnchor({
  challenge:tx,block,expectedCertificateDigest:certificateSha256(tx)
});
const replaceWitness=(tx,newBytes)=>({...tx,vin:tx.vin.map((v,i)=>i===0?{...v,witness:[newBytes,v.witness[1]]}:v)});
test('WJ01: composite sponsor uses a real P2WSH witness program',()=>{
  assert.equal(p2wshScriptPubKey.length,68);
  assert.equal(a.vin[0].scriptSig,'');
  assert.equal(a.vin[0].witness[1],'7551');
});
test('WJ02: Binohash-protected certificate output equals hash of actual witness',()=>{
  assert.equal(committed(a),true);assert.equal(committed(b),true);
});
test('WJ03: two independently chosen certificates produce distinct txids when output commitment changes',()=>{
  assert.notEqual(transactionId(a),transactionId(b));
});
test('WJ04: a witness mutation alone keeps txid fixed while changing wtxid',()=>{
  const mutated=replaceWitness(a,b.vin[0].witness[0]);
  assert.equal(transactionId(mutated),transactionId(a));
  assert.notEqual(witnessTransactionId(mutated),witnessTransactionId(a));
});
test('WJ05: genuine witness inclusion evidence distinguishes witness variants',()=>{
  const mutated=replaceWitness(a,b.vin[0].witness[0]);
  assert.equal(anchor(a,blockA),true);
  assert.equal(anchor(mutated,blockA),false);
});
test('WJ06: changed witness can obtain new synthetic inclusion proof but fails committed certificate equality',()=>{
  const mutated=replaceWitness(a,b.vin[0].witness[0]);
  assert.equal(anchor(mutated,syntheticWitnessBlock(mutated)),true);
  assert.equal(committed(mutated),false);
});
test('WJ07: changing witness without OP_RETURN leaves legacy Binohash signature valid',()=>{
  const mutated=replaceWitness(a,b.vin[0].witness[0]);
  assert.equal(verifyToyScript(a,BINOLOCK,{inputIndex:2}).valid,true);
  assert.equal(verifyToyScript(mutated,BINOLOCK,{inputIndex:2}).valid,true);
});
test('WJ08: changing OP_RETURN to match new witness breaks existing Binohash signature',()=>{
  const mutated=replaceWitness(a,b.vin[0].witness[0]);
  const fakeMatch={...mutated,vout:mutated.vout.map((o,i)=>i===0?{...o,scriptPubKey:'6a20'+certificateSha256(mutated)}:o)};
  assert.equal(committed(fakeMatch),true);
  assert.equal(verifyToyScript(fakeMatch,BINOLOCK,{inputIndex:2}).valid,false);
});
test('WJ09: authentic OP_RETURN plus correct synthetic inclusion are both required by intended BitVM predicate',()=>{
  const forged=replaceWitness(a,b.vin[0].witness[0]);
  const intended=(tx,block)=>anchor(tx,block)&&committed(tx);
  assert.equal(intended(a,blockA),true);
  assert.equal(intended(b,blockB),true);
  assert.equal(intended(forged,syntheticWitnessBlock(forged)),false);
});
test('WJ10: BIP141 inclusion does not prove canonical block or exact cumulative work',()=>{
  assert.equal(blockA.fakeBlock,true);
  assert.equal(Object.hasOwn(blockA,'validPow'),false);
  assert.equal(Object.hasOwn(blockA,'work'),false);
});
