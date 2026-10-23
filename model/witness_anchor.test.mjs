import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {transactionId,witnessTransactionId} from './txid_admission.mjs';
import {witnessChallengeTx,p2wshScriptPubKey,witnessScript,syntheticWitnessBlock,
        verifySyntheticWitnessAnchor,certificateSha256,merkleRoot,merklePath,verifyPath,sha256d} from './witness_anchor.mjs';

let a,b,block;
before(()=>{
  a=witnessChallengeTx('11'.repeat(32));
  b=witnessChallengeTx('22'.repeat(32));
  block=syntheticWitnessBlock(a);
});
const clone=x=>structuredClone(x);
const check=(challenge=a,ctx=block)=>verifySyntheticWitnessAnchor({challenge,block:ctx,expectedCertificateDigest:certificateSha256(challenge)});
test('WA01: changing a genuine SegWit witness preserves txid and changes wtxid',()=>{
  assert.equal(transactionId(a),transactionId(b));
  assert.notEqual(witnessTransactionId(a),witnessTransactionId(b));
});
test('WA02: challenge input is a native v0 P2WSH data-consuming script',()=>{
  const sha=createHash('sha256').update(Buffer.from('7551','hex')).digest('hex');
  assert.equal(p2wshScriptPubKey,'0020'+sha);
  assert.equal(witnessScript,'7551');
  assert.deepEqual(a.vin[0].witness,['11'.repeat(32),'7551']);
  assert.equal(a.vin[0].scriptSig,'');
});
test('WA03: certificate digest identifies actual witness bytes',()=>{
  assert.equal(certificateSha256(a),createHash('sha256').update(Buffer.from('11'.repeat(32),'hex')).digest('hex'));
  assert.notEqual(certificateSha256(a),certificateSha256(b));
});
test('WA04: synthetic BIP141 witness-to-coinbase-to-block-root path validates',()=>{
  assert.equal(check(),true);
  assert.equal(block.fakeBlock,true);
});
test('WA05: replacing certificate witness bytes breaks the existing inclusion proof',()=>{
  assert.equal(check(b,block),false);
});
test('WA06: a separately built synthetic block can commit the other witness variant',()=>{
  assert.equal(check(b,syntheticWitnessBlock(b)),true);
});
test('WA07: falsifying the witness Merkle root fails coinbase commitment',()=>{
  const c=clone(block);c.witnessMerkleRoot='ff'.repeat(32);
  assert.equal(check(a,c),false);
});
test('WA08: changing the coinbase reserved value breaks witness commitment',()=>{
  const c=clone(block);c.coinbaseTx.vin[0].witness[0]='dd'.repeat(32);
  assert.equal(check(a,c),false);
});
test('WA09: tampering coinbase OP_RETURN commitment invalidates BIP141 proof',()=>{
  const c=clone(block);c.coinbaseTx.vout[0].scriptPubKey='6a24aa21a9ed'+'ff'.repeat(32);
  assert.equal(check(a,c),false);
});
test('WA10: changing externally supplied block transaction root rejects coinbase inclusion',()=>{
  const c=clone(block);c.transactionMerkleRoot='ee'.repeat(32);
  assert.equal(check(a,c),false);
});
test('WA11: replacing coinbase Merkle sibling invalidates path',()=>{
  const c=clone(block);c.coinbaseTxidProof[0]='ff'.repeat(32);
  assert.equal(check(a,c),false);
});
test('WA12: replacing witness Merkle sibling invalidates path',()=>{
  const c=clone(block);c.witnessProof[0]='ee'.repeat(32);
  assert.equal(check(a,c),false);
});
test('WA13: missing witness commitment in coinbase fails',()=>{
  const c=clone(block);c.coinbaseTx.vout[0].scriptPubKey='51';
  assert.equal(check(a,c),false);
});
test('WA14: highest matching witness commitment output index wins (BIP141)',()=>{
  const c=clone(block);c.coinbaseTx.vout.push({valueSats:0n,scriptPubKey:'6a24aa21a9ed'+'ff'.repeat(32)});
  assert.equal(check(a,c),false);
});
test('WA15: independent Merkle path works for an odd number of leaves',()=>{
  const hash=x=>createHash('sha256').update(x).digest();
  const leaves=[hash('a'),hash('b'),hash('c')];
  for(let i=0;i<3;i++)assert.equal(verifyPath(leaves[i],i,merklePath(leaves,i),merkleRoot(leaves)),true);
});
test('WA16: witness commitment is SHA256d(witness_root || reserved)',()=>{
  const bytes=Buffer.concat([Buffer.from(block.witnessMerkleRoot,'hex'),Buffer.from(block.reservedValue,'hex')]);
  assert.equal(sha256d(bytes).toString('hex'),block.commitment);
});
test('WA17: inclusion alone cannot prove script validity',()=>{
  const invalid=clone(a);invalid.vin[0].witness[1]='7552'; // P2WSH witnessScript would not match original prevout.
  // A fabricated block can commit ANY serialized bytes. Script correctness is
  // an independent consensus condition, outside this Merkle proof.
  assert.equal(check(invalid,syntheticWitnessBlock(invalid)),true);
});
test('WA18: synthetic root carries no real PoW, canonicality or admission height',()=>{
  assert.equal(block.fakeBlock,true);
  assert.equal(Object.hasOwn(block,'confirmedHeight'),false);
  assert.equal(Object.hasOwn(block,'validPow'),false);
});
