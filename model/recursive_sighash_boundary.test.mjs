import test from 'node:test';
import assert from 'node:assert/strict';
import {legacySignatureHash} from './legacy_sighash.mjs';
import {transactionFixture} from './txid_admission.mjs';
import {dummyPool} from './binohash_finddelete_poc.mjs';
import {parseBitcoinSignature,parsePubkey,verifyECDSA,displayHashToZ} from './secp256k1_legacy_demo.mjs';

/**
 * A signature-type boundary on recursively pre-signed cursor transitions:
 * Every non-bug legacy ECDSA hash mode commits to its own input prevout.
 * The historical SIGHASH_SINGLE out-of-range bug removes that commitment,
 * but also ceases to authenticate ANY output, allowing arbitrary redirection.
 *
 * This is a constrained observation about legacy SIGHASH, not a no-covenant
 * theorem covering every possible Binohash/BitVM construction.
 */
const BASE=()=>({
  ...transactionFixture({outputScript:'51'}),
  vout:[
    {valueSats:0n,scriptPubKey:'6a20'+'aa'.repeat(32)},
    {valueSats:50000n,scriptPubKey:'51'}
  ],
  vin:[
    {prevTxid:'11'.repeat(32),prevVout:0,scriptSig:'',witness:[],sequence:0xfffffffe},
    {prevTxid:'22'.repeat(32),prevVout:0,scriptSig:'',witness:[],sequence:0xfffffffe}
  ]
});
const hash=(tx,mode)=>legacySignatureHash(tx,1,'51',mode);
const changedPrevout=tx=>({...tx,vin:tx.vin.map((v,i)=>i===1?{...v,prevTxid:'33'.repeat(32)}:v)});
const changedSuccessor=tx=>({...tx,vout:tx.vout.map((o,i)=>i===1?{...o,scriptPubKey:'6a20'+'cc'.repeat(32)}:o)});

for(const mode of [0x01,0x02,0x03,0x81,0x82,0x83]){
  test('Q01-'+mode.toString(16)+': normal ECDSA hash mode commits to signed input prevout',()=>{
    const original=BASE();
    assert.notEqual(hash(original,mode),hash(changedPrevout(original),mode));
  });
}
test('Q07: SIGHASH_SINGLE out-of-range bug makes prevout substitution invisible',()=>{
  const tx={...BASE(),vout:[{valueSats:0n,scriptPubKey:'51'}]};
  assert.equal(hash(tx,0x03),'00'.repeat(31)+'01');
  assert.equal(hash(tx,0x03),hash(changedPrevout(tx),0x03));
});
test('Q08: ANYONECANPAY cannot fix the out-of-range SINGLE bug',()=>{
  const tx={...BASE(),vout:[{valueSats:0n,scriptPubKey:'51'}]};
  assert.equal(hash(tx,0x83),'00'.repeat(31)+'01');
  assert.equal(hash(tx,0x83),hash(changedPrevout(tx),0x83));
});
test('Q09: the bugged SINGLE signature also ignores successor destinations',()=>{
  const tx={...BASE(),vout:[{valueSats:50000n,scriptPubKey:'51'}]};
  const changed={...tx,vout:[{valueSats:0n,scriptPubKey:'6a20'+'dd'.repeat(32)}]};
  assert.equal(hash(tx,0x03),hash(changed,0x03));
  assert.equal(hash(tx,0x83),hash(changed,0x83));
});
test('Q10: genuine dummy ECDSA signature verifies over buggy digest for unrelated outpoints',()=>{
  const dummy=dummyPool(1)[0];
  const signature=parseBitcoinSignature(dummy.signature);
  const original={...BASE(),vout:[{valueSats:0n,scriptPubKey:'51'}]};
  const altered=changedPrevout(original);
  for(const tx of [original,altered]){
    const z=displayHashToZ(hash(tx,signature.hashType));
    assert.equal(verifyECDSA({
      z,r:signature.r,s:signature.s,publicKey:parsePubkey(dummy.publicKey)
    }),true);
  }
});
test('Q11: SINGLE|ACP binds protected matching output but ignores unrelated certificate output',()=>{
  const tx=BASE();
  const certChange={...tx,vout:tx.vout.map((o,i)=>i===0?{...o,scriptPubKey:'6a20'+'bb'.repeat(32)}:o)};
  assert.equal(hash(tx,0x83),hash(certChange,0x83));
  assert.notEqual(hash(tx,0x83),hash(changedSuccessor(tx),0x83));
});
test('Q12: moving a future cursor to an unpredicted txid invalidates prior SINGLE|ACP authorization',()=>{
  const tx=BASE();
  assert.notEqual(hash(tx,0x83),hash(changedPrevout(tx),0x83));
});
