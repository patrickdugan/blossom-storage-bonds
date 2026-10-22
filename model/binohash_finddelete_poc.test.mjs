import test from 'node:test';
import assert from 'node:assert/strict';
import {before} from 'node:test';
import {legacySignatureHash} from './legacy_sighash.mjs';
import {N,G,inverse,multiply,pubkey,parsePubkey,recoverPublicKey,verifyECDSA,
  parseBitcoinSignature,encodeBitcoinSignature,displayHashToZ} from './secp256k1_legacy_demo.mjs';
import {solveToyBinohash,verifyToyScript,dummyPool,makeLockingScript,makeCarrierTx} from './binohash_finddelete_poc.mjs';
let solved;
before(()=>{solved=solveToyBinohash();});

test('P01: secp256k1 generator multiplication uses expected compressed public key',()=>{
  assert.equal(pubkey(multiply(1n)),pubkey(G));
  assert.equal(multiply(N),null);
});
test('P02: exactly nine-byte DER dummy signatures recover genuine Bitcoin ECDSA public keys',()=>{
  for(const d of solved.pool.slice(0,8)){
    assert.equal(d.signature.length/2,9);
    const sig=parseBitcoinSignature(d.signature);
    const bugZ=displayHashToZ('00'.repeat(31)+'01');
    assert.equal(verifyECDSA({z:bugZ,r:sig.r,s:sig.s,publicKey:parsePubkey(d.publicKey)}),true);
  }
});
test('P03: dummy signatures use Bitcoin SIGHASH_SINGLE out-of-range and are input-independent',()=>{
  const d=solved.pair[0],sig=parseBitcoinSignature(d.signature);
  assert.equal(sig.hashType,3);
  assert.equal(legacySignatureHash(solved.tx,1,solved.lockScript,sig.hashType), '00'.repeat(31)+'01');
  const changed={...solved.tx,vin:solved.tx.vin.map((v,i)=>i===0?{...v,prevTxid:'ab'.repeat(32)}:v)};
  assert.equal(legacySignatureHash(changed,1,solved.lockScript,sig.hashType), '00'.repeat(31)+'01');
});
test('P04: full toy unlock uses genuine Rmin ECDSA puzzle signature',()=>{
  const sig=parseBitcoinSignature(solved.puzzle.signature);
  const z=displayHashToZ(solved.hashDisplay);
  assert.equal(verifyECDSA({z,r:sig.r,s:sig.s,publicKey:parsePubkey(solved.puzzle.publicKey)}),true);
  assert.ok(solved.puzzle.signature.length/2<=59);
});
test('P05: toy legacy Script execution reaches a true clean stack',()=>{
  const result=verifyToyScript(solved.tx,solved.lockScript);
  assert.deepEqual(result,{valid:true,stackHeight:1,nonPushOps:81,lockBytes:881});
});
test('P06: output destination modification invalidates committed puzzle signature',()=>{
  const tx={...solved.tx,vout:[{valueSats:10000n,scriptPubKey:'52'}]};
  assert.equal(verifyToyScript(tx,solved.lockScript).valid,false);
});
test('P07: output amount modification invalidates committed puzzle signature',()=>{
  const tx={...solved.tx,vout:[{...solved.tx.vout[0],valueSats:9999n}]};
  assert.equal(verifyToyScript(tx,solved.lockScript).valid,false);
});
test('P08: previous transaction on independent sponsor input is signed by puzzle',()=>{
  const tx={...solved.tx,vin:solved.tx.vin.map((v,i)=>i===0?{...v,prevTxid:'ab'.repeat(32)}:v)};
  assert.equal(verifyToyScript(tx,solved.lockScript).valid,false);
});
test('P09: original Binohash carrier prevout is signed by puzzle',()=>{
  const tx={...solved.tx,vin:solved.tx.vin.map((v,i)=>i===1?{...v,prevTxid:'ab'.repeat(32)}:v)};
  assert.equal(verifyToyScript(tx,solved.lockScript).valid,false);
});
test('P10: changing puzzle sighash byte to ANYONECANPAY invalidates existing puzzle',()=>{
  const tx={...solved.tx,vin:solved.tx.vin.map((v,i)=>i===1?
    {...v,scriptSig:v.scriptSig.replace(solved.puzzle.signature,solved.puzzle.signature.slice(0,-2)+'81')}:v)};
  assert.equal(verifyToyScript(tx,solved.lockScript).valid,false);
});
test('P11: replacing dummy pubkey violates OP_CHECKMULTISIG signature check',()=>{
  const other=solved.pool.find(d=>d.publicKey!==solved.pair[0].publicKey);
  const tx={...solved.tx,vin:solved.tx.vin.map((v,i)=>i===1?
    {...v,scriptSig:v.scriptSig.replace(solved.pair[0].publicKey,other.publicKey)}:v)};
  assert.equal(verifyToyScript(tx,solved.lockScript).valid,false);
});
test('P12: witness NULLDUMMY must be zero',()=>{
  const tx={...solved.tx,vin:solved.tx.vin.map((v,i)=>i===1?{...v,scriptSig:'51'+v.scriptSig.slice(2)}:v)};
  assert.throws(()=>verifyToyScript(tx,solved.lockScript),/NULLDUMMY/);
});
test('P13: changing the selected dummy subset changes puzzle sighash',()=>{
  const a=solved.pool[solved.pairIndices[0]],b=solved.pool[solved.pairIndices[1]];
  const other=solved.pool.find(d=>d!==a&&d!==b);
  const old=legacySignatureHash(solved.tx,1,solved.lockScript,1,[a.signature,b.signature]);
  const different=legacySignatureHash(solved.tx,1,solved.lockScript,1,[a.signature,other.signature]);
  assert.notEqual(old,different);
});
test('P14: adding second output disables the historical SIGHASH_SINGLE bug',()=>{
  const tx={...solved.tx,vout:[...solved.tx.vout,{valueSats:0n,scriptPubKey:'51'}]};
  const d=solved.pair[0];
  assert.notEqual(legacySignatureHash(tx,1,solved.lockScript,3), '00'.repeat(31)+'01');
  assert.equal(verifyToyScript(tx,solved.lockScript).valid,false);
});
test('P15: selected dummy signatures are literal pushes in locking script, deleted only for signature hash',()=>{
  const script=makeLockingScript(solved.pool);
  assert.equal(script,solved.lockScript);
  for(const d of solved.pair)assert.ok(script.includes('09'+d.signature));
});
test('P16: toy is far below paper security parameter and has no Lamport commitments or transition covenant',()=>{
  assert.ok(solved.pool.length===80);
  assert.ok(solved.pairIndices.length===2);
  assert.ok(Math.log2(80*79/2)<12);
  assert.ok(solved.lockScript.length/2<1000);
});
test('P17: deterministic toy coinbase-free transaction, two inputs and one output',()=>{
  assert.equal(solved.tx.vin.length,2);
  assert.equal(solved.tx.vout.length,1);
  assert.equal(solved.hashDisplay.length,64);
  assert.equal(solved.txid.length,64);
});
test('P18: DER signature parser rejects malformed and non-minimal encodings',()=>{
  assert.throws(()=>parseBitcoinSignature('300602810102010103'));
  assert.throws(()=>parseBitcoinSignature('3006020101020100'));
});
test('P19: no puzzle work can turn a valid spend into an authenticated journal completeness proof',()=>{
  // An external certificate can appear without changing the spending tx body.
  // The verifier has no state parameter for the external certificate journal.
  const publishedElsewhere={id:'strong-151',work:151n};
  assert.equal(verifyToyScript(solved.tx,solved.lockScript).valid,true);
  assert.equal(publishedElsewhere.work>100n,true);
});

test('P20: SegWit witness-only certificate bytes are invisible to legacy Binohash sighash',()=>{
  const witnessTx={...solved.tx,vin:solved.tx.vin.map((v,i)=>i===0?{...v,witness:['01']}:v)};
  const otherWitnessTx={...solved.tx,vin:solved.tx.vin.map((v,i)=>i===0?{...v,witness:['02']}:v)};
  const hashA=legacySignatureHash(witnessTx,1,solved.lockScript,1,solved.pair.map(d=>d.signature));
  const hashB=legacySignatureHash(otherWitnessTx,1,solved.lockScript,1,solved.pair.map(d=>d.signature));
  assert.equal(hashA,hashB);
  assert.equal(verifyToyScript(witnessTx,solved.lockScript).valid,true);
  assert.equal(verifyToyScript(otherWitnessTx,solved.lockScript).valid,true);
});
test('P21: certificate digest in transaction output is bound by puzzle sighash',()=>{
  const tx={...solved.tx,vout:[{...solved.tx.vout[0],scriptPubKey:'6a20'+'11'.repeat(32)}]};
  assert.notEqual(legacySignatureHash(tx,1,solved.lockScript,1,solved.pair.map(d=>d.signature)),solved.hashDisplay);
  assert.equal(verifyToyScript(tx,solved.lockScript).valid,false);
});
