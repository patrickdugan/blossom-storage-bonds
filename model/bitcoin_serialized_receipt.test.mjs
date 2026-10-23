import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {parseTx} from '../layer1/onchain.ts';
import {
  createWitnessCommitmentEvidence,verifyWitnessCommitmentEvidence
} from './bitcoin_witness_commitment.mjs';
import {
  authenticateSerializedWitnessInclusion,readCanonicalWitnessStacks
} from './bitcoin_serialized_receipt.mjs';

const sha=b=>createHash('sha256').update(b).digest();
const sha2=b=>sha(sha(b));
const hash=b=>Buffer.from(sha2(b)).reverse().toString('hex');
const little=h=>Buffer.from(h,'hex').reverse();
const compact=n=>{if(n>=253)throw Error('tiny fixture only');return Buffer.from([n]);};
const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n>>>0);return b;};
const u64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b;};

function encodeTx(inputs,outputs) {
  const segwit=true;
  const a=[u32(2),Buffer.from([0,1]),compact(inputs.length)];
  for(const input of inputs) a.push(little(input.txid),u32(input.vout),
    compact(input.script.length),input.script,u32(input.sequence));
  a.push(compact(outputs.length));
  for(const o of outputs)a.push(u64(o.value),compact(o.script.length),o.script);
  if(segwit)for(const input of inputs){
    a.push(compact(input.witness.length));
    for(const x of input.witness)a.push(compact(x.length),x);
  }
  a.push(u32(0));
  return Buffer.concat(a);
}
const oneInput=(w)=>[{
  txid:'11'.repeat(32),vout:0,script:Buffer.alloc(0),
  sequence:0xfffffffd,witness:[w]
}];
function targetRaw(w=Buffer.alloc(16,0x44)){
  return encodeTx(oneInput(w),[{value:1000n,script:Buffer.from([0x51])}]);
}
const coinbaseInput=(reserved)=>[{
  txid:'00'.repeat(32),vout:0xffffffff,
  script:Buffer.from('03010000','hex'),
  sequence:0xffffffff,witness:[reserved]
}];
function syntheticReceipt(witnessRaw=targetRaw(),coinbaseWitness=Buffer.alloc(32,0x37)){
  const targetId=parseTx(witnessRaw).txid,targetWitnessId=hash(witnessRaw);
  const witnessRoot=sha2(Buffer.concat([Buffer.alloc(32),little(targetWitnessId)]));
  const commitment=sha2(Buffer.concat([witnessRoot,coinbaseWitness]));
  const commitmentScript=Buffer.from('6a24aa21a9ed'+commitment.toString('hex'),'hex');
  const cbRaw=encodeTx(coinbaseInput(coinbaseWitness),
    [{value:50_000_000_000n,script:Buffer.from([0x51])},
     {value:0n,script:commitmentScript}]);
  const cbId=parseTx(cbRaw).txid;
  const ordinaryRoot=sha2(Buffer.concat([little(cbId),little(targetId)]));
  const header=Buffer.alloc(80);
  header.writeInt32LE(0x20000000,0);
  Buffer.alloc(32,0xaa).copy(header,4);
  ordinaryRoot.copy(header,36);
  header.writeUInt32LE(1_700_000_000,68);
  header.writeUInt32LE(0x207fffff,72);
  header.writeUInt32LE(77,76);
  const w=createWitnessCommitmentEvidence({
    txids:[cbId,targetId],
    wtxids:['00'.repeat(32),targetWitnessId],
    targetIndex:1,blockHeaderHex:header.toString('hex'),
    reservedHex:coinbaseWitness.toString('hex'),
    coinbaseCommitmentScript:commitmentScript.toString('hex')
  });
  const proof=Buffer.concat([
    header,u32(2),compact(2),little(cbId),little(targetId),
    compact(1),Buffer.from([0x05])
  ]);
  return {
    txid:targetId,blockhash:w.blockhash,height:1,
    headerHex:header.toString('hex'),merkleRoot:Buffer.from(ordinaryRoot).reverse().toString('hex'),
    proofHex:proof.toString('hex'),
    witness:{...w,coinbaseRawHex:cbRaw.toString('hex'),
      witnessedRawHex:witnessRaw.toString('hex')}
  };
}

test('SR01: authentic raw coinbase and raw target form a portable dual-merkle receipt',()=>{
  const receipt=syntheticReceipt();
  const authenticated=authenticateSerializedWitnessInclusion(receipt);
  assert.equal(authenticated.txid,receipt.txid);
  assert.equal(authenticated.wtxid,receipt.witness.wtxid);
  assert.equal(authenticated.coinbaseTxid,receipt.witness.coinbaseTxid);
  assert.equal(authenticated.authenticatedWitness,true);
  assert.equal(authenticated.txIndex,1);
});
test('SR02: witness-only substitution preserves txid but fails original BIP141 anchor',()=>{
  const good=syntheticReceipt();
  const altered=targetRaw(Buffer.alloc(16,0x4a));
  assert.equal(parseTx(altered).txid,good.txid);
  assert.notEqual(hash(altered),good.witness.wtxid);
  assert.throws(()=>authenticateSerializedWitnessInclusion({
    ...good,witness:{...good.witness,witnessedRawHex:altered.toString('hex')}
  }),/wtxid/);
});
test('SR03: positive attack on weak verifier - free-standing forged commitment',()=>{
  const good=syntheticReceipt();
  const forgedTarget=targetRaw(Buffer.alloc(16,0xff));
  const fake=syntheticReceipt(forgedTarget);
  // The normal txid stays constant; the supplied fake coinbase output
  // commitment is NOT actually in the original serialized coinbase.
  assert.equal(good.txid,fake.txid);
  const forged={...good,witness:{
    ...fake.witness,coinbaseTxid:good.witness.coinbaseTxid,
    coinbaseTxidBranchHex:good.witness.coinbaseTxidBranchHex,
    coinbaseRawHex:good.witness.coinbaseRawHex,
    blockHeaderHex:good.witness.blockHeaderHex,blockhash:good.witness.blockhash,
  }};
  // Historical helper behavior: without authenticated raw coinbase bytes,
  // a free-standing commitment field still looks mathematically valid.
  const unboundFields={...forged.witness};
  delete unboundFields.coinbaseRawHex;
  delete unboundFields.witnessedRawHex;
  assert.equal(verifyWitnessCommitmentEvidence(unboundFields),true,
    'free-standing commitments cannot be treated as coinbase authentication');
  assert.throws(()=>authenticateSerializedWitnessInclusion(forged),
    /reported witness commitment does not match raw coinbase output/);
});
test('SR04: changing only coinbase witness reserved bytes keeps txid, rejects receipt',()=>{
  const good=syntheticReceipt(),coinbase=Buffer.from(good.witness.coinbaseRawHex,'hex');
  const reserved=Buffer.alloc(32,0x37);
  const at=coinbase.indexOf(reserved);
  assert.ok(at>0);
  coinbase[at]^=1;
  assert.equal(parseTx(coinbase).txid,good.witness.coinbaseTxid);
  assert.throws(()=>authenticateSerializedWitnessInclusion({
    ...good,witness:{...good.witness,coinbaseRawHex:coinbase.toString('hex')}
  }),/reserved value differs/);
});
test('SR05: removing or changing a raw coinbase commitment is detected by txid binding',()=>{
  const good=syntheticReceipt(),raw=Buffer.from(good.witness.coinbaseRawHex,'hex');
  const needle=Buffer.from('6a24aa21a9ed','hex'),at=raw.indexOf(needle);
  assert.ok(at>0);
  raw[at+7]^=1;
  assert.notEqual(parseTx(raw).txid,good.witness.coinbaseTxid);
  assert.throws(()=>authenticateSerializedWitnessInclusion({
    ...good,witness:{...good.witness,coinbaseRawHex:raw.toString('hex')}
  }),/raw coinbase transaction does not match/);
});
test('SR06: mismatch of BIP37 transaction slot and BIP141 witness slot fails',()=>{
  const good=syntheticReceipt();
  assert.throws(()=>authenticateSerializedWitnessInclusion({...good,
    witness:{...good.witness,txIndex:0}
  }),/transaction inclusion index disagrees|BIP141/);
});
test('SR07: reject absent, non-SegWit or truncated raw evidence',()=>{
  const good=syntheticReceipt();
  assert.throws(()=>authenticateSerializedWitnessInclusion({...good,witness:{
    ...good.witness,coinbaseRawHex:'ff'
  }}),/truncated|transaction/);
  const c=Buffer.from(good.witness.coinbaseRawHex,'hex');
  assert.throws(()=>readCanonicalWitnessStacks(c.subarray(0,c.length-2)),
    /truncated/);
  assert.throws(()=>authenticateSerializedWitnessInclusion({...good,witness:{
    ...good.witness,witnessedRawHex:'bad'
  }}),/invalid serialized/);
});

test('SR08: reject mismatched block transaction count between txid and wtxid paths',()=>{
  const good=syntheticReceipt();
  assert.throws(()=>authenticateSerializedWitnessInclusion({
    ...good,witness:{...good.witness,totalTransactions:3}
  }),/block transaction count/);
});
