import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  createWitnessCommitmentEvidence,verifyWitnessCommitmentEvidence,
  verifyIndexedMerkleBranch
} from './bitcoin_witness_commitment.mjs';

const sha=b=>createHash('sha256').update(b).digest();
const sha2=b=>sha(sha(b));
const internally=h=>Buffer.from(h,'hex').reverse();
const hex=b=>Buffer.from(b).reverse().toString('hex');
const h=i=>hex(sha2(Buffer.from('wtx-fixture-'+i)));
function genericRoot(leaves){
  let row=leaves.map(b=>Buffer.from(b));
  while(row.length>1){
    const next=[];
    for(let i=0;i<row.length;i+=2)
      next.push(sha2(Buffer.concat([row[i],row[i+1]??row[i]])));
    row=next;
  }
  return row[0];
}
function fixture(n,index){
  const txids=Array.from({length:n},(_,i)=>h(1000+i));
  const wtxids=Array.from({length:n},(_,i)=>h(2000+i));
  const normalRoot=genericRoot(txids.map(internally));
  const witnessRoot=genericRoot(wtxids.map((v,i)=>i===0?Buffer.alloc(32):internally(v)));
  const reserved=Buffer.alloc(32,0x6b);
  const commitment=sha2(Buffer.concat([witnessRoot,reserved])).toString('hex');
  const header=Buffer.alloc(80); header.writeInt32LE(0x20000000,0);
  Buffer.alloc(32,0x33).copy(header,4); normalRoot.copy(header,36);
  header.writeUInt32LE(1_700_000_000,68);
  header.writeUInt32LE(0x207fffff,72);
  header.writeUInt32LE(1234,76);
  return createWitnessCommitmentEvidence({txids,wtxids,targetIndex:index,
    blockHeaderHex:header.toString('hex'),reservedHex:reserved.toString('hex'),
    coinbaseCommitmentScript:'6a24aa21a9ed'+commitment});
}

test('WA01: BIP141 witness commitment validates block sizes including odd width',()=>{
  for(const n of [2,3,4,5,8,9]){
    for(const index of new Set([1,Math.floor(n/2),n-1])){
      const receipt=fixture(n,index);
      assert.equal(verifyWitnessCommitmentEvidence(receipt),true,'n='+n+', i='+index);
      assert.equal(receipt.totalTransactions,n);
      assert.equal(receipt.txIndex,index);
    }
  }
});
test('WA02: replacing only wtxid breaks witness proof even if txid unchanged',()=>{
  const valid=fixture(5,4);
  const altered={...valid,wtxid:'a3'.repeat(32)};
  assert.equal(verifyWitnessCommitmentEvidence(valid),true);
  assert.equal(verifyWitnessCommitmentEvidence(altered),false);
  assert.equal(valid.txid,altered.txid,'normal txid proof is unaffected');
});
test('WA03: changing witness reserved value or coinbase commitment fails',()=>{
  const v=fixture(3,1);
  assert.equal(verifyWitnessCommitmentEvidence({...v,reservedHex:'77'.repeat(32)}),false);
  assert.equal(verifyWitnessCommitmentEvidence({
    ...v,coinbaseCommitmentScript:'6a24aa21a9ed'+'88'.repeat(32)
  }),false);
});
test('WA04: changing coinbase txid proof, block root or header identity fails',()=>{
  const v=fixture(9,8);
  assert.equal(verifyWitnessCommitmentEvidence({...v,coinbaseTxid:'ff'.repeat(32)}),false);
  assert.equal(verifyWitnessCommitmentEvidence({...v,blockhash:'ff'.repeat(32)}),false);
  assert.equal(verifyWitnessCommitmentEvidence({...v,
    coinbaseTxidBranchHex:v.coinbaseTxidBranchHex.slice(1)}),false);
});
test('WA05: odd-tree duplicate siblings are checked explicitly',()=>{
  const valid=fixture(3,2);
  assert.equal(verifyWitnessCommitmentEvidence(valid),true);
  const altered=[...valid.witnessBranchHex];
  altered[0]='99'.repeat(32);
  assert.equal(verifyWitnessCommitmentEvidence({...valid,witnessBranchHex:altered}),false);
});
test('WA06: rejected malformed Merkle branch shape and wrong index',()=>{
  const valid=fixture(5,3);
  assert.equal(verifyWitnessCommitmentEvidence({...valid,txIndex:6}),false);
  assert.equal(verifyWitnessCommitmentEvidence({
    ...valid,witnessBranchHex:valid.witnessBranchHex.slice(1)}),false);
  assert.equal(verifyIndexedMerkleBranch(Buffer.alloc(31),0,2,[],Buffer.alloc(32)),false);
});
