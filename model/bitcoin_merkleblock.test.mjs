import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {parseBitcoinTxOutProof,proofIncludesTxid} from './bitcoin_merkleblock.mjs';

const twice=x=>createHash('sha256').update(
  createHash('sha256').update(x).digest()).digest();
const display=x=>Buffer.from(x).reverse().toString('hex');
const csize=n=>{if(n<253)return Buffer.from([n]);const b=Buffer.alloc(3);b[0]=253;b.writeUInt16LE(n,1);return b;};

function fixture(n,chosen){
  const leaves=Array.from({length:n},(_,i)=>twice(Buffer.from('tx-'+i)));
  const width=h=>Math.ceil(n/2**h);
  function nodeHash(h,pos){
    if(h===0)return leaves[pos];
    const left=nodeHash(h-1,pos*2);
    const right=pos*2+1<width(h-1)?nodeHash(h-1,pos*2+1):left;
    return twice(Buffer.concat([left,right]));
  }
  let height=0;
  while(width(height)>1)height++;
  const root=nodeHash(height,0);
  const matches=[];
  const flags=[];
  const hashes=[];
  function mark(h,pos) {
    const a=pos*2**h,b=Math.min(n,(pos+1)*2**h);
    const found=[...chosen].some(i=>i>=a&&i<b);
    flags.push(found?1:0);
    if(h===0||!found){
      hashes.push(nodeHash(h,pos));
      if(h===0&&found)matches.push({txid:display(leaves[pos]),index:pos});
    }else{
      mark(h-1,pos*2);
      if(pos*2+1<width(h-1))mark(h-1,pos*2+1);
    }
  }
  mark(height,0);
  const flagBytes=Buffer.alloc(Math.ceil(flags.length/8));
  flags.forEach((bit,i)=>{flagBytes[i>>3]|=bit<<(i&7);});
  const header=Buffer.alloc(80);
  header.writeInt32LE(0x20000000,0);
  Buffer.alloc(32,0xab).copy(header,4);
  root.copy(header,36);
  header.writeUInt32LE(1_700_000_000,68);
  header.writeUInt32LE(0x207fffff,72);
  header.writeUInt32LE(123,76);
  const count=Buffer.alloc(4);count.writeUInt32LE(n);
  const proof=Buffer.concat([header,count,csize(hashes.length),
    ...hashes,csize(flagBytes.length),flagBytes]);
  return {proofHex:proof.toString('hex'),expected:{blockhash:display(twice(header)),
    merkleRoot:display(root),matches,totalTransactions:n},bytes:proof};
}

test('MB01: independently built Bitcoin partial Merkle proofs validate odd and even trees',()=>{
  for(const n of [1,2,3,5,7,8,9]){
    for(const index of new Set([0,Math.floor(n/2),n-1])){
      const x=fixture(n,new Set([index]));
      const got=parseBitcoinTxOutProof(x.proofHex);
      assert.equal(got.blockhash,x.expected.blockhash);
      assert.equal(got.merkleRoot,x.expected.merkleRoot);
      assert.equal(got.totalTransactions,n);
      assert.deepEqual(got.matches,x.expected.matches);
      assert.equal(proofIncludesTxid(x.proofHex,got.matches[0].txid,got.blockhash).matches[0].index,index);
    }
  }
});
test('MB02: the same proof can authenticate two independent transaction leaves',()=>{
  const x=fixture(5,new Set([0,4]));
  const got=parseBitcoinTxOutProof(x.proofHex);
  assert.deepEqual(got.matches,x.expected.matches);
  assert.deepEqual(got.matches.map(v=>v.index),[0,4]);
});
test('MB03: mutated proof sibling bytes fail the block-header Merkle root',()=>{
  const x=fixture(5,new Set([4]));
  const bad=Buffer.from(x.bytes);
  // after 80-byte header + 4-byte nTransactions + 1-byte hash count
  bad[90]^=0x80;
  assert.throws(()=>parseBitcoinTxOutProof(bad.toString('hex')),
    /merkle root does not match/);
});
test('MB04: proof for a different confirmed transaction or header is rejected',()=>{
  const x=fixture(3,new Set([1]));
  const got=parseBitcoinTxOutProof(x.proofHex);
  assert.throws(()=>proofIncludesTxid(x.proofHex,'ff'.repeat(32),got.blockhash),
    /not anchored/);
  assert.throws(()=>proofIncludesTxid(x.proofHex,got.matches[0].txid,'ab'.repeat(32)),
    /not anchored/);
});
test('MB05: malformed and noncanonical serialized proof data fail closed',()=>{
  const x=fixture(3,new Set([1]));
  assert.throws(()=>parseBitcoinTxOutProof('ff'),/invalid|truncated/);
  assert.throws(()=>parseBitcoinTxOutProof(x.proofHex+'00'),/trailing bytes/);
  const noRoot=Buffer.from(x.bytes);noRoot[36]^=0x01;
  assert.throws(()=>parseBitcoinTxOutProof(noRoot.toString('hex')),
    /merkle root does not match/);
  const noFlags=Buffer.from(x.bytes);noFlags[noFlags.length-1]=0;
  assert.throws(()=>parseBitcoinTxOutProof(noFlags.toString('hex')),
    /no matched transaction|unused/);
});
test('MB06: zero transaction count and overflowing hash count fail closed',()=>{
  const x=fixture(3,new Set([1]));
  const badCount=Buffer.from(x.bytes);
  badCount.writeUInt32LE(0,80);
  assert.throws(()=>parseBitcoinTxOutProof(badCount.toString('hex')),
    /invalid merkle tree transaction count/);
  const badHashes=Buffer.from(x.bytes);
  badHashes[84]=99;
  assert.throws(()=>parseBitcoinTxOutProof(badHashes.toString('hex')),
    /invalid partial merkle hash count/);
});
