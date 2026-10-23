/**
 * Deterministic executable refinement tests for the real TypeScript epoch
 * Merkle verifier, with a separately coded SHA256 reference.
 *
 * The Lean MerkleBinding theorem is conditional on collision resistance and
 * checked path directions. These tests establish byte/shape correspondence
 * on selected widths; they are not a formal equivalence proof for all inputs.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  CHUNK,chunk,buildTree,merkleProof,merkleVerify,epochIndices,verifyEpoch,
  proveEpoch,leafHash,type EpochProof
} from './storage_bonds.ts';

const sha=(...bytes:Buffer[])=>createHash('sha256').update(Buffer.concat(bytes)).digest();
const x1=Buffer.from([1]),x0=Buffer.from([0]),x2=Buffer.from([2]);
const amount=n=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b;};
function independentRoot(chunks:Buffer[]):Buffer {
  if(chunks.length<1)throw Error('nonempty chunks');
  let row=chunks.map(c=>sha(x0,c));
  while(row.length>1){
    const next:Buffer[]=[];
    for(let i=0;i<row.length;i+=2)next.push(sha(x1,row[i],row[i+1]??row[i]));
    row=next;
  }
  return sha(x2,amount(chunks.length),row[0]);
}
const fixture=n=>Array.from({length:n},(_,i)=>{
  const b=Buffer.alloc(CHUNK);
  for(let j=0;j<CHUNK;j++)b[j]=(i*71+j*11+(j>>>5))&255;
  return b;
});
const allHeld=(chunks:Buffer[])=>new Map(chunks.map((c,i)=>[i,c] as const));
const nonce=Buffer.from(Array.from({length:32},(_,i)=>i*7&255));

test('MR01: domain-separated byte serialization matches independent SHA256 reference',()=>{
  for(const n of [1,2,3,5,7,8,9]){
    const ch=fixture(n),tree=buildTree(ch);
    assert.equal(tree.root.toString('hex'),independentRoot(ch).toString('hex'), 'n='+n);
    assert.equal(tree.n,n);
    assert.equal(leafHash(ch[0]).toString('hex'),sha(x0,ch[0]).toString('hex'));
  }
});
test('MR02: every canonical path opens for odd and even widths',()=>{
  for(const n of [1,2,3,5,7,8,9]){
    const ch=fixture(n),tree=buildTree(ch);
    for(let i=0;i<n;i++){
      const proof=merkleProof(tree,i);
      assert.equal(merkleVerify(tree.root,n,i,ch[i],proof),true,'n='+n+' index='+i);
      let width=n,want=0;
      while(width>1){width=Math.ceil(width/2);want++;}
      assert.equal(proof.length,want);
    }
  }
});
test('MR03: an odd last leaf duplicates its own hash at missing sibling',()=>{
  for(const n of [3,5,9]){
    const ch=fixture(n),tree=buildTree(ch),last=n-1;
    const proof=merkleProof(tree,last);
    assert.equal(proof[0].toString('hex'),leafHash(ch[last]).toString('hex'));
    const forged=[Buffer.alloc(32,0xff),...proof.slice(1)];
    assert.equal(merkleVerify(tree.root,n,last,ch[last],forged),false);
  }
});
test('MR04: index, committed length, root and chunk bytes remain binding',()=>{
  const ch=fixture(5),tree=buildTree(ch),proof=merkleProof(tree,4);
  assert.equal(merkleVerify(tree.root,5,4,ch[4],proof),true);
  assert.equal(merkleVerify(tree.root,4,4,ch[4],proof),false);
  assert.equal(merkleVerify(tree.root,5,3,ch[4],proof),false);
  assert.equal(merkleVerify(tree.root,5,4,ch[3],proof),false);
  assert.equal(merkleVerify(Buffer.alloc(32,0xaa),5,4,ch[4],proof),false);
  assert.equal(merkleVerify(tree.root,5,4,ch[4],proof.slice(1)),false);
});
test('MR05: partial final ciphertext chunk is padded to exactly 4 KiB',()=>{
  const data=Buffer.from('a1b2c3'.repeat(1500),'hex');
  const chunks=chunk(data);
  assert.equal(chunks.length,2);
  assert.equal(chunks[0].length,CHUNK);
  assert.equal(chunks[1].length,CHUNK);
  assert.equal(chunks[1].subarray(data.length-CHUNK).every(x=>x===0),true);
  assert.equal(buildTree(chunks).root.toString('hex'),independentRoot(chunks).toString('hex'));
  assert.equal(chunk(Buffer.alloc(0)).length,1);
});
test('MR06: a real epoch with deterministic indices accepts verified chunk paths',()=>{
  const ch=fixture(7),tree=buildTree(ch),proof=proveEpoch(allHeld(ch),tree,nonce,5);
  assert.equal(epochIndices(nonce,7,5).length,5);
  assert.equal(verifyEpoch(tree.root,7,nonce,5,proof),true);
});
test('MR07: the empty-sample payment bypass is rejected',()=>{
  const ch=fixture(3),tree=buildTree(ch);
  const zero:EpochProof={chunks:[],paths:[]};
  assert.equal(verifyEpoch(tree.root,3,nonce,0,zero),false);
  assert.throws(()=>epochIndices(nonce,3,0),/positive sample count/);
});
test('MR08: omitted, surplus and structurally invalid opening arrays fail closed',()=>{
  const ch=fixture(5),tree=buildTree(ch),proof=proveEpoch(allHeld(ch),tree,nonce,4);
  assert.equal(verifyEpoch(tree.root,5,nonce,4,{chunks:proof.chunks.slice(1),paths:proof.paths}),false);
  assert.equal(verifyEpoch(tree.root,5,nonce,4,{chunks:proof.chunks,paths:proof.paths.slice(0,2)}),false);
  assert.equal(verifyEpoch(tree.root,5,nonce,4,{chunks:[...proof.chunks,Buffer.alloc(CHUNK)],paths:proof.paths}),false);
  const withHole={chunks:[...proof.chunks],paths:[...proof.paths]};
  withHole.chunks[2]=undefined as unknown as Buffer;
  assert.equal(verifyEpoch(tree.root,5,nonce,4,withHole),false);
  const badPath={chunks:proof.chunks,paths:[...proof.paths]};
  badPath.paths[1]=[Buffer.alloc(31),...badPath.paths[1].slice(1)];
  assert.equal(verifyEpoch(tree.root,5,nonce,4,badPath),false);
});
test('MR09: wrong nonce, root dimensions, count and nonintegral sample requests fail',()=>{
  const ch=fixture(9),tree=buildTree(ch),proof=proveEpoch(allHeld(ch),tree,nonce,4);
  assert.equal(verifyEpoch(tree.root,9,Buffer.alloc(31),4,proof),false);
  assert.equal(verifyEpoch(Buffer.alloc(31),9,nonce,4,proof),false);
  assert.equal(verifyEpoch(tree.root,0,nonce,4,proof),false);
  assert.equal(verifyEpoch(tree.root,9,nonce,-1,proof),false);
  assert.equal(verifyEpoch(tree.root,9,nonce,1.5,proof),false);
  assert.throws(()=>epochIndices(nonce,0,4),/positive sample count/);
});
test('MR10: a sampled missing chunk cannot be replaced with an empty buffer',()=>{
  const ch=fixture(4),tree=buildTree(ch),idx=epochIndices(nonce,4,8);
  const held=allHeld(ch);
  held.delete(idx[0]);
  const proof=proveEpoch(held,tree,nonce,8);
  assert.equal(verifyEpoch(tree.root,4,nonce,8,proof),false);
});
