import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  decodeHeader,targetFromCompact,blockWork,verifyRegtestHeaderChain,
  bindInclusionToHeaderChain,REGTEST_GENESIS,REGTEST_BITS,REGTEST_POW_LIMIT
} from './regtest_header_chain.mjs';

const sha=b=>createHash('sha256').update(b).digest();
const doubleSha=b=>sha(sha(b));
const display=b=>Buffer.from(b).reverse().toString('hex');
const rawGenesis='01000000'+'00'.repeat(32)+
  '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a'+
  'dae5494d'+'ffff7f20'+'02000000';
function genesis(){return {height:0,hex:rawGenesis,hash:REGTEST_GENESIS};}
function mine(prev,merkle,height,time) {
  const header=Buffer.alloc(80);
  header.writeInt32LE(0x20000000,0);
  Buffer.from(prev,'hex').reverse().copy(header,4);
  Buffer.from(merkle,'hex').reverse().copy(header,36);
  header.writeUInt32LE(time,68);
  header.writeUInt32LE(REGTEST_BITS,72);
  const target=targetFromCompact(REGTEST_BITS);
  for(let nonce=0;nonce<10_000;nonce++){
    header.writeUInt32LE(nonce,76);
    const hash=display(doubleSha(header));
    if(BigInt('0x'+hash)<=target)
      return {height,hex:header.toString('hex'),hash};
  }
  throw Error('unexpectedly unable to mine test header');
}
function chain(count=5) {
  const rows=[genesis()];
  for(let i=1;i<count;i++){
    const last=decodeHeader(rows[i-1].hex);
    const merkle=display(doubleSha(Buffer.from('faux-merkle-'+i)));
    rows.push(mine(last.hash,merkle,i,1296688602+i*600));
  }
  return rows;
}
function mutated(row,apply) {
  const h=Buffer.from(row.hex,'hex');
  apply(h);
  return {...row,hex:h.toString('hex')};
}

test('HC01: pinned Bitcoin regtest genesis header hash and target',()=>{
  const hd=decodeHeader(rawGenesis);
  assert.equal(hd.hash,REGTEST_GENESIS);
  assert.equal(hd.bits,REGTEST_BITS);
  assert.equal(hd.prevHash,'00'.repeat(32));
  assert.equal(targetFromCompact(REGTEST_BITS),REGTEST_POW_LIMIT);
  assert.equal(blockWork(REGTEST_POW_LIMIT),2n);
});
test('HC02: independently mined linked headers and cumulative work verify',()=>{
  const records=chain(7);
  const proof=verifyRegtestHeaderChain(records,{
    expectedTip:records.at(-1).hash,checkpoints:[2,4,6]
  });
  assert.equal(proof.genesis,REGTEST_GENESIS);
  assert.equal(proof.headerCount,7);
  assert.equal(proof.tipHeight,6);
  assert.equal(proof.cumulativeWorkDecimal,'14');
  assert.equal(proof.checks.exactBigIntChainwork,true);
  assert.equal(proof.checkpoints.at(-1).height,6);
});
test('HC03: corrupted parent hash is not a valid contiguous anchored chain',()=>{
  const rows=chain(5);
  rows[3]=mutated(rows[3],h=>{h[4]^=1;});
  assert.throws(()=>verifyRegtestHeaderChain(rows),/claimed block hash|previous header hash|proof-of-work/);
});
test('HC04: bad PoW is rejected even with valid header length and bits',()=>{
  const rows=chain(3);
  let bad=null;
  const h=Buffer.from(rows[2].hex,'hex');
  for(let i=0;i<1000;i++){
    h.writeUInt32LE(i,76);
    if(BigInt('0x'+display(doubleSha(h)))>REGTEST_POW_LIMIT){
      bad={height:2,hex:h.toString('hex')};break;
    }
  }
  assert.ok(bad);
  rows[2]=bad;
  assert.throws(()=>verifyRegtestHeaderChain(rows),/proof-of-work/);
});
test('HC05: reject alternative bits even when the header can be mined',()=>{
  const rows=chain(3);
  rows[2]=mutated(rows[2],h=>{h.writeUInt32LE(0x207ffffe,72);});
  delete rows[2].hash;
  assert.throws(()=>verifyRegtestHeaderChain(rows),/unexpected regtest difficulty bits/);
});
test('HC06: reject invalid compact target encodings and zero',()=>{
  for(const bits of [0,0x01800000,0x207fffff|0x00800000,
     0x2300ffff,0x21010000,0x20000000]){
    assert.throws(()=>targetFromCompact(bits>>>0),/invalid/);
  }
  assert.throws(()=>blockWork(0n),/out of range/);
});
test('HC07: reject spoofed Core chainwork and missing genesis/short chain',()=>{
  const rows=chain(5);
  rows[3].chainwork='ffffffff';
  assert.throws(()=>verifyRegtestHeaderChain(rows),/cumulative chainwork/);
  delete rows[3].chainwork;
  assert.throws(()=>verifyRegtestHeaderChain(rows.slice(1)),/genesis|sequential/);
  assert.throws(()=>verifyRegtestHeaderChain(rows.slice(0,1)),/complete genesis/);
});
test('HC08: explicitly supplied minimum work prevents accepting truncated evidence',()=>{
  const rows=chain(7);
  const proof=verifyRegtestHeaderChain(rows);
  assert.throws(()=>verifyRegtestHeaderChain(rows.slice(0,4),
    {minimumChainwork:proof.cumulativeWorkDecimal}),/below explicitly required/);
});
test('HC09: median-time-past regression rejects timestamp replay',()=>{
  const rows=chain(5);
  const prev=decodeHeader(rows[3].hex);
  // Re-mine the last header with a timestamp earlier than previous median.
  rows[4]=mine(prev.hash,display(doubleSha(Buffer.from('bad-mtp'))),4,1296688601);
  assert.throws(()=>verifyRegtestHeaderChain(rows),/median-time-past/);
});
test('HC10: independently confirmed transaction proof binds to precise chain header',()=>{
  const rows=chain(6),verified=verifyRegtestHeaderChain(rows);
  const header=decodeHeader(rows[4].hex);
  const inclusion={
    height:4,blockhash:header.hash,headerHex:header.rawHex,merkleRoot:header.merkleRoot,
    witness:{blockhash:header.hash,blockHeaderHex:header.rawHex}
  };
  assert.equal(bindInclusionToHeaderChain(inclusion,rows,verified),true);
  assert.throws(()=>bindInclusionToHeaderChain({...inclusion,
    blockhash:'11'.repeat(32)},rows,verified),/not bound/);
  assert.throws(()=>bindInclusionToHeaderChain({...inclusion,
    witness:{...inclusion.witness,blockhash:'ff'.repeat(32)}},rows,verified),/not bound/);
  assert.throws(()=>bindInclusionToHeaderChain({...inclusion,height:99},rows,verified),/outside/);
});
test('HC11: known genesis and fixed PoW work do not establish greatest-work chain',()=>{
  const a=chain(6);
  const proof=verifyRegtestHeaderChain(a);
  assert.equal(proof.tipHeight,5);
  assert.equal(typeof proof.cumulativeWorkDecimal,'string');
  assert.equal(Object.hasOwn(proof.checks,'mostWorkAmongAllUnknownChains'),false);
});
