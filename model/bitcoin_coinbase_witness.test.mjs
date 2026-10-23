import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {parseCoinbaseWitnessRaw} from './bitcoin_coinbase_witness.mjs';

const sha=x=>createHash('sha256').update(x).digest();
const sha2=x=>sha(sha(x));
const rev=x=>Buffer.from(x).reverse().toString('hex');
const u32=x=>{const b=Buffer.alloc(4);b.writeUInt32LE(x);return b;};
const u64=x=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(x));return b;};
const coinbase=(nonce=Buffer.alloc(32,0x42),commit=Buffer.alloc(32,0x73),
  extraCommit=null)=>{
  const output=(script)=>Buffer.concat([u64(0),Buffer.from([script.length]),script]);
  const script=Buffer.concat([Buffer.from('6a24aa21a9ed','hex'),commit]);
  const outs=[output(Buffer.from([0x51])),output(script)];
  if(extraCommit)outs.push(output(Buffer.concat([Buffer.from('6a24aa21a9ed','hex'),extraCommit])));
  const vin=Buffer.concat([
    Buffer.from([1]),Buffer.alloc(32),u32(0xffffffff),
    Buffer.from([4,0x03,0x01,0x00,0x51]),u32(0xffffffff)
  ]);
  const vout=Buffer.concat([Buffer.from([outs.length]),...outs]);
  const ver=u32(2),lock=u32(0);
  const stripped=Buffer.concat([ver,vin,vout,lock]);
  const witness=Buffer.concat([Buffer.from([1,32]),nonce]);
  const full=Buffer.concat([ver,Buffer.from([0,1]),vin,vout,witness,lock]);
  return {raw:full,stripped,nonce,commit,txid:rev(sha2(stripped)),
    selectedCommit:(extraCommit??commit).toString('hex')};
};
test('CB01: nonce and selected commitment extracted from serialized SegWit coinbase',()=>{
  const x=coinbase();
  const parsed=parseCoinbaseWitnessRaw(x.raw.toString('hex'));
  assert.equal(parsed.txid,x.txid);
  assert.equal(parsed.reservedHex,x.nonce.toString('hex'));
  assert.equal(parsed.commitmentHex,x.selectedCommit);
  assert.equal(parsed.outputCount,2);
});
test('CB02: highest-index witness commitment output takes precedence',()=>{
  const x=coinbase(undefined,undefined,Buffer.alloc(32,0x55));
  const parsed=parseCoinbaseWitnessRaw(x.raw.toString('hex'));
  assert.equal(parsed.commitmentHex,'55'.repeat(32));
  assert.equal(parsed.outputCount,3);
});
test('CB03: replacing coinbase witness reserved value preserves txid but alters evidence',()=>{
  const a=coinbase(Buffer.alloc(32,0x42));
  const b=coinbase(Buffer.alloc(32,0x43));
  const parsedA=parseCoinbaseWitnessRaw(a.raw.toString('hex'));
  const parsedB=parseCoinbaseWitnessRaw(b.raw.toString('hex'));
  assert.equal(parsedA.txid,parsedB.txid);
  assert.notEqual(parsedA.reservedHex,parsedB.reservedHex);
});
test('CB04: changing coinbase output commitment changes the coinbase txid',()=>{
  const a=coinbase(undefined,Buffer.alloc(32,0x44));
  const b=coinbase(undefined,Buffer.alloc(32,0x45));
  const pa=parseCoinbaseWitnessRaw(a.raw.toString('hex'));
  const pb=parseCoinbaseWitnessRaw(b.raw.toString('hex'));
  assert.notEqual(pa.txid,pb.txid);
});
test('CB05: truncated coinbase, malformed marker, missing commitment fail closed',()=>{
  const c=coinbase();
  assert.throws(()=>parseCoinbaseWitnessRaw('abcd'),/invalid|truncated/);
  const badMarker=Buffer.from(c.raw);badMarker[5]=2;
  assert.throws(()=>parseCoinbaseWitnessRaw(badMarker.toString('hex')),/marker/);
  const cut=Buffer.from(c.raw.subarray(0,c.raw.length-5));
  assert.throws(()=>parseCoinbaseWitnessRaw(cut.toString('hex')),/truncated|trailer/);
});
test('CB06: invalid reserved item length or previous outpoint is rejected',()=>{
  const c=coinbase();
  const prev=Buffer.from(c.raw);
  prev[7]^=0x80;
  assert.throws(()=>parseCoinbaseWitnessRaw(prev.toString('hex')),/prevhash/);
  const malformed=Buffer.from(c.raw);
  malformed[malformed.length-37]=31;
  assert.throws(()=>parseCoinbaseWitnessRaw(malformed.toString('hex')),
    /reserved value|trailer|truncated/);
});
