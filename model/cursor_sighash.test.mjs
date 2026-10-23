import test from 'node:test';
import assert from 'node:assert/strict';
import {fundingFixture} from './utxo_admission_graph.mjs';
import {cursorGenesis,cursorUpdate,jointSettlement} from './journal_cursor.mjs';
import {legacySignatureHash} from './legacy_sighash.mjs';

const digest=(tx, mode, index=0)=>legacySignatureHash(tx,index,'51',mode);
function fixtures() {
  const f=fundingFixture();
  const initial=cursorGenesis({source:f.independentUTXO,sourceValue:10000n});
  const weak=cursorUpdate({cursor:initial,certificateId:'weak-100',work:100n,validatedWork:true});
  const strong=cursorUpdate({cursor:weak,certificateId:'strong-151',work:151n,validatedWork:true});
  const make=(cursor)=>jointSettlement({bond:f.bond,cursor,bondValue:149000n,settlementHeight:150}).tx;
  return {fund:f.bond,initial,weak,strong,make};
}
function changeCursorOnly(tx,otherCursor) {
  const other=structuredClone(tx);
  other.vin[1].prevTxid=otherCursor.ref.txid;
  other.vin[1].prevVout=otherCursor.ref.vout;
  return other;
}

test('H01: SIGHASH_ALL on bond input changes when journal cursor input changes',()=>{
  const f=fixtures(), old=f.make(f.weak);
  assert.notEqual(digest(old,0x01),digest(changeCursorOnly(old,f.strong),0x01));
});
test('H02: SIGHASH_ALL|ANYONECANPAY on bond input ignores changed cursor input',()=>{
  const f=fixtures(),old=f.make(f.weak);
  assert.equal(digest(old,0x81),digest(changeCursorOnly(old,f.strong),0x81));
});
test('H03: SIGHASH_NONE on bond input still includes other input prevouts',()=>{
  const f=fixtures(),old=f.make(f.weak);
  assert.notEqual(digest(old,0x02),digest(changeCursorOnly(old,f.strong),0x02));
});
test('H04: SIGHASH_NONE|ANYONECANPAY on bond input ignores changed cursor input',()=>{
  const f=fixtures(),old=f.make(f.weak);
  assert.equal(digest(old,0x82),digest(changeCursorOnly(old,f.strong),0x82));
});
test('H05: SIGHASH_NONE ignores malicious redirection of payout output',()=>{
  const f=fixtures(), tx=f.make(f.strong), changed=structuredClone(tx);
  changed.vout[0].scriptPubKey='6a20'+'aa'.repeat(32);
  assert.equal(digest(tx,0x02),digest(changed,0x02));
  assert.notEqual(digest(tx,0x01),digest(changed,0x01));
});
test('H06: SIGHASH_ALL|ANYONECANPAY still commits to payout outputs',()=>{
  const f=fixtures(), tx=f.make(f.strong), changed=structuredClone(tx);
  changed.vout[0].scriptPubKey='6a20'+'aa'.repeat(32);
  assert.notEqual(digest(tx,0x81),digest(changed,0x81));
});
test('H07: signature of cursor input itself commits to its own cursor outpoint in ANYONECANPAY',()=>{
  const f=fixtures(), old=f.make(f.weak);
  assert.notEqual(digest(old,0x81,1),digest(changeCursorOnly(old,f.strong),0x81,1));
});
test('H08: settled amount changes SIGHASH_ALL but not SIGHASH_NONE',()=>{
  const f=fixtures(), tx=f.make(f.strong), changed=structuredClone(tx);
  changed.vout[0].valueSats -=1000n;
  assert.notEqual(digest(tx,0x01),digest(changed,0x01));
  assert.equal(digest(tx,0x02),digest(changed,0x02));
});
test('H09: all four canonical signature-hash modes produce distinct digests',()=>{
  const f=fixtures(),tx=f.make(f.strong);
  const hashes=[0x01,0x02,0x81,0x82].map(x=>digest(tx,x));
  assert.equal(new Set(hashes).size,4);
});
test('H10: stale and strong cursor settlement requires new pinning for SIGHASH_ALL',()=>{
  const f=fixtures(),stale=f.make(f.weak),fresh=f.make(f.strong);
  assert.notEqual(digest(stale,0x01),digest(fresh,0x01));
});
