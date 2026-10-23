import test from 'node:test';
import assert from 'node:assert/strict';
import {fundingFixture} from './utxo_admission_graph.mjs';
import {cursorGenesis,cursorUpdate,freezeCursor} from './journal_cursor.mjs';
import {transactionId,signedDescendant,descendantReferencesParent} from './txid_admission.mjs';
const cutoff=20;
function setup() {
  const f=fundingFixture();
  const genesis=cursorGenesis({source:f.independentUTXO,sourceValue:10000n});
  f.ledger.apply(genesis.tx,{height:2,authorized:true});
  return {...f,cursor:genesis};
}
const spend=(f,tx,height)=>f.ledger.apply(tx,{height,authorized:true});
const challenge=(cur,id,work)=>cursorUpdate({cursor:cur,certificateId:id,work:BigInt(work),validatedWork:true});

test('F01: a challenge transaction remains UTXO-valid after cutoff without extra Script gating',()=>{
  const f=setup();const high=challenge(f.cursor,'strong-151',151);
  assert.doesNotThrow(()=>spend(f,high.tx,21));
});
test('F02: freeze locktime makes freeze too early at cutoff height',()=>{
  const f=setup(),freeze=freezeCursor({cursor:f.cursor,admissionEnd:cutoff});
  assert.throws(()=>spend(f,freeze.tx,cutoff),/not final/);
});
test('F03: freeze becomes UTXO-valid in the block after cutoff',()=>{
  const f=setup(),freeze=freezeCursor({cursor:f.cursor,admissionEnd:cutoff});
  assert.doesNotThrow(()=>spend(f,freeze.tx,cutoff+1));
});
test('F04: late challenge can win a race against freeze if it spends the live cursor first',()=>{
  const f=setup(),freeze=freezeCursor({cursor:f.cursor,admissionEnd:cutoff});
  spend(f,challenge(f.cursor,'strong-151',151).tx,cutoff+1);
  assert.throws(()=>spend(f,freeze.tx,cutoff+1),/missing or spent prevout/);
});
test('F05: a confirmed freeze blocks late challenges through spent outpoint',()=>{
  const f=setup(),freeze=freezeCursor({cursor:f.cursor,admissionEnd:cutoff});
  spend(f,freeze.tx,cutoff+1);
  assert.throws(()=>spend(f,challenge(f.cursor,'strong-151',151).tx,cutoff+2),/missing or spent prevout/);
});
test('F06: stronger last-block challenge changes freeze prevout, invalidates stale presigned freeze',()=>{
  const f=setup(),freeze=freezeCursor({cursor:f.cursor,admissionEnd:cutoff});
  const high=challenge(f.cursor,'strong-151',151);spend(f,high.tx,cutoff);
  assert.throws(()=>spend(f,freeze.tx,cutoff+1),/missing or spent prevout/);
  const renewed=freezeCursor({cursor:high,admissionEnd:cutoff});
  assert.notEqual(transactionId(freeze.tx),transactionId(renewed.tx));
  assert.doesNotThrow(()=>spend(f,renewed.tx,cutoff+1));
});
test('F07: fully presigned descendants cannot survive changed freeze input',()=>{
  const f=setup(),freeze=freezeCursor({cursor:f.cursor,admissionEnd:cutoff});
  const child=signedDescendant(transactionId(freeze.tx));
  const high=challenge(f.cursor,'strong-151',151);
  const renewed=freezeCursor({cursor:high,admissionEnd:cutoff});
  assert.equal(descendantReferencesParent(child,renewed.tx),false);
});
