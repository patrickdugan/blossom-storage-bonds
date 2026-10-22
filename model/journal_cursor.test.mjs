import test from 'node:test';
import assert from 'node:assert/strict';
import {transactionId, signedDescendant, descendantReferencesParent} from './txid_admission.mjs';
import {fundingFixture,directProviderRefund} from './utxo_admission_graph.mjs';
import {cursorGenesis,cursorUpdate,jointSettlement,destroyCursor,proposedCursorInvariants} from './journal_cursor.mjs';

const apply=(ledger,tx,height=100)=>ledger.apply(tx,{height,authorized:true});
function setup(){
  const f=fundingFixture();
  const genesis=cursorGenesis({source:f.independentUTXO,sourceValue:10000n});
  apply(f.ledger,genesis.tx,2);
  return {...f,cursor:genesis};
}
const step=(c,id,work)=>cursorUpdate({cursor:c,certificateId:id,work:BigInt(work),validatedWork:true});
const settle=(bond,cursor,settlementHeight=150)=>jointSettlement({bond,cursor,bondValue:149000n,settlementHeight});

test('C01: independent live cursor chain leaves collateral untouched during admission',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);
  apply(f.ledger,low.tx,10);
  assert.equal(f.ledger.has(f.bond),true);
  assert.equal(f.ledger.has(low.ref),true);
});
test('C02: after weak->strong updates, settlement on initial cursor is UTXO-invalid',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  const high=step(low,'strong-151',151);apply(f.ledger,high.tx,20);
  assert.throws(()=>apply(f.ledger,settle(f.bond,f.cursor).tx,151),/missing or spent prevout/);
});
test('C03: after weak->strong updates, settlement on weak cursor is also invalid',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  const high=step(low,'strong-151',151);apply(f.ledger,high.tx,20);
  assert.throws(()=>apply(f.ledger,settle(f.bond,low).tx,151),/missing or spent prevout/);
});
test('C04: settlement including bond and live stronger cursor has both outpoints',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  const high=step(low,'strong-151',151);apply(f.ledger,high.tx,20);
  const ss=settle(f.bond,high);
  assert.equal(ss.tx.vin.length,2);
  assert.equal(ss.tx.vin[0].prevTxid,f.bond.txid);
  assert.equal(ss.tx.vin[1].prevTxid,high.ref.txid);
  assert.equal(ss.tx.vout[0].valueSats,155000n);
});
test('C05: stale settlement cannot win by changing only its claimed root',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  const high=step(low,'strong-151',151);apply(f.ledger,high.tx,20);
  const stale=settle(f.bond,low); stale.boundJournalRoot=high.root;
  assert.throws(()=>apply(f.ledger,stale.tx,151),/missing or spent prevout/);
});
test('C06: checkpoint after stronger challenge can settle only under authorization oracle',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  const high=step(low,'strong-151',151);apply(f.ledger,high.tx,20);
  const ss=settle(f.bond,high);
  assert.throws(()=>f.ledger.apply(ss.tx,{height:151,authorized:false}),/authorization unverified/);
  assert.doesNotThrow(()=>apply(f.ledger,ss.tx,151));
});
test('C07: original provider-only refund remains valid unless bond leaf removed',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  const high=step(low,'strong-151',151);apply(f.ledger,high.tx,20);
  // This is the old refund path; it ignores the journal cursor entirely.
  assert.doesNotThrow(()=>apply(f.ledger,directProviderRefund(f.bond),151));
});
test('C08: first challenger cannot finalize journal forever if successor remains live',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  assert.equal(f.ledger.has(low.ref),true);
  const high=step(low,'strong-151',151);
  assert.doesNotThrow(()=>apply(f.ledger,high.tx,20));
});
test('C09: malicious cursor spend can burn journal absent transition covenant',()=>{
  const f=setup();
  const burned=destroyCursor(f.cursor);apply(f.ledger,burned,10);
  assert.equal(f.ledger.has(f.cursor.ref),false);
  assert.throws(()=>apply(f.ledger,settle(f.bond,f.cursor).tx,151),/missing or spent prevout/);
});
test('C10: stronger update with unverified work is rejected only by external oracle',()=>{
  const f=setup();
  assert.throws(()=>cursorUpdate({cursor:f.cursor,certificateId:'forged-151',work:151n,
    validatedWork:false}),/verification oracle/);
});
test('C11: lower-work updates rejected by local template, needs consensus enforcement',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  assert.throws(()=>step(low,'weaker',90),/non-increasing/);
});
test('C12: equal-work competing forks require an explicit policy, not strict-greater cursor',()=>{
  const f=setup();const low=step(f.cursor,'fork-A',100);apply(f.ledger,low.tx,10);
  assert.throws(()=>step(low,'fork-B',100),/non-increasing/);
});
test('C13: update txid depends on certificate bytes and journal root',()=>{
  const f=setup();const a=step(f.cursor,'fork-A',100);const b=step(f.cursor,'fork-B',100);
  assert.notEqual(transactionId(a.tx),transactionId(b.tx));
});
test('C14: pre-signed next-cursor tx breaks when first certificate differs',()=>{
  const f=setup();const a=step(f.cursor,'fork-A',100);const b=step(f.cursor,'fork-B',100);
  const child=signedDescendant(transactionId(a.tx));
  assert.equal(descendantReferencesParent(child,b.tx),false);
});
test('C15: cursor-root check catches deliberate omission of newer state in local specification',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);const high=step(low,'strong-151',151);
  const stale=settle(f.bond,low);
  assert.equal(proposedCursorInvariants({liveCursor:high,settlement:stale}).referencesLiveCursor,false);
  assert.equal(proposedCursorInvariants({liveCursor:high,settlement:stale}).enforceableOnCurrentBitcoin,false);
});
test('C16: attempted settlement before cutoff remains timelocked even with correct cursor',()=>{
  const f=setup();const ss=settle(f.bond,f.cursor);
  assert.throws(()=>apply(f.ledger,ss.tx,150),/not final/);
});
test('C17: journal cursor fee depletion makes indefinite updates impossible without topups',()=>{
  const f=setup();let cur=f.cursor;
  for(let i=1;i<9;i++) cur=step(cur,`c-${i}`,i*10);
  assert.equal(cur.budget,1000n);
  assert.throws(()=>step(cur,'last',90),/insufficient/);
});
test('C18: current checkpoint commitment cannot validate remote certificate completeness',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);
  assert.equal(low.root.length,64);
  assert.equal(low.work,100n);
  const check=proposedCursorInvariants({liveCursor:low,settlement:settle(f.bond,low)});
  assert.equal(check.referencesLiveCursor,true);
  assert.ok(check.unresolved.includes('exact-work chain proof binding'));
});
test('C19: future settlement input set changes with each appended challenge',()=>{
  const f=setup();const low=step(f.cursor,'weak',100),high=step(low,'strong-151',151);
  assert.notEqual(transactionId(settle(f.bond,f.cursor).tx),transactionId(settle(f.bond,low).tx));
  assert.notEqual(transactionId(settle(f.bond,low).tx),transactionId(settle(f.bond,high).tx));
});
test('C20: an admitted weak fork must remain challengeable before cutoff by a stronger fork',()=>{
  const f=setup();const low=step(f.cursor,'weak',100);apply(f.ledger,low.tx,10);
  const high=step(low,'strong-151',151);apply(f.ledger,high.tx,20);
  assert.equal(f.ledger.has(high.ref),true);
  assert.equal(f.ledger.has(low.ref),false);
});
