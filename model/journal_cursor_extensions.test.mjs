import test from 'node:test';
import assert from 'node:assert/strict';
import {transactionId} from './txid_admission.mjs';
import {fundingFixture} from './utxo_admission_graph.mjs';
import {cursorGenesis,cursorUpdate} from './journal_cursor.mjs';
const apply=(ledger,tx,height=100)=>ledger.apply(tx,{height,authorized:true});
function setup(){const f=fundingFixture();const cursor=cursorGenesis({source:f.independentUTXO,sourceValue:10000n});apply(f.ledger,cursor.tx,2);return {...f,cursor};}
const step=(cursor,id,work)=>cursorUpdate({cursor,certificateId:id,work:BigInt(work),validatedWork:true});
test('C21: duplicate equal-work certificate cannot append a second time in ideal policy',()=>{
  const f=setup();const low=step(f.cursor,'fork-A',100);
  assert.throws(()=>cursorUpdate({cursor:low,certificateId:'fork-A',work:100n,validatedWork:true,allowTies:true}),/duplicate certificate/);
});
test('C22: stronger work supersedes max tie candidates in expected ideal state',()=>{
  const f=setup();const a=step(f.cursor,'fork-A',100),b=cursorUpdate({cursor:a,certificateId:'fork-B',work:100n,validatedWork:true,allowTies:true});
  const strong=step(b,'strong-151',151);
  assert.deepEqual(strong.bestIds,['strong-151']);
});
test('C23: sponsored cursor append preserves locked value and uses a second input',()=>{
  const f=setup();const sponsorRef={txid:'33'.repeat(32),vout:0};
  f.ledger.utxos.set(`${sponsorRef.txid}:0`,{amount:1000n,scriptPubKey:'51'});
  const next=cursorUpdate({cursor:f.cursor,certificateId:'weak',work:100n,
    validatedWork:true,fee:1000n,sponsor:{ref:sponsorRef,value:1000n}});
  assert.equal(next.tx.vin.length,2);
  assert.equal(next.budget,f.cursor.budget);
  assert.equal(next.tx.vout[0].valueSats,f.cursor.budget);
  assert.doesNotThrow(()=>apply(f.ledger,next.tx,10));
});
test('C24: sponsored append with change preserves cursor as output zero',()=>{
  const f=setup();const sponsorRef={txid:'33'.repeat(32),vout:0};
  f.ledger.utxos.set(`${sponsorRef.txid}:0`,{amount:2500n,scriptPubKey:'51'});
  const next=cursorUpdate({cursor:f.cursor,certificateId:'weak',work:100n,
    validatedWork:true,fee:1000n,sponsor:{ref:sponsorRef,value:2500n}});
  assert.equal(next.tx.vout.length,2);
  assert.equal(next.tx.vout[1].valueSats,1500n);
  assert.equal(next.ref.vout,0);
  assert.doesNotThrow(()=>apply(f.ledger,next.tx,10));
});
test('C25: malformed sponsor input, self-sponsorship and insufficient fee rejected',()=>{
  const f=setup();const base={cursor:f.cursor,certificateId:'weak',work:100n,validatedWork:true,fee:1000n};
  assert.throws(()=>cursorUpdate({...base,sponsor:{ref:f.cursor.ref,value:1000n}}),/invalid sponsor/);
  assert.throws(()=>cursorUpdate({...base,sponsor:{ref:{txid:'33'.repeat(32),vout:0},value:999n}}),/invalid sponsor/);
});
test('C26: sponsored and unsponsored update commitments match but transaction IDs differ',()=>{
  const f=setup();const base={cursor:f.cursor,certificateId:'weak',work:100n,validatedWork:true,fee:1000n};
  const a=cursorUpdate(base);
  const b=cursorUpdate({...base,sponsor:{ref:{txid:'33'.repeat(32),vout:0},value:1000n}});
  assert.equal(a.root,b.root);
  assert.notEqual(transactionId(a.tx),transactionId(b.tx));
});

test('C27: opt-in tied maximum is retained by the journal cursor',()=>{
  const f=setup();const a=step(f.cursor,'fork-A',100);
  const b=cursorUpdate({cursor:a,certificateId:'fork-B',work:100n,validatedWork:true,allowTies:true});
  assert.deepEqual(b.bestIds,['fork-A','fork-B']);
  assert.equal(b.work,100n);
});
