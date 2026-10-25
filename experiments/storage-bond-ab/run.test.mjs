import test from 'node:test';
import assert from 'node:assert/strict';
import {scenario,challenge,SCENARIOS} from './shared/scenario.mjs';
import {runScenario,runAll,summarizeCSV} from './run.mjs';
import {makeSentinelBackend} from './a-sentinel/adapter.mjs';
import {makeLayerTreeBackend} from './b-layertree/adapter.mjs';

const holder=(r,backend,name) =>
  r.backends.find(b=>b.backend===backend).settlements.find(s=>s.holder===name);

test('common 60k/40k terms and genuine deterministic Merkle openings',()=>{
  const sc=scenario();
  assert.equal(sc.terms.reduce((s,t)=>s+t.stake,0),100_000);
  const a=challenge(sc.events.find(e=>e.id==='alice'&&e.epoch===1));
  assert.equal(a.verified,true);
  assert.equal(a.evidenceClass,'real-sha256-merkle-reference-proof-model');
  assert.equal(a.nonce.length,64);
  const deleted=challenge(sc.events.find(e=>e.id==='alice'&&e.epoch===2));
  assert.equal(deleted.verified,false);
  assert.equal(deleted.witness.response,null);
  assert.equal(deleted.deletedChunk!==null,true);
  assert(deleted.selected.includes(deleted.deletedChunk));
  assert.equal(deleted.evidenceHash,challenge(sc.events.find(e=>e.id==='alice'&&e.epoch===2)).evidenceHash);
});

test('actual reference sentinel Script recognizes a pending deleted-window challenge',()=>{
  const sc=scenario(),a=makeSentinelBackend(sc);
  const e1=sc.events.find(e=>e.id==='alice'&&e.epoch===1);
  const e2=sc.events.find(e=>e.id==='alice'&&e.epoch===2);
  const p1=a.step(e1,challenge(e1));
  assert.equal(p1.pdp,'valid');
  const p2=a.step(e2,challenge(e2));
  assert.equal(p2.challenge,'pending');
  assert.equal(p2.scriptWrongAnswerRejected,true);
  assert.equal(p2.deadline,56);
  assert.throws(()=>a.step({kind:'settle',id:'alice',winner:'client',height:55}),/CSV/);
  assert.equal(a.step({kind:'settle',id:'alice',winner:'client',height:56}).payout.amount,60_000);
  assert.throws(()=>a.step({kind:'settle',id:'alice',winner:'client',height:57}),/already settled/);
});

test('storage fault scenario pays 60k client and returns 40k Bob provider for both',()=>{
  const r=runScenario('storage-fault');
  assert.equal(r.comparison.A.rejected,0);
  assert.equal(r.comparison.B.rejected,0);
  assert.equal(r.comparison.A.unresolvedSats,0);
  assert.equal(r.comparison.B.unresolvedSats,0);
  assert.equal(holder(r,'A-sentinel','alice').winner,'client');
  assert.equal(holder(r,'B-layertree','alice').winner,'client');
  assert.equal(holder(r,'A-sentinel','bob').winner,'provider');
  assert.equal(holder(r,'B-layertree','bob').winner,'provider');
  assert.equal(holder(r,'A-sentinel','alice').amount,60_000);
  assert.equal(holder(r,'B-layertree','bob').amount,40_000);
});

test('healthy service uses full-term provider refunds under both mechanisms',()=>{
  const r=runScenario('healthy');
  assert.equal(r.comparison.A.rejected,0);
  assert.equal(r.comparison.B.rejected,0);
  assert.deepEqual(r.comparison.A.settlements,{alice:'provider',bob:'provider'});
  assert.deepEqual(r.comparison.B.settlements,{alice:'provider',bob:'provider'});
  assert.equal(r.comparison.B.unresolvedSats,0);
});

test('a dishonest threshold can authorize a false fault while reference PDP passes',()=>{
  const r=runScenario('false-fault');
  const e=r.trace.find(row=>row.event.kind==='proof'&&row.event.id==='alice'&&row.event.epoch===2);
  assert.equal(e.sharedEvidence.actualPdpVerdict,'pass');
  assert.equal(e.sharedEvidence.claimedVerdict,'fault');
  assert.equal(e.A.receipt.acceptedFault,false);
  assert.equal(e.B.receipt.falseFaultAccepted,true);
  assert.equal(r.comparison.B.falseFaultsAccepted,1);
  assert.equal(r.comparison.A.settlements.alice,undefined);
  assert.equal(r.comparison.B.settlements.alice,'client');
  assert.equal(r.comparison.A.unresolvedSats,60_000);
  assert.equal(r.comparison.B.unresolvedSats,0);
  assert(r.trace.some(row=>row.event.kind==='settle'&&row.event.id==='alice'&&!row.A.ok&&row.B.ok));
});

test('quorum unavailable: sentinel exits proceed, federated state remains blocked',()=>{
  const r=runScenario('quorum-outage');
  assert.equal(r.comparison.A.unresolvedSats,0);
  assert.equal(r.comparison.B.unresolvedSats,100_000);
  assert.equal(r.comparison.B.accepted,0);
  assert(r.trace.every(row=>!row.B.ok));
  assert.equal(r.comparison.A.rejected,0);
});

test('a nonexistent quorum signature in the model must not count as FROST',()=>{
  const r=runScenario('storage-fault');
  assert.equal(r.realFrostSignatures,0);
  assert.equal(r.bitcoinTransactionsBroadcast,0);
  assert.equal(r.filecoinConsensusProofs,0);
  assert.equal(r.comparison.testnetComparable,false);
  const b=r.backends.find(x=>x.backend==='B-layertree');
  assert.equal(b.trust.thresholdVotesCryptographicallyVerified,false);
  assert.equal(b.trust.bitcoinNodeConfirmed,false);
  const a=r.backends.find(x=>x.backend==='A-sentinel');
  assert.equal(a.trust.actualBip341SighashVerified,false);
  assert.equal(a.trust.exactRecipientBoundByScript,false);
  assert.equal(b.metrics.bitcoinFeeVbytesMeasured,null);
  assert.equal(r.comparison.B.estimatedVbytes,null);
});

test('regression transcript remains deterministic across reruns',()=>{
  assert.deepEqual(runAll(),runAll());
  assert.deepEqual(runAll().map(r=>r.scenario),[...SCENARIOS]);
});

test('source evidence is unchanged even when the federation forges its verdict',()=>{
  const base=scenario('healthy').events.find(e=>e.id==='alice'&&e.epoch===2);
  const fraud=scenario('false-fault').events.find(e=>e.id==='alice'&&e.epoch===2);
  const a=challenge(base),b=challenge(fraud);
  assert.equal(a.evidenceHash,b.evidenceHash);
  assert.equal(a.verified,b.verified);
  assert.notEqual(a.assertedVerdict,b.assertedVerdict);
});

test('CSV reports measured and illustrative values in separate columns',()=>{
  const csv=summarizeCSV(runAll());
  const rows=csv.trim().split('\n');
  assert.equal(rows.length,1+SCENARIOS.length*2);
  assert.match(rows[0],/actual_testnet_confirmations/);
  assert.equal(rows[1].split(',').length,10);
  assert.match(rows.join('\n'),/"false-fault"/);
});

test('wrong settled epoch, wrong holder and replay remain rejected',()=>{
  const sc=scenario(),a=makeSentinelBackend(sc),b=makeLayerTreeBackend(sc);
  assert.throws(()=>a.step({kind:'proof',id:'mallory',epoch:1,height:50},
    challenge({kind:'proof',id:'mallory',epoch:1,storage:'intact'})),/unknown client/);
  const e=sc.events.find(e=>e.id==='bob'&&e.epoch===1);
  const p=challenge(e);a.step(e,p);b.step(e,p);
  assert.throws(()=>a.step(e,p),/stale/);
  assert.throws(()=>b.step(e,p),/replayed/);
  assert.throws(()=>b.step({kind:'settle',id:'mallory',winner:'client',height:100}),/unknown bond ID/);
});
