import {test} from 'node:test';
import assert from 'node:assert/strict';
import {genesis,refresh,observe,payout,admit,compromisedThreshold,bareScriptTimeoutRace}
  from './layertree_bond_overlay.mjs';
const O = s => s.repeat(64)+':0';
const t = (id,stake) => ({id,provider:'miner-'+id,client:id,deal:'deal-'+id,sector:'sector-'+id,
  nonce:id+'-nonce',proofKind:'filecoin-windowpost',stake,clientScript:'5120'+('a'.repeat(64)),
  providerScript:'5120'+('b'.repeat(64)),startEpoch:1,endEpoch:3,refundHeight:100,
  challengeBlocks:6});
const S = () => genesis({outpoint:O('0'),signers:['f1','f2','f3'],threshold:2,
  terms:[t('alice',60000),t('bob',40000)]});
const Q=['f1','f2'];
const r = (s,to=O('1')) => ({kind:'refresh',before:s.root,from:s.carrier.outpoint,to,
  generation:s.carrier.generation+1,value:s.carrier.value,externalFee:500});
const e = (s,id,epoch,verdict='pass') => ({kind:'observe',before:s.root,id,
  deal:'deal-'+id,sector:'sector-'+id,proofKind:'filecoin-windowpost',epoch,verdict,
  evidenceHash:'e'.repeat(64),checkpoint:'f'.repeat(64),finalizedEpoch:epoch+10,
  bitcoinHeight:50});
const settle = (s,id,winner,height,to,remaining) => ({kind:'settle',before:s.root,id,
  from:s.carrier.outpoint,to,remaining,winner,height,value:id==='alice'?60000:40000,
  script:winner==='client'?'5120'+'a'.repeat(64):'5120'+'b'.repeat(64)});
test('pooled 60/40 principal',()=>{const s=S();assert.equal(s.carrier.value,100000);
  assert.equal(s.bitcoinEnforced,false);assert.equal(s.filecoinCheckpointVerified,false);});
test('noninteractive refresh preserves both balances',()=>{const s=S(),n=refresh(s,r(s),Q);
  assert.equal(n.carrier.value,100000);assert.deepEqual(n.bonds,s.bonds);
  assert.notEqual(n.root,s.root);assert.equal(n.usedOutpoints.length,1);});
test('threshold and replay controls',()=>{const s=S();assert.throws(()=>refresh(s,r(s),['f1']),/insufficient/);
  assert.throws(()=>refresh(s,r(s),['f1','f1']),/duplicate/);
  assert.throws(()=>refresh(s,r(s),['f1','mallory']),/unknown/);
  const n=refresh(s,r(s),Q);assert.throws(()=>refresh(n,r(s),Q),/stale/);
  assert.throws(()=>refresh(n,r(n,O('0')),Q),/lineage/);});
test('refresh rejects principal theft and invalid funding',()=>{const s=S();
  assert.throws(()=>refresh(s,{...r(s),value:99999},Q),/theft/);
  assert.throws(()=>refresh(s,{...r(s),externalFee:-1},Q),/fee/);
  assert.throws(()=>refresh(s,{...r(s),generation:4},Q),/generation/);});
test('wrong Filecoin sector, protocol and finality rejected',()=>{const s=S();
  for(const mutate of [{sector:'wrong'},{proofKind:'blossom-pdp'},{finalizedEpoch:0}])
    assert.throws(()=>observe(s,{...e(s,'alice',1),...mutate},Q));});
test('fresh evidence required for each successful epoch',()=>{const s=S(),n=observe(s,e(s,'bob',1),Q);
  assert.equal(n.bonds[1].lastEpoch,1);
  assert.throws(()=>observe(n,e(n,'bob',1),Q),/replayed/);
  assert.throws(()=>observe(n,e(n,'bob',3),Q),/skipped/);});
test('fault freezes replies and matures only after six Bitcoin blocks',()=>{const s=S(),n=observe(s,e(s,'alice',1,'fault'),Q);
  assert.equal(n.bonds[0].challenge.deadline,56);
  assert.throws(()=>observe(n,e(n,'alice',2),Q),/frozen/);
  assert.throws(()=>payout(n,settle(n,'alice','client',55,O('2'),40000),Q),/unmatured/);
  const paid=payout(n,settle(n,'alice','client',56,O('2'),40000),Q);
  assert.equal(paid.carrier.value,40000);assert.equal(paid.bonds[0].closed.winner,'client');});
test('refund cannot bypass unresolved fault',()=>{const n=observe(S(),e(S(),'alice',1,'fault'),Q);
  assert.throws(()=>payout(n,settle(n,'alice','provider',101,O('2'),40000),Q),/contested/);});
test('correct recipient and exact remainder enforced',()=>{const s=S(),n=observe(s,e(s,'alice',1,'fault'),Q),a=settle(n,'alice','client',56,O('2'),40000);
  assert.throws(()=>payout(n,{...a,script:'51'},Q),/wrong client/);
  assert.throws(()=>payout(n,{...a,remaining:39999},Q),/underfunded/);
  assert.throws(()=>payout(n,{...a,value:59999},Q),/amount/);});
test('provider refund requires all three proofs and height',()=>{let s=S();
  for(let epoch=1;epoch<=3;epoch++)s=observe(s,e(s,'bob',epoch),Q);
  assert.throws(()=>payout(s,settle(s,'bob','provider',100,O('3'),60000),Q),/premature/);
  const paid=payout(s,settle(s,'bob','provider',101,O('3'),60000),Q);
  assert.equal(paid.carrier.value,60000);});
test('shared pool closes without duplicating collateral',()=>{let s=S();
  s=observe(s,e(s,'alice',1,'fault'),Q);
  for(let ep=1;ep<=3;ep++)s=observe(s,e(s,'bob',ep),Q);
  s=payout(s,settle(s,'alice','client',56,O('2'),40000),Q);
  s=payout(s,settle(s,'bob','provider',101,null,0),Q);
  assert.equal(s.carrier.value,0);assert.equal(s.carrier.outpoint,null);
  assert.throws(()=>payout(s,settle(s,'alice','client',102,null,0),Q),/double payout/);});
test('lineage tombstones reject reused provider nonce',()=>{const s=S();const dup=t('new',20000);
  dup.provider='miner-alice';dup.nonce='alice-nonce';
  assert.throws(()=>admit(s,{kind:'admit',before:s.root,from:O('0'),to:O('2'),value:120000,terms:dup},Q),/historical/);});
test('permissioned federation can authorize a fake external fault',()=>{const s=S();
  const fake={...e(s,'alice',1,'fault'),checkpoint:'0'.repeat(64)};
  assert(observe(s,fake,Q).bonds[0].challenge);
  assert.equal(compromisedThreshold(s,['f1']),false);
  assert.equal(compromisedThreshold(s,['f1','f2']),true);});
test('unbounded late response competes with client forfeiture after CLTV',()=>{
  const w=bareScriptTimeoutRace({height:99,deadline:98,providerKnowsAnswer:true});
  assert(w.clientForfeitEligible&&w.providerLateResponseEligible);
  assert.equal(w.consensusGuaranteesExclusiveVerdict,false);});
