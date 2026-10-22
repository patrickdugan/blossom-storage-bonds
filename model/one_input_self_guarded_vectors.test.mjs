import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {TopologyLedger} from './utxo_admission_graph.mjs';
import {transactionId,witnessTransactionId} from './txid_admission.mjs';
import {BOND,CERTIFICATE,RESPONSE_TOKEN,FORFEIT_HEIGHT} from './fixed_payout_consensus_vectors.mjs';
import {SELF_GUARDED_P2WSH,SELF_GUARDED_SCRIPT,bip143AllDigest} from './self_guarded_payout_vectors.mjs';
import {oneInputSamples,oneInputSelfGuardedVectors} from './one_input_self_guarded_vectors.mjs';

let f,rows,tx;
before(()=>{
  f=oneInputSelfGuardedVectors();
  rows=new Map(f.cases.map(v=>[v.name,v]));
  tx=oneInputSamples();
});
const accepted=name=>rows.get(name).expected_valid;
const fresh=()=>new TopologyLedger([
  {txid:BOND.txid,vout:BOND.vout,amount:BOND.amount,scriptPubKey:SELF_GUARDED_P2WSH}
]);
const apply=(ledger,t,height)=>ledger.apply(t,{height,authorized:true});

test('SI01: settlement needs only one funding UTXO and has no optional guardian or sponsor',()=>{
  assert.equal(f.facts.noSponsorInput,true);
  assert.equal(tx.provider.vin.length,1);
  assert.equal(tx.forfeit.vin.length,1);
  assert.equal(tx.provider.vin[0].prevTxid,BOND.txid);
});
test('SI02: provider and timeout spending templates both have a valid internal bond signature',()=>{
  assert.equal(accepted('single-bond-provider-with-correct-mock-opening'),true);
  assert.equal(accepted('single-bond-timeout-forfeit'),true);
  assert.equal(f.facts.bondScript,SELF_GUARDED_SCRIPT);
  assert.equal(f.facts.payoutSats,'148000');
});
test('SI03: hashlocked provider opening and certificate are needed',()=>{
  for(const name of ['single-bond-wrong-response','single-bond-empty-response',
    'single-bond-wrong-certificate','single-bond-replaced-script',
    'single-bond-missing-signature'])assert.equal(accepted(name),false);
  assert.equal(tx.provider.vin[0].witness[0],RESPONSE_TOKEN);
  assert.equal(tx.provider.vin[0].witness[2],CERTIFICATE);
});
test('SI04: single-input bond signing pins payout script and amount',()=>{
  for(const name of ['single-bond-redirected-payout','single-bond-shaved-payout',
    'single-bond-mutated-opreturn'])assert.equal(accepted(name),false);
});
test('SI05: once signed, even a new sponsor input invalidates old BIP143 authorization',()=>{
  assert.equal(accepted('single-bond-appended-sponsor'),false);
  assert.equal(accepted('single-bond-changed-prevout'),false);
});
test('SI06: a retained setup signer reauthorizes malicious payouts even in one-input design',()=>{
  assert.equal(accepted('single-bond-redirect-resigned-with-public-fixture-key'),true);
  assert.equal(accepted('single-bond-re-sign-to-burn-with-retained-key'),true);
  assert.equal(f.facts.setupKeyPublicForResearch,true);
});
test('SI07: timeout branch enforces BIP65 CLTV and the same certificate commitment',()=>{
  assert.equal(accepted('single-bond-timeout-before-cltv-resigned'),false);
  assert.equal(accepted('single-bond-timeout-final-sequence-resigned'),false);
  assert.equal(accepted('single-bond-timeout-wrong-certificate'),false);
  assert.equal(accepted('single-bond-timeout-redirected-payout'),false);
});
test('SI08: model forfeit can confirm after CLTV and consumes the only bond input',()=>{
  const ledger=fresh();
  assert.throws(()=>apply(ledger,tx.forfeit,FORFEIT_HEIGHT),/not final/);
  const r=apply(ledger,tx.forfeit,FORFEIT_HEIGHT+1);
  assert.equal(r.fee,1000n);
  assert.equal(ledger.has(BOND),false);
  assert.throws(()=>apply(ledger,tx.provider,FORFEIT_HEIGHT+2),/missing or spent prevout/);
});
test('SI09: provider confirmation first makes challenger timeout double spend impossible',()=>{
  const ledger=fresh();
  apply(ledger,tx.provider,151);
  assert.throws(()=>apply(ledger,tx.forfeit,FORFEIT_HEIGHT+1),/missing or spent prevout/);
});
test('SI10: one-input BIP143 digest still ignores witness-only certificate substitution',()=>{
  const changed={...tx.provider,vin:[{...tx.provider.vin[0],
    witness:[RESPONSE_TOKEN,'01','ef'.repeat(32),...tx.provider.vin[0].witness.slice(3)]}]};
  const digest=t=>bip143AllDigest(t,0,SELF_GUARDED_SCRIPT,BOND.amount).toString('hex');
  assert.equal(digest(tx.provider),digest(changed));
  assert.equal(transactionId(tx.provider),transactionId(changed));
  assert.notEqual(witnessTransactionId(tx.provider),witnessTransactionId(changed));
  assert.equal(f.facts.providerTxid,f.facts.witnessModifiedTxid);
  assert.notEqual(f.facts.providerWtxid,f.facts.witnessModifiedWtxid);
});
test('SI11: a provider response can still confirm after forfeiture eligibility',()=>{
  assert.equal(accepted('single-bond-response-still-valid-after-timeout'),true);
  const ledger=fresh();
  assert.doesNotThrow(()=>apply(ledger,tx.providerLate,FORFEIT_HEIGHT+6));
});
test('SI12: one-input valid settlement no longer risks spending a separately funded sponsor',()=>{
  const ledger=fresh();
  const r=apply(ledger,tx.provider,151);
  assert.equal(r.fee,1000n);
  assert.equal(r.spent.length,1);
  assert.equal(r.created.length,2);
});
test('SI13: expected consensus outcomes are defined for all 19 attacks and controls',()=>{
  assert.equal(f.cases.length,19);
  assert.equal(f.input_index,0);
  assert.equal(f.script_pub_key,SELF_GUARDED_P2WSH);
  for(const c of f.cases)assert.equal(typeof c.expected_valid,'boolean');
});
test('SI14: neither exact-work nor sound proof verification is part of the witness script',()=>{
  assert.equal(Object.hasOwn(f.facts,'validatedWork'),false);
  assert.equal(Object.hasOwn(f.facts,'proofVerified'),false);
  assert.equal(f.warning.includes('no work proof'),true);
});