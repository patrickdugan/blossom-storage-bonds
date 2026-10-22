import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {TopologyLedger} from './utxo_admission_graph.mjs';
import {transactionId,witnessTransactionId} from './txid_admission.mjs';
import {BOND,CERTIFICATE,RESPONSE_TOKEN,FORFEIT_HEIGHT,ESCROW_P2WSH} from './fixed_payout_consensus_vectors.mjs';
import {
  BYPASS_PAYOUT,unguardedBondBypassSamples,unguardedBondBypassVectors
} from './bond_only_bypass_vectors.mjs';
import {
  SPONSOR,SELF_GUARDED_SCRIPT,SELF_GUARDED_P2WSH,
  bip143AllDigest,selfGuardedSamples,selfGuardedConsensusVectors
} from './self_guarded_payout_vectors.mjs';

let a,b,old,good,prior;
before(()=>{
  a=unguardedBondBypassVectors();
  b=selfGuardedConsensusVectors();
  old=new Map(a.cases.map(x=>[x.name,x]));
  good=new Map(b.cases.map(x=>[x.name,x]));
  prior=unguardedBondBypassSamples();
});
const results=x=>good.get(x).expected_inputs.map(i=>i.expected_valid);
const at=(ledger,tx,height)=>ledger.apply(tx,{height,authorized:true});
const oldLedger=()=>new TopologyLedger([
  {txid:BOND.txid,vout:BOND.vout,amount:BOND.amount,scriptPubKey:ESCROW_P2WSH},
  {txid:'b2'.repeat(32),vout:0,amount:5000n,scriptPubKey:'51'}
]);
const newLedger=()=>new TopologyLedger([
  {txid:BOND.txid,vout:BOND.vout,amount:BOND.amount,scriptPubKey:SELF_GUARDED_P2WSH},
  {txid:SPONSOR.txid,vout:SPONSOR.vout,amount:SPONSOR.amount,scriptPubKey:SPONSOR.scriptPubKey}
]);
test('UB01: original independent-guardian bond can be spent without guardian input',()=>{
  assert.equal(a.input_index,0);
  assert.equal(a.facts.independentGuardianRequiredByBondScript,false);
  assert.equal(old.get('unguarded-provider-redirects-bond-alone').expected_valid,true);
  assert.equal(prior.directSpend.vin.length,1);
  assert.equal(prior.directSpend.vout[0].scriptPubKey,BYPASS_PAYOUT);
});
test('UB02: old bond-only spend wins at UTXO layer and leaves guardian outpoint untouched',()=>{
  const ledger=oldLedger();
  const spend=at(ledger,prior.directSpend,151);
  assert.equal(spend.fee,1000n);
  assert.equal(ledger.has(BOND),false);
  assert.equal(ledger.has({txid:'b2'.repeat(32),vout:0}),true);
});
test('UB03: old P2WSH Script accepts an arbitrary burn through excessive fee',()=>{
  assert.equal(old.get('unguarded-provider-can-burn-bond-as-fee').expected_valid,true);
  assert.equal(old.get('unguarded-provider-with-unapproved-extra-output').expected_valid,true);
});
test('UB04: old timeout path likewise spends bond without guardian or protected recipient',()=>{
  assert.equal(old.get('unguarded-timeout-redirects-bond-alone').expected_valid,true);
  assert.equal(prior.timeoutSpend.vin.length,1);
  const ledger=oldLedger();
  assert.throws(()=>at(ledger,prior.timeoutSpend,FORFEIT_HEIGHT),/not final/);
  assert.doesNotThrow(()=>at(ledger,prior.timeoutSpend,FORFEIT_HEIGHT+1));
});
test('UB05: the certificate, response and CLTV checks still work in unsafe escrow',()=>{
  for(const id of ['unguarded-timeout-before-cltv','unguarded-provider-wrong-response',
    'unguarded-provider-wrong-certificate'])assert.equal(old.get(id).expected_valid,false);
});
test('UB06: all old attack vectors explicitly describe input-zero Script results',()=>{
  assert.equal(a.cases.length,7);
  for(const c of a.cases)assert.equal(typeof c.expected_valid,'boolean');
});
test('SG01: repaired bond Script begins with its own CHECKSIGVERIFY authorization',()=>{
  assert.equal(SELF_GUARDED_SCRIPT.slice(0,2),'21'); // 33-byte compressed pubkey
  assert.equal(SELF_GUARDED_SCRIPT.slice(68,70),'ad'); // OP_CHECKSIGVERIFY
  assert.equal(b.checks[0].script_pub_key,SELF_GUARDED_P2WSH);
  assert.equal(b.facts.guardingInputIndex,0);
});
test('SG02: correct certificate and mock response remain spendable under self-guard',()=>{
  assert.deepEqual(results('self-guard-provider-certificate-and-answer'),[true,true]);
  const sample=selfGuardedSamples().provider;
  assert.equal(sample.vin[0].witness[2],CERTIFICATE);
  assert.equal(sample.vin[0].witness[0],RESPONSE_TOKEN);
  assert.equal(sample.vin[0].witness.at(-1),SELF_GUARDED_SCRIPT);
});
test('SG03: missing signature, wrong witness and wrong answer all fail bond input',()=>{
  for(const id of ['self-guard-wrong-answer','self-guard-empty-answer',
    'self-guard-wrong-certificate','self-guard-missing-setup-signature',
    'self-guard-witness-script-substitution'])
    assert.deepEqual(results(id),[false,true]);
});
test('SG04: changing destination, amount or OP_RETURN fails authorization at the bond',()=>{
  for(const id of ['self-guard-redirected-provider-payout',
    'self-guard-shaved-provider-payout','self-guard-mutated-opreturn'])
    assert.deepEqual(results(id),[false,true]);
});
test('SG05: detaching sponsor input fails BIP143 bond authorization',()=>{
  assert.deepEqual(results('self-guard-bond-only-detached-sponsor'),[false,false]);
  assert.deepEqual(results('self-guard-timeout-only-detached-sponsor'),[false,false]);
  assert.equal(old.get('unguarded-provider-redirects-bond-alone').expected_valid,true);
});
test('SG06: changing any bound input or adding a sponsor likewise fails bond signature',()=>{
  for(const id of ['self-guard-changed-sponsor','self-guard-changed-bond-outpoint',
    'self-guard-added-input'])assert.deepEqual(results(id),[false,true]);
});
test('SG07: a retained setup key still re-signs a malicious payout successfully',()=>{
  assert.equal(b.facts.setupSecretAvailableInTest,true);
  assert.deepEqual(results('self-guard-provider-resigned-redirect-with-public-test-key'),[true,true]);
  assert.deepEqual(results('self-guard-forfeit-payout-resigned-with-test-key'),[true,true]);
});
test('SG08: forfeit path Script requires CLTV and nonfinal bond sequence',()=>{
  assert.deepEqual(results('self-guard-forfeit-after-cltv'),[true,true]);
  assert.deepEqual(results('self-guard-forfeit-before-cltv-resigned'),[false,true]);
  assert.deepEqual(results('self-guard-forfeit-final-sequence-resigned'),[false,true]);
});
test('SG09: pre-signed forfeit output cannot be redirected without re-signing',()=>{
  assert.deepEqual(results('self-guard-forfeit-payout-redirect'),[false,true]);
});
test('SG10: BIP143 ALL digest binds outputs and input list, but not witness-only changes',()=>{
  const {provider}=selfGuardedSamples();
  const mutOut={...provider,vout:provider.vout.map((o,i)=>i===1?{...o,valueSats:1n}:o)};
  const bondOnly={...provider,vin:[provider.vin[0]]};
  const wrongWitness={...provider,vin:provider.vin.map((v,i)=>i===0?
    {...v,witness:['ff'.repeat(32),...v.witness.slice(1)]}:v)};
  const digest=t=>bip143AllDigest(t,0,SELF_GUARDED_SCRIPT,BOND.amount).toString('hex');
  assert.equal(digest(provider),digest(wrongWitness));
  assert.notEqual(digest(provider),digest(mutOut));
  assert.notEqual(digest(provider),digest(bondOnly));
});
test('SG11: witness certificate swap retains txid even though Script rejects it',()=>{
  assert.equal(b.facts.originalTxid,b.facts.wrongCertificateTxid);
  assert.notEqual(b.facts.originalWtxid,b.facts.wrongCertificateWtxid);
});
test('SG12: forfeit at height 161 consumes the guarded bond and sponsor, provider then conflicts',()=>{
  const ledger=newLedger(),{forfeit,provider}=selfGuardedSamples();
  assert.throws(()=>at(ledger,forfeit,FORFEIT_HEIGHT),/not final/);
  const r=at(ledger,forfeit,FORFEIT_HEIGHT+1);
  assert.equal(r.fee,4000n);
  assert.equal(ledger.has(BOND),false);
  assert.equal(ledger.has(SPONSOR),false);
  assert.throws(()=>at(ledger,provider,FORFEIT_HEIGHT+2),/missing or spent prevout/);
});
test('SG13: provider response accepted first makes later forfeit UTXO-invalid',()=>{
  const ledger=newLedger(),{provider,forfeit}=selfGuardedSamples();
  at(ledger,provider,151);
  assert.throws(()=>at(ledger,forfeit,FORFEIT_HEIGHT+1),/missing or spent prevout/);
});
test('SG14: even self-guarding cannot invalidate a provider response after cutoff',()=>{
  assert.deepEqual(results('self-guard-provider-response-remains-valid-after-deadline'),[true,true]);
  const ledger=newLedger(),{providerLate}=selfGuardedSamples();
  assert.doesNotThrow(()=>at(ledger,providerLate,FORFEIT_HEIGHT+6));
});
test('SG15: fixture is a static certificate, mock response and public unsafe signing key',()=>{
  assert.equal(b.warning.includes('Static cert and mock answer'),true);
  assert.equal(Object.hasOwn(b.facts,'authenticatedChainWork'),false);
  assert.equal(Object.hasOwn(b.facts,'bitcoinConfirmedHeight'),false);
});
test('SG16: each Core check records expected individual input validity',()=>{
  assert.equal(b.cases.length,21);
  for(const c of b.cases){
    assert.deepEqual(c.expected_inputs.map(x=>x.input_index),[0,1]);
    assert.equal(c.expected_valid,c.expected_inputs.every(x=>x.expected_valid));
  }
});