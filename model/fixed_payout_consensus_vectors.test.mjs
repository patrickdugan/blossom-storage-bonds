import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {transactionId,witnessTransactionId} from './txid_admission.mjs';
import {TopologyLedger} from './utxo_admission_graph.mjs';
import {ContestSpecification} from './contest_spec.mjs';
import {
  CERTIFICATE,OTHER_CERTIFICATE,RESPONSE_TOKEN,WRONG_RESPONSE,
  CERTIFICATE_SHA256,RESPONSE_SHA256,FORFEIT_HEIGHT,
  BOND,GUARDIAN,ESCROW_SCRIPT,ESCROW_P2WSH,GUARDIAN_SCRIPT,
  PROVIDER_PAYOUT_SCRIPT,CHALLENGER_PAYOUT_SCRIPT,
  fixedPayoutSamples,fixedPayoutConsensusVectors
} from './fixed_payout_consensus_vectors.mjs';

const h=hex=>createHash('sha256').update(Buffer.from(hex,'hex')).digest('hex');
let f,rows,tx;
before(()=>{
  f=fixedPayoutConsensusVectors();
  rows=new Map(f.cases.map(c=>[c.name,c]));
  tx=fixedPayoutSamples();
});
const get=name=>rows.get(name);
const checks=name=>get(name).expected_inputs.map(x=>x.expected_valid);
const fresh=()=>new TopologyLedger([
  {txid:BOND.txid,vout:BOND.vout,amount:BOND.amount,scriptPubKey:ESCROW_P2WSH},
  {txid:GUARDIAN.txid,vout:GUARDIAN.vout,amount:GUARDIAN.amount,scriptPubKey:GUARDIAN_SCRIPT}
]);
const apply=(ledger,spend,height,authorized=true)=>ledger.apply(spend,{height,authorized});

test('CP01: P2WSH commits to the exact certificate and mock response in each branch',()=>{
  assert.equal(CERTIFICATE_SHA256,h(CERTIFICATE));
  assert.equal(RESPONSE_SHA256,h(RESPONSE_TOKEN));
  assert.equal(ESCROW_SCRIPT,'a820'+CERTIFICATE_SHA256+'8863a820'+RESPONSE_SHA256+'876702a000b1755168');
  assert.equal(ESCROW_P2WSH,'0020'+h(ESCROW_SCRIPT));
});
test('CP02: both outcomes consume the same bond and pre-signed guardian outpoints',()=>{
  assert.deepEqual(tx.provider.vin.map(i=>i.prevTxid),tx.forfeit.vin.map(i=>i.prevTxid));
  assert.equal(tx.provider.vin[0].prevTxid,BOND.txid);
  assert.equal(tx.forfeit.vin[1].prevTxid,GUARDIAN.txid);
  assert.notEqual(transactionId(tx.provider),transactionId(tx.forfeit));
});
test('CP03: only certificate and mock response openings allow provider Script acceptance',()=>{
  assert.deepEqual(checks('fixed-provider-with-mock-response'),[true,true]);
  assert.deepEqual(checks('fixed-provider-wrong-response'),[false,true]);
  assert.deepEqual(checks('fixed-provider-empty-response'),[false,true]);
  assert.deepEqual(checks('fixed-provider-wrong-certificate'),[false,true]);
  assert.deepEqual(checks('fixed-provider-altered-witness-program'),[false,true]);
  assert.notEqual(CERTIFICATE_SHA256,h(OTHER_CERTIFICATE));
  assert.notEqual(RESPONSE_SHA256,h(WRONG_RESPONSE));
});
test('CP04: substituted certificate changes wtxid but preserves txid and guardian signature',()=>{
  assert.equal(f.facts.providerTxid,f.facts.wrongCertificateTxid);
  assert.notEqual(f.facts.providerWtxid,f.facts.wrongCertificateWtxid);
  assert.equal(transactionId(tx.provider),get('fixed-provider-wrong-certificate').txid);
});
test('CP05: original guardian rejects tampering with provider payout and claim commitment',()=>{
  assert.deepEqual(checks('fixed-provider-redirected-payout'),[true,false]);
  assert.deepEqual(checks('fixed-provider-reduced-payout'),[true,false]);
  assert.deepEqual(checks('fixed-provider-mutated-claim-commitment'),[true,false]);
  assert.equal(f.facts.guardianSighashType,1);
});
test('CP06: retained guardian test key can re-sign a malicious output (setup trust hazard)',()=>{
  assert.equal(f.facts.guardianSecretPublicInTest,true);
  assert.deepEqual(checks('fixed-provider-resigned-redirect-with-public-test-key'),[true,true]);
  assert.equal(get('fixed-provider-resigned-redirect-with-public-test-key').expected_valid,true);
});
test('CP07: guardian ALL signature also binds both input outpoints and blocks appended fee input',()=>{
  for(const attack of ['fixed-provider-changed-guardian-prevout',
     'fixed-provider-changed-bond-prevout','fixed-provider-added-fee-input']){
    assert.deepEqual(checks(attack),[true,false]);
  }
});
test('CP08: timeout path uses CLTV 160 with non-final bond sequence',()=>{
  assert.equal(tx.forfeit.lockTime,FORFEIT_HEIGHT);
  assert.equal(tx.forfeit.vin[0].sequence,0xfffffffe);
  assert.deepEqual(tx.forfeit.vin[0].witness,['',CERTIFICATE,ESCROW_SCRIPT]);
  assert.deepEqual(checks('fixed-timeout-forfeit-to-challenger'),[true,true]);
  assert.deepEqual(checks('fixed-timeout-before-cltv-with-fresh-guardian'),[false,true]);
  assert.deepEqual(checks('fixed-timeout-final-sequence-with-fresh-guardian'),[false,true]);
});
test('CP09: pre-signed guardian fixes challenger recipient and amount in timeout branch',()=>{
  assert.deepEqual(checks('fixed-timeout-redirected-payout'),[true,false]);
  assert.deepEqual(checks('fixed-timeout-reduced-payout'),[true,false]);
  assert.equal(tx.provider.vout[1].scriptPubKey,PROVIDER_PAYOUT_SCRIPT);
  assert.equal(tx.forfeit.vout[1].scriptPubKey,CHALLENGER_PAYOUT_SCRIPT);
  assert.equal(tx.provider.vout[1].valueSats,tx.forfeit.vout[1].valueSats);
});
test('CP10: native P2WSH cleanstack rejects surplus response token in timeout branch',()=>{
  assert.deepEqual(checks('fixed-timeout-extra-stack-item'),[false,true]);
  assert.deepEqual(checks('fixed-provider-cannot-switch-to-timeout-before-cltv'),[false,true]);
});
test('CP11: timeout transaction cannot confirm at lock height in topology model',()=>{
  const ledger=fresh();
  assert.throws(()=>apply(ledger,tx.forfeit,FORFEIT_HEIGHT),/not final/);
  assert.equal(ledger.has(BOND),true);
});
test('CP12: a valid timeout spend consumes escrow and guardian, preventing later provider exit',()=>{
  const ledger=fresh();
  const r=apply(ledger,tx.forfeit,FORFEIT_HEIGHT+1);
  assert.equal(r.fee,4000n);
  assert.equal(ledger.has(BOND),false);
  assert.equal(ledger.has(GUARDIAN),false);
  assert.throws(()=>apply(ledger,tx.provider,FORFEIT_HEIGHT+2),/missing or spent prevout/);
});
test('CP13: an earlier valid provider spend likewise excludes later timeout spend',()=>{
  const ledger=fresh();
  const r=apply(ledger,tx.provider,FORFEIT_HEIGHT-1);
  assert.equal(r.fee,4000n);
  assert.throws(()=>apply(ledger,tx.forfeit,FORFEIT_HEIGHT+1),/missing or spent prevout/);
});
test('CP14: absent witness answer is Script-invalid even though topology oracle could approve a spend',()=>{
  assert.equal(get('fixed-provider-empty-response').expected_valid,false);
  const ledger=fresh();
  assert.throws(()=>apply(ledger,tx.provider,151,false),/authorization unverified/);
  assert.equal(ledger.has(BOND),true);
});
test('CP15: provider answer remains Script-valid after forfeiture time if collateral is still unspent',()=>{
  assert.deepEqual(checks('fixed-provider-late-response-still-script-valid'),[true,true]);
  const ledger=fresh();
  const r=apply(ledger,tx.providerLate,FORFEIT_HEIGHT+6);
  assert.equal(r.fee,4000n);
  assert.equal(ledger.has(BOND),false);
});
test('CP16: ideal answered-by-deadline policy and late Script-valid path still disagree',()=>{
  const policy=new ContestSpecification({admissionEnd:20,responseBlocks:5});
  policy.submit({id:'strong-151',headerRoot:'bb'.repeat(32),work:151n,height:20},
    {confirmedHeight:20,verifiedExactWork:true});
  policy.freeze(21);
  assert.equal(policy.payout(FORFEIT_HEIGHT+6),'forfeit');
  assert.equal(get('fixed-provider-late-response-still-script-valid').expected_valid,true);
});
test('CP17: fixed certificate evidence is a tag; no work or Bitcoin inclusion is checked by Script',()=>{
  assert.equal(CERTIFICATE.length,64);
  assert.equal(Object.hasOwn(f.facts,'validatedExactWork'),false);
  assert.equal(Object.hasOwn(f.facts,'canonicalAnchor'),false);
  assert.equal(f.warning.includes('MOCK HASHLOCK'),true);
});
test('CP18: full expected per-input results are enumerated for every consensus case',()=>{
  assert.equal(f.cases.length,20);
  assert.equal(f.checks.length,2);
  for(const c of f.cases){
    assert.deepEqual(c.expected_inputs.map(i=>i.input_index),[0,1]);
    assert.equal(c.expected_valid,c.expected_inputs.every(i=>i.expected_valid));
    assert.equal(typeof c.tx_hex,'string');
  }
});