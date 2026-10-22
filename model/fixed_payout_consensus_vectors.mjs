/**
 * ADR-008: fixed-certificate conditional collateral payout, verified by
 * offline Bitcoin Core per-input Script checks.
 *
 * Bond input 0: P2WSH SHA256(certificate) gate, with a mock response hashlock
 * or an nLockTime/CLTV challenger-forfeit branch.
 * Guardian input 1: pre-signed legacy P2PK SIGHASH_ALL protecting BOTH input
 * outpoints and the exact output scripts/amounts in each outcome.
 *
 * This is a bounded, setup-chosen certificate. The hashlock stands for a
 * FUTURE sound BitVM adjudication output, NOT a proof verifier: knowledge of
 * the preimage alone opens the provider path. CLTV is only a lower-bound
 * timeout, and cannot invalidate a provider response after that height.
 *
 * Fabricated UTXOs, publicly known test keys, no Bitcoin node or funding.
 */
import {createHash} from 'node:crypto';
import {legacySignatureHash,encodePushData} from './legacy_sighash.mjs';
import {N,mod,inverse,multiply,pubkey,encodeBitcoinSignature,displayHashToZ} from './secp256k1_legacy_demo.mjs';
import {serializeTransaction,transactionId,witnessTransactionId} from './txid_admission.mjs';

const sha256=b=>createHash('sha256').update(b).digest('hex');
const shaHex=hex=>sha256(Buffer.from(hex,'hex'));
const ID=hex=>hex.repeat(32);
const fixedBytes=x=>typeof x==='string'&&/^[0-9a-f]{64}$/i.test(x);
const changeInput=(tx,index,patch)=>({...tx,vin:tx.vin.map((v,i)=>index===i?{...v,...patch}:v)});
const changeOutput=(tx,index,patch)=>({...tx,vout:tx.vout.map((v,i)=>index===i?{...v,...patch}:v)});

export const CERTIFICATE='ab'.repeat(32); // labeled toy certificate, not 151 real headers
export const OTHER_CERTIFICATE='cd'.repeat(32);
export const RESPONSE_TOKEN='12'.repeat(32); // public MOCK response, not a BitVM verdict
export const WRONG_RESPONSE='34'.repeat(32);
export const FORFEIT_HEIGHT=160; // earliest confirming height 161 under nLockTime=160
export const BOND=Object.freeze({txid:ID('a1'),vout:0,amount:149000n});
export const GUARDIAN=Object.freeze({txid:ID('b2'),vout:0,amount:5000n});
export const CERTIFICATE_SHA256=shaHex(CERTIFICATE);
export const RESPONSE_SHA256=shaHex(RESPONSE_TOKEN);
const PROVIDER_PUBKEY=pubkey(multiply(13n));
const CHALLENGER_PUBKEY=pubkey(multiply(17n));
const GUARDIAN_PRIVATE=5n; // PUBLIC fixed scalar, research ONLY
const GUARDIAN_NONCE=11n; // PUBLIC and reused: insecure outside this fixture
const GUARDIAN_PUBKEY=pubkey(multiply(GUARDIAN_PRIVATE));
export const PROVIDER_PAYOUT_SCRIPT=encodePushData(PROVIDER_PUBKEY)+'ac';
export const CHALLENGER_PAYOUT_SCRIPT=encodePushData(CHALLENGER_PUBKEY)+'ac';
export const GUARDIAN_SCRIPT=encodePushData(GUARDIAN_PUBKEY)+'ac';

// OP_SHA256 <cert_sha256> OP_EQUALVERIFY
// OP_IF OP_SHA256 <response_sha256> OP_EQUAL
// OP_ELSE <160> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE OP_ENDIF
//
// Stack for provider: [response, true_selector, certificate].
// Stack for timeout: [false_selector, certificate].
export const ESCROW_SCRIPT=
  'a820'+CERTIFICATE_SHA256+'88'+
  '63a820'+RESPONSE_SHA256+'87'+
  '6702a000b1755168';
export const ESCROW_P2WSH='0020'+shaHex(ESCROW_SCRIPT);

const providerWitness=[RESPONSE_TOKEN,'01',CERTIFICATE,ESCROW_SCRIPT];
const timeoutWitness=['',CERTIFICATE,ESCROW_SCRIPT];

function baseTransaction({branch='provider',lockTime=branch==='provider'?0:FORFEIT_HEIGHT,
                           witness=branch==='provider'?providerWitness:timeoutWitness}={}) {
  const payout=branch==='provider'?PROVIDER_PAYOUT_SCRIPT:CHALLENGER_PAYOUT_SCRIPT;
  return {
    version:2,lockTime,
    vin:[
      {prevTxid:BOND.txid,prevVout:BOND.vout,scriptSig:'',sequence:0xfffffffe,witness:[...witness]},
      {prevTxid:GUARDIAN.txid,prevVout:GUARDIAN.vout,scriptSig:'',sequence:0xfffffffe,witness:[]}
    ],
    vout:[
      {valueSats:0n,scriptPubKey:'6a20'+CERTIFICATE_SHA256},
      {valueSats:150000n,scriptPubKey:payout}
    ]
  };
}
function preSignGuardian(tx){
  // SIGHASH_ALL binds both input prevouts, all outputs, nLockTime, and
  // relevant sequences, while the bond witness remains outside legacy sighash.
  const sighash=legacySignatureHash(tx,1,GUARDIAN_SCRIPT,1);
  const z=displayHashToZ(sighash);
  const r=mod(multiply(GUARDIAN_NONCE).x,N);
  let s=mod(inverse(GUARDIAN_NONCE,N)*(z+r*GUARDIAN_PRIVATE),N);
  if(s>N/2n)s=N-s;
  const scriptSig=encodePushData(encodeBitcoinSignature(r,s,1));
  return changeInput(tx,1,{scriptSig});
}
export function fixedPayoutSamples(){
  const provider=preSignGuardian(baseTransaction());
  const forfeit=preSignGuardian(baseTransaction({branch:'forfeit'}));
  const providerLate=preSignGuardian(baseTransaction({lockTime:FORFEIT_HEIGHT+5}));
  return {provider,forfeit,providerLate};
}
const row=(name,tx,bondValid,guardianValid,reason)=>({
  name,tx_hex:serializeTransaction(tx,true).toString('hex'),
  stripped_tx_hex:serializeTransaction(tx,false).toString('hex'),
  txid:transactionId(tx),wtxid:witnessTransactionId(tx),
  expected_valid:bondValid&&guardianValid,
  expected_inputs:[
    {input_index:0,expected_valid:bondValid},
    {input_index:1,expected_valid:guardianValid}
  ],reason
});
export function fixedPayoutConsensusVectors(){
  const {provider,forfeit,providerLate}=fixedPayoutSamples();
  const withWitness=(tx,witness)=>changeInput(tx,0,{witness:[...witness]});
  const wrongAnswer=withWitness(provider,[WRONG_RESPONSE,'01',CERTIFICATE,ESCROW_SCRIPT]);
  const absentAnswer=withWitness(provider,['','01',CERTIFICATE,ESCROW_SCRIPT]);
  const wrongCertificate=withWitness(provider,[RESPONSE_TOKEN,'01',OTHER_CERTIFICATE,ESCROW_SCRIPT]);
  const alteredScript='a820'+shaHex(OTHER_CERTIFICATE)+'88'+ESCROW_SCRIPT.slice(70);
  const wrongScript=withWitness(provider,[RESPONSE_TOKEN,'01',OTHER_CERTIFICATE,alteredScript]);
  const reroutedProvider=changeOutput(provider,1,{scriptPubKey:CHALLENGER_PAYOUT_SCRIPT});
  const shavedProvider=changeOutput(provider,1,{valueSats:1n});
  const providerResignedRedirect=preSignGuardian(reroutedProvider);
  const changedCommit=changeOutput(provider,0,{scriptPubKey:'6a20'+shaHex(OTHER_CERTIFICATE)});
  const changedGuardian=changeInput(provider,1,{prevTxid:ID('dc')});
  const changedBond=changeInput(provider,0,{prevTxid:ID('ef')});
  const addedFee={...provider,vin:[...provider.vin,{prevTxid:ID('f1'),prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]}]};
  const earlyForfeit=preSignGuardian({...forfeit,lockTime:FORFEIT_HEIGHT-1});
  const finalSequenceForfeit=preSignGuardian(changeInput(forfeit,0,{sequence:0xffffffff}));
  const reroutedForfeit=changeOutput(forfeit,1,{scriptPubKey:PROVIDER_PAYOUT_SCRIPT});
  const shavedForfeit=changeOutput(forfeit,1,{valueSats:1n});
  const strayForfeit=withWitness(forfeit,[RESPONSE_TOKEN,'',CERTIFICATE,ESCROW_SCRIPT]);
  const providerClaimsTimeout=withWitness(provider,['',CERTIFICATE,ESCROW_SCRIPT]);
  return {
    schema:'bsb/unfunded-multi-script-vectors/v1',
    checks:[
      {input_index:0,script_pub_key:ESCROW_P2WSH,spent_output_amount_sats:Number(BOND.amount)},
      {input_index:1,script_pub_key:GUARDIAN_SCRIPT,spent_output_amount_sats:Number(GUARDIAN.amount)}
    ],
    warning:'STATIC CERTIFICATE AND MOCK HASHLOCK. Offline Core verifies scripts per input only; no sound BitVM/chainwork proof, no funded UTXOs, no block-height check or upper-bound response clock.',
    facts:{
      certificate:CERTIFICATE,
      certificateDigest:CERTIFICATE_SHA256,
      mockResponseDigest:RESPONSE_SHA256,
      guardianSighashType:1,
      fixedBondPrevout:BOND.txid+':'+BOND.vout,
      fixedGuardianPrevout:GUARDIAN.txid+':'+GUARDIAN.vout,
      providerPayoutScript:PROVIDER_PAYOUT_SCRIPT,
      challengerPayoutScript:CHALLENGER_PAYOUT_SCRIPT,
      escrowScript:ESCROW_SCRIPT,
      forfeitHeight:FORFEIT_HEIGHT,
      modeledEarliestForfeitConfirmationHeight:FORFEIT_HEIGHT+1,
      providerTxid:transactionId(provider),
      wrongCertificateTxid:transactionId(wrongCertificate),
      providerWtxid:witnessTransactionId(provider),
      wrongCertificateWtxid:witnessTransactionId(wrongCertificate),
      forfeitTxid:transactionId(forfeit),
      providerPayoutValueSats:'150000',
      forfeitPayoutValueSats:'150000',
      fixedFeeSats:'4000',
      guardianSecretPublicInTest:true
    },
    cases:[
      row('fixed-provider-with-mock-response',provider,true,true,'certificate and mock response hash checks pass'),
      row('fixed-provider-wrong-response',wrongAnswer,false,true,'provider lacks correct response preimage'),
      row('fixed-provider-empty-response',absentAnswer,false,true,'empty answer cannot satisfy SHA256 gate'),
      row('fixed-provider-wrong-certificate',wrongCertificate,false,true,'certificate hash mismatch in common P2WSH condition'),
      row('fixed-provider-altered-witness-program',wrongScript,false,true,'witnessScript cannot be substituted to match alternate certificate'),
      row('fixed-provider-redirected-payout',reroutedProvider,true,false,'pre-signed ALL guardian protects recipient'),
      row('fixed-provider-resigned-redirect-with-public-test-key',providerResignedRedirect,true,true,'negative control: retained guardian secret can reauthorize a malicious payout'),
      row('fixed-provider-reduced-payout',shavedProvider,true,false,'pre-signed ALL guardian protects amount'),
      row('fixed-provider-mutated-claim-commitment',changedCommit,true,false,'pre-signed ALL guardian protects OP_RETURN digest'),
      row('fixed-provider-changed-guardian-prevout',changedGuardian,true,false,'ALL guardian binds its spent outpoint'),
      row('fixed-provider-changed-bond-prevout',changedBond,true,false,'ALL guardian binds bond input as well'),
      row('fixed-provider-added-fee-input',addedFee,true,false,'ALL signature binds complete input set; no sponsorship flexibility'),
      row('fixed-timeout-forfeit-to-challenger',forfeit,true,true,'CLTV lower-bound branch and protected challenger payout'),
      row('fixed-timeout-before-cltv-with-fresh-guardian',earlyForfeit,false,true,'nLockTime 159 less than CLTV 160'),
      row('fixed-timeout-final-sequence-with-fresh-guardian',finalSequenceForfeit,false,true,'bond input final sequence disables CLTV branch'),
      row('fixed-timeout-redirected-payout',reroutedForfeit,true,false,'pre-signed forfeit guardian protects output recipient'),
      row('fixed-timeout-reduced-payout',shavedForfeit,true,false,'pre-signed forfeit guardian protects amount'),
      row('fixed-timeout-extra-stack-item',strayForfeit,false,true,'native witness cleanstack rejects unused answer'),
      row('fixed-provider-cannot-switch-to-timeout-before-cltv',providerClaimsTimeout,false,true,'original provider tx has nLockTime 0'),
      row('fixed-provider-late-response-still-script-valid',providerLate,true,true,'shows absence of upper deadline in the provider Script branch')
    ]
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href){
  console.log(JSON.stringify(fixedPayoutConsensusVectors(),null,2));
}