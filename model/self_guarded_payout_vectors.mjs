/**
 * ADR-009 repair candidate: the pre-signed ALL guardian authorization is part
 * of the BOND'S OWN P2WSH witness script, so the bond cannot simply omit the
 * guardian input. The signature uses BIP143 SegWit-v0 digest hashing.
 *
 * Still bounded to a setup-selected certificate and mock response hashlock.
 * Requires secure destruction of setup signing key. It is neither BitVM
 * verification nor a dynamic permissionless fork challenge protocol.
 *
 * All UTXOs and private keys are fabricated/public research fixtures.
 */
import {createHash} from 'node:crypto';
import {compactSize,serializeTransaction,transactionId,witnessTransactionId} from './txid_admission.mjs';
import {encodePushData} from './legacy_sighash.mjs';
import {N,mod,inverse,multiply,pubkey,encodeBitcoinSignature} from './secp256k1_legacy_demo.mjs';
import {
  BOND,CERTIFICATE,OTHER_CERTIFICATE,RESPONSE_TOKEN,WRONG_RESPONSE,
  CERTIFICATE_SHA256,RESPONSE_SHA256,FORFEIT_HEIGHT,
  PROVIDER_PAYOUT_SCRIPT,CHALLENGER_PAYOUT_SCRIPT
} from './fixed_payout_consensus_vectors.mjs';

const sha256=b=>createHash('sha256').update(b).digest();
const sha256d=b=>sha256(sha256(b));
const shaHex=hex=>sha256(Buffer.from(hex,'hex')).toString('hex');
const u32=x=>{const b=Buffer.alloc(4);b.writeUInt32LE(x>>>0);return b;};
const u64=x=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(x));return b;};
const hx=x=>Buffer.from(x,'hex');
const prevout=i=>Buffer.concat([Buffer.from(hx(i.prevTxid)).reverse(),u32(i.prevVout)]);
const output=o=>{const script=hx(o.scriptPubKey);return Buffer.concat([u64(o.valueSats),compactSize(script.length),script]);};
const ID=x=>x.repeat(32);
const changeInput=(tx,k,patch)=>({...tx,vin:tx.vin.map((v,i)=>i===k?{...v,...patch}:v)});
const changeOutput=(tx,k,patch)=>({...tx,vout:tx.vout.map((v,i)=>i===k?{...v,...patch}:v)});

export const SPONSOR=Object.freeze({txid:ID('d4'),vout:0,amount:5000n,scriptPubKey:'51'});
const SIGNER_PRIVATE=19n; // PUBLIC TEST SCALAR - never a real key
const SIGNER_NONCE=29n; // PUBLIC, REUSED TEST NONCE - never production-safe
const PUBKEY=pubkey(multiply(SIGNER_PRIVATE));
// <setup-pubkey> OP_CHECKSIGVERIFY
// OP_SHA256 <certificate> OP_EQUALVERIFY
// OP_IF OP_SHA256 <mock-answer> OP_EQUAL
// OP_ELSE <160> CLTV DROP TRUE ENDIF
export const SELF_GUARDED_SCRIPT=
  encodePushData(PUBKEY)+'ad'+
  'a820'+CERTIFICATE_SHA256+'88'+
  '63a820'+RESPONSE_SHA256+'87'+
  '6702a000b1755168';
export const SELF_GUARDED_P2WSH='0020'+shaHex(SELF_GUARDED_SCRIPT);

/** Restricted BIP143 signing digest for native-v0 P2WSH SIGHASH_ALL (0x01).
 * No other flags, CODESEPARATOR, nested P2SH or Taproot are implemented. */
export function bip143AllDigest(tx,index,scriptCodeHex,spentAmount){
  if(!Number.isInteger(index)||index<0||index>=tx.vin.length)throw new RangeError('bad signed input index');
  if(!Number.isInteger(tx.version)||!Number.isInteger(tx.lockTime)||
     !Number.isInteger(spentAmount)&&typeof spentAmount!=='bigint')throw new TypeError('invalid tx metadata');
  const script=hx(scriptCodeHex);
  const input=tx.vin[index];
  const allPrevouts=sha256d(Buffer.concat(tx.vin.map(prevout)));
  const allSequences=sha256d(Buffer.concat(tx.vin.map(i=>u32(i.sequence))));
  const allOutputs=sha256d(Buffer.concat(tx.vout.map(output)));
  const preimage=Buffer.concat([
    u32(tx.version),allPrevouts,allSequences,
    prevout(input),compactSize(script.length),script,
    u64(spentAmount),u32(input.sequence),allOutputs,u32(tx.lockTime),u32(1)
  ]);
  return sha256d(preimage);
}
export function signSelfGuardedBond(tx) {
  const digest=bip143AllDigest(tx,0,SELF_GUARDED_SCRIPT,BOND.amount);
  const z=BigInt('0x'+digest.toString('hex'));
  const r=mod(multiply(SIGNER_NONCE).x,N);
  let s=mod(inverse(SIGNER_NONCE,N)*(z+r*SIGNER_PRIVATE),N);
  if(s>N/2n)s=N-s;
  const signature=encodeBitcoinSignature(r,s,1);
  const wit=tx.vin[0].witness;
  if(!wit||wit.length<2||wit[wit.length-1]!==SELF_GUARDED_SCRIPT)
    throw Error('expected prepared P2WSH witness and script');
  return changeInput(tx,0,{witness:[...wit.slice(0,-2),signature,SELF_GUARDED_SCRIPT]});
}
const providerWitness=[RESPONSE_TOKEN,'01',CERTIFICATE,'',SELF_GUARDED_SCRIPT];
const forfeitWitness=['',CERTIFICATE,'',SELF_GUARDED_SCRIPT];
function baseTransaction({branch='provider',lockTime=branch==='forfeit'?FORFEIT_HEIGHT:0}={}) {
  return {version:2,lockTime,
    vin:[
      {prevTxid:BOND.txid,prevVout:BOND.vout,scriptSig:'',sequence:0xfffffffe,
        witness:[...(branch==='provider'?providerWitness:forfeitWitness)]},
      {prevTxid:SPONSOR.txid,prevVout:SPONSOR.vout,scriptSig:'',sequence:0xfffffffe,witness:[]}
    ],
    vout:[
      {valueSats:0n,scriptPubKey:'6a20'+CERTIFICATE_SHA256},
      {valueSats:150000n,scriptPubKey:branch==='provider'?PROVIDER_PAYOUT_SCRIPT:CHALLENGER_PAYOUT_SCRIPT}
    ]
  };
}
export function selfGuardedSamples(){
  const provider=signSelfGuardedBond(baseTransaction());
  const forfeit=signSelfGuardedBond(baseTransaction({branch:'forfeit'}));
  const providerLate=signSelfGuardedBond(baseTransaction({lockTime:FORFEIT_HEIGHT+5}));
  return {provider,forfeit,providerLate};
}
const row=(name,tx,bondAccept,sponsorAccept,explanation)=>({
  name,tx_hex:serializeTransaction(tx,true).toString('hex'),
  stripped_tx_hex:serializeTransaction(tx,false).toString('hex'),
  txid:transactionId(tx),wtxid:witnessTransactionId(tx),
  expected_valid:bondAccept&&sponsorAccept,
  expected_inputs:[
    {input_index:0,expected_valid:bondAccept},
    {input_index:1,expected_valid:sponsorAccept}
  ],explanation
});
export function selfGuardedConsensusVectors(){
  const {provider,forfeit,providerLate}=selfGuardedSamples();
  const withWitness=(tx,w)=>changeInput(tx,0,{witness:[...w]});
  const w=provider.vin[0].witness;
  const otherCert=withWitness(provider,[w[0],w[1],OTHER_CERTIFICATE,w[3],w[4]]);
  const otherAnswer=withWitness(provider,[WRONG_RESPONSE,...w.slice(1)]);
  const emptyAnswer=withWitness(provider,['',...w.slice(1)]);
  const noAuthorization=withWitness(provider,[...w.slice(0,-2),'',SELF_GUARDED_SCRIPT]);
  const differentScript=withWitness(provider,[...w.slice(0,-1),'7551']);
  const payoutChange=changeOutput(provider,1,{scriptPubKey:CHALLENGER_PAYOUT_SCRIPT});
  const payoutReSigned=signSelfGuardedBond(payoutChange);
  const feeChange=changeOutput(provider,1,{valueSats:1n});
  const commitmentChange=changeOutput(provider,0,{scriptPubKey:'6a20'+'ee'.repeat(32)});
  const bondOnly={...provider,vin:[provider.vin[0]]};
  const forfeitBondOnly={...forfeit,vin:[forfeit.vin[0]]};
  const differentSponsor=changeInput(provider,1,{prevTxid:ID('e5')});
  const changedBond=changeInput(provider,0,{prevTxid:ID('b7')});
  const extraInput={...provider,vin:[...provider.vin,{
    prevTxid:ID('f6'),prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]
  }]};
  const earlyForfeit=signSelfGuardedBond({...forfeit,lockTime:FORFEIT_HEIGHT-1});
  const finalSeqForfeit=signSelfGuardedBond(changeInput(forfeit,0,{sequence:0xffffffff}));
  const forfeitureRedirect=changeOutput(forfeit,1,{scriptPubKey:PROVIDER_PAYOUT_SCRIPT});
  const forfeitureRedirectResigned=signSelfGuardedBond(forfeitureRedirect);
  return {
    schema:'bsb/unfunded-multi-script-vectors/v1',
    checks:[
      {input_index:0,script_pub_key:SELF_GUARDED_P2WSH,spent_output_amount_sats:Number(BOND.amount)},
      {input_index:1,script_pub_key:SPONSOR.scriptPubKey,spent_output_amount_sats:Number(SPONSOR.amount)}
    ],
    warning:'SELF-GUARDING P2WSH research fixture, public insecure signing key and nonce. Static cert and mock answer. libbitcoinconsensus is per-input only; no actual BitVM proof, funding, chainwork or enforceable response upper deadline.',
    facts:{
      version:'bsb/self-guarded/v1',
      selfGuardedP2wsh:SELF_GUARDED_P2WSH,
      script:SELF_GUARDED_SCRIPT,
      mockCertificateDigest:CERTIFICATE_SHA256,
      mockResponseDigest:RESPONSE_SHA256,
      guardedSighashType:1,
      guardingInputIndex:0,
      preSignedInputCount:2,
      setupSecretAvailableInTest:true,
      originalTxid:transactionId(provider),
      wrongCertificateTxid:transactionId(otherCert),
      originalWtxid:witnessTransactionId(provider),
      wrongCertificateWtxid:witnessTransactionId(otherCert),
      forfeitHeight:FORFEIT_HEIGHT
    },
    cases:[
      row('self-guard-provider-certificate-and-answer',provider,true,true,'good fixed certificate and mock response'),
      row('self-guard-wrong-answer',otherAnswer,false,true,'certificate matches but answer fails'),
      row('self-guard-empty-answer',emptyAnswer,false,true,'empty preimage fails answer SHA256'),
      row('self-guard-wrong-certificate',otherCert,false,true,'fixed certificate SHA256 equality fails'),
      row('self-guard-missing-setup-signature',noAuthorization,false,true,'CHECKSIGVERIFY is in the bond itself'),
      row('self-guard-witness-script-substitution',differentScript,false,true,'P2WSH witness program fixes script bytes'),
      row('self-guard-redirected-provider-payout',payoutChange,false,true,'BIP143 SIGHASH_ALL binds exact output script'),
      row('self-guard-provider-resigned-redirect-with-public-test-key',payoutReSigned,true,true,
        'retained setup key allows malicious payout, never deploy this fixture'),
      row('self-guard-shaved-provider-payout',feeChange,false,true,'BIP143 SIGHASH_ALL binds exact amount'),
      row('self-guard-mutated-opreturn',commitmentChange,false,true,'BIP143 SIGHASH_ALL binds output0 commitment'),
      row('self-guard-bond-only-detached-sponsor',bondOnly,false,false,'bond signature commits to the missing second input'),
      row('self-guard-timeout-only-detached-sponsor',forfeitBondOnly,false,false,'same protection covers forfeit branch'),
      row('self-guard-changed-sponsor',differentSponsor,false,true,'hashPrevouts and hashSequence bind fee source'),
      row('self-guard-changed-bond-outpoint',changedBond,false,true,'BIP143 signs the bond outpoint'),
      row('self-guard-added-input',extraInput,false,true,'BIP143 signed full input list'),
      row('self-guard-forfeit-after-cltv',forfeit,true,true,'nLockTime 160, nonfinal sequence, fixed challenger output'),
      row('self-guard-forfeit-before-cltv-resigned',earlyForfeit,false,true,'valid signature cannot waive CLTV'),
      row('self-guard-forfeit-final-sequence-resigned',finalSeqForfeit,false,true,'valid signature cannot waive BIP65 sequence requirement'),
      row('self-guard-forfeit-payout-redirect',forfeitureRedirect,false,true,'pre-signed payout restriction lives in the bond'),
      row('self-guard-forfeit-payout-resigned-with-test-key',forfeitureRedirectResigned,true,true,
        'retained setup key can redirect timeout payout too'),
      row('self-guard-provider-response-remains-valid-after-deadline',providerLate,true,true,
        'CLTV cannot enforce an upper bound on the provider response branch')
    ]
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(selfGuardedConsensusVectors(),null,2));