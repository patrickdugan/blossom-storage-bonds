/**
 * ADR-010: One-input, self-guarding, pre-signed escrow candidate.
 *
 * Removes ADR-009's externally spendable OP_TRUE sponsor UTXO. Both mutually
 * exclusive payouts spend ONLY the P2WSH bond and carry a BIP143 SIGHASH_ALL
 * signature checked inside that bond's own witness script.
 *
 * No external guardian/sponsor is needed to enforce the example payout. Fee
 * adjustment is restricted by the fixed signature and script. The certificate
 * and mock answer are still preselected, and no dynamic work or BitVM proof
 * is verified. Public key and signature-generation secret are TEST-ONLY.
 */
import {serializeTransaction,transactionId,witnessTransactionId} from './txid_admission.mjs';
import {
  BOND,CERTIFICATE,OTHER_CERTIFICATE,RESPONSE_TOKEN,WRONG_RESPONSE,
  CERTIFICATE_SHA256,FORFEIT_HEIGHT,PROVIDER_PAYOUT_SCRIPT,
  CHALLENGER_PAYOUT_SCRIPT
} from './fixed_payout_consensus_vectors.mjs';
import {
  SELF_GUARDED_SCRIPT,SELF_GUARDED_P2WSH,signSelfGuardedBond
} from './self_guarded_payout_vectors.mjs';
import {selfGuardedSamples} from './self_guarded_payout_vectors.mjs';

const changeWitness=(tx,witness)=>({...tx,vin:tx.vin.map((v,i)=>i===0?{...v,witness}:v)});
const changeOutput=(tx,k,patch)=>({...tx,vout:tx.vout.map((v,i)=>i===k?{...v,...patch}:v)});
const changeBond=(tx,patch)=>({...tx,vin:tx.vin.map((v,i)=>i===0?{...v,...patch}:v)});
const ID=hex=>hex.repeat(32);

function oneInput(twoInputTx){
  // The original signature is invalid when a sponsor is removed. Re-sign in
  // the setup phase, before destroying the assumed signing key.
  const tx={
    ...twoInputTx,
    vin:[{...twoInputTx.vin[0]}],
    vout:twoInputTx.vout.map((v,i)=>i===1?{...v,valueSats:148000n}:v)
  };
  return signSelfGuardedBond(tx);
}
export function oneInputSamples(){
  const variants=selfGuardedSamples();
  return {
    provider:oneInput(variants.provider),
    forfeit:oneInput(variants.forfeit),
    providerLate:oneInput(variants.providerLate)
  };
}
const row=(name,tx,valid,explanation)=>({
  name,tx_hex:serializeTransaction(tx,true).toString('hex'),
  stripped_tx_hex:serializeTransaction(tx,false).toString('hex'),
  txid:transactionId(tx),wtxid:witnessTransactionId(tx),
  expected_valid:valid,explanation
});
export function oneInputSelfGuardedVectors(){
  const {provider,forfeit,providerLate}=oneInputSamples();
  const w=provider.vin[0].witness;
  const otherCert=changeWitness(provider,[w[0],w[1],OTHER_CERTIFICATE,w[3],w[4]]);
  const wrongAnswer=changeWitness(provider,[WRONG_RESPONSE,...w.slice(1)]);
  const emptyAnswer=changeWitness(provider,['',...w.slice(1)]);
  const wrongProgram=changeWitness(provider,[...w.slice(0,-1),'7551']);
  const missingSig=changeWitness(provider,[...w.slice(0,-2),'',SELF_GUARDED_SCRIPT]);
  const redirected=changeOutput(provider,1,{scriptPubKey:CHALLENGER_PAYOUT_SCRIPT});
  const redirectedReSigned=signSelfGuardedBond(redirected);
  const shaved=changeOutput(provider,1,{valueSats:1n});
  const changedCommit=changeOutput(provider,0,{scriptPubKey:'6a20'+ID('ff')});
  const unrelatedSponsor={...provider,vin:[...provider.vin,{
    prevTxid:ID('44'),prevVout:0,sequence:0xfffffffe,scriptSig:'',witness:[]
  }]};
  const changedBond=changeBond(provider,{prevTxid:ID('de')});
  const tooEarly=signSelfGuardedBond({...forfeit,lockTime:FORFEIT_HEIGHT-1});
  const finalSeq=signSelfGuardedBond(changeBond(forfeit,{sequence:0xffffffff}));
  const divertedTimeout=changeOutput(forfeit,1,{scriptPubKey:PROVIDER_PAYOUT_SCRIPT});
  const timeoutWrongCertificate=changeWitness(forfeit,['',OTHER_CERTIFICATE,...forfeit.vin[0].witness.slice(2)]);
  const feeBurnReSigned=signSelfGuardedBond(changeOutput(provider,1,{valueSats:0n,
    scriptPubKey:'6a20'+'ab'.repeat(32)}));
  return {
    schema:'bsb/unfunded-script-vectors/v1',
    input_index:0,script_pub_key:SELF_GUARDED_P2WSH,
    spent_output_amount_sats:Number(BOND.amount),
    warning:'No sponsor needed. Fixed setup pre-signatures and SHA256 mock answer, public insecure signer. Core Script only: no work proof, dynamic cert, funded spend, actual height or timely response upper bound.',
    facts:{
      inputCount:1,
      bondPrevout:BOND.txid+':0',
      bondScript:SELF_GUARDED_SCRIPT,
      noSponsorInput:true,
      providerPayoutScript:PROVIDER_PAYOUT_SCRIPT,
      challengerPayoutScript:CHALLENGER_PAYOUT_SCRIPT,
      payoutSats:'148000',
      feeSats:'1000',
      setupKeyPublicForResearch:true,
      mockCertificateDigest:CERTIFICATE_SHA256,
      forfeitHeight:FORFEIT_HEIGHT,
      providerTxid:transactionId(provider),
      witnessModifiedTxid:transactionId(otherCert),
      providerWtxid:witnessTransactionId(provider),
      witnessModifiedWtxid:witnessTransactionId(otherCert)
    },
    cases:[
      row('single-bond-provider-with-correct-mock-opening',provider,true,'pre-signed bond authorizes provider payout'),
      row('single-bond-wrong-response',wrongAnswer,false,'mock response hash mismatch'),
      row('single-bond-empty-response',emptyAnswer,false,'empty answer fails hash'),
      row('single-bond-wrong-certificate',otherCert,false,'certificate digest fixed in script'),
      row('single-bond-replaced-script',wrongProgram,false,'P2WSH program hash binds witness script'),
      row('single-bond-missing-signature',missingSig,false,'bond CHECKSIGVERIFY required'),
      row('single-bond-redirected-payout',redirected,false,'pre-signed bond signature fixes destination'),
      row('single-bond-redirect-resigned-with-public-fixture-key',redirectedReSigned,true,
        'retained setup key defeats payout restriction'),
      row('single-bond-shaved-payout',shaved,false,'pre-signed bond signature fixes satoshis'),
      row('single-bond-mutated-opreturn',changedCommit,false,'pre-signed bond signature fixes certificate commitment output'),
      row('single-bond-appended-sponsor',unrelatedSponsor,false,'SIGHASH_ALL rejects extra input'),
      row('single-bond-changed-prevout',changedBond,false,'SIGHASH_ALL commits to bond outpoint'),
      row('single-bond-timeout-forfeit',forfeit,true,'same bond, separate pre-signed challenger payout after CLTV'),
      row('single-bond-timeout-before-cltv-resigned',tooEarly,false,'CLTV threshold enforced with valid signature'),
      row('single-bond-timeout-final-sequence-resigned',finalSeq,false,'CLTV sequence enforced with valid signature'),
      row('single-bond-timeout-redirected-payout',divertedTimeout,false,'challenger destination bound by signature'),
      row('single-bond-timeout-wrong-certificate',timeoutWrongCertificate,false,'shared certificate gate applies to both branches'),
      row('single-bond-response-still-valid-after-timeout',providerLate,true,
        'valid proof preimage can still race with forfeit after deadline'),
      row('single-bond-re-sign-to-burn-with-retained-key',feeBurnReSigned,true,
        'public test signer can burn almost all bond value by paying fees')
    ]
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(oneInputSelfGuardedVectors(),null,2));