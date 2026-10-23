/**
 * Consensus-level negative control: an independent CLTV provider refund path.
 *
 * Unfunded representative scripts and public test key, not the unavailable
 * Phase 7 Bitcoin Core mining fixture or a deployed Taproot leaf.
 *
 * Core checks BOTH Script inputs; an admission journal is external to this tx.
 * The experiment asks whether a valid provider refund becomes Script-invalid
 * merely because a stronger certificate was published elsewhere. It does not.
 */
import {createHash} from 'node:crypto';
import {legacySignatureHash,encodePushData} from './legacy_sighash.mjs';
import {N,mod,inverse,multiply,pubkey,encodeBitcoinSignature,displayHashToZ} from './secp256k1_legacy_demo.mjs';
import {serializeTransaction,transactionId,witnessTransactionId} from './txid_admission.mjs';
import {p2wshScriptPubKey,witnessScript} from './witness_anchor.mjs';

const ID = byte => byte.repeat(32);
const D = 2n;
const K = 7n;
const SIGHASH_ALL_ANYONECANPAY = 0x81;
const PUB = pubkey(multiply(D));
// Minimal signed-magnitude ScriptNum 150 is 0x9600: <150> CLTV DROP <pub> CHECKSIG.
export const PROVIDER_REFUND_SCRIPT = '029600b175' + encodePushData(PUB) + 'ac';
export const REFUND_BOND = Object.freeze({txid:ID('11'),vout:0,amount:149000n});
export const REFUND_FEE_INPUT = Object.freeze({txid:ID('22'),vout:0,amount:5000n});
export const INDEPENDENT_JOURNAL_FUND = Object.freeze({txid:ID('33'),vout:0,amount:10000n});
const certificateTag = label => createHash('sha256')
  .update('BSB/UNFUNDED-REFUND-CONTEXT/TAG-ONLY\0' + label).digest('hex');

const changeInput=(tx,index,patch)=>({...tx,vin:tx.vin.map((v,i)=>i===index?{...v,...patch}:v)});
const changeOutput=(tx,index,patch)=>({...tx,vout:tx.vout.map((v,i)=>i===index?{...v,...patch}:v)});

function providerSign(tx) {
  const digest=legacySignatureHash(tx,0,PROVIDER_REFUND_SCRIPT,SIGHASH_ALL_ANYONECANPAY);
  const z=displayHashToZ(digest);
  const r=mod(multiply(K).x,N);
  let s=mod(inverse(K,N)*(z+r*D),N);
  if(s>N/2n)s=N-s;
  const sig=encodePushData(encodeBitcoinSignature(r,s,SIGHASH_ALL_ANYONECANPAY));
  return changeInput(tx,0,{scriptSig:sig});
}
function baseRefund(witnessHex) {
  return {
    version:2,lockTime:150,
    vin:[
      {prevTxid:REFUND_BOND.txid,prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]},
      {prevTxid:REFUND_FEE_INPUT.txid,prevVout:0,scriptSig:'',sequence:0xfffffffe,
        witness:[witnessHex,witnessScript]}
    ],
    vout:[{valueSats:148000n,scriptPubKey:encodePushData(PUB)+'ac'}]
  };
}
export function providerRefundSamples() {
  const weak=providerSign(baseRefund(certificateTag('weak-100')));
  const strong=changeInput(weak,1,{witness:[certificateTag('strong-151'),witnessScript]});
  const huge=changeInput(weak,1,{witness:['ee'.repeat(520),witnessScript]});
  return {weak,strong,huge};
}
const row=(name,tx,refundValid=true,feeValid=true,context='')=>({
  name,
  tx_hex:serializeTransaction(tx,true).toString('hex'),
  stripped_tx_hex:serializeTransaction(tx,false).toString('hex'),
  txid:transactionId(tx),
  wtxid:witnessTransactionId(tx),
  context,
  expected_valid:refundValid&&feeValid,
  expected_inputs:[
    {input_index:0,expected_valid:refundValid},
    {input_index:1,expected_valid:feeValid}
  ]
});
export function refundBypassConsensusVectors() {
  const {weak,strong,huge}=providerRefundSamples();
  const sponsorSwapped=changeInput(strong,1,{prevTxid:ID('44')});
  const outputRedirected=changeOutput(strong,0,{scriptPubKey:'51'});
  const outputDevalued=changeOutput(strong,0,{valueSats:1n});
  const cltvNotMet=providerSign({...strong,lockTime:149});
  const finalSequence=providerSign(changeInput(strong,0,{sequence:0xffffffff}));
  const noProviderSignature=changeInput(strong,0,{scriptSig:''});
  const wrongBondPrevout=changeInput(strong,0,{prevTxid:ID('55')});
  return {
    schema:'bsb/unfunded-multi-script-vectors/v1',
    checks:[
      {input_index:0,script_pub_key:PROVIDER_REFUND_SCRIPT,spent_output_amount_sats:Number(REFUND_BOND.amount)},
      {input_index:1,script_pub_key:p2wshScriptPubKey,spent_output_amount_sats:Number(REFUND_FEE_INPUT.amount)}
    ],
    warning:'Unfunded, synthetic outpoints, representative CLTV P2PK path, public private key and certificate TAGS only. Script verification does not check journal history, chain inclusion or exact work.',
    facts:{
      bondPrevout:REFUND_BOND.txid+':0',
      journalFundPrevout:INDEPENDENT_JOURNAL_FUND.txid+':0',
      oldRefundCltvHeight:150,
      expectedEarliestConfirmationHeight:151,
      signedInputCount:2,
      refundInputIndex:0,
      sponsoredInputIndex:1,
      sighashType:SIGHASH_ALL_ANYONECANPAY,
      weakTxid:transactionId(weak),
      strongerTxid:transactionId(strong),
      weakWtxid:witnessTransactionId(weak),
      strongerWtxid:witnessTransactionId(strong),
      providerSignatureUnchanged:weak.vin[0].scriptSig===strong.vin[0].scriptSig,
      noJournalCursorInput:strong.vin.every(v=>v.prevTxid!==INDEPENDENT_JOURNAL_FUND.txid)
    },
    cases:[
      row('provider-refund-weak-certificate-tag',weak,true,true,'journal external'),
      row('provider-refund-strong-151-certificate-tag',strong,true,true,'strong is a tag, not a verified 151-header certificate'),
      row('provider-refund-after-external-weak-to-strong-journal',strong,true,true,'the prior challenge history is invisible to Script and leaves refund bytes unchanged'),
      row('provider-refund-max-size-witness-tag',huge,true,true,'520-byte native v0 witness stack item'),
      row('provider-refund-swapped-fee-input',sponsorSwapped,true,true,'provider signature has ANYONECANPAY'),
      row('provider-refund-redirected-payout',outputRedirected,false,true,'SIGHASH_ALL protects output script'),
      row('provider-refund-devalued-payout',outputDevalued,false,true,'SIGHASH_ALL protects payout amount'),
      row('provider-refund-re-signed-under-CLTV',cltvNotMet,false,true,'locktime 149 fails the CLTV 150 requirement'),
      row('provider-refund-re-signed-with-final-sequence',finalSequence,false,true,'CLTV requires a non-final sequence'),
      row('provider-refund-without-provider-signature',noProviderSignature,false,true,'provider CHECKSIG enforces its key'),
      row('provider-refund-changed-bond-prevout',wrongBondPrevout,false,true,'provider signature commits to its own outpoint')
    ]
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(refundBypassConsensusVectors(),null,2));