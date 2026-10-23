/**
 * ADR-009 negative control: ADR-008's guardian is an OPTIONAL second input.
 * Its independent P2WSH bond script checks certificate/answer, but does not
 * require a guardian prevout or sign the payout.
 *
 * All fixtures are UNFUNDED. A witness with the publicly known mock answer
 * may spend the bond ALONE to an arbitrary output. This is consensus Script-
 * valid even when a different two-input template was pre-signed elsewhere.
 */
import {encodePushData} from './legacy_sighash.mjs';
import {pubkey,multiply} from './secp256k1_legacy_demo.mjs';
import {serializeTransaction,transactionId,witnessTransactionId} from './txid_admission.mjs';
import {
  BOND,CERTIFICATE,OTHER_CERTIFICATE,RESPONSE_TOKEN,WRONG_RESPONSE,
  ESCROW_SCRIPT,ESCROW_P2WSH,FORFEIT_HEIGHT
} from './fixed_payout_consensus_vectors.mjs';

export const BYPASS_PAYOUT=encodePushData(pubkey(multiply(23n)))+'ac';
const make=(name,{branch='provider',certificate=CERTIFICATE,answer=RESPONSE_TOKEN,
                      lockTime=branch==='provider'?0:FORFEIT_HEIGHT,
                      outputScript=BYPASS_PAYOUT,outputValue=148000n}={},expected=true)=>{
  const witness=branch==='provider'
    ?[answer,'01',certificate,ESCROW_SCRIPT]
    :['',certificate,ESCROW_SCRIPT];
  const tx={
    version:2,lockTime,
    vin:[{prevTxid:BOND.txid,prevVout:BOND.vout,scriptSig:'',sequence:0xfffffffe,witness}],
    vout:[{valueSats:outputValue,scriptPubKey:outputScript}]
  };
  return {name,tx,expected_valid:expected,tx_hex:serializeTransaction(tx,true).toString('hex'),
    txid:transactionId(tx),wtxid:witnessTransactionId(tx)};
};
export function unguardedBondBypassVectors(){
  const spend=make('unguarded-provider-redirects-bond-alone');
  const theft=make('unguarded-provider-can-burn-bond-as-fee',
    {outputScript:'6a20'+'ef'.repeat(32),outputValue:0n});
  const timeout=make('unguarded-timeout-redirects-bond-alone',{branch:'timeout'});
  const early=make('unguarded-timeout-before-cltv',{branch:'timeout',lockTime:FORFEIT_HEIGHT-1},false);
  const wrong=make('unguarded-provider-wrong-response',{answer:WRONG_RESPONSE},false);
  const other=make('unguarded-provider-wrong-certificate',{certificate:OTHER_CERTIFICATE},false);
  const extra=make('unguarded-provider-with-unapproved-extra-output');
  extra.tx.vout.push({valueSats:0n,scriptPubKey:'6a20'+'aa'.repeat(32)});
  extra.tx_hex=serializeTransaction(extra.tx,true).toString('hex');
  extra.txid=transactionId(extra.tx);
  extra.wtxid=witnessTransactionId(extra.tx);
  const cases=[spend,theft,timeout,early,wrong,other,extra].map(({name,tx,expected_valid,tx_hex,txid,wtxid})=>({
    name,tx_hex,txid,wtxid,expected_valid
  }));
  return {
    schema:'bsb/unfunded-script-vectors/v1',
    input_index:0,script_pub_key:ESCROW_P2WSH,
    spent_output_amount_sats:Number(BOND.amount),
    warning:'ADVERSARIAL positive cases: bond-only direct spend bypasses optional external guardian. The public test response is not a BitVM proof.',
    facts:{
      bondPrevout:BOND.txid+':'+BOND.vout,
      independentGuardianRequiredByBondScript:false,
      stolenPayoutScript:BYPASS_PAYOUT,
      bondOnlyInputCount:1,
      bondOnlyProviderTxid:spend.txid,
      timeoutBondOnlyTxid:timeout.txid
    },
    cases
  };
}
export function unguardedBondBypassSamples(){
  return {
    directSpend:make('direct').tx,
    timeoutSpend:make('timeout',{branch:'timeout'}).tx
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(unguardedBondBypassVectors(),null,2));