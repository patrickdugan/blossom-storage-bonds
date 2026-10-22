/**
 * First concrete composite carrier experiment:
 *
 * Input 1: pre-signed P2PK SIGHASH_SINGLE|ANYONECANPAY cursor spend.
 *          Its signature commits exactly to output 1, preserving amount/script.
 * Input 2: toy Binohash FindAndDelete legacy bare Script, after final output.
 *          A fresh puzzle binds certificate in output 0, both prevouts and
 *          the locked cursor output. It is cheap, insecure, and only a demo.
 *
 * Assumes an existing, precisely-known current cursor outpoint, and
 * separately funded carrier/sponsor outpoints. All are fabricated; Bitcoin
 * Core only verifies Script for individually supplied inputs.
 * The next cursor txid is dynamic, so no recursive presignature exists.
 */
import {dummyPool,makeLockingScript,solveToyBinohash} from './binohash_finddelete_poc.mjs';
import {signOne,P2PK} from './single_acp_successor_vectors.mjs';
import {transactionId,serializeTransaction,witnessTransactionId} from './txid_admission.mjs';
import {p2wshScriptPubKey,witnessScript} from './witness_anchor.mjs';

const POOL=dummyPool();
export const BINOLOCK=makeLockingScript(POOL);
const ID=h=>h.repeat(32);
const OP_RETURN=hex=>'6a20'+hex.repeat(32);
const VALUE=40000n;

function txTemplate({certificate='aa',cursorPrev=ID('22'),sponsorPrev=ID('11'),cursorScript=P2PK,cursorValue=VALUE}={}) {
  const empty={version:2,lockTime:0,
    vin:[
      {prevTxid:sponsorPrev,prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[certificate.repeat(32),witnessScript]},
      {prevTxid:cursorPrev,prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]},
      {prevTxid:ID('33'),prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]}
    ],
    vout:[
      {valueSats:0n,scriptPubKey:OP_RETURN(certificate)},
      {valueSats:cursorValue,scriptPubKey:cursorScript},
    ]};
  return signOne(empty);
}
const setOut=(tx,i,changes)=>({...tx,vout:tx.vout.map((out,j)=>i===j?{...out,...changes}:out)});
const setIn=(tx,i,changes)=>({...tx,vin:tx.vin.map((input,j)=>i===j?{...input,...changes}:input)});
const grind=tx=>solveToyBinohash({tx,pool:POOL,inputIndex:2}).tx;
const vector=(name,tx,expect,perInput)=>({
  name,tx_hex:serializeTransaction(tx,true).toString('hex'),stripped_tx_hex:serializeTransaction(tx,false).toString('hex'),
  txid:transactionId(tx),wtxid:witnessTransactionId(tx),
  expected_valid:expect,expected_inputs:perInput
});
function inputResults(cursor,puzzle){
  return [{input_index:0,expected_valid:true},{input_index:1,expected_valid:cursor},{input_index:2,expected_valid:puzzle}];
}
export function compositeCursorConsensusVectors(){
  const a=grind(txTemplate({certificate:'aa'}));
  const b=grind(txTemplate({certificate:'bb'}));
  const certificateChanged=setOut(a,0,{scriptPubKey:OP_RETURN('cc')});
  const redirectedBase=setOut(a,1,{scriptPubKey:OP_RETURN('dd')});
  const redirected=grind(redirectedBase);
  const devalued=grind(setOut(a,1,{valueSats:1n}));
  const sponsorChanged=setIn(a,0,{prevTxid:ID('44')});
  const sponsorRegrind=grind(sponsorChanged);
  const oldCursorChanged=setIn(a,1,{prevTxid:ID('55')});
  const supplementalWitness=setIn(a,0,{witness:['42'.repeat(80),witnessScript]});
  const nextA=grind(txTemplate({certificate:'ee',cursorPrev:transactionId(a)}));
  const nextStale=setIn(nextA,1,{prevTxid:transactionId(b)});
  const nextB=grind(txTemplate({certificate:'ee',cursorPrev:transactionId(b)}));
  return {
    schema:'bsb/unfunded-multi-script-vectors/v1',
    checks:[
      {input_index:0,script_pub_key:p2wshScriptPubKey,spent_output_amount_sats:1000},
      {input_index:1,script_pub_key:P2PK,spent_output_amount_sats:Number(VALUE)},
      {input_index:2,script_pub_key:BINOLOCK,spent_output_amount_sats:5000}
    ],
    warning:'UNFUNDED input-level Script checks only; toy Binohash t=2 with no secure collision resistance',
    interpretation:'The two signatures jointly enforce one fixed cursor successor and bind an arbitrary certificate output. The presigned successor cannot be reused for unknown next-generation outpoints.',
    commitments:{
      initial_cursor_prevout:a.vin[1].prevTxid,
      first_a_txid:transactionId(a),
      first_b_txid:transactionId(b),
      next_a_cursor_prevout:nextA.vin[1].prevTxid,
      next_b_cursor_prevout:nextB.vin[1].prevTxid,
      output_a:a.vout[1].scriptPubKey,
      output_b:b.vout[1].scriptPubKey,
      first_a_sig:a.vin[1].scriptSig,
      first_b_sig:b.vin[1].scriptSig
    },
    cases:[
      vector('composite-challenger-A',a,true,inputResults(true,true)),
      vector('composite-challenger-B',b,true,inputResults(true,true)),
      vector('certificate-mutation-without-new-binohash',certificateChanged,false,inputResults(true,false)),
      vector('regrind-burn-at-protected-output',redirected,false,inputResults(false,true)),
      vector('regrind-steal-protected-cursor-value',devalued,false,inputResults(false,true)),
      vector('sponsor-mutation-without-regrind',sponsorChanged,false,inputResults(true,false)),
      vector('sponsor-mutation-with-fresh-binohash',sponsorRegrind,true,inputResults(true,true)),
      vector('cursor-prevout-mutation-without-new-signatures',oldCursorChanged,false,inputResults(false,false)),
      vector('unrelated-segwit-witness-uncaptured',supplementalWitness,true,inputResults(true,true)),
      vector('composite-next-cursor-signed-for-A',nextA,true,inputResults(true,true)),
      vector('composite-next-cursor-A-signature-on-B',nextStale,false,inputResults(false,false)),
      vector('composite-next-cursor-signed-for-B',nextB,true,inputResults(true,true)),
    ]
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(compositeCursorConsensusVectors(),null,2));
