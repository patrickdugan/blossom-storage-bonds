/**
 * Consensus-backed one-hop successor template experiment.
 *
 * With a fixed *current* prevout, a legacy P2PK ECDSA signature with
 * SIGHASH_SINGLE|ANYONECANPAY can pin the correspondingly indexed output,
 * leaving unrelated inputs and outputs available to a permissionless relay.
 *
 * This is an off-chain pre-authorization for ONE UTXO. It cannot authorize
 * the NEXT successor whose txid is unknown when signing, and it cannot check
 * header validity. Fixed test private keys, entirely UNFUNDED.
 */
import { legacySignatureHash,encodePushData } from './legacy_sighash.mjs';
import { serializeTransaction,transactionId } from './txid_admission.mjs';
import { N,mod,inverse,multiply,pubkey,encodeBitcoinSignature,displayHashToZ } from './secp256k1_legacy_demo.mjs';

const D=2n,K=7n;
const PUB=pubkey(multiply(D));
export const P2PK=encodePushData(PUB)+'ac';
const HASH_TYPE=0x83;
const X32=v=>v.repeat(32);
export function signOne(tx,script=P2PK,secret=D) {
  const digest=legacySignatureHash(tx,1,script,HASH_TYPE);
  const z=displayHashToZ(digest);
  const R=multiply(K);
  const r=mod(R.x,N);
  let s=mod(inverse(K,N)*(z+r*secret),N);
  if(s>N/2n)s=N-s;
  const signature=encodeBitcoinSignature(r,s,HASH_TYPE);
  return {...tx,vin:tx.vin.map((x,i)=>i===1?{...x,scriptSig:encodePushData(signature)}:x)};
}
function baseTransaction({sourceTxid=X32('55'),certificate='aa',sponsorTxid=X32('11'),successorScript=P2PK,successorValue=40000n}={}) {
  return {
    version:2,lockTime:0,
    vin:[
      {prevTxid:sponsorTxid,prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]},
      {prevTxid:sourceTxid,prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]}
    ],
    vout:[
      {valueSats:0n,scriptPubKey:'6a20'+certificate.repeat(32)},
      {valueSats:successorValue,scriptPubKey:successorScript},
      {valueSats:500n,scriptPubKey:'51'}
    ]
  };
}
function edit(tx,patch){return {...tx,...patch};}
function replaceOutput(tx,index,patch){
  return {...tx,vout:tx.vout.map((out,i)=>i===index?{...out,...patch}:out)};
}
function replaceInput(tx,index,patch){
  return {...tx,vin:tx.vin.map((input,i)=>i===index?{...input,...patch}:input)};
}
function vec(name,tx,expected_valid) {
  return {name,tx_hex:serializeTransaction(tx).toString('hex'),txid:transactionId(tx),expected_valid};
}
export function signedSingleSuccessorVectors() {
  const a=signOne(baseTransaction({certificate:'aa'}));
  const b=replaceOutput(a,0,{scriptPubKey:'6a20'+'bb'.repeat(32)});
  const sponsor=replaceInput(a,0,{prevTxid:X32('33')});
  const change=replaceOutput(a,2,{scriptPubKey:'52',valueSats:1200n});
  const robbed=replaceOutput(a,1,{scriptPubKey:'6a20'+'cc'.repeat(32)});
  const shaved=replaceOutput(a,1,{valueSats:1n});
  const wrongCursor=replaceInput(a,1,{prevTxid:X32('44')});
  const childA=signOne(baseTransaction({sourceTxid:transactionId(a),sponsorTxid:X32('66'),certificate:'cd'}));
  const childUsingB=replaceInput(childA,1,{prevTxid:transactionId(b)});
  const childUsingFresh=signOne(baseTransaction({sourceTxid:transactionId(b),sponsorTxid:X32('66'),certificate:'cd'}));

  return {
    schema:'bsb/unfunded-script-vectors/v1',
    input_index:1,
    script_pub_key:P2PK,
    spent_output_amount_sats:40000,
    security:'bare legacy P2PK single input verified only; test private scalar 2 is PUBLIC; no Bitcoin UTXO or proofs',
    finding:'Pre-signed output-1 protects successor for one known input. External certificate and sponsor mutations remain possible, but the next cursor needs a new signature tied to the first transaction txid.',
    relationships:{
      parentA:transactionId(a),
      parentB:transactionId(b),
      childAPrevout:childA.vin[1].prevTxid,
      childBPrevout:childUsingFresh.vin[1].prevTxid,
      aSuccessorScript:a.vout[1].scriptPubKey,
      bSuccessorScript:b.vout[1].scriptPubKey,
      aSuccessorValue:a.vout[1].valueSats.toString(),
      bSuccessorValue:b.vout[1].valueSats.toString(),
      certificateA:a.vout[0].scriptPubKey,
      certificateB:b.vout[0].scriptPubKey,
      sourcePrevout:a.vin[1].prevTxid
    },
    cases:[
      vec('signed-successor-template-A',a,true),
      vec('change-certificate-output-zero',b,true),
      vec('replace-unrelated-sponsor-input',sponsor,true),
      vec('change-unprotected-output-two',change,true),
      vec('redirect-protected-successor-output-one',robbed,false),
      vec('steal-protected-successor-amount',shaved,false),
      vec('replace-protected-current-cursor-input',wrongCursor,false),
      vec('presigned-next-generation-for-parent-A',childA,true),
      vec('stale-next-generation-signature-on-parent-B',childUsingB,false),
      vec('freshly-signed-next-generation-for-parent-B',childUsingFresh,true)
    ]
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(signedSingleSuccessorVectors(),null,2));
