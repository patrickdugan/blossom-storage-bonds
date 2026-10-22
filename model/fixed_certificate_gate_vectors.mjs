/**
 * ADR-007: consensus-enforced one-hop certificate-to-output gate.
 *
 * A fixed P2WSH witness script OP_SHA256 <digestA> OP_EQUAL enforces that the
 * certificate is exactly the PRESELECTED A (modulo SHA256 collision).
 * A legacy P2PK SIGHASH_ALL|ANYONECANPAY signature fixes BOTH output 0's
 * digest commitment and output 1's successor script/value. A separate
 * insecure toy Binohash signs the remaining non-witness transaction.
 *
 * All inputs/outpoints are fabricated; keys and toy puzzle parameters public.
 * This is a deliberately NON-permissionless, ONE-HOP control experiment.
 */
import {createHash} from 'node:crypto';
import {legacySignatureHash,encodePushData} from './legacy_sighash.mjs';
import {N,mod,inverse,multiply,encodeBitcoinSignature,displayHashToZ} from './secp256k1_legacy_demo.mjs';
import {P2PK} from './single_acp_successor_vectors.mjs';
import {compositeAnchoringSamples,BINOLOCK} from './composite_cursor_consensus_vectors.mjs';
import {dummyPool,solveToyBinohash} from './binohash_finddelete_poc.mjs';
import {serializeTransaction,transactionId,witnessTransactionId} from './txid_admission.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const rawHash=hex=>hash(Buffer.from(hex,'hex'));
const CERT_A='aa'.repeat(32);
const CERT_C='cc'.repeat(32);
const TYPE=0x81;
const D=2n,K=7n;
const ID=x=>x.repeat(32);
const changeInput=(tx,i,patch)=>({...tx,vin:tx.vin.map((v,j)=>j===i?{...v,...patch}:v)});
const changeOutput=(tx,i,patch)=>({...tx,vout:tx.vout.map((v,j)=>j===i?{...v,...patch}:v)});
const certificateScript=digest=>'a820'+digest+'87'; // OP_SHA256 PUSH32 OP_EQUAL
const witnessProgram=script=>'0020'+rawHash(script);
function guardAllOutputs(tx){
  const d=legacySignatureHash(tx,1,P2PK,TYPE);
  const z=displayHashToZ(d);
  const r=mod(multiply(K).x,N);
  let s=mod(inverse(K,N)*(z+r*D),N);
  if(s>N/2n)s=N-s;
  return changeInput(tx,1,{scriptSig:encodePushData(encodeBitcoinSignature(r,s,TYPE))});
}
const grind=tx=>solveToyBinohash({tx,pool:dummyPool(),inputIndex:2}).tx;

export function fixedCertificateGateSamples(){
  const script=certificateScript(rawHash(CERT_A));
  const original=compositeAnchoringSamples().a;
  // Replace the permissive OP_DROP witness with a fixed certificate hash gate.
  // Re-sign the cursor because the hash type now covers output 0 AND output 1.
  const withGate=changeInput(original,0,{witness:[CERT_A,script]});
  const blankCursor=changeInput(withGate,1,{scriptSig:''});
  const good=grind(guardAllOutputs(blankCursor));
  return {good,script,certificate:CERT_A,witnessProgram:witnessProgram(script)};
}
const caseRow=(name,tx,checks,description)=>({
  name,tx_hex:serializeTransaction(tx,true).toString('hex'),
  stripped_tx_hex:serializeTransaction(tx,false).toString('hex'),
  txid:transactionId(tx),wtxid:witnessTransactionId(tx),
  expected_valid:checks.every(x=>x),
  expected_inputs:checks.map((valid,i)=>({input_index:i,expected_valid:valid})),
  description
});
export function fixedCertificateGateVectors(){
  const {good,script,witnessProgram:program}=fixedCertificateGateSamples();
  const badWitness=changeInput(good,0,{witness:[CERT_C,script]});
  const otherScript=certificateScript(rawHash(CERT_C));
  const swappedScript=changeInput(good,0,{witness:[CERT_C,otherScript]});
  const shiftedCommit=changeOutput(good,0,{scriptPubKey:'6a20'+rawHash(CERT_C)});
  const regroundCommit=grind(shiftedCommit);
  const alteredSuccessor=grind(changeOutput(good,1,{scriptPubKey:'6a20'+ID('ff')}));
  const alteredValue=grind(changeOutput(good,1,{valueSats:1n}));
  const alteredBoth=grind(changeOutput(badWitness,0,{scriptPubKey:'6a20'+rawHash(CERT_C)}));
  const shiftedSponsor=changeInput(good,0,{prevTxid:ID('44')});
  const shiftedSponsorReground=grind(shiftedSponsor);
  return {
    schema:'bsb/unfunded-multi-script-vectors/v1',
    checks:[
      {input_index:0,script_pub_key:program,spent_output_amount_sats:1000},
      {input_index:1,script_pub_key:P2PK,spent_output_amount_sats:40000},
      {input_index:2,script_pub_key:BINOLOCK,spent_output_amount_sats:5000}
    ],
    warning:'Unfunded input-level Core Script only; fixed certificate A, publicly known guardian key, insecure toy Binohash; cannot admit arbitrary challenger certificates or validate chain work.',
    facts:{
      fixedCertificate:CERT_A,
      fixedCertificateSha256:rawHash(CERT_A),
      secondCertificateSha256:rawHash(CERT_C),
      fixedWitnessScript:script,
      spentP2wshScriptPubKey:program,
      commitmentScript:good.vout[0].scriptPubKey,
      protectedSuccessorScript:good.vout[1].scriptPubKey,
      protectedSuccessorAmount:good.vout[1].valueSats.toString(),
      guardianSighashType:TYPE,
      originalTxid:transactionId(good),
      substitutedWitnessTxid:transactionId(badWitness),
      originalWtxid:witnessTransactionId(good),
      substitutedWitnessWtxid:witnessTransactionId(badWitness)
    },
    cases:[
      caseRow('static-certificate-A-binds-witness-output-and-successor',good,[true,true,true],
        'P2WSH enforces fixed cert hash; pre-signed guardian fixes both outputs'),
      caseRow('static-gate-rejects-witness-certificate-C',badWitness,[false,true,true],
        'same txid, new wtxid; certificate does not match fixed SHA256 gate'),
      caseRow('static-gate-rejects-new-witness-script',swappedScript,[false,true,true],
        'changing verifier script changes witness program hash'),
      caseRow('static-commitment-mutation-unreground',shiftedCommit,[true,false,false],
        'guardian ALL signature and legacy Binohash both reject changed OP_RETURN'),
      caseRow('static-commitment-mutation-reground',regroundCommit,[true,false,true],
        'fresh Binohash does not bypass guardian ALL signature'),
      caseRow('static-successor-script-mutation-reground',alteredSuccessor,[true,false,true],
        'guardian rejects burned successor even with fresh Binohash'),
      caseRow('static-successor-value-mutation-reground',alteredValue,[true,false,true],
        'guardian rejects reduced successor amount even with fresh Binohash'),
      caseRow('static-mutate-both-certificate-and-commitment',alteredBoth,[false,false,true],
        'P2WSH rejects new cert and guardian rejects new output digest'),
      caseRow('static-change-fee-prevout-without-regrind',shiftedSponsor,[true,true,false],
        'guardian allows external input but Binohash must be regrinded'),
      caseRow('static-change-fee-prevout-and-regrind',shiftedSponsorReground,[true,true,true],
        'unrelated sponsor can contribute fees without provider new signature')
    ]
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(fixedCertificateGateVectors(),null,2));