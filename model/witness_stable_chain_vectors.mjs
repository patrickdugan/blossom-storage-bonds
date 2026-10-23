/**
 * Two-generation pre-signed cursor graph with witness-only certificate changes.
 *
 * Both generations have known txids because changing only witness contents
 * preserves txid. A pre-signed second-generation successor therefore remains
 * spendable after EITHER witness version of generation zero.
 *
 * This uses a known setup signature for each of two generations. It does NOT
 * establish that any witness certificate is valid or matches the fixed signed
 * OP_RETURN digest; those are separate BitVM acceptance requirements.
 *
 * All prevouts are fabricated; offline Core verifies scripts per input only.
 */
import {compositeAnchoringSamples,BINOLOCK} from './composite_cursor_consensus_vectors.mjs';
import {p2wshScriptPubKey,witnessScript,certificateSha256,syntheticWitnessBlock} from './witness_anchor.mjs';
import {signOne,P2PK} from './single_acp_successor_vectors.mjs';
import {solveToyBinohash,dummyPool} from './binohash_finddelete_poc.mjs';
import {serializeTransaction,transactionId,witnessTransactionId} from './txid_admission.mjs';

const ID=h=>h.repeat(32);
const pool=dummyPool();
const rewrite=(tx,index,changes)=>({...tx,vin:tx.vin.map((i,k)=>index===k?{...i,...changes}:i)});
const witnessVersion=(tx,hex)=>rewrite(tx,0,{witness:[hex.repeat(32),witnessScript]});
function stage2Template(a,b) {
  const tx=rewrite(b,1,{prevTxid:transactionId(a),prevVout:1,scriptSig:''});
  // In this RESEARCH fixture, authorizing keys are public constants.
  // Real trust model: this signature would need to be created BEFORE
  // genesis funding, while the stage0 txid is already known.
  const authorized=signOne(tx);
  return solveToyBinohash({tx:authorized,pool,inputIndex:2}).tx;
}
const vec=(name,tx,valid,inputs)=>({
  name,tx_hex:serializeTransaction(tx,true).toString('hex'),
  stripped_tx_hex:serializeTransaction(tx,false).toString('hex'),
  txid:transactionId(tx),wtxid:witnessTransactionId(tx),
  expected_valid:valid,
  expected_inputs:[{input_index:0,expected_valid:inputs[0]},
    {input_index:1,expected_valid:inputs[1]},
    {input_index:2,expected_valid:inputs[2]}]
});
export function witnessStableChainVectors(){
  const {a,b}=compositeAnchoringSamples();
  const aWitnessAltered=witnessVersion(a,'cc');
  const second=stage2Template(a,b);
  const secondWitnessAltered=witnessVersion(second,'dd');
  const changedPrevout=rewrite(second,1,{prevTxid:ID('66')});
  const secondBurn={...second,vout:second.vout.map((o,k)=>k===1?{...o,scriptPubKey:'6a20'+ID('ff')}:o)};
  const secondRegrindBurn=solveToyBinohash({tx:secondBurn,pool,inputIndex:2}).tx;
  return {
    schema:'bsb/unfunded-multi-script-vectors/v1',
    checks:[
      {input_index:0,script_pub_key:p2wshScriptPubKey,spent_output_amount_sats:1000},
      {input_index:1,script_pub_key:P2PK,spent_output_amount_sats:40000},
      {input_index:2,script_pub_key:BINOLOCK,spent_output_amount_sats:5000}
    ],
    witnessScript,
    warning:'fully unfunded; signatures use test public keys; certificates are arbitrary bytes, not work proofs',
    facts:{
      parentTxid:transactionId(a),parentAltTxid:transactionId(aWitnessAltered),
      parentWtxid:witnessTransactionId(a),parentAltWtxid:witnessTransactionId(aWitnessAltered),
      childPrevout:second.vin[1].prevTxid,childVout:second.vin[1].prevVout,
      childTxid:transactionId(second),childAltTxid:transactionId(secondWitnessAltered),
      childWtxid:witnessTransactionId(second),childAltWtxid:witnessTransactionId(secondWitnessAltered),
      parentCommittedHash:certificateSha256(a),
      parentAltCertificateHash:certificateSha256(aWitnessAltered),
      childCommittedHash:certificateSha256(second),
      childAltCertificateHash:certificateSha256(secondWitnessAltered),
      setupSignature:second.vin[1].scriptSig,
      witnessOnlyAlternateHasSameAuthorization:second.vin[1].scriptSig===stage2Template(aWitnessAltered,b).vin[1].scriptSig,
      syntheticParentAnchor:syntheticWitnessBlock(a).fakeBlock
    },
    cases:[
      vec('generation-0-certificate-A',a,true,[true,true,true]),
      vec('generation-0-witness-only-C',aWitnessAltered,true,[true,true,true]),
      vec('generation-1-certificate-B',second,true,[true,true,true]),
      vec('generation-1-witness-only-D',secondWitnessAltered,true,[true,true,true]),
      vec('generation-1-with-wrong-prevout',changedPrevout,false,[true,false,false]),
      vec('generation-1-regrind-for-burn',secondRegrindBurn,false,[true,false,true]),
    ]
  };
}
if(process.argv[1] && import.meta.url === new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(witnessStableChainVectors(),null,2));
