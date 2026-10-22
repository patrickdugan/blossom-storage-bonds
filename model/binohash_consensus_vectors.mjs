/**
 * Deterministic, UNFUNDED research vectors for Bitcoin Core script consensus.
 * Runs no node, mining, proof job or Binohash production grinding.
 *
 * Each fixture includes the bare legacy scriptPubKey for the input at index 1
 * and a raw serialization of the complete spending transaction. Other inputs
 * are arbitrary dummy prevouts because a single-input script verifier needs
 * no UTXO set. Success means input 1's SCRIPT evaluation, not full tx validity.
 *
 * Run: node model/binohash_consensus_vectors.mjs > /tmp/binohash-vectors.json
 */
import {solveToyBinohash,verifyToyScript,dummyPool,makeCarrierTx} from './binohash_finddelete_poc.mjs';
import {serializeTransaction,transactionId} from './txid_admission.mjs';

export function consensusVectors(){
  const pool=dummyPool();
  const s=solveToyBinohash({pool});
  const burned=solveToyBinohash({pool,tx:makeCarrierTx({output:'6a20'+'ab'.repeat(32)})});
  const orig=s.tx;
  const changeInput=(index,edit)=>({...orig,vin:orig.vin.map((v,i)=>i===index?edit(v):v)});
  const mutateSig=(sighashType)=>changeInput(1,v=>({...v,scriptSig:v.scriptSig.replace(s.puzzle.signature,s.puzzle.signature.slice(0,-2)+sighashType)}));
  const cases=[
    ['original-puzzle-succeeds',orig,true],
    ['reground-to-burn-cursor-successfully',burned.tx,true],
    ['redirect-settlement',{...orig,vout:[{...orig.vout[0],scriptPubKey:'52'}]},false],
    ['alter-output-value',{...orig,vout:[{...orig.vout[0],valueSats:9999n}]},false],
    ['change-sponsor-prevout',changeInput(0,v=>({...v,prevTxid:'ab'.repeat(32)})),false],
    ['change-carrier-prevout',changeInput(1,v=>({...v,prevTxid:'cd'.repeat(32)})),false],
    ['swap-sighash-all-to-acp',mutateSig('81'),false],
    ['add-second-output-disables-single-bug',{...orig,vout:[...orig.vout,{valueSats:0n,scriptPubKey:'51'}]},false],
    ['nonzero-multisig-dummy',changeInput(1,v=>({...v,scriptSig:'51'+v.scriptSig.slice(2)})),false],
  ];
  return {
    schema:'bsb/unfunded-script-vectors/v1',
    validation:'one input Script verification only, not transaction confirmation or UTXO spendability',
    input_index:1,script_pub_key:s.lockScript,spent_output_amount_sats:50000,
    toy_security:'80 choose 2, one short-signature puzzle, public dummy secrets; unsafe for funds',
    attack:'independent successful regrind to OP_RETURN burn output: a Binohash signature binds a chosen transaction but does not authorize its successor',
    signer_selection:s.pairIndices,
    cases:cases.map(([name,tx,expected_valid])=>({name,tx_hex:serializeTransaction(tx).toString('hex'),
      txid:transactionId(tx),expected_valid,model_valid:!name.includes('nonzero-multisig-dummy')?
        verifyToyScript(tx,s.lockScript).valid:false})),
  };
}
if(process.argv[1] && import.meta.url === new URL('file://'+process.argv[1]).href){
  console.log(JSON.stringify(consensusVectors(),null,2));
}
