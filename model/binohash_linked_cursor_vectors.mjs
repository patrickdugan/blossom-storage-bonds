/**
 * Offline Bitcoin Core libbitcoinconsensus vectors for a two-generation
 * Binohash "journal cursor" with a malicious alternate successor.
 *
 * Every transaction is deliberately UNFUNDED and legacy bare-script based.
 * The spent script is identical at all generations. Bitcoin Core verifies
 * one selected input, not UTXO existence, graph ancestry, miner policy,
 * exact-work proofs, or collateral settlement.
 */
import { dummyPool, makeLockingScript, makeCarrierTx, solveToyBinohash } from './binohash_finddelete_poc.mjs';
import { transactionId, serializeTransaction, witnessTransactionId } from './txid_admission.mjs';

const sha = value => value.repeat(32);
const POOL = dummyPool();
const LOCK = makeLockingScript(POOL);
const BURN = '6a20' + 'ab'.repeat(32);

function resolve({prev0,prev1,output=LOCK}) {
  return solveToyBinohash({ pool: POOL, tx: makeCarrierTx({prev0,prev1,output}) });
}
function replaceInput(tx,index,change) {
  return {...tx,vin:tx.vin.map((x,i)=>i===index?{...x,...change}:x)};
}
const vector = (name,tx,valid,extra={}) => ({
  name,
  tx_hex: serializeTransaction(tx,true).toString('hex'),
  txid: transactionId(tx),
  wtxid: witnessTransactionId(tx),
  expected_valid: valid,
  ...extra
});
export function linkedCursorConsensusVectors() {
  const j0 = resolve({prev0:sha('11'),prev1:sha('22')});
  const j1 = resolve({prev0:sha('33'),prev1:transactionId(j0.tx)});
  const j1Burn = resolve({prev0:sha('33'),prev1:transactionId(j0.tx),output:BURN});
  const j2 = resolve({prev0:sha('44'),prev1:transactionId(j1.tx)});

  // Same raw legacy Script signature remains valid if the certificate is placed
  // only in a different input's SegWit witness. This is a witness-blind field.
  // Both transactions have the same txid but different wtxid.
  const witnessOnly = replaceInput(j1.tx,0,{witness:['51'.repeat(80)]});
  const witnessOther = replaceInput(j1.tx,0,{witness:['52'.repeat(80)]});

  const alteredInput = replaceInput(j1.tx,1,{prevTxid:sha('55')});
  const ungroundedBurn = {...j1.tx,vout:j1Burn.tx.vout};

  return {
    schema: 'bsb/unfunded-script-vectors/v1',
    input_index:1,
    script_pub_key:LOCK,
    spent_output_amount_sats:10000,
    validation:'offline Script of input 1 only; source outpoints and funds are fabricated',
    attack:'A fresh valid signature can consume J0 into a burn output instead of an authorized J1, with equal Bitcoin Script validity',
    chain: {
      initial:'22'.repeat(32)+':0',
      parent_txid: transactionId(j0.tx),
      first_successor_txid:transactionId(j1.tx),
      malicious_alternative_txid:transactionId(j1Burn.tx),
      second_successor_txid:transactionId(j2.tx),
      original_parent: j0.tx.vin[1].prevTxid,
      honest_successor_prevout: j1.tx.vin[1].prevTxid,
      malicious_successor_prevout: j1Burn.tx.vin[1].prevTxid,
      later_successor_prevout: j2.tx.vin[1].prevTxid,
      parent_script_pub_key:LOCK,
      successor_script_pub_key:j0.tx.vout[0].scriptPubKey,
      malicious_script_pub_key:j1Burn.tx.vout[0].scriptPubKey,
      honest_script_pub_key:j1.tx.vout[0].scriptPubKey
    },
    cases:[
      vector('cursor-J0-creates-J1-like-output',j0.tx,true),
      vector('honest-cursor-J1-rearms-script',j1.tx,true),
      vector('stronger-cursor-J2-rearms-script',j2.tx,true),
      vector('malicious-challenger-burns-J1',j1Burn.tx,true),
      vector('unreground-output-replacement-is-rejected',ungroundedBurn,false),
      vector('unreground-parent-prevout-substitution-is-rejected',alteredInput,false),
      vector('witness-only-certificate-A-passes',witnessOnly,true),
      vector('witness-only-certificate-B-passes',witnessOther,true),
    ]
  };
}
if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1]).href)
  console.log(JSON.stringify(linkedCursorConsensusVectors(),null,2));
