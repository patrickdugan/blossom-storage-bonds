/**
 * Portable authenticated BIP141 receipt, conditional on an authenticated
 * Bitcoin header and on chain-valid transaction/UTXO context.
 *
 * Unlike verifyWitnessCommitmentEvidence, this checks the claimed
 * coinbase reserved value and OP_RETURN commitment against the ACTUAL
 * serialized coinbase transaction whose txid is Merkle-included in the
 * header. It also recomputes the target's txid/wtxid from raw bytes.
 *
 * A valid receipt is a cryptographic inclusion statement. It does NOT
 * verify the active best chain, block proof of work, full transaction
 * consensus, or the storage-certificate verifier.
 */
import {createHash} from 'node:crypto';
import {parseTx} from '../layer1/onchain.ts';
import {proofIncludesTxid} from './bitcoin_merkleblock.mjs';
import {verifyWitnessCommitmentEvidence} from './bitcoin_witness_commitment.mjs';

const doubleSha=b=>createHash('sha256').update(
  createHash('sha256').update(b).digest()).digest();
const displayedHash=b=>Buffer.from(doubleSha(b)).reverse().toString('hex');
const requiredHex=(s,label)=>{
  if(typeof s!=='string'||s.length%2||!(/^[0-9a-f]+$/i.test(s)))
    throw Error('invalid serialized '+label+' hex');
  return Buffer.from(s,'hex');
};

/** Parse witness records and enforce canonical Bitcoin CompactSize lengths.
 * This supplements parseTx(), which deliberately returns stripped tx data
 * without a witness-stack collection. */
export function readCanonicalWitnessStacks(raw){
  if(!Buffer.isBuffer(raw)||raw.length<12)
    throw Error('truncated witness-bearing Bitcoin transaction');
  let off=0;
  function take(n){
    if(!Number.isSafeInteger(n)||n<0||off+n>raw.length)
      throw Error('truncated witness transaction');
    const x=raw.subarray(off,off+n);off+=n;return x;
  }
  function u8(){return take(1)[0];}
  function compact(){
    const k=u8();
    if(k<253)return k;
    if(k===253){
      const n=take(2).readUInt16LE(0);
      if(n<253)throw Error('noncanonical compactSize');
      return n;
    }
    if(k===254){
      const n=take(4).readUInt32LE(0);
      if(n<=65535)throw Error('noncanonical compactSize');
      return n;
    }
    const n=take(8).readBigUInt64LE(0);
    if(n<=0xffffffffn||n>BigInt(Number.MAX_SAFE_INTEGER))
      throw Error('unsupported large compactSize');
    return Number(n);
  }
  take(4); // version
  if(u8()!==0||u8()!==1)
    throw Error('serialized receipt requires canonical SegWit marker and flag');
  const count=compact();
  if(count<1||count>100_000)throw Error('bad witness transaction input count');
  for(let i=0;i<count;i++){
    take(36);take(compact());take(4);
  }
  const nOutputs=compact();
  if(nOutputs<1||nOutputs>100_000)throw Error('bad witness transaction output count');
  for(let i=0;i<nOutputs;i++){
    take(8);take(compact());
  }
  const stacks=[];
  for(let i=0;i<count;i++){
    const n=compact();
    if(n>100_000)throw Error('unbounded witness element count');
    const elements=[];
    for(let j=0;j<n;j++)elements.push(Buffer.from(take(compact())));
    stacks.push(elements);
  }
  take(4); // locktime
  if(off!==raw.length)throw Error('trailing bytes after witness transaction');
  return stacks;
}

export function authenticateSerializedWitnessInclusion(inclusion){
  if(!inclusion||typeof inclusion!=='object')
    throw Error('missing Bitcoin inclusion evidence');
  const w=inclusion.witness;
  if(!w||typeof w!=='object')
    throw Error('missing BIP141 witness inclusion evidence');
  const targetRaw=requiredHex(w.witnessedRawHex,'target transaction');
  const coinbaseRaw=requiredHex(w.coinbaseRawHex,'coinbase');
  const target=parseTx(targetRaw);
  const coinbase=parseTx(coinbaseRaw);
  if(target.txid!==inclusion.txid||target.txid!==w.txid)
    throw Error('raw target transaction does not match committed txid');
  if(coinbase.txid!==w.coinbaseTxid)
    throw Error('raw coinbase transaction does not match anchored coinbase txid');
  if(coinbase.inputs.length!==1||
     coinbase.inputs[0].txid!=='00'.repeat(32)||
     coinbase.inputs[0].vout!==0xffffffff)
    throw Error('witness commitment source is not a Bitcoin coinbase');
  const targetStacks=readCanonicalWitnessStacks(targetRaw);
  if(targetStacks.length!==target.inputs.length||
     targetStacks.every(stack=>stack.length===0))
    throw Error('target must carry a SegWit witness');
  const coinbaseStacks=readCanonicalWitnessStacks(coinbaseRaw);
  if(coinbaseStacks.length!==1||coinbaseStacks[0].length!==1||
     coinbaseStacks[0][0].length!==32)
    throw Error('BIP141 coinbase reserved value is not a sole 32-byte witness item');
  const reserved=coinbaseStacks[0][0].toString('hex');
  if(reserved!==w.reservedHex.toLowerCase())
    throw Error('coinbase reserved value differs from serialized coinbase witness');
  const commitOutputs=coinbase.outputs
    .map(output=>output.script.toString('hex'))
    .filter(script=>script.startsWith('6a24aa21a9ed')&&script.length>=76);
  if(commitOutputs.length===0)
    throw Error('raw coinbase lacks the BIP141 commitment output');
  const selected=commitOutputs.at(-1);
  if(selected!==w.coinbaseCommitmentScript.toLowerCase())
    throw Error('reported witness commitment does not match raw coinbase output');
  const actualWtxid=displayedHash(targetRaw);
  if(actualWtxid!==w.wtxid)
    throw Error('raw SegWit transaction does not match claimed wtxid');
  const normal=proofIncludesTxid(inclusion.proofHex,target.txid,inclusion.blockhash);
  if(normal.matches.length!==1||
     normal.matches[0].index!==w.txIndex)
    throw Error('transaction inclusion index disagrees with witness position');
  if(normal.headerHex!==inclusion.headerHex||
     normal.merkleRoot!==inclusion.merkleRoot||
     w.blockHeaderHex!==normal.headerHex||
     w.blockhash!==normal.blockhash)
    throw Error('txid and wtxid proofs have different Bitcoin headers');
  if(!verifyWitnessCommitmentEvidence(w))
    throw Error('BIP141 witness-to-coinbase commitment proof invalid');
  return {
    txid:target.txid,
    wtxid:actualWtxid,
    coinbaseTxid:coinbase.txid,
    blockhash:normal.blockhash,
    txIndex:w.txIndex,
    blockHeaderHex:normal.headerHex,
    coinbaseCommitmentScript:selected,
    authenticatedTxid:true,
    authenticatedWitness:true,
    authenticationScope:'Bitcoin header commitment; chain bestness and block/UTXO validity external'
  };
}
