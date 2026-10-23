/**
 * BIP141 witness-inclusion anchoring experiment.
 *
 * Synthetic block only: confirms Merkle and coinbase witness-commitment
 * arithmetic, NOT proof of work, Bitcoin block validity, chain canonicality,
 * inclusion height, spend authorization, or an on-chain BitVM payout rule.
 *
 * Transaction txid does not include witness. A later real Bitcoin block
 * commitment can authenticate the wtxid instead. This module models that
 * cryptographic path without constructing or mining a real block.
 */
import {createHash} from 'node:crypto';
import {transactionId,witnessTransactionId,transactionFixture} from './txid_admission.mjs';

const sha256=b=>createHash('sha256').update(b).digest();
export const sha256d=b=>sha256(sha256(b));
const HASH0=Buffer.alloc(32);
const MAGIC='6a24aa21a9ed';
function h32(hex){if(typeof hex!=='string'||!/^[0-9a-f]{64}$/i.test(hex))throw new TypeError('hash must be 32-byte hex');return Buffer.from(hex,'hex');}
function displayToInternal(hex){return Buffer.from(h32(hex)).reverse();}
function pair(a,b){return sha256d(Buffer.concat([a,b]));}
const hexes = a => a.map(b=>b.toString('hex'));
export const witnessScript='7551'; // OP_DROP OP_TRUE, consumes witness data and leaves one true
export const p2wshScriptPubKey='0020'+sha256(Buffer.from(witnessScript,'hex')).toString('hex');

export function witnessChallengeTx(certificateHex='11'.repeat(32)){
  if(typeof certificateHex!=='string'||certificateHex.length%2||!/^[0-9a-f]*$/i.test(certificateHex)||certificateHex.length===0)
    throw new TypeError('invalid witness certificate bytes');
  if(certificateHex.length/2>520)throw new RangeError('oversized v0 witness stack element');
  return {
    version:2,lockTime:0,
    vin:[{prevTxid:'11'.repeat(32),prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[certificateHex,witnessScript]}],
    vout:[{valueSats:1000n,scriptPubKey:'51'}]
  };
}
export function merkleRoot(leaves){
  if(!Array.isArray(leaves)||leaves.length===0)throw new RangeError('nonempty Merkle leaves required');
  let row=leaves.map(b=>Buffer.from(b));
  if(row.some(b=>b.length!==32))throw new RangeError('invalid leaf size');
  while(row.length>1){
    const next=[];for(let i=0;i<row.length;i+=2)next.push(pair(row[i],row[i+1]??row[i]));
    row=next;
  }
  return row[0];
}
export function merklePath(leaves,index){
  if(!Array.isArray(leaves)||!Number.isSafeInteger(index)||index<0||index>=leaves.length)
    throw new RangeError('invalid Merkle index');
  let pos=index,row=leaves.map(b=>Buffer.from(b)),proof=[];
  if(row.some(b=>b.length!==32))throw new RangeError('invalid leaf size');
  while(row.length>1){
    const sib=pos^1;proof.push(Buffer.from(row[sib]??row[pos]));
    const next=[];for(let i=0;i<row.length;i+=2)next.push(pair(row[i],row[i+1]??row[i]));
    row=next;pos=Math.floor(pos/2);
  }
  return proof;
}
export function verifyPath(leaf,index,proof,root){
  if(!Buffer.isBuffer(leaf)||leaf.length!==32||!Buffer.isBuffer(root)||root.length!==32||
    !Number.isSafeInteger(index)||index<0||!Array.isArray(proof))return false;
  let pos=index,current=leaf;
  for(const sibling of proof){
    if(!Buffer.isBuffer(sibling)||sibling.length!==32)return false;
    current=(pos&1)?pair(sibling,current):pair(current,sibling);
    pos=Math.floor(pos/2);
  }
  return current.equals(root)&&pos===0;
}
const coinbase=(commitment,reserved)=>({
  version:2,lockTime:0,
  vin:[{prevTxid:'00'.repeat(32),prevVout:0xffffffff,scriptSig:'03010000',sequence:0xffffffff,witness:[reserved.toString('hex')]}],
  vout:[{valueSats:0n,scriptPubKey:MAGIC+commitment.toString('hex')}]
});
function findCommitment(c){
  // BIP141: the highest output index matching the commitment magic wins.
  let found=null;
  for(const out of c.vout)if(typeof out.scriptPubKey==='string' && out.scriptPubKey.toLowerCase().startsWith(MAGIC) &&
    out.scriptPubKey.length>=MAGIC.length+64)found=Buffer.from(out.scriptPubKey.slice(MAGIC.length,MAGIC.length+64),'hex');
  return found;
}
export function syntheticWitnessBlock(challenge){
  const filler=transactionFixture({witness:[]});
  const reserved=h32('77'.repeat(32));
  const witnessLeaves=[HASH0,displayToInternal(witnessTransactionId(challenge)),displayToInternal(witnessTransactionId(filler))];
  const witnessRoot=merkleRoot(witnessLeaves);
  const commitment=sha256d(Buffer.concat([witnessRoot,reserved]));
  const coinbaseTx=coinbase(commitment,reserved);
  const txLeaves=[displayToInternal(transactionId(coinbaseTx)),displayToInternal(transactionId(challenge)),displayToInternal(transactionId(filler))];
  const transactionRoot=merkleRoot(txLeaves);
  return {
    fakeBlock:true, coinbaseTx,
    transactionMerkleRoot:transactionRoot.toString('hex'),
    witnessMerkleRoot:witnessRoot.toString('hex'),
    witnessProof:hexes(merklePath(witnessLeaves,1)),
    coinbaseTxidProof:hexes(merklePath(txLeaves,0)),
    reservedValue:reserved.toString('hex'),
    witnessIndex:1,coinbaseIndex:0,
    commitment:commitment.toString('hex'),
  };
}
export function verifySyntheticWitnessAnchor({challenge,block,expectedCertificateDigest}){
  if(!block?.fakeBlock||!challenge?.vin?.[0]?.witness?.[0])return false;
  let wRoot,txRoot,reserved,proofW,proofTx;
  try{
    wRoot=h32(block.witnessMerkleRoot);txRoot=h32(block.transactionMerkleRoot);
    reserved=h32(block.coinbaseTx?.vin?.[0]?.witness?.[0]);
    proofW=block.witnessProof.map(h32);proofTx=block.coinbaseTxidProof.map(h32);
    if(expectedCertificateDigest && sha256(Buffer.from(challenge.vin[0].witness[0],'hex')).toString('hex')!==expectedCertificateDigest)
      return false;
    const commit=sha256d(Buffer.concat([wRoot,reserved]));
    const stored=findCommitment(block.coinbaseTx);
    if(!stored||!stored.equals(commit))return false;
    if(!verifyPath(displayToInternal(witnessTransactionId(challenge)),block.witnessIndex,proofW,wRoot))return false;
    if(!verifyPath(displayToInternal(transactionId(block.coinbaseTx)),block.coinbaseIndex,proofTx,txRoot))return false;
    return true;
  }catch{return false;}
}
export function certificateSha256(challenge){
  return sha256(Buffer.from(challenge.vin[0].witness[0],'hex')).toString('hex');
}
