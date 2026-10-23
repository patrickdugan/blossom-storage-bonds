/**
 * BIP141 witness commitment proof construction and independent verification.
 *
 * A witness-bearing transaction is committed by:
 *  1. its wtxid in the block's witness Merkle tree (coinbase leaf is zero),
 *  2. SHA256d(witnessRoot || coinbase witness reserved value) in the selected
 *     coinbase OP_RETURN 6a24aa21a9ed <32 bytes> output, and
 *  3. the coinbase txid in the normal block transaction Merkle root/header.
 *
 * The caller MUST additionally prove that the selected output is really in
 * the serialized coinbase (and that the reserved value is its actual witness).
 * A full validating node does this in our regtest audit. This module does
 * NOT prove header PoW, canonical chainwork or full Bitcoin consensus.
 */
import {createHash} from 'node:crypto';

const sha=b=>createHash('sha256').update(b).digest();
const sha2=b=>sha(sha(b));
const h32=x=>{
  if(typeof x!=='string'||!/^[0-9a-f]{64}$/i.test(x))throw Error('hash must be 32-byte hex');
  return Buffer.from(x,'hex');
};
const internal=x=>Buffer.from(h32(x)).reverse();
const displayed=b=>Buffer.from(b).reverse().toString('hex');
const magic='6a24aa21a9ed';

function merkleRow(nodes){
  const next=[];
  for(let i=0;i<nodes.length;i+=2)
    next.push(sha2(Buffer.concat([nodes[i],nodes[i+1]??nodes[i]])));
  return next;
}
function treeAndBranch(leaves,index){
  if(!Array.isArray(leaves)||leaves.length<1||!Number.isSafeInteger(index)||
     index<0||index>=leaves.length)throw Error('invalid Merkle tree index');
  let row=leaves.map(x=>Buffer.from(x)),pos=index;
  if(row.some(x=>x.length!==32))throw Error('Merkle leaf must be 32 bytes');
  const branch=[];
  while(row.length>1){
    branch.push(Buffer.from(row[pos^1]??row[pos]));
    row=merkleRow(row);
    pos=Math.floor(pos/2);
  }
  return {root:row[0],branch};
}
export function verifyIndexedMerkleBranch(leaf,index,total,branch,root){
  if(!Buffer.isBuffer(leaf)||leaf.length!==32||!Buffer.isBuffer(root)||root.length!==32||
     !Number.isSafeInteger(total)||total<1||total>1_000_000||
     !Number.isSafeInteger(index)||index<0||index>=total||
     !Array.isArray(branch))return false;
  let depth=0,width=total;
  while(width>1){depth++;width=Math.ceil(width/2);}
  if(branch.length!==depth)return false;
  let current=leaf,pos=index;
  width=total;
  for(const sibling of branch){
    if(!Buffer.isBuffer(sibling)||sibling.length!==32)return false;
    if((pos^1)>=width && !sibling.equals(current))return false;
    current=pos&1?
      sha2(Buffer.concat([sibling,current])):
      sha2(Buffer.concat([current,sibling]));
    pos=Math.floor(pos/2);
    width=Math.ceil(width/2);
  }
  return current.equals(root)&&pos===0;
}
export function createWitnessCommitmentEvidence({
    txids,wtxids,targetIndex,blockHeaderHex,reservedHex,coinbaseCommitmentScript}){
  if(!Array.isArray(txids)||!Array.isArray(wtxids)||
     txids.length!==wtxids.length||txids.length<2||
     !Number.isInteger(targetIndex)||targetIndex<1||targetIndex>=txids.length)
    throw Error('invalid block transaction set for witness commitment');
  const normalLeaves=txids.map(internal);
  const witnessLeaves=wtxids.map((w,i)=>i===0?Buffer.alloc(32):internal(w));
  const txTree=treeAndBranch(normalLeaves,0);
  const witnessTree=treeAndBranch(witnessLeaves,targetIndex);
  const header=Buffer.from(blockHeaderHex,'hex');
  if(header.length!==80)throw Error('expected Bitcoin 80-byte block header');
  if(!header.subarray(36,68).equals(txTree.root))
    throw Error('normal transaction Merkle tree not anchored to block header');
  const reserved=h32(reservedHex);
  const commitment=sha2(Buffer.concat([witnessTree.root,reserved])).toString('hex');
  if(typeof coinbaseCommitmentScript!=='string'||
     !coinbaseCommitmentScript.toLowerCase().startsWith(magic+commitment))
    throw Error('coinbase witness commitment does not match witness tree and reserved value');
  const receipt={
    blockhash:displayed(sha2(header)),
    blockHeaderHex:header.toString('hex'),
    txid:txids[targetIndex],
    wtxid:wtxids[targetIndex],
    txIndex:targetIndex,
    totalTransactions:txids.length,
    witnessBranchHex:witnessTree.branch.map(x=>x.toString('hex')),
    witnessRootHex:witnessTree.root.toString('hex'),
    coinbaseTxid:txids[0],
    coinbaseTxidBranchHex:txTree.branch.map(x=>x.toString('hex')),
    reservedHex,
    coinbaseCommitmentScript:coinbaseCommitmentScript.toLowerCase()
  };
  if(!verifyWitnessCommitmentEvidence(receipt))
    throw Error('freshly constructed witness commitment proof failed independent verification');
  return receipt;
}
export function verifyWitnessCommitmentEvidence(evidence){
  try{
    if(typeof evidence!=='object'||evidence===null)return false;
    const header=Buffer.from(evidence.blockHeaderHex,'hex');
    if(header.length!==80||displayed(sha2(header))!==evidence.blockhash)return false;
    const ordinaryRoot=header.subarray(36,68);
    const witnessRoot=h32(evidence.witnessRootHex);
    const witnessBranch=evidence.witnessBranchHex.map(x=>Buffer.from(x,'hex'));
    const coinbaseBranch=evidence.coinbaseTxidBranchHex.map(x=>Buffer.from(x,'hex'));
    const n=evidence.totalTransactions,i=evidence.txIndex;
    if(!Number.isSafeInteger(n)||n<2||!Number.isSafeInteger(i)||i<1||i>=n)return false;
    if(!verifyIndexedMerkleBranch(internal(evidence.wtxid),i,n,witnessBranch,witnessRoot))
      return false;
    if(!verifyIndexedMerkleBranch(internal(evidence.coinbaseTxid),0,n,coinbaseBranch,ordinaryRoot))
      return false;
    const expectedCommit=sha2(Buffer.concat([witnessRoot,h32(evidence.reservedHex)])).toString('hex');
    if(typeof evidence.coinbaseCommitmentScript!=='string'||
       !evidence.coinbaseCommitmentScript.toLowerCase().startsWith(magic+expectedCommit))
      return false;
    return true;
  }catch{return false;}
}
