/**
 * Independent BIP37 CMerkleBlock / CPartialMerkleTree parser for
 * Bitcoin Core's gettxoutproof serialized proof.
 *
 * This verifies the matched transaction leaf and partial Merkle tree against
 * the block header hash, but it DOES NOT determine which header is active,
 * Bitcoin PoW/chainwork, block transaction validity or UTXO unspent status.
 * Those are delegated to an authenticated header chain / full node.
 */
import {createHash} from 'node:crypto';

const doubleSha=b=>{
  const h=createHash('sha256').update(b).digest();
  return createHash('sha256').update(h).digest();
};
const asHexRe=/^[0-9a-f]+$/i;
const displayHash=b=>Buffer.from(b).reverse().toString('hex');

export function parseBitcoinTxOutProof(rawHex){
  if(typeof rawHex!=='string'||rawHex.length%2!==0||
     rawHex.length<178||!asHexRe.test(rawHex))
    throw Error('invalid Bitcoin partial merkle proof hex');
  const bytes=Buffer.from(rawHex,'hex');
  let offset=0;
  function take(n){
    if(!Number.isSafeInteger(n)||n<0||offset+n>bytes.length)
      throw Error('truncated Bitcoin partial merkle proof');
    const value=bytes.subarray(offset,offset+n);
    offset+=n;
    return value;
  }
  function u8(){return take(1)[0];}
  function u16(){return take(2).readUInt16LE(0);}
  function u32(){return take(4).readUInt32LE(0);}
  function compact(){
    const op=u8();
    if(op<253)return op;
    if(op===253){
      const v=u16();
      if(v<253)throw Error('noncanonical compactSize');
      return v;
    }
    if(op===254){
      const v=u32();
      if(v<=65535)throw Error('noncanonical compactSize');
      return v;
    }
    const val=take(8).readBigUInt64LE();
    if(val<=0xffffffffn||val>BigInt(Number.MAX_SAFE_INTEGER))
      throw Error('invalid compactSize width');
    return Number(val);
  }
  const header=take(80);
  const total=u32();
  if(total<1||total>1_000_000)throw Error('invalid merkle tree transaction count');
  const numHashes=compact();
  if(numHashes<1||numHashes>total)throw Error('invalid partial merkle hash count');
  const hashes=[];
  for(let i=0;i<numHashes;i++)hashes.push(take(32));
  const nFlags=compact();
  if(nFlags===0||nFlags>Math.ceil((total*2)/8)+2)
    throw Error('invalid merkle bit field size');
  const flags=take(nFlags);
  if(offset!==bytes.length)throw Error('trailing bytes after partial merkle proof');
  let height=0;
  const width=h=>Math.ceil(total/2**h);
  while(width(height)>1)height++;
  let bitIndex=0,hashIndex=0;
  const matched=[];
  function traverse(h,pos){
    if(bitIndex>=flags.length*8)throw Error('not enough partial merkle flag bits');
    const flagged=(flags[bitIndex>>3]>>(bitIndex&7))&1;
    bitIndex++;
    if(h===0||flagged===0){
      if(hashIndex>=hashes.length)throw Error('exhausted partial merkle hashes');
      const digest=hashes[hashIndex++];
      if(h===0&&flagged===1)matched.push({txid:displayHash(digest),index:pos});
      return digest;
    }
    const left=traverse(h-1,pos*2);
    let right;
    if(pos*2+1<width(h-1)){
      right=traverse(h-1,pos*2+1);
      if(left.equals(right))
        throw Error('duplicate sibling mutation in partial merkle tree');
    }else right=left;
    return doubleSha(Buffer.concat([left,right]));
  }
  const calculated=traverse(height,0);
  if(hashIndex!==hashes.length||Math.ceil(bitIndex/8)!==flags.length)
    throw Error('unused partial merkle hashes or flag bytes');
  // Canonical Bitcoin Core vBits serialization pads with zero high bits.
  for(let k=bitIndex;k<flags.length*8;k++){
    if(((flags[k>>3]>>(k&7))&1)!==0)
      throw Error('nonzero merkle flag padding');
  }
  if(!calculated.equals(header.subarray(36,68)))
    throw Error('partial merkle root does not match Bitcoin block header');
  if(matched.length===0)throw Error('no matched transaction in partial merkle proof');
  return {
    headerHex:header.toString('hex'),
    blockhash:displayHash(doubleSha(header)),
    merkleRoot:displayHash(calculated),
    totalTransactions:total,
    matches:matched,
    usedFlagBits:bitIndex,
    suppliedHashes:numHashes
  };
}

export function proofIncludesTxid(proofHex,txid,blockhash){
  const decoded=parseBitcoinTxOutProof(proofHex);
  if(decoded.blockhash!==blockhash||
     !decoded.matches.some(match=>match.txid===txid))
    throw Error('transaction proof is not anchored to requested block and txid');
  return decoded;
}
