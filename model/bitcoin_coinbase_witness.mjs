/**
 * Strict Bitcoin Core-compatible parser for the coinbase fields needed to
 * bind a BIP141 witness commitment into the ordinary txid Merkle tree.
 *
 * This parser extracts the selected highest-index OP_RETURN witness
 * commitment and the 32-byte coinbase reserved witness from the SAME
 * serialized raw SegWit coinbase. It recomputes the non-witness txid.
 *
 * It is not a general block/transaction consensus interpreter.
 */
import {createHash} from 'node:crypto';
const sha=x=>createHash('sha256').update(x).digest();
const sha2=x=>sha(sha(x));
const display=x=>Buffer.from(x).reverse().toString('hex');
const MAGIC='6a24aa21a9ed';

export function parseCoinbaseWitnessRaw(rawHex){
  if(typeof rawHex!=='string'||rawHex.length%2!==0||
     !/^[0-9a-f]+$/i.test(rawHex)||rawHex.length<210)
    throw Error('invalid serialized coinbase');
  const raw=Buffer.from(rawHex,'hex');
  let pos=0;
  function take(len){
    if(!Number.isSafeInteger(len)||len<0||pos+len>raw.length)
      throw Error('truncated coinbase bytes');
    const v=raw.subarray(pos,pos+len);pos+=len;return v;
  }
  const uint8=()=>take(1)[0];
  const uint16=()=>take(2).readUInt16LE(0);
  const uint32=()=>take(4).readUInt32LE(0);
  function compactSize(){
    const op=uint8();
    if(op<253)return op;
    if(op===253){const n=uint16();if(n<253)throw Error('noncanonical compactSize');return n;}
    if(op===254){const n=uint32();if(n<=65535)throw Error('noncanonical compactSize');return n;}
    const n=take(8).readBigUInt64LE();
    if(n<=0xffffffffn||n>1_000_000n)throw Error('invalid compactSize');
    return Number(n);
  }
  const version=uint32();
  if(version<1)throw Error('invalid coinbase transaction version');
  if(raw[pos++]!==0||raw[pos++]!==1)
    throw Error('coinbase witness requires marker 00 and flag 01');
  const inputStart=pos;
  if(compactSize()!==1)throw Error('coinbase must have exactly one input');
  const prevhash=take(32);
  if(!prevhash.equals(Buffer.alloc(32)))throw Error('coinbase prevhash is not zero');
  if(uint32()!==0xffffffff)throw Error('coinbase prevout index must be final');
  const scriptLength=compactSize();
  if(scriptLength<2||scriptLength>100)throw Error('invalid coinbase scriptSig length');
  take(scriptLength);
  uint32();
  const outputCount=compactSize();
  if(outputCount<1||outputCount>100)throw Error('bad coinbase output count');
  const outputs=[];
  for(let i=0;i<outputCount;i++){
    take(8);
    const size=compactSize();
    if(size>10000)throw Error('oversized coinbase output script');
    outputs.push(take(size).toString('hex'));
  }
  const outputsEnd=pos;
  const witnessItems=compactSize();
  if(witnessItems<1||witnessItems>100)throw Error('coinbase missing witness items');
  let reserved=null;
  for(let i=0;i<witnessItems;i++){
    const len=compactSize();
    if(len>1_000_000)throw Error('oversized coinbase witness item');
    const item=take(len);
    if(i===0)reserved=Buffer.from(item);
  }
  if(raw.length-pos!==4)throw Error('unexpected coinbase trailer');
  const locktime=take(4);
  if(!reserved||reserved.length!==32)
    throw Error('coinbase witness reserved value must be exactly 32 bytes');
  const selected=outputs.filter(x=>x.startsWith(MAGIC)&&x.length>=76).at(-1);
  if(!selected)throw Error('coinbase missing BIP141 witness commitment output');
  const stripped=Buffer.concat([
    raw.subarray(0,4),raw.subarray(inputStart,outputsEnd),locktime
  ]);
  return {
    txid:display(sha2(stripped)),
    reservedHex:reserved.toString('hex'),
    commitmentScript:selected,
    commitmentHex:selected.slice(MAGIC.length,MAGIC.length+64),
    outputCount,version,
    rawBytes:raw.length
  };
}
