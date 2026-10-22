/**
 * Legacy (pre-SegWit) Bitcoin SIGHASH preimage and FindAndDelete research lab.
 * This implements the digest calculation, not signature verification, proof-of-work
 * grinding, Bitcoin Script execution, or a complete Binohash protocol.
 */
import { createHash } from 'node:crypto';
import { serializeTransaction } from './txid_admission.mjs';

const hash256 = b => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
function checkedHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-f]*$/i.test(hex)) throw new TypeError('invalid hex');
  return Buffer.from(hex, 'hex');
}
function withU32(value) {const b=Buffer.alloc(4);b.writeUInt32LE(value >>> 0);return b;}

class Cursor {
  constructor(bytes) {this.b=bytes;this.off=0;}
  take(n) {if (!Number.isSafeInteger(n)||n<0||this.off+n>this.b.length) throw new RangeError('truncated transaction');const out=this.b.subarray(this.off,this.off+n);this.off+=n;return out;}
  u32() {return this.take(4).readUInt32LE();}
  varint() {
    const b=this.take(1)[0];
    if(b<253) return b;
    const size=b===253?2:b===254?4:8;
    let x=0n;const v=this.take(size);
    for(let i=size-1;i>=0;i--)x=(x<<8n)|BigInt(v[i]);
    if(x>BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('varint exceeds safe integer');
    return Number(x);
  }
  varbytes() {return this.take(this.varint()).toString('hex');}
}
export function decodeLegacyTransaction(hex) {
  const c=new Cursor(checkedHex(hex));
  const version=c.u32();
  const nIn=c.varint();
  if(nIn===0) throw new RangeError('legacy serializer expects at least one input');
  const vin=[];
  for(let i=0;i<nIn;i++)vin.push({
    prevTxid:Buffer.from(c.take(32)).reverse().toString('hex'),prevVout:c.u32(),scriptSig:c.varbytes(),sequence:c.u32(),witness:[]
  });
  const nOut=c.varint(),vout=[];
  for(let i=0;i<nOut;i++)vout.push({valueSats:c.take(8).readBigUInt64LE(),scriptPubKey:c.varbytes()});
  const lockTime=c.u32();
  if(c.off!==c.b.length) throw new RangeError('trailing bytes in legacy transaction');
  return {version,vin,vout,lockTime};
}
// A script opcode parser is necessary: an 0xab *inside* pushed bytes is data,
// whereas an OP_CODESEPARATOR at an opcode boundary is removed for legacy sighash.
function nextOpcode(script, pos) {
  if(pos>=script.length) throw new RangeError('end of script');
  const opcode=script[pos++];let dataLen=0;
  if(opcode>=1&&opcode<=75)dataLen=opcode;
  if(opcode===0x4c) {if(pos>=script.length)throw new RangeError('truncated PUSHDATA1');dataLen=script[pos++];}
  if(opcode===0x4d) {if(pos+2>script.length)throw new RangeError('truncated PUSHDATA2');dataLen=script.readUInt16LE(pos);pos+=2;}
  if(opcode===0x4e) {if(pos+4>script.length)throw new RangeError('truncated PUSHDATA4');dataLen=script.readUInt32LE(pos);pos+=4;}
  if(pos+dataLen>script.length)throw new RangeError('truncated script push');
  return {opcode,end:pos+dataLen};
}
export function stripCodeSeparators(scriptHex) {
  const s=checkedHex(scriptHex),pieces=[];
  for(let pos=0;pos<s.length;){const op=nextOpcode(s,pos);if(op.opcode!==0xab)pieces.push(s.subarray(pos,op.end));pos=op.end;}
  return Buffer.concat(pieces).toString('hex');
}
export function encodePushData(hex) {
  const b=checkedHex(hex);
  if(b.length<=75)return Buffer.concat([Buffer.from([b.length]),b]).toString('hex');
  if(b.length<=255)return Buffer.concat([Buffer.from([0x4c,b.length]),b]).toString('hex');
  throw new RangeError('push data too large for this research implementation');
}
export function findAndDelete(scriptHex, signatureHex) {
  const script=checkedHex(scriptHex),target=Buffer.from(encodePushData(signatureHex),'hex');
  let removed=0;const chunks=[];
  for(let pos=0;pos<script.length;){
    // Bitcoin Core's FindAndDelete deletes a push at an opcode boundary, possibly repeated.
    while(target.length&&pos+target.length<=script.length&&script.subarray(pos,pos+target.length).equals(target)){
      pos+=target.length;removed++;
    }
    if(pos>=script.length)break;
    const op=nextOpcode(script,pos);chunks.push(script.subarray(pos,op.end));pos=op.end;
  }
  return {script:Buffer.concat(chunks).toString('hex'),removed};
}
export function legacySignatureHash(tx,index,scriptCodeHex,hashType,deletedSignatures=[]) {
  if(!Number.isInteger(index)||index<0||index>=tx.vin.length) throw new RangeError('bad input index');
  let script=scriptCodeHex;
  for(const signature of deletedSignatures)script=findAndDelete(script,signature).script;
  script=stripCodeSeparators(script);
  const flag=hashType>>>0,mode=flag&31;
  // The historical SIGHASH_SINGLE bug returns the uint256 constant 1.
  if(mode===3&&index>=tx.vout.length)return '00'.repeat(31)+'01';
  const vin=tx.vin.map((v,i)=>({...v,scriptSig:i===index?script:'',witness:[],
    sequence:i!==index&&(mode===2||mode===3)?0:v.sequence}));
  let vout=tx.vout.map(o=>({...o}));
  if(mode===2)vout=[];
  if(mode===3)vout=[...Array(index)].map(()=>({valueSats:(1n<<64n)-1n,scriptPubKey:''})).concat(vout[index]);
  const copy={version:tx.version,vin:(flag&0x80)?[vin[index]]:vin,vout,lockTime:tx.lockTime};
  // SIGHASH_NONE has zero outputs. Our general transaction serializer enforces
  // outputs for normal transaction identity, so encode the signature preimage here.
  const raw=serializeForLegacySighash(copy);
  return Buffer.from(hash256(Buffer.concat([raw,withU32(flag)]))).reverse().toString('hex');
}
function serializeForLegacySighash(tx) {
  if(tx.vout.length)return serializeTransaction(tx);
  // Version + inputs + 0 outputs + locktime. This is a SIGHASH preimage only.
  const dummy={...tx,vout:[{valueSats:0n,scriptPubKey:''}]};
  const raw=serializeTransaction(dummy);
  const head=raw.subarray(0,raw.length-14); // drop nOut, 8-byte amount, 1-byte scriptLen, 4-byte locktime
  return Buffer.concat([head,Buffer.from([0]),raw.subarray(raw.length-4)]);
}
