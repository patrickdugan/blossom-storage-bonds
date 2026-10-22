/**
 * Research-only toy execution of the **actual cryptographic primitives** behind
 * Binohash on Bitcoin legacy Script: 9-byte ECDSA dummy signatures valid under
 * the SIGHASH_SINGLE bug, subset-controlled FindAndDelete, and an Rmin puzzle.
 *
 * Deliberately tiny WORK (one DER byte) and t=2, with public toy secrets.
 * This is not the production two-round Binohash construction, not a covenant,
 * not a Bitcoin Core consensus verifier and not suitable for collateral.
 */
import {legacySignatureHash,encodePushData} from './legacy_sighash.mjs';
import {transactionId} from './txid_admission.mjs';
import {
  N,G,mod,inverse,multiply,pubkey,parsePubkey,verifyECDSA,
  recoverPublicKey,encodeBitcoinSignature,parseBitcoinSignature,displayHashToZ
} from './secp256k1_legacy_demo.mjs';

const OP_DROP='75', OP_CHECKMULTISIG='ae';
const OP_0='00', OP_3='53';
const BUG_Z=displayHashToZ('00'.repeat(31)+'01');
const signRmin = (z) => {
  const k=inverse(2n,N),r=mod(multiply(k).x,N);
  const d=inverse(r,N); // r*d == 1 so s = 2(z+1)
  const s=mod(2n*(z+1n),N);
  return {r,s,publicKey:pubkey(multiply(d)),signature:encodeBitcoinSignature(r,s,1)};
};

export function dummyPool(n=80){
  if(!Number.isSafeInteger(n)||n<1||n>127)throw RangeError('toy dummy pool size must be 1..127');
  const ret=[];
  for(let i=1;i<=n;i++){
    const r=1n,s=BigInt(i);
    const signature=encodeBitcoinSignature(r,s,3);
    const publicKey=pubkey(recoverPublicKey({z:BUG_Z,r,s,odd:false}));
    ret.push({index:i-1,r,s,signature,publicKey});
  }
  return ret;
}
export function makeLockingScript(pool){
  // Raw bare legacy locking script. Pool pushes affect FindAndDelete; OP_DROP
  // discards them. All pubkeys and signatures are on stack from scriptSig.
  return pool.map(d=>encodePushData(d.signature)).join('')+
    OP_DROP.repeat(pool.length)+OP_CHECKMULTISIG;
}
export function makeCarrierTx({prev0='11'.repeat(32),prev1='22'.repeat(32),output='51'}={}){
  return {version:2,vin:[
    {prevTxid:prev0,prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]},
    {prevTxid:prev1,prevVout:0,scriptSig:'',sequence:0xfffffffe,witness:[]}
  ],vout:[{valueSats:10000n,scriptPubKey:output}],lockTime:0};
}
export function makeUnlockingScript(pair,puzzleSignature,puzzlePubkey){
  if(pair.length!==2)throw Error('toy t=2');
  const [a,b]=pair;
  return OP_0+[a.signature,b.signature,puzzleSignature].map(encodePushData).join('')+
    OP_3+[a.publicKey,b.publicKey,puzzlePubkey].map(encodePushData).join('')+OP_3;
}
export function solveToyBinohash({tx=makeCarrierTx(),pool=dummyPool(),maxLength=59}={}){
  if(tx.vin.length<2||tx.vout.length!==1)throw Error('toy requires input 1 and exactly one output');
  const script=makeLockingScript(pool);
  for(let i=0;i<pool.length;i++)for(let j=i+1;j<pool.length;j++){
    const pair=[pool[i],pool[j]];
    const z=displayHashToZ(legacySignatureHash(tx,1,script,1,pair.map(d=>d.signature)));
    const puzzle=signRmin(z);
    if(Buffer.from(puzzle.signature,'hex').length>maxLength)continue;
    const unlocking=makeUnlockingScript(pair,puzzle.signature,puzzle.publicKey);
    const funded={...tx,vin:tx.vin.map((input,k)=>k===1?{...input,scriptSig:unlocking}:input)};
    return {tx:funded,lockScript:script,unlocking,pool,pairIndices:[i,j],pair,puzzle,hashDisplay:legacySignatureHash(tx,1,script,1,pair.map(d=>d.signature)),attempts:i*(2*pool.length-i-1)/2+(j-i),toyDigest:[i,j],txid:transactionId(funded)};
  }
  throw Error('no toy small-signature puzzle solution');
}
function readOp(bytes,pos){
  if(pos>=bytes.length)throw Error('read past script');
  const opcode=bytes[pos++]; let len=0;
  if(opcode>=1&&opcode<=75)len=opcode;
  if(opcode===0x4c){if(pos>=bytes.length)throw Error('truncated PUSHDATA1');len=bytes[pos++];}
  if(opcode===0x4d){if(pos+2>bytes.length)throw Error('truncated PUSHDATA2');len=bytes.readUInt16LE(pos);pos+=2;}
  if(pos+len>bytes.length)throw Error('truncated push');
  return {opcode,data:len?bytes.subarray(pos,pos+len):null,end:pos+len};
}
export function verifyToyScript(tx,lockScript,{inputIndex=1}={}){
  // Minimal interpreter for OP_0, OP_N, PUSH, DROP and CHECKMULTISIG.
  // Does not implement all Bitcoin Script consensus checks or script flags.
  const stack=[],scriptSig=tx.vin[inputIndex]?.scriptSig;
  if(scriptSig===undefined)throw Error('missing carrier input');
  let ops=0,removed=0;
  const exec=(hex,isLock)=>{
    const raw=Buffer.from(hex,'hex');
    for(let pos=0;pos<raw.length;){const op=readOp(raw,pos);pos=op.end;const opcode=op.opcode;
      if(opcode===0){stack.push(Buffer.alloc(0));continue;}
      if(op.data){stack.push(Buffer.from(op.data));continue;}
      if(opcode>=0x51&&opcode<=0x60){stack.push(Buffer.from([opcode-0x50]));continue;}
      if(!isLock)throw Error('scriptSig must be push-only');
      ++ops;
      if(opcode===0x75){if(!stack.length)throw Error('DROP underflow');stack.pop();continue;}
      if(opcode===0xae){
        const n=stack.pop()?.[0];if(!Number.isInteger(n)||n<0||n>20)throw Error('bad public key count');
        const keys=[];for(let k=0;k<n;k++)keys.unshift(stack.pop()?.toString('hex'));
        const m=stack.pop()?.[0];if(!Number.isInteger(m)||m<0||m>n)throw Error('bad signature count');
        const sigs=[];for(let k=0;k<m;k++)sigs.unshift(stack.pop()?.toString('hex'));
        const dummy=stack.pop();if(!dummy||dummy.length!==0)throw Error('NULLDUMMY violated');
        if(keys.some(k=>!k)||sigs.some(s=>!s))throw Error('missing signature or pubkey');
        const signatures=sigs.slice();let sigIdx=0,keyIdx=0,valid=true;
        while(sigIdx<signatures.length&&keyIdx<keys.length){
          let ok=false;
          try{
            const sig=parseBitcoinSignature(signatures[sigIdx]);
            const digest=legacySignatureHash(tx,inputIndex,lockScript,sig.hashType,signatures);
            const z=displayHashToZ(digest);
            ok=verifyECDSA({z,r:sig.r,s:sig.s,publicKey:parsePubkey(keys[keyIdx])});
          }catch{}
          if(ok)sigIdx++;
          keyIdx++;
          if(signatures.length-sigIdx>keys.length-keyIdx){valid=false;break;}
        }
        stack.push(valid&&sigIdx===signatures.length?Buffer.from([1]):Buffer.alloc(0));
        continue;
      }
      throw Error('unsupported op '+opcode.toString(16));
    }
  };
  exec(scriptSig,false);exec(lockScript,true);
  return {valid:stack.length===1&&stack[0].length>0&&stack[0][0]!==0,
    stackHeight:stack.length,nonPushOps:ops,lockBytes:lockScript.length/2};
}
