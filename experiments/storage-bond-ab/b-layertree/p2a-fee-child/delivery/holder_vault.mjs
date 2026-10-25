/** Offline, experimental holder receipt protocol for a FROST/P2A recovery manifest.
 * Signatures authenticate transport; a separately protected append-only anchor
 * detects rollback of the package directory. Bitcoin validity is verified by
 * the existing Bitcoin Core runner, not by this module.
 */
import {createHash, sign, verify} from 'node:crypto';
import {constants} from 'node:fs';
import {open, mkdir, readdir, readFile, rmdir, stat} from 'node:fs/promises';
import {join, resolve} from 'node:path';

const DELIVERY='bsb-p2a-holder-delivery-v1';
const ACK='bsb-p2a-holder-ack-v1';
const ANCHOR='bsb-p2a-holder-anchor-v1';
const NET='disposable-regtest-only';
const tag=(kind,obj)=>Buffer.concat([Buffer.from('BSB/'+kind+'/v1\0'),Buffer.from(JSON.stringify(obj))]);
const sha=b=>createHash('sha256').update(b).digest('hex');
const ok=(c,m)=>{if(!c)throw Error(m);};
const h64=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const b64=s=>{ok(typeof s==='string'&&s.length%4!==1&&/^[A-Za-z0-9+/]*={0,2}$/.test(s),'noncanonical base64');const b=Buffer.from(s,'base64');ok(b.toString('base64')===s,'noncanonical base64');return b;};
const keys=(o,names)=>{ok(o&&typeof o==='object'&&!Array.isArray(o)&&
  Object.keys(o).sort().join('|')===names.slice().sort().join('|'),'unexpected '+names[0]+' fields');};
const validHolder=h=>h==='alice'||h==='bob';
const fileName=n=>'g-'+String(n).padStart(8,'0')+'.json';
const asciiHex=s=>typeof s==='string'&&s.length>=120&&s.length%2===0&&/^[a-fA-F0-9]+$/.test(s);
const satsFor=(m,holder)=>holder==='alice'?m.aliceSats:m.bobSats;
const id=s=>typeof s==='string'&&/^[a-f0-9]{64}:[0-9]+$/.test(s);

/** Transport-only structural checks, deliberately NOT a Bitcoin script verifier. */
export function inspectManifest(bytes,holder,pinnedScript){
  ok(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=2_000_000,'manifest size');
  let m;try{m=JSON.parse(bytes.toString('utf8'));}catch{throw Error('manifest JSON');}
  ok(m?.schema==='bsb-frost-v3-p2a-frozen-v1'&&m.network===NET&&
    m.principalSats===100000&&m.aliceSats===60000&&m.bobSats===40000&&
    m.feeIndependentSignedParents===true&&m.zeroValueAnchorScriptPubkeyHex==='51024e73'&&
    m.beneficiaryScripts?.[holder]===pinnedScript&&
    Number.isSafeInteger(m.currentGeneration)&&m.currentGeneration>=0&&
    Array.isArray(m.generations)&&m.generations.length===m.currentGeneration+1,
    'manifest chain, principal or pinned beneficiary script mismatch');
  for(let i=0;i<m.generations.length;i++){
    const row=m.generations[i];
    ok(row?.generation===i&&id(row.carrierBefore)&&
      typeof row.carrierScriptPubkeyHex==='string'&&
      /^5120[a-f0-9]{64}$/.test(row.carrierScriptPubkeyHex),
      'invalid frozen generation carrier');
    for(const first of ['alice','bob']){
      const other=first==='alice'?'bob':'alice';
      const p=row.branches?.[first], a=satsFor(m,first), b=satsFor(m,other);
      ok(p?.otherOwner===other&&p.firstReceivesSats===a&&
        p.secondReceivesSats===b&&p.noFeeInputsInEitherFrostSignature===true,
        'missing complete alternative owner recovery');
      for(const [step,recipient,amount,input,outs] of [
        ['first',first,a,row.carrierBefore,[
          [b,row.carrierScriptPubkeyHex],[a,m.beneficiaryScripts[first]],[0,'51024e73']]],
        ['second',other,b,p?.first?.txid+':0',[[b,m.beneficiaryScripts[other]],[0,'51024e73']]]]){
        const t=p[step];
        ok(t?.generation===i&&t?.ownerOrder===(step==='first'?first:other)&&
          t.step===step&&t.version===3&&t.parentMinerFeeSats===0&&
          t.feeInputsSignedByFrost===false&&t.sighashType==='BIP341-SIGHASH_DEFAULT'&&
          t.anchorScript==='51024e73'&&t.anchorIndex===outs.length-1&&
          t.carrierInput===input&&t.carrierOutputSats===(step==='first'?100000:b)&&
          h64(t.txid)&&h64(t.wtxid)&&asciiHex(t.signedHex)&&
          Array.isArray(t.outputAgreement)&&t.outputAgreement.length===outs.length&&
          outs.every(([value,script],j)=>t.outputAgreement[j]?.vout===j&&
            t.outputAgreement[j].sats===value&&t.outputAgreement[j].script===script),
          'missing or mismatched frozen signed parent for '+recipient);
      }
      ok(p.descendantOutpoint===p.first.txid+':0',
        'wrong successor outpoint');
    }
  }
  return m;
}

export function issueDelivery({holder,manifestBytes,previousDeliveryDigest=null,signingKey,pinnedScript}){
  ok(validHolder(holder),'invalid holder');
  ok(previousDeliveryDigest===null||h64(previousDeliveryDigest),'bad previous delivery digest');
  const m=inspectManifest(manifestBytes,holder,pinnedScript);
  const row=m.generations[m.currentGeneration];
  const payload={schema:DELIVERY,network:NET,holder,generation:m.currentGeneration,
    previousDeliveryDigest,carrierBefore:row.carrierBefore,
    holderScript:pinnedScript,manifestSha256:sha(manifestBytes),
    manifestBase64:manifestBytes.toString('base64')};
  const signature=sign(null,tag('P2A-DELIVERY',payload),signingKey).toString('base64');
  return {payload,signature};
}

export function authenticateDelivery(envelope,{holder,signerPublicKey,pinnedScript}){
  keys(envelope,['payload','signature']);
  const p=envelope.payload;
  keys(p,['schema','network','holder','generation','previousDeliveryDigest',
    'carrierBefore','holderScript','manifestSha256','manifestBase64']);
  ok(p.schema===DELIVERY&&p.network===NET&&p.holder===holder&&
    p.holderScript===pinnedScript&&Number.isSafeInteger(p.generation)&&
    p.generation>=0&&(p.previousDeliveryDigest===null||h64(p.previousDeliveryDigest))&&
    h64(p.manifestSha256)&&id(p.carrierBefore),'wrong signed delivery domain or holder');
  const bytes=b64(p.manifestBase64);
  ok(sha(bytes)===p.manifestSha256,'manifest bytes replaced');
  const m=inspectManifest(bytes,holder,pinnedScript);
  ok(p.generation===m.currentGeneration&&
    p.carrierBefore===m.generations[m.currentGeneration].carrierBefore,
    'signed envelope not bound to latest carrier');
  ok(verify(null,tag('P2A-DELIVERY',p),signerPublicKey,b64(envelope.signature)),
    'delivery signature rejected');
  return {generation:p.generation,deliveryDigest:sha(Buffer.from(JSON.stringify(envelope))),
    manifestSha256:p.manifestSha256,carrierBefore:p.carrierBefore,
    previousDeliveryDigest:p.previousDeliveryDigest};
}

async function syncDir(dir){const d=await open(dir,'r');try{await d.sync();}finally{await d.close();}}
async function writeOnce(dir,name,obj){
  const filename=join(dir,name);
  const f=await open(filename,constants.O_CREAT|constants.O_EXCL|
    constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
  try{await f.writeFile(JSON.stringify(obj)+'\n');await f.sync();}
  finally{await f.close();}
  await syncDir(dir);
}
const numbered=f=>/^g-[0-9]{8,}\.json$/.test(f);

/** An anchor directory MUST be on storage the package adversary cannot rewind. */
export async function readHolderState({packageDir,anchorDir,holder,signerPublicKey,pinnedScript}){
  ok(resolve(packageDir)!==resolve(anchorDir),'anchor must be separate from package directory');
  await mkdir(packageDir,{recursive:true,mode:0o700});
  await mkdir(anchorDir,{recursive:true,mode:0o700});
  ok((await stat(packageDir)).isDirectory()&&(await stat(anchorDir)).isDirectory(),
    'unsafe vault directory');
  const [packages,anchors]=await Promise.all([readdir(packageDir),readdir(anchorDir)]);
  const ps=packages.filter(numbered).sort(),as=anchors.filter(numbered).sort();
  ok(ps.length===packages.length&&as.length===anchors.filter(f=>f!=='.writer-lock').length,
    'unexpected vault files or pending package');
  ok(ps.join('|')===as.join('|'),'anchor/package mismatch or interrupted write');
  let previous=null,latest=null;
  for(const filename of ps){
    let obj, anchor;
    try{obj=JSON.parse(await readFile(join(packageDir,filename),'utf8'));
      anchor=JSON.parse(await readFile(join(anchorDir,filename),'utf8'));}
    catch{throw Error('truncated or missing recovery record');}
    const verified=authenticateDelivery(obj,{holder,signerPublicKey,pinnedScript});
    keys(anchor,['schema','holder','generation','deliveryDigest','previousDeliveryDigest']);
    ok(anchor.schema===ANCHOR&&anchor.holder===holder&&
      filename===fileName(verified.generation)&&
      (previous===null||verified.generation===previous.generation+1)&&
      anchor.generation===verified.generation&&
      anchor.deliveryDigest===verified.deliveryDigest&&
      anchor.previousDeliveryDigest===verified.previousDeliveryDigest&&
      verified.previousDeliveryDigest===(previous?.deliveryDigest??null),
      'rollback, fork, gap or corrupted recovery checkpoint');
    latest=verified;previous=verified;
  }
  return latest;
}

export function makeAck(state,holder,holderPrivateKey){
  const payload={schema:ACK,network:NET,holder,generation:state.generation,
    deliveryDigest:state.deliveryDigest,manifestSha256:state.manifestSha256,
    carrierBefore:state.carrierBefore};
  return {payload,signature:sign(null,tag('P2A-ACK',payload),holderPrivateKey).toString('base64')};
}
export function verifyAck(ack,holder,holderPublicKey,expected){
  keys(ack,['payload','signature']);
  keys(ack.payload,['schema','network','holder','generation','deliveryDigest',
    'manifestSha256','carrierBefore']);
  const p=ack.payload;
  ok(p.schema===ACK&&p.network===NET&&p.holder===holder&&
    p.generation===expected.generation&&p.manifestSha256===expected.manifestSha256&&
    p.carrierBefore===expected.carrierBefore&&h64(p.deliveryDigest)&&
    (!expected.deliveryDigest||p.deliveryDigest===expected.deliveryDigest)&&
    verify(null,tag('P2A-ACK',p),holderPublicKey,b64(ack.signature)),
    'unsigned, stale or mismatched holder acknowledgement');
  return true;
}
export function refreshAcknowledged(acks,holderKeys,expected){
  ok(acks&&typeof acks==='object'&&Object.keys(acks).sort().join('|')==='alice|bob',
    'both independent holders must acknowledge one exact signed generation');
  for(const holder of ['alice','bob'])verifyAck(acks[holder],holder,holderKeys[holder],expected);
  return true;
}

export async function receiveDelivery({packageDir,anchorDir,holder,signerPublicKey,
  pinnedScript,holderPrivateKey,envelope}){
  ok(validHolder(holder),'invalid holder');
  const verified=authenticateDelivery(envelope,{holder,signerPublicKey,pinnedScript});
  await mkdir(anchorDir,{recursive:true,mode:0o700});
  const lock=join(anchorDir,'.writer-lock');
  await mkdir(lock,{mode:0o700}); // concurrent writers / crashed previous delivery fail closed
  try{
    const previous=await readHolderState({packageDir,anchorDir,holder,
      signerPublicKey,pinnedScript});
    ok((previous===null&&verified.previousDeliveryDigest===null)||
      (previous!==null&&verified.generation===previous.generation+1&&
        verified.previousDeliveryDigest===previous.deliveryDigest),
      'stale, skipped or equivocating delivery rejected');
    await writeOnce(packageDir,fileName(verified.generation),envelope);
    await writeOnce(anchorDir,fileName(verified.generation),{
      schema:ANCHOR,holder,generation:verified.generation,
      deliveryDigest:verified.deliveryDigest,
      previousDeliveryDigest:verified.previousDeliveryDigest});
    const committed=await readHolderState({packageDir,anchorDir,holder,
      signerPublicKey,pinnedScript});
    ok(committed.deliveryDigest===verified.deliveryDigest,
      'holder durable checkpoint verification failed');
    return makeAck(committed,holder,holderPrivateKey);
  }finally{await rmdir(lock);await syncDir(anchorDir);}
}
