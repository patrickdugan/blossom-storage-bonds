import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtemp,mkdir,readFile,writeFile,rm,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {issueDelivery,receiveDelivery,readHolderState,authenticateDelivery,
  refreshAcknowledged,inspectManifest,verifyAck} from './holder_vault.mjs';

const hash=s=>createHash('sha256').update(s).digest('hex');
const scripts={alice:'0014'+'11'.repeat(20),bob:'0014'+'22'.repeat(20)};
const V='5120'+'cd'.repeat(32);
function parent(i,first,step,carrier,outputs){
  const txid=hash(i+':'+first+':'+step);
  return {generation:i,ownerOrder:step==='first'?first:(first==='alice'?'bob':'alice'),
    step,txid,wtxid:hash(txid),signedHex:'030000000001'+('ee'.repeat(150)),
    vsize:250,version:3,carrierInput:carrier,
    carrierOutputSats:step==='first'?100000:(first==='alice'?40000:60000),
    anchorIndex:outputs.length-1,anchorScript:'51024e73',
    parentMinerFeeSats:0,feeInputsSignedByFrost:false,
    sighashType:'BIP341-SIGHASH_DEFAULT',
    outputAgreement:outputs.map(([sats,script],vout)=>({vout,sats,script}))};
}
function toyManifest(current){
  const rows=[];
  for(let i=0;i<=current;i++){
    const carrier=hash('carrier-'+i)+':0',branches={};
    for(const first of ['alice','bob']){
      const other=first==='alice'?'bob':'alice';
      const a=first==='alice'?60000:40000,b=100000-a;
      const firstTx=parent(i,first,'first',carrier,[[b,V],[a,scripts[first]],[0,'51024e73']]);
      const secondTx=parent(i,first,'second',firstTx.txid+':0',[[b,scripts[other]],[0,'51024e73']]);
      branches[first]={first:firstTx,second:secondTx,firstReceivesSats:a,
        secondReceivesSats:b,otherOwner:other,
        descendantOutpoint:firstTx.txid+':0',noFeeInputsInEitherFrostSignature:true};
    }
    rows.push({generation:i,carrierBefore:carrier,carrierScriptPubkeyHex:V,
      branches,refreshBroadcast:i<current?{txid:hash('refresh-'+i)}:null});
  }
  return Buffer.from(JSON.stringify({schema:'bsb-frost-v3-p2a-frozen-v1',
    network:'disposable-regtest-only',principalSats:100000,aliceSats:60000,
    bobSats:40000,feeIndependentSignedParents:true,
    zeroValueAnchorScriptPubkeyHex:'51024e73',beneficiaryScripts:scripts,
    currentGeneration:current,generations:rows}));
}
async function fixture(t){
  const base=await mkdtemp(join(tmpdir(),'bsb-holder-delivery-'));
  t.after(()=>rm(base,{recursive:true,force:true}));
  const sender=generateKeyPairSync('ed25519');
  const holders={alice:generateKeyPairSync('ed25519'),bob:generateKeyPairSync('ed25519')};
  const opts=h=>({packageDir:join(base,h,'packages'),anchorDir:join(base,h+'-anchor'),
    holder:h,signerPublicKey:sender.publicKey,pinnedScript:scripts[h],
    holderPrivateKey:holders[h].privateKey});
  const issue=(h,manifest,prev=null)=>issueDelivery({holder:h,manifestBytes:manifest,
    previousDeliveryDigest:prev,signingKey:sender.privateKey,pinnedScript:scripts[h]});
  const receive=(h,e)=>receiveDelivery({...opts(h),envelope:e});
  const state=h=>readHolderState(opts(h));
  const publicKeys={alice:holders.alice.publicKey,bob:holders.bob.publicKey};
  return {base,opts,issue,receive,state,publicKeys,holders,sender};
}

// The small synthetic manifest is intentionally STRUCTURAL; only the actual
// Bitcoin Core runner authenticates the real FROST transaction witnesses.
test('each holder durably acknowledges an identical signed generation',async t=>{
  const f=await fixture(t),m=toyManifest(2),expected={generation:2,
    manifestSha256:hash(m),carrierBefore:JSON.parse(m).generations[2].carrierBefore};
  const a=await f.receive('alice',f.issue('alice',m));
  const b=await f.receive('bob',f.issue('bob',m));
  assert.ok(refreshAcknowledged({alice:a,bob:b},f.publicKeys,expected));
  assert.equal((await f.state('alice')).generation,2);
  assert.equal((await f.state('bob')).manifestSha256,hash(m));
  assert.notEqual(a.payload.deliveryDigest,b.payload.deliveryDigest);
  const files=await readdir(f.opts('alice').anchorDir);
  assert.deepEqual(files,['g-00000002.json']);
});

test('signed bytes, correct owner and pinned script are mandatory',async t=>{
  const f=await fixture(t),m=toyManifest(2);
  const original=f.issue('alice',m);
  const corrupted=structuredClone(original);
  corrupted.payload.manifestBase64=Buffer.from('tampered').toString('base64');
  assert.throws(()=>authenticateDelivery(corrupted,f.opts('alice')),/manifest bytes replaced/);
  const wrongHolder=structuredClone(original);
  wrongHolder.payload.holder='bob';
  assert.throws(()=>authenticateDelivery(wrongHolder,f.opts('alice')),/wrong signed delivery/);
  const old=generateKeyPairSync('ed25519');
  assert.throws(()=>authenticateDelivery(original,{...f.opts('alice'),signerPublicKey:old.publicKey}),
    /signature rejected/);
  const wrongScript=structuredClone(JSON.parse(m));
  wrongScript.beneficiaryScripts.alice='0014'+'99'.repeat(20);
  assert.throws(()=>inspectManifest(Buffer.from(JSON.stringify(wrongScript)),'alice',scripts.alice),
    /pinned beneficiary script/);
  const badAmount=structuredClone(JSON.parse(m));
  badAmount.generations[2].branches.alice.first.outputAgreement[1].sats=59999;
  assert.throws(()=>inspectManifest(Buffer.from(JSON.stringify(badAmount)),'alice',scripts.alice),
    /mismatched frozen signed parent/);
  const wrongWitness=structuredClone(JSON.parse(m));
  wrongWitness.generations[2].branches.alice.first.signedHex='aa';
  assert.throws(()=>inspectManifest(Buffer.from(JSON.stringify(wrongWitness)),'alice',scripts.alice),
    /mismatched frozen signed parent/);
});

test('restart, replay, equivocation, generation gaps and ancestry mismatch fail closed',async t=>{
  const f=await fixture(t),m2=toyManifest(2),m3=toyManifest(3),m4=toyManifest(4);
  const e2=f.issue('alice',m2);
  await f.receive('alice',e2);
  await assert.rejects(f.receive('alice',e2),/stale, skipped/);
  await assert.rejects(f.receive('alice',f.issue('alice',m3)),/stale, skipped/);
  await assert.rejects(f.receive('alice',f.issue('alice',m4,
    (await f.state('alice')).deliveryDigest)),/stale, skipped/);
  const e3=f.issue('alice',m3,(await f.state('alice')).deliveryDigest);
  await f.receive('alice',e3);
  assert.equal((await f.state('alice')).generation,3);
  await assert.rejects(f.receive('alice',f.issue('alice',m3,
    (await f.state('alice')).deliveryDigest)),/stale, skipped/);
  const swap=structuredClone(e3);
  swap.payload.carrierBefore=hash('swapped')+':0';
  assert.throws(()=>authenticateDelivery(swap,f.opts('alice')),
    /not bound to latest carrier/);
});

test('disk rollback, tampering and partial write are caught using separate anchor',async t=>{
  const f=await fixture(t),m2=toyManifest(2),m3=toyManifest(3);
  await f.receive('alice',f.issue('alice',m2));
  const prior=await readFile(join(f.opts('alice').packageDir,'g-00000002.json'));
  await f.receive('alice',f.issue('alice',m3,(await f.state('alice')).deliveryDigest));
  await rm(join(f.opts('alice').packageDir,'g-00000003.json'));
  await assert.rejects(f.state('alice'),/anchor\/package mismatch/);
  await writeFile(join(f.opts('alice').packageDir,'g-00000003.json'),prior);
  await assert.rejects(f.state('alice'),/rollback, fork, gap/);
  await writeFile(join(f.opts('alice').packageDir,'g-00000003.json'),'{');
  await assert.rejects(f.state('alice'),/truncated or missing/);
  const g4=join(f.opts('alice').packageDir,'g-00000004.json');
  await writeFile(g4,'{}');
  await assert.rejects(f.state('alice'),/anchor\/package mismatch/);
});

test('holder ACK signature is independently authenticated and bound to same package',async t=>{
  const f=await fixture(t),m2=toyManifest(2),m3=toyManifest(3);
  const a=await f.receive('alice',f.issue('alice',m2));
  const b=await f.receive('bob',f.issue('bob',m2));
  const expected={generation:2,manifestSha256:hash(m2),
    carrierBefore:JSON.parse(m2).generations[2].carrierBefore};
  assert.ok(verifyAck(a,'alice',f.publicKeys.alice,expected));
  assert.throws(()=>refreshAcknowledged({alice:a,bob:a},f.publicKeys,expected),
    /holder acknowledgement/);
  const forged=structuredClone(a);forged.payload.manifestSha256=hash(m3);
  assert.throws(()=>verifyAck(forged,'alice',f.publicKeys.alice,expected),
    /holder acknowledgement/);
  assert.throws(()=>refreshAcknowledged({alice:a,bob:b},f.publicKeys,
    {...expected,generation:3}),/holder acknowledgement/);
  assert.throws(()=>refreshAcknowledged({alice:a},f.publicKeys,expected),
    /both independent holders/);
});

test('same source cannot record two competing updates under concurrent writers',async t=>{
  const f=await fixture(t),m2=toyManifest(2);
  const e=f.issue('alice',m2);
  const results=await Promise.allSettled([f.receive('alice',e),f.receive('alice',e)]);
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
  assert.equal(results.filter(x=>x.status==='rejected').length,1);
  assert.equal((await f.state('alice')).generation,2);
});
