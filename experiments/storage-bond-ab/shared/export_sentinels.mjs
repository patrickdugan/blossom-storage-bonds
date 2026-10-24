#!/usr/bin/env node
/**
 * Export the SHARED A/B Blossom SHA256-PDP scenarios as real Taproot sentinel
 * witness commitments for the unchanged Phase-1 Rust Bitcoin Core harness.
 *
 * This is reproducible research evidence, not a live provider erasure proof:
 * the old Rust fixture demands all preimages at construction time, including
 * the counterfactual opening for an "offline/deleted" participant. Such bytes
 * are PUBLIC TEST VALUES and could be reused by an adversarial respondent.
 * We test Bitcoin Script commitment and honest storage/Merkle arithmetic,
 * NOT a provider's inability to recover data from this fixture.
 */
import {readFile, mkdir, open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve, join} from 'node:path';
import {scenario, challenge} from './scenario.mjs';
const sha256=data=>createHash('sha256').update(data).digest('hex');
const yes=(ok,msg)=>{if(!ok)throw Error(msg);};
const hex=b=>Buffer.from(b).toString('hex');
function equal(a,b){return Buffer.from(a).equals(Buffer.from(b));}
const base='storage-fault';
const originalWidePath=new URL('../../../fixtures/sentinels.json',import.meta.url);
function eventFor(config,holder,epoch) {
  const e=config.events.find(e=>e.kind==='proof'&&e.id===holder&&e.epoch===epoch);
  return e ?? {kind:'proof',id:holder,epoch,height:epoch+40,storage:'intact'};
}

export async function prepareFixtures() {
  const config=scenario(base);
  const original=JSON.parse(await readFile(originalWidePath,'utf8'));
  const wide=original.wide;
  yes(typeof wide?.preimage==='string' && wide.preimage.length===1040,
    'original wide relay-policy fixture missing');
  const produced=[];
  for(const holder of ['alice','bob']) {
    const sentinels=[],evidence=[];
    let root=null;
    for(const epoch of [1,2,3]) {
      const e=eventFor(config,holder,epoch);
      const observed=challenge(e);
      const counterfactual=challenge({...e,storage:'intact',assertedVerdict:undefined});
      yes(observed.root===counterfactual.root &&
        equal(observed.witness.sentinel.r,counterfactual.witness.sentinel.r) &&
        equal(observed.witness.sentinel.h,counterfactual.witness.sentinel.h),
        'source commitment changed when data was deleted');
      yes(counterfactual.verified===true &&
        counterfactual.witness.response?.length===80,'intact reference proof/response missing');
      yes(observed.witness.wrong.length===80 &&
        observed.witness.wrong.subarray(0,16).equals(observed.witness.sentinel.r),
        'malformed adjacent-chunk attack witness');
      const sen=observed.witness.sentinel;
      const response=counterfactual.witness.response;
      yes(sha256(sen.r)===hex(sen.s) &&
        sha256(response)===hex(sen.h) &&
        sha256(observed.witness.wrong)!==hex(sen.h),
        'Merkle-derived sentinel hash mismatch');
      if(root!==null)yes(observed.root===root,'participant commitment root changed');
      root=observed.root;
      if(holder==='alice'&&epoch===2) {
        yes(observed.verified===false && observed.witness.response===null &&
          observed.deletedChunk!==null &&
          observed.selected.includes(observed.deletedChunk),
          'deleted Alice data did not actually fail reference Merkle verification');
      } else yes(observed.verified===true,'unexpected missing storage evidence for '+holder+'/'+epoch);
      sentinels.push({
        i:epoch-1,
        idx:sen.idx,
        r:hex(sen.r),s:hex(sen.s),h:hex(sen.h),
        preimage:hex(response),
        wrong_preimage:hex(observed.witness.wrong),
      });
      evidence.push({
        epoch, sourceProofRoot:observed.root,sourceEvidenceHash:observed.evidenceHash,
        sourceVerdict:observed.verified?'pass':'fault',
        storageCase:e.storage,
        nonce:observed.nonce,
        selectedChunks:observed.selected,
        sentinelChunk:Math.floor(sen.idx/64),
        publicCounterfactualOpeningIncluded:observed.witness.response===null,
        hypotheticalEpoch:!config.events.some(q=>
          q.kind==='proof'&&q.id===holder&&q.epoch===epoch),
      });
    }
    const fixture={
      n:8,root,sentinels,wide,
      fixtureClass:'SHARED_BLOSSOM_PDP_WITH_PUBLIC_COUNTERFACTUAL_PREIMAGES',
      holder,proofScenario:base,
      independentMerkleEvidence:evidence,
    };
    produced.push({holder,fixture,evidence});
  }
  return produced;
}

export async function emit(outDir) {
  yes(typeof outDir==='string'&&outDir.length>0,'supply --out directory');
  const path=resolve(outDir);
  await mkdir(path,{recursive:true,mode:0o700});
  const prepared=await prepareFixtures(),files=[];
  async function save(name,data){
    const target=join(path,name);
    const raw=JSON.stringify(data,null,2)+'\n';
    const handle=await open(target,'wx',0o600);
    try{await handle.writeFile(raw);await handle.sync();}finally{await handle.close();}
    return {file:name,sha256:sha256(Buffer.from(raw)),bytes:Buffer.byteLength(raw)};
  }
  for(const {holder,fixture,evidence} of prepared) {
    const written=await save(holder+'-sentinels.json',fixture);
    files.push({...written,holder,sourceRoot:fixture.root,
      observations:evidence});
  }
  const manifest={
    schema:'bsb-ab-pdp-to-taproot-fixture-v1',
    scenario:base,source:'reference-SHA256-Merkle-implementation',
    network:'disposable-regtest-only',
    generatedFromPublishedTestData:true,
    demonstratesCryptographicStorageNonavailability:false,
    publicCounterfactualDeletedPreimageIncluded:true,
    originalRustSentinelScriptUnchanged:true,
    files,
  };
  await save('pdp-taproot-manifest.json',manifest);
  return manifest;
}
async function main(args) {
  yes(args.length===2&&args[0]==='--out','usage: node export_sentinels.mjs --out PRIVATE-DIR');
  const r=await emit(args[1]);
  console.log(JSON.stringify({schema:r.schema,scenario:r.scenario,
    sourceRoots:r.files.map(f=>({holder:f.holder,root:f.sourceRoot,hash:f.sha256})),
    deletedAliceEpoch2:r.files[0].observations[1].sourceVerdict==='fault',
    doesNotProveDataWithholding:true},null,2));
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===resolve(process.argv[1])){
  main(process.argv.slice(2)).catch(e=>{console.error(e.message);process.exitCode=1;});
}
