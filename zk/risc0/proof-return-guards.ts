// Exercise the transfer gate using a real graph snapshot and a deliberately replayed old proof.
// The forged case must pass metadata checks and fail the native pairing equation.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { termPublicInput } from "../../model/bitvm_term.ts";
import { checkProofReturn, checkProofReturnReady, sealProofReturn } from "./proof-return.ts";

const opt=(name:string)=>{const i=process.argv.indexOf(`--${name}`);return i<0?undefined:process.argv[i+1];};
const req=(name:string)=>{const value=opt(name);assert.ok(value,`--${name} required`);return value;};
const snapshotDir=resolve(req("snapshot")),terms=resolve(req("terms")),checker=req("checker"),out=resolve(req("dir"));
assert.ok(!existsSync(out),"guard output directory must be new");mkdirSync(out);
const json=(path:string)=>JSON.parse(readFileSync(path,"utf8"));
const save=(path:string,value:any)=>writeFileSync(path,JSON.stringify(value,null,2)+"\n");
const repo=resolve(dirname(fileURLToPath(import.meta.url)),"../..");
const old=json(join(repo,"results/bitvm2-spike.json")),snapshot=json(join(snapshotDir,"snapshot.json")),setup=json(terms);
assert.notEqual(old.m2.term.preimage,snapshot.expected_preimage,"test requires a new chain snapshot");
const stale=join(out,"stale");mkdirSync(stale);save(join(stale,"fixture.json"),old);
assert.throws(()=>checkProofReturn(snapshotDir,stale,setup),/different chain snapshot/);

const forged=join(out,"forged-metadata"),g16=join(forged,"g16");mkdirSync(forged);mkdirSync(g16);
const fixture=structuredClone(old);fixture.snapshot=structuredClone(snapshot);
const chain=fixture.m2.header_chain,term=fixture.m2.term,g=fixture.m3.groth16,t=snapshot.term;
g.proof=json(join(repo,"results/bitvm2-spike-groth16/proof.json"));
chain.tip_height=snapshot.chain.tip_height;chain.tip_hash=snapshot.chain.tip_hash;chain.total_work=BigInt(snapshot.chain.total_work).toString(16).padStart(64,"0");
term.preimage=snapshot.expected_preimage;term.journal=snapshot.expected_journal;term.image_id=snapshot.image_ids.term;
for(const name of ["first","step","epochs","depth"])term[name]=t[name];
fixture.m2.holds=Array.from({length:t.epochs},(_,i)=>{
  const height=t.first+i*t.step,statement=json(join(snapshotDir,`hold-${height}/statement.json`));
  return {height,journal:statement.journal,image_id:snapshot.image_ids.hold};
});
const publicInput=termPublicInput({holdId:Buffer.from(snapshot.image_ids.hold,"hex"),headerChainId:Buffer.from(snapshot.image_ids.header_chain,"hex"),q:t.q,dealCount:t.deal_count,dealsDigest:Buffer.from(t.deals_digest,"hex"),firstHeight:t.first,step:t.step,epochs:t.epochs,depth:t.depth},
  {tipHeight:snapshot.chain.tip_height,tipHash:Buffer.from(snapshot.chain.tip_hash,"hex").reverse(),totalWork:BigInt(snapshot.chain.total_work)},
  {controlRoot:Buffer.from(g.control_root,"hex"),termId:Buffer.from(g.pre_state,"hex"),postState:Buffer.from(g.post_state,"hex"),bn254ControlId:Buffer.from(g.bn254_control_id,"hex")}).toString();
g.journal=snapshot.expected_journal;g.public_output_dec=publicInput;
g.public_output_hex=BigInt(publicInput).toString(16).padStart(62,"0");g.expected_output_hex=g.public_output_hex;
save(join(forged,"fixture.json"),fixture);save(join(forged,"ids.json"),snapshot.image_ids);
save(join(forged,"chain.json"),chain);save(join(forged,"term.json"),term);
save(join(g16,"groth16.json"),g);save(join(g16,"proof.json"),g.proof);save(join(g16,"public.json"),[publicInput]);
writeFileSync(join(g16,"vk.json"),readFileSync(join(snapshotDir,"vk.json")));
sealProofReturn(snapshotDir,forged,setup);assert.equal(checkProofReturnReady(snapshotDir,forged,setup).publicInput,publicInput);
const native=spawnSync(checker,[g16,"--wrong-public",publicInput==="1"?"2":"1","--verify-only"],{encoding:"utf8",windowsHide:true,timeout:120_000});
if(native.error)throw native.error;
assert.notEqual(native.status,0);assert.match(native.stdout,/arkworks: honest false/);
writeFileSync(join(out,"native-rejection.log"),native.stdout+native.stderr);

const publicFile=join(g16,"public.json"),originalPublic=readFileSync(publicFile);
writeFileSync(publicFile,Buffer.concat([originalPublic,Buffer.from("\n")]));
assert.throws(()=>checkProofReturnReady(snapshotDir,forged,setup),/returned files changed/);
writeFileSync(publicFile,originalPublic);
const idsFile=join(forged,"ids.json"),originalIds=readFileSync(idsFile);
save(idsFile,{...snapshot.image_ids,term:"00".repeat(32)});
assert.throws(()=>checkProofReturn(snapshotDir,forged,setup),/returned term image differs/);writeFileSync(idsFile,originalIds);
assert.throws(()=>checkProofReturn(snapshotDir,forged,{...setup,constants_digest:"00".repeat(32)}));
fixture.snapshot.generated+=" altered";save(join(forged,"fixture.json"),fixture);
assert.throws(()=>checkProofReturn(snapshotDir,forged,setup),/snapshot manifest differs/);
// Leave a consistent, explicitly counterfeit return for a coordinator rejection test.
fixture.snapshot.generated=snapshot.generated;save(join(forged,"fixture.json"),fixture);
assert.equal(checkProofReturnReady(snapshotDir,forged,setup).publicInput,publicInput);
const result={network:"regtest",snapshotJournal:snapshot.expected_journal,staleSnapshotRejected:true,forgedMetadataAcceptedWithoutClaimingProofValidity:true,replayedProofRejectedByNativePairing:true,changedCopiedFileRejected:true,changedGuestIdRejected:true,changedWrapperRejected:true,changedManifestRejected:true,scope:"Transfer and cryptographic guards only; no provider signatures requested or generated"};
save(join(out,"results.json"),result);console.log(JSON.stringify(result));
