// Check a fully copied proof return against this graph's snapshot and setup terms.
// Metadata checks do not verify a proof: the coordinator must run the native Groth16
// verifier before it supplies a request to the waiting one-time signer.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { termJournal, termPreimage, termPublicInput, wrapConstantsDigest } from "../../model/bitvm_term.ts";

export const RETURN_FILES = ["fixture.json","ids.json","chain.json","term.json","g16/groth16.json","g16/vk.json","g16/proof.json","g16/public.json"];
export const READY_FILE = "RETURN_READY.json";
export interface ProofSetup { network: string; prefix: string; constants_digest: string; vk_sha256: string }
const sha = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");
const json = (path: string): any => {
  assert.ok(statSync(path).size < 8_000_000, `unexpected JSON file size: ${path}`);
  const text=readFileSync(path,"utf8").trim();
  try{return JSON.parse(text);}catch{return JSON.parse(text.split("\n").pop()!);}
};
export function checkProofReturn(snapshotDir: string, returned: string, setup: ProofSetup) {
  const snapshot=json(join(snapshotDir,"snapshot.json")),fixture=json(join(returned,"fixture.json"));
  assert.equal(snapshot.format,"bsb/fresh-proof-snapshot/v1");assert.equal(snapshot.network,"regtest");assert.equal(setup.network,"regtest");
  assert.equal(snapshot.expected_preimage.slice(0,268),setup.prefix,"snapshot differs from the setup-time term");
  assert.equal(fixture.m2.term.preimage,snapshot.expected_preimage,"returned proof belongs to a different chain snapshot");
  assert.deepEqual(fixture.snapshot,snapshot,"returned snapshot manifest differs from the graph's own inputs");
  const ids=json(join(returned,"ids.json"));
  for(const name of ["hold","term","header_chain"])assert.equal(ids[name],snapshot.image_ids[name],`returned ${name} image differs`);
  const hashes=json(join(snapshotDir,"chain/hashes.json"));assert.equal(hashes.chain,"regtest");
  const t=snapshot.term;
  const term={holdId:Buffer.from(snapshot.image_ids.hold,"hex"),headerChainId:Buffer.from(snapshot.image_ids.header_chain,"hex"),q:t.q,dealCount:t.deal_count,dealsDigest:Buffer.from(t.deals_digest,"hex"),firstHeight:t.first,step:t.step,epochs:t.epochs,depth:t.depth};
  const claim={tipHeight:snapshot.chain.tip_height,tipHash:Buffer.from(snapshot.chain.tip_hash,"hex").reverse(),totalWork:BigInt(snapshot.chain.total_work)};
  assert.equal(hashes.hashes.length,claim.tipHeight+1);assert.equal(hashes.hashes[claim.tipHeight],snapshot.chain.tip_hash);
  const preimage=termPreimage(term,claim).toString("hex"),journal=termJournal(term,claim).toString("hex");
  assert.equal(preimage,snapshot.expected_preimage);assert.equal(journal,snapshot.expected_journal);
  const provenTerm=json(join(returned,"term.json"));assert.deepEqual(provenTerm,fixture.m2.term);
  assert.equal(provenTerm.preimage,preimage);assert.equal(provenTerm.journal,journal);assert.equal(provenTerm.image_id,snapshot.image_ids.term);
  for(const name of ["first","step","epochs","depth"])assert.equal(provenTerm[name],t[name]);
  const chain=json(join(returned,"chain.json"));assert.deepEqual(chain,fixture.m2.header_chain);
  assert.equal(chain.tip_height,claim.tipHeight);assert.equal(chain.tip_hash,snapshot.chain.tip_hash);assert.equal(BigInt("0x"+chain.total_work),claim.totalWork);
  assert.equal(fixture.m2.holds.length,t.epochs);
  for(let i=0;i<t.epochs;i++){
    const height=t.first+i*t.step,hold=fixture.m2.holds[i],statement=json(join(snapshotDir,`hold-${height}/statement.json`));
    assert.equal(hold.height,height);assert.equal(hold.journal,statement.journal);assert.equal(hold.image_id,snapshot.image_ids.hold);
  }
  const g=json(join(returned,"g16/groth16.json"));assert.deepEqual(g,fixture.m3.groth16);
  assert.equal(g.journal,journal);assert.equal(g.pre_state,snapshot.image_ids.term);
  const constants={controlRoot:Buffer.from(g.control_root,"hex"),termId:Buffer.from(g.pre_state,"hex"),postState:Buffer.from(g.post_state,"hex"),bn254ControlId:Buffer.from(g.bn254_control_id,"hex")};
  assert.equal(wrapConstantsDigest(constants).toString("hex"),setup.constants_digest);
  const expected=termPublicInput(term,claim,constants).toString();
  assert.equal(g.public_output_dec,expected);assert.deepEqual(json(join(returned,"g16/public.json")),[expected]);
  assert.equal(sha(readFileSync(join(returned,"g16/vk.json"))),setup.vk_sha256);
  assert.deepEqual(json(join(returned,"g16/proof.json")),g.proof);
  return {snapshot,publicInput:expected,files:Object.fromEntries(RETURN_FILES.map(name=>[name,sha(readFileSync(join(returned,name)))]))};
}
export function sealProofReturn(snapshotDir:string,returned:string,setup:ProofSetup):void{
  const checked=checkProofReturn(snapshotDir,returned,setup);
  writeFileSync(join(returned,READY_FILE),JSON.stringify({format:"bsb/proof-return-ready/v1",snapshot_journal:checked.snapshot.expected_journal,files:checked.files,verification:"metadata and file hashes only; native Groth16 verification still required"},null,2)+"\n",{flag:"wx"});
}
export function checkProofReturnReady(snapshotDir:string,returned:string,setup:ProofSetup){
  const ready=json(join(returned,READY_FILE));assert.equal(ready.format,"bsb/proof-return-ready/v1");
  const checked=checkProofReturn(snapshotDir,returned,setup);
  assert.equal(ready.snapshot_journal,checked.snapshot.expected_journal);assert.deepEqual(ready.files,checked.files,"returned files changed after their transfer was sealed");
  return checked;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [snapshotDir,returned,terms]=process.argv.slice(2);assert.ok(snapshotDir&&returned&&terms,"<snapshot-dir> <copied-proof-dir> <terms.json>");
  sealProofReturn(resolve(snapshotDir),resolve(returned),json(resolve(terms)));
  console.log(JSON.stringify({transferReady:join(resolve(returned),READY_FILE),proofVerified:false}));
}
