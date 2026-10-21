// Native provider guards, without a Bitcoin node. No secret keys are logged or saved.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
const opt=(name:string)=>{const i=process.argv.indexOf(`--${name}`);return i<0?undefined:process.argv[i+1];};
const req=(name:string)=>{const value=opt(name);assert.ok(value,`--${name} required`);return value;};
const checker=req("checker"),dir=resolve(req("dir")),checked=resolve(req("assertions"));
assert.ok(!existsSync(dir),"guard directory must be new");mkdirSync(dir);
const repo=resolve(dirname(fileURLToPath(import.meta.url)),"../..");
const fixturePath=join(repo,"results/bitvm2-spike.json"),proofDir=join(repo,"results/bitvm2-spike-groth16");
const fixture=JSON.parse(readFileSync(fixturePath,"utf8"));
const original={format:"bsb/storage-setup/v1",network:"regtest",prefix:fixture.m2.term.preimage.slice(0,268),constants_digest:fixture.m3.groth16.constants_digest,vk_sha256:"2941dff0bd962ff8610773c9659c10d0dec561db1e2f6afecfbbe0d9cb457a7d",config:{term_end:220,kickoff_deadline:240,final_deadline:290,challenge_blocks:6,assert_blocks:12,dispute_blocks:6,slot_value:20_000,marker_value:1_000_000}};
const results:any[]=[];
for(const kind of ["wrong-term","wrong-wrapper","false-proof","unchecked-assertions","one-shot"]){
  const setup=structuredClone(original),caseDir=join(dir,kind);mkdirSync(caseDir);
  if(kind==="wrong-term"){const prefix=Buffer.from(setup.prefix,"hex");prefix.writeUInt32BE(17,78);setup.prefix=prefix.toString("hex");}
  if(kind==="wrong-wrapper"){const constants=Buffer.from(setup.constants_digest,"hex");constants[0]^=1;setup.constants_digest=constants.toString("hex");}
  const terms=join(caseDir,"terms.json"),output=join(caseDir,"witnesses.json"),second=join(caseDir,"must-not-be-signed.json");writeFileSync(terms,JSON.stringify(setup));
  let selectedProof=proofDir,selectedAssertions=checked;
  if(kind==="false-proof"){
    selectedProof=join(caseDir,"false-proof");mkdirSync(selectedProof);
    for(const name of ["vk.json","public.json"])writeFileSync(join(selectedProof,name),readFileSync(join(proofDir,name)));
    const proof=JSON.parse(readFileSync(join(proofDir,"proof.json"),"utf8"));proof.pi_a=["1","2","1"];writeFileSync(join(selectedProof,"proof.json"),JSON.stringify(proof));
  }
  if(kind==="unchecked-assertions"){
    const assertions=JSON.parse(readFileSync(checked,"utf8"));assertions.scripts_checked=false;
    selectedAssertions=join(caseDir,"unchecked.json");writeFileSync(selectedAssertions,JSON.stringify(assertions));
  }
  const process=spawn(checker,["provider",terms],{windowsHide:true,stdio:["pipe","pipe","pipe"]});
  let stderr="",ready=false,completed=false;
  process.stderr!.on("data",data=>{stderr+=String(data);});
  const lines=createInterface({input:process.stdout!});
  lines.on("line",line=>{
    if(!line.startsWith("BSB_LIFECYCLE "))return;
    const event=JSON.parse(line.slice(14));
    if(event.provider_ready){
      ready=true;
      const request={fixture:fixturePath,proof_dir:selectedProof,assertions:selectedAssertions,output};
      // Even if a second complete request is queued, the signer must exit after the first.
      process.stdin!.end(JSON.stringify(request)+"\n"+(kind==="one-shot"?JSON.stringify({...request,output:second})+"\n":""));
    }
    if(event.provider_complete)completed=true;
  });
  const code=await new Promise<number|null>((ok,bad)=>{process.once("error",bad);process.once("close",ok);});lines.close();
  assert.equal(ready,true,`${kind}: provider must first commit fresh public keys`);
  if(kind==="one-shot"){
    assert.equal(code,0);assert.equal(completed,true);assert.ok(existsSync(output));assert.ok(!existsSync(second));
    results.push({case:kind,signedRequests:1,secondRequestSigned:false});
  }else{
    assert.notEqual(code,0);assert.equal(completed,false);assert.ok(!existsSync(output));
    const reason=kind==="wrong-term"?/setup-time term/:kind==="wrong-wrapper"?/setup-time image/:kind==="false-proof"?/verify_proof/:/scripts_checked|left: Bool\(false\)/;
    assert.match(stderr,reason);
    results.push({case:kind,rejected:true,witnessFileWritten:false});
  }
}
writeFileSync(join(dir,"results.json"),JSON.stringify({guards:results},null,2)+"\n");
console.log(JSON.stringify({guardsPassed:results.length,result:join(dir,"results.json")}));
