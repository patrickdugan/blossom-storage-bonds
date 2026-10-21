// End-to-end refusal of a replayed proof whose metadata matches a new funded graph.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const opt=(name:string)=>{const i=process.argv.indexOf(`--${name}`);return i<0?undefined:process.argv[i+1];};
const req=(name:string)=>{const value=opt(name);assert.ok(value,`--${name} required`);return value;};
const root=resolve(req("dir")),output=resolve(req("out")),repo=resolve(dirname(fileURLToPath(import.meta.url)),"../..");
const checker=req("checker"),proofChecker=req("proof-checker"),partials=req("partials"),bitcoind=req("bitcoind");
assert.ok(!existsSync(root)&&!existsSync(output),"new test and output paths required");mkdirSync(root);
const nodeDir=join(root,"node"),returned=join(root,"returned"),mustNotExist=join(root,"must-not-exist.json"),guards=join(root,"guards");
const coordinator=spawn(process.execPath,[join(repo,"zk/bitvm-check/lifecycle-regtest.ts"),"--bitcoind",bitcoind,"--checker",checker,"--proof-checker",proofChecker,"--partials",partials,"--dir",nodeDir,"--out",mustNotExist,"--fresh-proof-dir",returned,"--proof-wait-ms","120000"],{windowsHide:true,stdio:["ignore","pipe","pipe"]});
let stdout="",stderr="";
coordinator.stderr!.on("data",data=>{stderr+=String(data);});
const exited=new Promise<number|null>((ok,bad)=>{coordinator.once("error",bad);coordinator.once("close",ok);});
const lines=createInterface({input:coordinator.stdout!});
const ready=new Promise<any>((ok,bad)=>{
  lines.on("line",line=>{stdout+=line+"\n";try{const event=JSON.parse(line);if(event.proofJobReady)ok(event);}catch{}});
  exited.then(code=>bad(Error(`coordinator exited ${code} before test input; ${stderr}`)),bad);
});
try{
  const job=await ready;
  assert.equal(job.status,"awaiting_proof_return");assert.equal(job.return_directory,returned);
  assert.ok(!existsSync(join(nodeDir,"term-witnesses.json")));
  const guard=spawn(process.execPath,[join(repo,"zk/risc0/proof-return-guards.ts"),"--snapshot",job.snapshot,"--terms",join(nodeDir,"terms.json"),"--checker",proofChecker,"--dir",guards],{windowsHide:true,stdio:["ignore","pipe","pipe"]});
  let guardLog="";guard.stdout!.on("data",data=>{guardLog+=String(data);});guard.stderr!.on("data",data=>{guardLog+=String(data);});
  const guardCode=await new Promise<number|null>((ok,bad)=>{guard.once("error",bad);guard.once("close",ok);});
  writeFileSync(join(root,"guards.log"),guardLog,{flag:"wx"});assert.equal(guardCode,0,guardLog);
  // Rename a fully copied directory, including its readiness manifest, in one operation.
  renameSync(join(guards,"forged-metadata"),returned);
  assert.equal(await exited,1,"coordinator must fail on the native pairing check");
  const failed=JSON.parse(readFileSync(join(nodeDir,"proof-job.json"),"utf8"));
  assert.equal(failed.status,"failed");assert.match(failed.error,/fresh-native-verification exited 101/);
  assert.match(readFileSync(join(nodeDir,"fresh-native-verification.log"),"utf8"),/arkworks: honest false/);
  assert.ok(!readFileSync(join(nodeDir,"provider.log"),"utf8").includes('"provider_complete":true'));
  for(const name of ["term-witnesses.json","fresh-assertions.json","asserted.json"])assert.ok(!existsSync(join(nodeDir,name)));
  assert.ok(!existsSync(mustNotExist));assert.match(readFileSync(join(nodeDir,"regtest/debug.log"),"utf8"),/Shutdown done/);
  for(const pid of [failed.provider_pid,failed.core_pid,failed.coordinator_pid]){
    assert.throws(()=>process.kill(pid,0),(error:any)=>error.code==="ESRCH",`test process ${pid} remains alive`);
  }
  const result={network:"regtest",case:"old proof relabelled to the new graph snapshot",snapshotJournal:failed.expected_journal,metadataPassed:true,nativePairingRejected:true,providerWitnessesWritten:false,checkedAssertionsProduced:false,providerComplete:false,coreShutdown:true,testProcessesExited:true,events:failed.events};
  writeFileSync(output,JSON.stringify(result,null,2)+"\n",{flag:"wx"});console.log(JSON.stringify(result));
}finally{
  // The test's short coordinator deadline invokes its normal Core/provider cleanup
  // even if guard construction fails; never kill the unrelated live proof run.
  await exited.catch(()=>undefined);lines.close();
  writeFileSync(join(root,"coordinator.log"),stdout+stderr,{flag:"wx"});
}
