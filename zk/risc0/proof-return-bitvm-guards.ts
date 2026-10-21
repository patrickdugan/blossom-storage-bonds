// Transfer-integrity guards only; this test does not execute BitVM or prove a new statement.
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {spawnSync} from "node:child_process";
import {mkdirSync,readFileSync,writeFileSync} from "node:fs";
import {join,resolve} from "node:path";
import {checkReturnedBitvm} from "./proof-return.ts";
const opt=(name:string)=>{const i=process.argv.indexOf(`--${name}`);return i<0?undefined:process.argv[i+1];};
const req=(name:string)=>{const value=opt(name);assert.ok(value,`--${name} required`);return value;};
const dir=resolve(req("dir")),g16=resolve(req("g16")),checker=req("checker");
mkdirSync(dir);mkdirSync(join(dir,"g16"));mkdirSync(join(dir,"bitvm"));
for(const name of ["vk.json","proof.json","public.json"])writeFileSync(join(dir,"g16",name),readFileSync(join(g16,name)),{flag:"wx"});
writeFileSync(join(dir,"bitvm/assertions.json"),readFileSync(req("assertions")),{flag:"wx"});
writeFileSync(join(dir,"bitvm/result.json"),readFileSync(req("report")),{flag:"wx"});
const publicInput=JSON.parse(readFileSync(join(g16,"public.json"),"utf8"))[0];
const manifest=()=>({format:"bsb/bitvm-proof-return/v1",checker_sha256:createHash("sha256").update(readFileSync(checker)).digest("hex"),files:Object.fromEntries(["g16/vk.json","g16/proof.json","g16/public.json","bitvm/result.json","bitvm/assertions.json"].map(name=>[name,createHash("sha256").update(readFileSync(join(dir,name))).digest("hex")]))});
const seal=()=>writeFileSync(join(dir,"bitvm/manifest.json"),JSON.stringify(manifest()));
seal();assert.ok(checkReturnedBitvm(dir,publicInput));
const cases:string[]=[];
for(const name of ["g16/proof.json","bitvm/result.json","bitvm/assertions.json"]){
  const path=join(dir,name),original=readFileSync(path);writeFileSync(path,Buffer.concat([original,Buffer.from("\n")]));
  assert.throws(()=>checkReturnedBitvm(dir,publicInput),/differ from its manifest/);writeFileSync(path,original);cases.push("changed "+name);
}
const path=join(dir,"bitvm/assertions.json"),original=readFileSync(path);
for(const kind of ["wrong-public","unchecked","bad-shape","invalid-byte","wrong-encoded-public"]){
  const a=JSON.parse(original.toString());
  if(kind==="wrong-public")a.public_input=publicInput==="1"?"2":"1";
  if(kind==="unchecked")a.scripts_checked=false;
  if(kind==="bad-shape")a.hashes.pop();
  if(kind==="invalid-byte")a.fields[0][0]=256;
  if(kind==="wrong-encoded-public")a.public[0][0]^=1;
  writeFileSync(path,JSON.stringify(a));seal();assert.throws(()=>checkReturnedBitvm(dir,publicInput));cases.push(kind);
}
writeFileSync(path,original);seal();assert.ok(checkReturnedBitvm(dir,publicInput));
const run=(file:string)=>{const r=spawnSync(checker,["--audit-report",file],{encoding:"utf8",windowsHide:true,timeout:30_000});if(r.error)throw r.error;return r;};
assert.equal(run(join(dir,"bitvm/result.json")).status,0);
const report=JSON.parse(readFileSync(join(dir,"bitvm/result.json"),"utf8"));report.honest.all_disprove_scripts_fail=false;
const bad=join(dir,"bad-outcomes.json");writeFileSync(bad,JSON.stringify(report));assert.notEqual(run(bad).status,0);cases.push("failed full-verifier outcome");
const result={scope:"Transfer and recorded-outcome guards only; no new proof or BitVM execution",passed:cases.length,cases};
writeFileSync(join(dir,"results.json"),JSON.stringify(result,null,2)+"\n");console.log(JSON.stringify(result));
