// Deliberately incomplete ANYONECANPAY marker attachment designs; private regtest only.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync,mkdirSync,writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join,resolve } from "node:path";
import { createInterface } from "node:readline";

const opt=(name:string)=>{const i=process.argv.indexOf(`--${name}`);return i<0?undefined:process.argv[i+1];};
const req=(name:string)=>{const v=opt(name);assert.ok(v,`--${name} required`);return v;};
const dir=resolve(req("dir")),output=resolve(req("out"));
assert.ok(!existsSync(dir)&&!existsSync(output),"new paths required");mkdirSync(dir);
const server=createServer();await new Promise<void>((ok,bad)=>{server.once("error",bad);server.listen(0,"127.0.0.1",ok);});
const port=(server.address() as {port:number}).port;await new Promise<void>(ok=>server.close(()=>ok()));
const core=spawn(req("bitcoind"),["-regtest=1",`-datadir=${dir}`,"-server=1","-txindex=1","-listen=0","-connect=0","-dnsseed=0","-discover=0","-persistmempool=0","-acceptnonstdtxn=1",`-rpcport=${port}`,"-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=bsb","-rpcpassword=bsb-regtest-only","-fallbackfee=0.00002"],{windowsHide:true,stdio:"ignore"});
let coreFailure:Error|undefined;core.once("error",e=>{coreFailure=e;});
const coreExited=new Promise<void>(ok=>core.once("close",()=>ok()));
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function rpc(method:string,params:unknown[]=[],wallet=false):Promise<any>{
  const response=await fetch(`http://127.0.0.1:${port}${wallet?"/wallet/binding":""}`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},body:JSON.stringify({jsonrpc:"2.0",id:"late-marker",method,params}),signal:AbortSignal.timeout(30_000)});
  const v=await response.json() as any;if(v.error)throw Error(`${method}: ${JSON.stringify(v.error)}`);return v.result;
}
const workers:ReturnType<typeof spawn>[]=[];
function worker(args:string[]){
  const child=spawn(req("checker"),args,{windowsHide:true,stdio:["pipe","pipe","pipe"]});workers.push(child);
  let readyOk!:(v:any)=>void,doneOk!:(v:any)=>void,readyBad!:(e:Error)=>void,doneBad!:(e:Error)=>void;
  const ready=new Promise<any>((ok,bad)=>{readyOk=ok;readyBad=bad;}),done=new Promise<any>((ok,bad)=>{doneOk=ok;doneBad=bad;});done.catch(()=>undefined);
  const lines=createInterface({input:child.stdout!});let error="";child.stderr!.on("data",x=>{error+=x.toString();});
  lines.on("line",line=>{if(line.startsWith("BSB_ATTACH ")){try{const v=JSON.parse(line.slice(11));if(v.ready)readyOk(v);if(v.complete)doneOk(v);}catch(e){readyBad(e as Error);doneBad(e as Error);}}});
  const exited=new Promise<void>((ok,bad)=>{child.once("error",bad);child.once("close",code=>code===0?ok():bad(Error(`worker exited ${code}: ${error}`)));});exited.catch(e=>{readyBad(e);doneBad(e);});
  return {child,ready,done,exited,lines};
}
async function fund(info:any){
  assert.equal(info.network,"regtest");const outputs=Object.fromEntries(info.funding.map((f:any)=>[f.address,f.sats/1e8]));assert.equal(Object.keys(outputs).length,info.funding.length);
  const p=await rpc("walletcreatefundedpsbt",[[],outputs,0,{replaceable:false},true],true);
  const signed=await rpc("walletprocesspsbt",[p.psbt],true),funding=await rpc("finalizepsbt",[signed.psbt]);assert.equal(funding.complete,true);
  const d=await rpc("decoderawtransaction",[funding.hex]);
  const vouts=info.funding.map((f:any)=>{const v=d.vout.find((v:any)=>v.scriptPubKey.address===f.address);assert.ok(v);assert.equal(Math.round(v.value*1e8),f.sats);return v.n;});
  return {...funding,txid:d.txid,vouts};
}
const admitted:any[]=[],rejected:any[]=[],mined:any[]=[];
async function accept(name:string,record:any){const v=(await rpc("testmempoolaccept",[[record.hex]]))[0];assert.equal(v.allowed,true,`${name}: ${JSON.stringify(v)}`);assert.equal(v.txid,record.txid);admitted.push({name,txid:v.txid,wtxid:v.wtxid});}
async function reject(name:string,record:any){const v=(await rpc("testmempoolaccept",[[record.hex]]))[0];assert.equal(v.allowed,false,name);assert.match(v["reject-reason"],/script|signature|Schnorr/i);rejected.push({name,reason:v["reject-reason"],hex:record.hex});}
let report:any;
try {
  for(const start=Date.now();;){if(coreFailure)throw coreFailure;assert.equal(core.exitCode,null);try{assert.equal((await rpc("getblockchaininfo")).chain,"regtest");break;}catch{}assert.ok(Date.now()-start<60_000);await pause(200);}
  assert.equal(await rpc("getconnectioncount"),0);await rpc("createwallet",["binding"]);const mining=await rpc("getnewaddress",[],true);await rpc("generatetoaddress",[101,mining]);
  const setup=worker(["setup"]),info=await setup.ready;assert.equal(info.funding.length,4);const funding=await fund(info);
  setup.child.stdin!.end(JSON.stringify({network:"regtest",txid:funding.txid,vouts:funding.vouts})+"\n");
  const templates=await setup.done;await setup.exited;setup.lines.close();assert.equal(setup.child.exitCode,0);const setupExitedAt=new Date().toISOString();
  const tag=randomBytes(32),late=worker(["late",tag.toString("hex")]),lateInfo=await late.ready;
  assert.equal(lateInfo.funding.length,2);assert.ok(!info.setup_public_keys.includes(lateInfo.late_public_key));
  await rpc("sendrawtransaction",[funding.hex]);await rpc("generatetoaddress",[1,mining]);
  const lateFunding=await fund(lateInfo);
  late.child.stdin!.end(JSON.stringify({network:"regtest",txid:lateFunding.txid,vouts:lateFunding.vouts,setup:templates})+"\n");
  const result=await late.done;await late.exited;late.lines.close();assert.equal(late.child.exitCode,0);assert.equal(result.late_public_key,lateInfo.late_public_key);
  await rpc("sendrawtransaction",[lateFunding.hex]);await rpc("generatetoaddress",[1,mining]);
  writeFileSync(join(dir,"public-vectors.json"),JSON.stringify({setup:templates,late:result,late_info:lateInfo},null,2)+"\n",{flag:"wx"});
  const t=result.transactions;
  for(const mode of ["single","all"]){
    await accept(`${mode}-honest-late-marker`,t[`${mode}_honest`]);
    await reject(`${mode}-honest-marker-equal-work`,t[`${mode}_equal_work`]);
    await reject(`${mode}-honest-marker-wrong-tag`,t[`${mode}_wrong_tag`]);
    await accept(`${mode}-trivial-marker-bypasses-comparison`,t[`${mode}_trivial`]);
    await accept(`${mode}-marker-omission`,t[`${mode}_omitted`]);
    await reject(`${mode}-redirected-payout`,t[`${mode}_redirected`]);
    await reject(`${mode}-annex-added-after-presigning`,t[`${mode}_late_annex`]);
  }
  await accept("strict-original-marker",t.strict_original);
  for(const name of ["strict_omitted","strict_honest_substitution","strict_trivial_substitution","strict_equal_work"])await reject(name,t[name]);
  for(const [name,record] of [["single-trivial-marker",t.single_trivial],["all-marker-omission",t.all_omitted],["strict-original-control",t.strict_original]] as [string,any][]){
    const txid=await rpc("sendrawtransaction",[record.hex]);assert.equal(txid,record.txid);await rpc("generatetoaddress",[1,mining]);
    const readback=await rpc("getrawtransaction",[txid,true]);assert.ok(readback.confirmations>=1);assert.equal(readback.hex,record.hex);assert.equal(readback.vout[0].scriptPubKey.hex,templates.payout_script);assert.equal(Math.round(readback.vout[0].value*1e8),99_995_000);
    mined.push({name,txid,wtxid:readback.hash,input_count:readback.vin.length,payout_sats:99_995_000,payout_script:readback.vout[0].scriptPubKey.hex,hex:record.hex});
  }
  report={format:"bsb/late-marker-attachment-regtest/v1",network:"regtest",core:(await rpc("getnetworkinfo")).subversion,
    checks:{setupExitedBeforeFunding:true,setupExitObservedAt:setupExitedAt,lateChallengerKeyCreatedAfterSetupExit:true,lateTagChosenAfterSetupExit:true,latePublicKey:lateInfo.late_public_key,lateTag:tag.toString("hex"),singleAnyoneCanPayAcceptsTrivialMarker:true,allAnyoneCanPayAcceptsTrivialMarker:true,bothFlexibleSignaturesAllowMarkerOmission:true,payoutRemainsPinned:true,defaultSignatureRejectsChangedOrMissingMarker:true,lateAnnexInvalidatesExistingSignatures:true,nodesIsolated:await rpc("getconnectioncount")===0},
    funding:{original:funding.txid,late:lateFunding.txid},admitted,rejected,mined,scope:templates.scope};
} finally {
  for(const child of workers)if(child.exitCode===null){child.kill();await new Promise<void>(ok=>child.once("close",()=>ok()));}
  if(core.exitCode===null){await rpc("stop").catch(()=>undefined);const stopped=await Promise.race([coreExited.then(()=>true),pause(10_000).then(()=>false)]);if(!stopped){core.kill();await coreExited;}}
  assert.equal(core.exitCode,0,"Core must exit cleanly");
}
report.checks.nodeStopped=true;
writeFileSync(output,JSON.stringify(report,null,2)+"\n",{flag:"wx"});
console.log(JSON.stringify({...report,rejected:report.rejected.map(({hex,...v}:any)=>v),mined:report.mined.map(({hex,...v}:any)=>v),output}));
