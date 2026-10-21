// Counterexamples to naive runtime input binding. These are not chain-work proofs.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { parseTx } from "../../layer1/onchain.ts";

const opt = (name: string) => { const i = process.argv.indexOf(`--${name}`); return i < 0 ? undefined : process.argv[i+1]; };
const req = (name: string) => { const v = opt(name); assert.ok(v, `--${name} is required`); return v; };
const dir = resolve(req("dir")), output = resolve(req("out"));
assert.ok(!existsSync(dir) && !existsSync(output), "new data and output paths required"); mkdirSync(dir);
const server = createServer();
await new Promise<void>((ok,bad) => { server.once("error",bad); server.listen(0,"127.0.0.1",ok); });
const port = (server.address() as {port:number}).port; await new Promise<void>(ok => server.close(() => ok()));
const core = spawn(req("bitcoind"),["-regtest=1",`-datadir=${dir}`,"-server=1","-txindex=1","-listen=0","-connect=0","-dnsseed=0","-discover=0","-persistmempool=0",`-rpcport=${port}`,"-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=bsb","-rpcpassword=bsb-regtest-only","-fallbackfee=0.00002"],{windowsHide:true,stdio:"ignore"});
let failure: Error | undefined; core.once("error",error => { failure=error; });
const coreExited = new Promise<void>(ok => core.once("close",() => ok()));
const pause = (ms:number) => new Promise(r => setTimeout(r,ms));
async function rpc(method:string,params:unknown[]=[],wallet=false):Promise<any> {
  const response=await fetch(`http://127.0.0.1:${port}${wallet?"/wallet/binding":""}`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},body:JSON.stringify({jsonrpc:"2.0",id:"input-binding",method,params}),signal:AbortSignal.timeout(30_000)});
  const value=await response.json() as any; if(value.error)throw Error(`${method}: ${JSON.stringify(value.error)}`); return value.result;
}
const compact = (n:number) => { if(n<253)return Buffer.from([n]); assert.ok(n<=65535); const b=Buffer.alloc(3); b[0]=253;b.writeUInt16LE(n,1);return b; };
// Preserve every non-witness byte unless a case explicitly tests a body change.
function encode(record:any,work:number,data:Buffer,body?:Buffer):string {
  const stripped=body??parseTx(Buffer.from(record.hex,"hex")).stripped;
  const number=Buffer.alloc(2);number.writeUInt16LE(work);
  const witness:Buffer[]=record.witness.map((v:string)=>Buffer.from(v,"hex"));
  witness[0]=number;witness[1]=data;
  return Buffer.concat([stripped.subarray(0,4),Buffer.from([0,1]),stripped.subarray(4,-4),compact(witness.length),...witness.flatMap(v=>[compact(v.length),v]),stripped.subarray(-4)]).toString("hex");
}
const admitted:any[]=[],rejected:any[]=[],mined:any[]=[];
async function accept(name:string,hex:string) { const result=(await rpc("testmempoolaccept",[[hex]]))[0];assert.equal(result.allowed,true,`${name}: ${JSON.stringify(result)}`);admitted.push({name,txid:result.txid,wtxid:result.wtxid}); }
async function reject(name:string,hex:string,reason:RegExp) { const result=(await rpc("testmempoolaccept",[[hex]]))[0];assert.equal(result.allowed,false,name);assert.match(result["reject-reason"],reason);rejected.push({name,reason:result["reject-reason"]}); }
let setup:ReturnType<typeof spawn>|undefined,report:any;
try {
  for(const start=Date.now();;) { if(failure)throw failure;assert.equal(core.exitCode,null);try{assert.equal((await rpc("getblockchaininfo")).chain,"regtest");break;}catch{}assert.ok(Date.now()-start<60_000);await pause(200); }
  assert.equal(await rpc("getconnectioncount"),0);
  await rpc("createwallet",["binding"]);const mining=await rpc("getnewaddress",[],true);await rpc("generatetoaddress",[101,mining]);
  let readyOk!:(v:any)=>void,completeOk!:(v:any)=>void,readyBad!:(e:Error)=>void,completeBad!:(e:Error)=>void;
  const ready=new Promise<any>((ok,bad)=>{readyOk=ok;readyBad=bad;}),complete=new Promise<any>((ok,bad)=>{completeOk=ok;completeBad=bad;});complete.catch(()=>undefined);
  setup=spawn(req("checker"),[],{windowsHide:true,stdio:["pipe","pipe","pipe"]});const active=setup;
  const lines=createInterface({input:active.stdout!});
  let setupError="";active.stderr!.on("data",data=>{setupError+=data.toString();});
  lines.on("line",line=>{if(line.startsWith("BSB_BINDING ")){try{const event=JSON.parse(line.slice(12));if(event.ready)readyOk(event);if(event.complete)completeOk(event);}catch(e){readyBad(e as Error);completeBad(e as Error);}}});
  const exited=new Promise<void>((ok,bad)=>{active.once("error",bad);active.once("close",code=>code===0?ok():bad(Error(`setup exited ${code}: ${setupError}`)));});exited.catch(e=>{readyBad(e);completeBad(e);});
  const info=await ready;assert.equal(info.network,"regtest");assert.equal(info.funding.length,3);
  const outputs=Object.fromEntries(info.funding.map((address:string)=>[address,1]));assert.equal(Object.keys(outputs).length,3);
  const psbt=await rpc("walletcreatefundedpsbt",[[],outputs,0,{replaceable:false},true],true);
  const signed=await rpc("walletprocesspsbt",[psbt.psbt],true),funding=await rpc("finalizepsbt",[signed.psbt]);assert.equal(funding.complete,true);
  const decoded=await rpc("decoderawtransaction",[funding.hex]);
  const vouts=info.funding.map((address:string)=>{const o=decoded.vout.find((v:any)=>v.scriptPubKey.address===address);assert.ok(o);return o.n;});
  active.stdin!.end(JSON.stringify({network:"regtest",txid:decoded.txid,vouts})+"\n");const result=await complete;await exited;lines.close();assert.equal(active.exitCode,0);setup=undefined;
  // Choose both arbitrary candidate tags only after the signer has exited.
  const a=randomBytes(32),b=randomBytes(32),fixed=Buffer.alloc(32,1),t=result.transactions;
  assert.notDeepEqual(a,b);assert.notDeepEqual(a,fixed);assert.notDeepEqual(b,fixed);
  writeFileSync(join(dir,"presigned-public-templates.json"),JSON.stringify(result,null,2)+"\n",{flag:"wx"});
  await rpc("sendrawtransaction",[funding.hex]);await rpc("generatetoaddress",[1,mining]);
  async function send(name:string,hex:string) { await accept(name,hex);const txid=await rpc("sendrawtransaction",[hex]);await rpc("generatetoaddress",[1,mining]);const tx=await rpc("getrawtransaction",[txid,true]);assert.ok(tx.confirmations>=1);mined.push({name,txid,wtxid:tx.hash,hex}); }
  const parentA=encode(t.unbound_parent,444,a),parentB=encode(t.unbound_parent,468,b);
  const decodedA=await rpc("decoderawtransaction",[parentA]),decodedB=await rpc("decoderawtransaction",[parentB]);
  assert.equal(decodedA.txid,decodedB.txid);assert.notEqual(decodedA.hash,decodedB.hash);
  await accept("unbound-parent-substituted-witness",parentB);await send("unbound-parent-announces-444",parentA);
  await reject("unbound-response-444-does-not-beat-466",encode(t.unbound_child,444,a),/script/);
  await send("unbound-response-substitutes-468-and-another-tag",encode(t.unbound_child,468,b));
  await reject("fixed-parent-wrong-tag",encode(t.fixed_parent,468,b),/script/);
  await reject("fixed-parent-wrong-work",encode(t.fixed_parent,444,fixed),/script/);
  await send("fixed-parent-announces-precommitted-468",encode(t.fixed_parent,468,fixed));
  await reject("fixed-response-wrong-tag",encode(t.fixed_child,468,b),/script/);
  await reject("fixed-response-wrong-work",encode(t.fixed_child,444,fixed),/script/);
  const redirected=Buffer.from(parseTx(Buffer.from(t.fixed_child.hex,"hex")).stripped);redirected[redirected.length-5]^=1;
  await reject("redirected-fixed-response-payout",encode(t.fixed_child,468,fixed,redirected),/script/);
  await send("fixed-response-matches-precommitted-468",encode(t.fixed_child,468,fixed));
  const changed=Buffer.from(parseTx(Buffer.from(t.output_parent.hex,"hex")).stripped);a.copy(changed,changed.length-36);
  assert.notEqual(parseTx(changed).txid,t.output_parent.txid);
  await reject("late-output-commitment-invalidates-parent-signature",encode(t.output_parent,444,a,changed),/script/);
  await send("different-output-parent-presigned-during-setup",encode(t.output_parent_alternative,444,a));
  await reject("original-descendant-cannot-find-old-parent",encode(t.output_child,468,b),/missing|spent/);
  const rewired=Buffer.from(parseTx(Buffer.from(t.output_child.hex,"hex")).stripped);Buffer.from(t.output_parent_alternative.txid,"hex").reverse().copy(rewired,5);
  await reject("rewired-descendant-invalidates-presignature",encode(t.output_child,468,b,rewired),/script/);
  report={format:"bsb/input-binding-regtest/v1",network:"regtest",core:(await rpc("getnetworkinfo")).subversion,
    checks:{setupExitedBeforeFunding:true,candidateTagsChosenAfterSetupExit:true,unboundWitnessKeepsTxid:true,unboundWitnessChangesWtxid:true,unboundDescendantAcceptedDifferentInput:true,fixedCommitmentEnforcesEquality:true,lateOutputChangesTxid:true,nodesIsolated:await rpc("getconnectioncount")===0},
    witnessComparison:{parentTxid:decodedA.txid,announcedWork:444,responseWork:468,referenceWork:466,announcedTag:a.toString("hex"),responseTag:b.toString("hex"),parentA_wtxid:decodedA.hash,parentB_wtxid:decodedB.hash},
    admitted,rejected,mined,scope:result.scope};
} finally {
  if(setup&&setup.exitCode===null){setup.kill();await new Promise<void>(ok=>setup!.once("close",()=>ok()));}
  if(core.exitCode===null){await rpc("stop").catch(()=>undefined);const stopped=await Promise.race([coreExited.then(()=>true),pause(10_000).then(()=>false)]);if(!stopped){core.kill();await coreExited;}}
  assert.equal(core.exitCode,0,"Core must exit cleanly");
}
report.checks.nodeStopped=true;
writeFileSync(output,JSON.stringify(report,null,2)+"\n",{flag:"wx"});
console.log(JSON.stringify({...report,mined:report.mined.map(({hex,...tx}:any)=>tx),output}));
