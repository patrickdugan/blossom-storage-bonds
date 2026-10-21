// Verify setup-before-funding and one-shot proof signing at term end on fresh local Core.
// This lifecycle regression uses the existing proof; the new-chain proof run remains separate.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { parseTx, taprootAddress } from "../../layer1/onchain.ts";

const opt = (name: string) => { const i = process.argv.indexOf(`--${name}`); return i < 0 ? undefined : process.argv[i+1]; };
const req = (name: string) => { const value = opt(name); assert.ok(value, `--${name} is required`); return value; };
const root = resolve(req("dir")), output = resolve(req("out")), checker = req("checker");
const partials = resolve(req("partials")), checked = resolve(req("assertions"));
const kind = opt("scenario") ?? "honest";
assert.ok(["honest", "silence"].includes(kind));
assert.ok(!existsSync(root) && !existsSync(output), "new node and output directories required");
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const fixturePath = resolve(opt("fixture") ?? join(repo, "results/bitvm2-spike.json"));
const proofDir = resolve(opt("proof-dir") ?? join(repo, "results/bitvm2-spike-groth16"));
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const prefix = Buffer.from(fixture.m2.term.preimage, "hex").subarray(0,134);
const first = prefix.readUInt32BE(118), last = first+(prefix.readUInt32BE(126)-1)*prefix.readUInt32BE(122)+prefix.readUInt32BE(130);
const termEnd = last + 24;
const setup = { format:"bsb/storage-setup/v1", network:"regtest", prefix:prefix.toString("hex"),
  constants_digest:fixture.m3.groth16.constants_digest, vk_sha256:"2941dff0bd962ff8610773c9659c10d0dec561db1e2f6afecfbbe0d9cb457a7d",
  config:{term_end:termEnd,kickoff_deadline:termEnd+20,final_deadline:termEnd+70,challenge_blocks:6,assert_blocks:12,dispute_blocks:6,slot_value:20_000,marker_value:1_000_000} };
mkdirSync(root);
const setupPath = join(root,"terms.json"), registrationPath = join(root,"public-keys.json"), graphPath = join(root,"presigned.json"), witnessPath = join(root,"term-witnesses.json"), attachedPath = join(root,"asserted.json");
writeFileSync(setupPath, JSON.stringify(setup), {flag:"wx"});
const vkOnly = join(root,"vk-only"); mkdirSync(vkOnly);
writeFileSync(join(vkOnly,"vk.json"),readFileSync(join(proofDir,"vk.json")),{flag:"wx"});
assert.deepEqual((await import("node:fs")).readdirSync(vkOnly),["vk.json"]);
const sleep = (ms:number) => new Promise(r=>setTimeout(r,ms));
const portServer = createServer(); await new Promise<void>((ok,bad)=>{portServer.once("error",bad);portServer.listen(0,"127.0.0.1",ok);});
const port = (portServer.address() as {port:number}).port; await new Promise<void>(ok=>portServer.close(()=>ok()));
const core = spawn(req("bitcoind"),["-regtest=1",`-datadir=${root}`,"-server=1","-txindex=1","-listen=0","-connect=0","-dnsseed=0","-discover=0","-acceptnonstdtxn=1","-limitclustersize=2000","-persistmempool=0",`-rpcport=${port}`,"-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=bsb","-rpcpassword=bsb-regtest-only","-fallbackfee=0.00002"],{windowsHide:true,stdio:"ignore"});
let coreError:Error|undefined;core.once("error",e=>{coreError=e;});
async function rpc(method:string,params:unknown[]=[],wallet=false):Promise<any>{
  const response=await fetch(`http://127.0.0.1:${port}${wallet?"/wallet/lifecycle":""}`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},body:JSON.stringify({jsonrpc:"2.0",id:"lifecycle",method,params}),signal:AbortSignal.timeout(120_000)});
  const result=await response.json() as any;if(result.error)throw Error(`${method}: ${JSON.stringify(result.error)}`);return result.result;
}
const children:ReturnType<typeof spawn>[]=[];
function child(args:string[],name:string){
  const proc=spawn(checker,args,{windowsHide:true,stdio:["pipe","pipe","pipe"]}); children.push(proc);
  const log=createWriteStream(join(root,`${name}.log`),{flags:"wx"}); proc.stderr!.pipe(log,{end:false});
  const pending=new Map<string,{ok:(v:any)=>void,bad:(e:Error)=>void}>(),events=new Map<string,any>();
  let failure:Error|undefined,closed=false;
  const lines=createInterface({input:proc.stdout!});
  lines.on("line",line=>{log.write(line+"\n");if(line.startsWith("BSB_LIFECYCLE ")){
    try{const value=JSON.parse(line.slice(14));for(const key of Object.keys(value))if(value[key]===true){events.set(key,value);pending.get(key)?.ok(value);}}
    catch(error){failure=error as Error;for(const waiter of pending.values())waiter.bad(failure);}
  }});
  const exited=new Promise<void>((ok,bad)=>{proc.once("error",bad);proc.once("close",code=>{closed=true;lines.close();log.end();if(code===0)ok();else bad(Error(`${name} exited ${code}; inspect ${name}.log`));for(const [key,waiter] of pending)if(!events.has(key))waiter.bad(Error(`${name} closed without ${key}`));});});
  exited.catch(error=>{failure=error;for(const waiter of pending.values())waiter.bad(error);});
  return {proc,exited,wait:(key:string)=>events.has(key)?Promise.resolve(events.get(key)):failure?Promise.reject(failure):closed?Promise.reject(Error(`${name} closed without ${key}`)):new Promise<any>((ok,bad)=>pending.set(key,{ok,bad}))};
}
const events:any[]=[],mined:any[]=[],rejected:any[]=[];
let report:any;
try{
  for(const started=Date.now();;){if(coreError)throw coreError;if(core.exitCode!==null)throw Error("Core exited");try{if((await rpc("getblockchaininfo")).chain==="regtest")break;}catch{}assert.ok(Date.now()-started<60_000,"Core startup timeout");await sleep(200);}
  const version=(await rpc("getnetworkinfo")).subversion;
  await rpc("createwallet",["lifecycle"]);const mining=await rpc("getnewaddress",[],true);await rpc("generatetoaddress",[101,mining]);
  assert.ok(await rpc("getblockcount")+1<first);
  const note=async(name:string)=>events.push({name,height:await rpc("getblockcount"),at:new Date().toISOString()});
  const provider=child(["provider",setupPath],"provider");
  const ready=await provider.wait("provider_ready");
  writeFileSync(registrationPath,JSON.stringify(ready.registration),{flag:"wx"});await note("provider_public_keys_committed");
  const committee=child(["setup",setupPath,registrationPath,vkOnly,partials,graphPath],"committee");
  const meta=await committee.wait("setup_ready");assert.equal(meta.network,"regtest");
  const psbt=await rpc("walletcreatefundedpsbt",[[],{[meta.funding_address]:1},0,{replaceable:false},true],true);
  const signed=await rpc("walletprocesspsbt",[psbt.psbt],true);const funding=await rpc("finalizepsbt",[signed.psbt]);assert.equal(funding.complete,true);
  const decoded=await rpc("decoderawtransaction",[funding.hex]);const coin=decoded.vout.find((v:any)=>v.scriptPubKey.address===meta.funding_address);assert.ok(coin);
  committee.proc.stdin!.end(JSON.stringify({network:"regtest",txid:decoded.txid,vout:coin.n,sats:100_000_000,height:await rpc("getblockcount")})+"\n");
  await committee.wait("setup_complete");await committee.exited;assert.equal(committee.proc.exitCode,0);assert.equal(provider.proc.exitCode,null);
  assert.ok(!existsSync(witnessPath));await note("committee_exited_before_funding");
  let graph=JSON.parse(readFileSync(graphPath,"utf8"));
  assert.equal(txids(graph).length,12);
  await rpc("sendrawtransaction",[funding.hex]);await rpc("generatetoaddress",[1,mining]);await note("funding_mined_before_first_epoch");
  assert.ok(await rpc("getblockcount")<first);
  const mine=async(n:number)=>{if(n>0)await rpc("generatetoaddress",[n,mining]);};
  const send=async(name:string)=>{const record=graph.transactions[name];const admission=(await rpc("testmempoolaccept",[[record.hex]]))[0];assert.equal(admission.allowed,true,`${name}: ${JSON.stringify(admission)}`);assert.equal(await rpc("sendrawtransaction",[record.hex]),record.txid);await mine(1);assert.ok((await rpc("getrawtransaction",[record.txid,true])).confirmations>=1);mined.push({name,txid:record.txid,vsize:record.vsize});};
  const reject=async(name:string,reason:RegExp,hex=graph.transactions[name].hex)=>{const result=(await rpc("testmempoolaccept",[[hex]]))[0];assert.equal(result.allowed,false);assert.match(result["reject-reason"],reason);rejected.push({name,reason:result["reject-reason"]});};
  await reject("kickoff",/non-final/);
  await mine(termEnd-await rpc("getblockcount"));await note("term_end_reached_without_assertion_witnesses");
  await send("kickoff");await send("challenge");
  if(kind==="silence"){
    provider.proc.stdin!.end();await provider.exited.catch(()=>undefined);assert.notEqual(provider.proc.exitCode,0);
    assert.ok(!existsSync(witnessPath));await reject("assert-timeout",/non-BIP68-final/);
    await mine(setup.config.assert_blocks);await send("assert-timeout");await send("slots-timeout");
  }else{
    await reject("assert-commit-0",/script/);await reject("assert-final",/missing|spent/);
    const before=txids(graph);
    provider.proc.stdin!.end(JSON.stringify({fixture:fixturePath,proof_dir:proofDir,assertions:checked,output:witnessPath})+"\n");
    await provider.wait("provider_complete");await provider.exited;assert.equal(provider.proc.exitCode,0);await note("provider_signed_once_at_term_end");
    // An output from different setup keys cannot be substituted, before any Core broadcast.
    const swapped=JSON.parse(readFileSync(witnessPath,"utf8"));swapped.registration.keys[0][0][0]^=1;
    const swappedPath=join(root,"wrong-keys.json");writeFileSync(swappedPath,JSON.stringify(swapped),{flag:"wx"});
    const wrong=child(["attach",graphPath,swappedPath,join(root,"must-not-exist.json")],"wrong-keys");
    await wrong.exited.catch(()=>undefined);assert.notEqual(wrong.proc.exitCode,0);assert.ok(!existsSync(join(root,"must-not-exist.json")));rejected.push({name:"substituted-setup-keys",reason:"registration differs"});
    const attaching=child(["attach",graphPath,witnessPath,attachedPath],"attach");
    await attaching.wait("attached");await attaching.exited;graph=JSON.parse(readFileSync(attachedPath,"utf8"));
    assert.deepEqual(txids(graph),before,"term-end proof must only change witnesses");
    await send("assert-commit-0");await send("assert-commit-1");await send("assert-final");
    await reject("slash",/script/);await reject("refund",/non-BIP68-final/);await mine(setup.config.dispute_blocks);await send("refund");
  }
  const terminal=kind==="honest"?["refund"]:["assert-timeout","slots-timeout"];
  const payouts=terminal.map(name=>{
    const record=graph.transactions[name],decoded=parseTx(Buffer.from(record.hex,"hex"));
    assert.equal(decoded.txid,mined.find(t=>t.name===name)!.txid);assert.equal(decoded.outputs.length,1);
    const output=decoded.outputs[0];assert.equal(output.script.subarray(0,2).toString("hex"),"5120");
    const address=taprootAddress(output.script.subarray(2).toString("hex"),"regtest");
    assert.equal(address,kind==="honest"?meta.provider_address:meta.client_address);
    return {name,address,sats:Number(output.value),txid:decoded.txid};
  });
  assert.ok(payouts.reduce((sum,p)=>sum+p.sats,0)>90_000_000);
  report={network:"regtest",core:version,scenario:kind,scope:"separate committee/provider lifecycle using the existing phase-6 proof; fresh-chain proof and heavier-chain challenge remain",events,mined,rejected,payouts,committeeExitedBeforeFunding:true,termEndWitnessesOnly:kind==="honest",publicKeysCommittedBeforeFirstEpoch:true};
}finally{
  for(const process of children)if(process.exitCode===null)process.kill();
  if(core.exitCode===null&&!coreError){await rpc("stop").catch(()=>undefined);for(let i=0;i<100&&core.exitCode===null;i++)await sleep(100);if(core.exitCode===null)core.kill();}
}
assert.match(readFileSync(join(root,"regtest/debug.log"),"utf8"),/Shutdown done/);
mkdirSync(dirname(output),{recursive:true});writeFileSync(output,JSON.stringify({...report,nodeStopped:true},null,2)+"\n",{flag:"wx"});
console.log(JSON.stringify({result:output,scenario:kind,mined:mined.length,rejected:rejected.length,nodeStopped:true}));
function txids(graph:any):string[]{return Object.entries(graph.transactions).map(([name,value])=>`${name}:${(value as any).txid}`).sort();}
