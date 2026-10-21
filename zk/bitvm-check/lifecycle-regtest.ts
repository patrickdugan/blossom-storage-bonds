// Verify setup-before-funding and one-shot proof signing at term end on fresh local Core.
// Default: historical-proof regression. --fresh-proof-dir waits for the same run's real proof,
// independently verifies it, executes its chunks, and only then requests one-time signing.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { checkProofReturnReady, READY_FILE } from "../risc0/proof-return.ts";
import { parseTx, taprootAddress } from "../../layer1/onchain.ts";

const opt = (name: string) => { const i = process.argv.indexOf(`--${name}`); return i < 0 ? undefined : process.argv[i+1]; };
const req = (name: string) => { const value = opt(name); assert.ok(value, `--${name} is required`); return value; };
const root = resolve(req("dir")), output = resolve(req("out")), checker = req("checker");
const partials = resolve(req("partials"));
const freshDir = opt("fresh-proof-dir") ? resolve(opt("fresh-proof-dir")!) : undefined;
const proofChecker = freshDir ? req("proof-checker") : undefined;
const requireReturnedBitvm=process.argv.includes("--require-returned-bitvm");
assert.ok(!requireReturnedBitvm||freshDir,"returned BitVM mode requires a fresh proof");
let checked = freshDir ? join(root,"fresh-assertions.json") : resolve(req("assertions"));
assert.ok(!freshDir || !existsSync(freshDir), "fresh proof return directory must not exist at setup");
const kind = opt("scenario") ?? "honest";
assert.ok(["honest", "silence"].includes(kind));
assert.ok(!freshDir || kind === "honest", "fresh proof mode requires the honest lifecycle");
assert.ok(!existsSync(root) && !existsSync(output), "new node and output directories required");
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
let fixturePath = resolve(opt("fixture") ?? join(repo, "results/bitvm2-spike.json"));
let proofDir = resolve(opt("proof-dir") ?? join(repo, "results/bitvm2-spike-groth16"));
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const prefix = Buffer.from(fixture.m2.term.preimage, "hex").subarray(0,134);
const first = prefix.readUInt32BE(118), last = first+(prefix.readUInt32BE(126)-1)*prefix.readUInt32BE(122)+prefix.readUInt32BE(130);
const termEnd = last + 24;
const journal=process.argv.includes("--journal"),version=journal?"v2":"v1";
const setup = { format:`bsb/storage-setup/${version}`, network:"regtest", prefix:prefix.toString("hex"),
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
function child(args:string[],name:string,executable=checker){
  const proc=spawn(executable,args,{windowsHide:true,stdio:["pipe","pipe","pipe"]}); children.push(proc);
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
let report:any, freshEvidence:any;
const proofJobPath=join(root,"proof-job.json");
try{
  for(const started=Date.now();;){if(coreError)throw coreError;if(core.exitCode!==null)throw Error("Core exited");try{if((await rpc("getblockchaininfo")).chain==="regtest")break;}catch{}assert.ok(Date.now()-started<60_000,"Core startup timeout");await sleep(200);}
  const coreVersion=(await rpc("getnetworkinfo")).subversion;
  await rpc("createwallet",["lifecycle"]);const mining=await rpc("getnewaddress",[],true);await rpc("generatetoaddress",[101,mining]);
  assert.ok(await rpc("getblockcount")+1<first);
  const note=async(name:string)=>events.push({name,height:await rpc("getblockcount"),at:new Date().toISOString()});
  const provider=child(["provider",setupPath],"provider");
  const ready=await provider.wait("provider_ready");
  assert.equal(ready.registration.format,`bsb/provider-public-keys/${version}`);
  assert.equal(ready.registration.keys.length,journal?382:381);
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
  assert.equal(graph.format,`bsb/presigned-storage-graph/${version}`);
  await rpc("sendrawtransaction",[funding.hex]);await rpc("generatetoaddress",[1,mining]);await note("funding_mined_before_first_epoch");
  assert.ok(await rpc("getblockcount")<first);
  const mine=async(n:number)=>{if(n>0)await rpc("generatetoaddress",[n,mining]);};
  const send=async(name:string)=>{const record=graph.transactions[name];const admission=(await rpc("testmempoolaccept",[[record.hex]]))[0];assert.equal(admission.allowed,true,`${name}: ${JSON.stringify(admission)}`);assert.equal(await rpc("sendrawtransaction",[record.hex]),record.txid);await mine(1);assert.ok((await rpc("getrawtransaction",[record.txid,true])).confirmations>=1);mined.push({name,txid:record.txid,vsize:record.vsize});};
  const reject=async(name:string,reason:RegExp,hex=graph.transactions[name].hex)=>{const result=(await rpc("testmempoolaccept",[[hex]]))[0];assert.equal(result.allowed,false);assert.match(result["reject-reason"],reason);rejected.push({name,reason:result["reject-reason"]});};
  await reject("kickoff",/non-final/);
  await mine(termEnd-await rpc("getblockcount"));await note("term_end_reached_without_assertion_witnesses");
  if(freshDir){
    const snapshotDir=join(root,"input-snapshot");
    const capture=child([join(repo,"zk/risc0/capture-snapshot.ts"),"--rpc-port",String(port),"--to",String(termEnd),"--out",snapshotDir],"same-chain-capture",process.execPath);
    capture.proc.stdin!.end();await capture.exited;
    const snapshotPath=join(snapshotDir,"snapshot.json"),snapshot=JSON.parse(readFileSync(snapshotPath,"utf8"));
    assert.equal(snapshot.expected_preimage.slice(0,268),setup.prefix,"fresh holdings must use the precommitted deal roots and epoch schedule");
    assert.equal(snapshot.chain.tip_height,termEnd);assert.equal(snapshot.chain.tip_hash,await rpc("getblockhash",[termEnd]));
    const digest=(path:string)=>createHash("sha256").update(readFileSync(path)).digest("hex");
    snapshot.lifecycle={funding_txid:decoded.txid,setup_sha256:digest(setupPath),presigned_graph_sha256:digest(graphPath),public_keys_height:events[0].height,funding_height:events.find(e=>e.name==="funding_mined_before_first_epoch").height};
    writeFileSync(snapshotPath,JSON.stringify(snapshot,null,2)+"\n");
    await note("own_chain_snapshot_ready_for_proving");
    const job={format:"bsb/lifecycle-proof-job/v1",status:"awaiting_proof_return",snapshot:snapshotDir,return_directory:freshDir,ready_file:join(freshDir,READY_FILE),expected_journal:snapshot.expected_journal,core_pid:core.pid,provider_pid:provider.proc.pid,coordinator_pid:process.pid,events};
    writeFileSync(proofJobPath,JSON.stringify(job,null,2)+"\n",{flag:"wx"});
    console.log(JSON.stringify({proofJobReady:true,file:proofJobPath,...job}));
    const waitMs=Number(opt("proof-wait-ms")??7_200_000);assert.ok(Number.isSafeInteger(waitMs)&&waitMs>0);
    for(const started=Date.now();!existsSync(job.ready_file);){
      assert.equal(provider.proc.exitCode,null,"provider exited before its term-end proof");assert.equal(core.exitCode,null,"graph node exited while awaiting proof");
      assert.ok(Date.now()-started<waitMs,"fresh proof return timed out; this one-time setup cannot be restarted");await sleep(2000);
    }
    const returned=checkProofReturnReady(snapshotDir,freshDir,setup);
    assert.ok(!requireReturnedBitvm||returned.bitvm,"this lifecycle requires the VPS BitVM result; local execution is disabled");
    assert.equal(await rpc("getblockhash",[snapshot.chain.tip_height]),snapshot.chain.tip_hash,"proof snapshot was reorged out before assertion");
    proofDir=join(freshDir,"g16");fixturePath=join(freshDir,"fixture.json");
    const wrong=returned.publicInput==="1"?"2":"1";
    const native=child([proofDir,"--wrong-public",wrong,"--verify-only"],"fresh-native-verification",proofChecker!);native.proc.stdin!.end();await native.exited;
    if(returned.bitvm){
      const audit=child(["--audit-report",join(freshDir,"bitvm/result.json")],"returned-bitvm-report-audit",proofChecker!);audit.proc.stdin!.end();await audit.exited;
      checkProofReturnReady(snapshotDir,freshDir,setup);
      const bytes=readFileSync(join(freshDir,"bitvm/assertions.json"));
      assert.equal(createHash("sha256").update(bytes).digest("hex"),returned.bitvm.assertionsSha256);
      writeFileSync(checked,bytes,{flag:"wx"});
    }else{
      const chunks=child([proofDir,"--wrong-public",wrong,"--assertions-only","--assertions-out",checked],"fresh-chunk-assertions",proofChecker!);chunks.proc.stdin!.end();await chunks.exited;
    }
    freshEvidence={snapshot_journal:snapshot.expected_journal,tip_height:snapshot.chain.tip_height,tip_hash:snapshot.chain.tip_hash,public_input:returned.publicInput,nativeGroth16Verified:true,unsignedChunksExecuted:!returned.bitvm,fullBitvmExecutedOnVps:!!returned.bitvm,returnedBitvm:returned.bitvm,returnedFiles:returned.files};
    await note("fresh_proof_verified_for_own_chain");
    writeFileSync(proofJobPath,JSON.stringify({...job,status:"proof_verified",evidence:freshEvidence,events},null,2)+"\n");
  }
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
    if(journal){
      for(const kind of ["missing-journal","wrong-journal-metadata","legacy-witness-format"]){
        const changed=JSON.parse(readFileSync(witnessPath,"utf8"));
        if(kind==="missing-journal")changed.witnesses.pop();
        if(kind==="wrong-journal-metadata")changed.term_journal="00".repeat(32);
        if(kind==="legacy-witness-format")changed.format="bsb/term-end-witnesses/v1";
        const path=join(root,kind+".json"),out=join(root,kind+"-must-not-exist.json");
        writeFileSync(path,JSON.stringify(changed),{flag:"wx"});
        const invalid=child(["attach",graphPath,path,out],kind);
        await invalid.exited.catch(()=>undefined);assert.notEqual(invalid.proc.exitCode,0);assert.ok(!existsSync(out));
        rejected.push({name:kind,reason:"invalid v2 attachment rejected before output"});
      }
    }
    const attaching=child(["attach",graphPath,witnessPath,attachedPath],"attach");
    await attaching.wait("attached");await attaching.exited;graph=JSON.parse(readFileSync(attachedPath,"utf8"));
    assert.deepEqual(txids(graph),before,"term-end proof must only change witnesses");
    assert.equal(graph.format,`bsb/asserted-storage-graph/${version}`);
    if(journal){assert.equal(graph.term_journal_slot,381);assert.equal(graph.term_journal,createHash("sha256").update(Buffer.from(graph.preimage??JSON.parse(readFileSync(witnessPath,"utf8")).preimage,"hex")).digest("hex"));}
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
  report={network:"regtest",core:coreVersion,setupVersion:journal?"v2":"v1",commitments:ready.registration.keys.length,journalBinding:journal,termJournal:graph.term_journal,termJournalSlot:graph.term_journal_slot,scenario:kind,scope:freshDir?"fresh proof from this graph's own regtest chain, with setup before funding and signing at term end; heavier-chain challenge remains":"separate committee/provider lifecycle using the existing phase-6 proof; fresh-chain proof and heavier-chain challenge remain",freshProof:freshEvidence,events,mined,rejected,payouts,committeeExitedBeforeFunding:true,termEndWitnessesOnly:kind==="honest",publicKeysCommittedBeforeFirstEpoch:true};
}catch(error){
  if(freshDir&&existsSync(proofJobPath)){
    const job=JSON.parse(readFileSync(proofJobPath,"utf8"));writeFileSync(proofJobPath,JSON.stringify({...job,status:"failed",error:String(error),events},null,2)+"\n");
  }
  throw error;
}finally{
  for(const process of children)if(process.exitCode===null)process.kill();
  if(core.exitCode===null&&!coreError){await rpc("stop").catch(()=>undefined);for(let i=0;i<100&&core.exitCode===null;i++)await sleep(100);if(core.exitCode===null)core.kill();}
}
assert.match(readFileSync(join(root,"regtest/debug.log"),"utf8"),/Shutdown done/);
mkdirSync(dirname(output),{recursive:true});writeFileSync(output,JSON.stringify({...report,nodeStopped:true},null,2)+"\n",{flag:"wx"});
console.log(JSON.stringify({result:output,scenario:kind,mined:mined.length,rejected:rejected.length,nodeStopped:true}));
function txids(graph:any):string[]{return Object.entries(graph.transactions).map(([name,value])=>`${name}:${(value as any).txid}`).sort();}
