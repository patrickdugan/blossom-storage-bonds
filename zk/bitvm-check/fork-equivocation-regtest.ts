// A separate counterexample and delayed recovery experiment; never changes a funded storage graph.
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {createWriteStream,existsSync,mkdirSync,readFileSync,writeFileSync} from "node:fs";
import {createServer} from "node:net";
import {dirname,join,resolve} from "node:path";
import {createInterface} from "node:readline";
import {fileURLToPath} from "node:url";
import {parseTx,taprootAddress} from "../../layer1/onchain.ts";
const opt=(n:string)=>{const i=process.argv.indexOf(`--${n}`);return i<0?undefined:process.argv[i+1];};
const req=(n:string)=>{const x=opt(n);assert.ok(x,`--${n} required`);return x;};
const root=resolve(req("dir")),out=resolve(req("out"));assert.ok(!existsSync(root)&&!existsSync(out));mkdirSync(root);
const fixture=resolve(dirname(fileURLToPath(import.meta.url)),"../../results/bitvm-cumulative-work-compact.json");
const reserve=createServer();await new Promise<void>(r=>reserve.listen(0,"127.0.0.1",r));const port=(reserve.address() as {port:number}).port;await new Promise<void>(r=>reserve.close(()=>r()));
const core=spawn(req("bitcoind"),["-regtest=1",`-datadir=${root}`,"-server=1","-txindex=1","-listen=0","-connect=0","-dnsseed=0","-discover=0","-acceptnonstdtxn=1","-limitclustersize=2000","-persistmempool=0",`-rpcport=${port}`,"-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=bsb","-rpcpassword=bsb-regtest-only","-fallbackfee=0.00002"],{windowsHide:true,stdio:"ignore"});
let coreError:Error|undefined;core.once("error",e=>{coreError=e;});const sleep=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function rpc(method:string,params:unknown[]=[],wallet=false):Promise<any>{const response=await fetch(`http://127.0.0.1:${port}${wallet?"/wallet/equivocation":""}`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},body:JSON.stringify({jsonrpc:"2.0",id:"eq",method,params}),signal:AbortSignal.timeout(60_000)});const v=await response.json() as any;if(v.error)throw Error(JSON.stringify(v.error));return v.result;}
let helper:ReturnType<typeof spawn>|undefined,report:any;
try{
  for(const start=Date.now();;){if(coreError)throw coreError;assert.equal(core.exitCode,null);try{if((await rpc("getblockchaininfo")).chain==="regtest")break;}catch{}assert.ok(Date.now()-start<60_000);await sleep(200);}
  const version=(await rpc("getnetworkinfo")).subversion;await rpc("createwallet",["equivocation"]);const mining=await rpc("getnewaddress",[],true);const mine=async(n=1)=>rpc("generatetoaddress",[n,mining]);await mine(101);
  const cases:any[]=[];
  for(const kind of ["recover-before-deadline","no-response-before-refund"]){
    const dir=join(root,kind);helper=spawn(req("checker"),[fixture,dir],{windowsHide:true,stdio:["pipe","pipe","pipe"]});
    const log=createWriteStream(join(root,kind+".log"));helper.stderr!.pipe(log,{end:false});
    let readyResolve:(v:any)=>void,readyReject:(e:Error)=>void;
    const ready=new Promise<any>((ok,bad)=>{readyResolve=ok;readyReject=bad;});
    const lines=createInterface({input:helper.stdout!});lines.on("line",line=>{log.write(line+"\n");if(line.startsWith("BSB_EQUIVOCATION ")){const v=JSON.parse(line.slice(17));if(v.ready)readyResolve(v);}});
    const exited=new Promise<void>((ok,bad)=>{helper!.once("error",e=>{readyReject(e);bad(e);});helper!.once("close",code=>{log.end();lines.close();if(code===0)ok();else{const e=Error(`native helper exit ${code}`);readyReject(e);bad(e);}});});exited.catch(()=>{});
    const info=await ready;
    const psbt=await rpc("walletcreatefundedpsbt",[[],{[info.control]:1,[info.proof]:0.01},0,{replaceable:false},true],true);
    const processed=await rpc("walletprocesspsbt",[psbt.psbt],true);const funding=await rpc("finalizepsbt",[processed.psbt]);assert.equal(funding.complete,true);
    const decoded=await rpc("decoderawtransaction",[funding.hex]);const control=decoded.vout.find((v:any)=>v.scriptPubKey.address===info.control),proof=decoded.vout.find((v:any)=>v.scriptPubKey.address===info.proof);assert.ok(control&&proof);
    helper.stdin!.end(JSON.stringify({txid:decoded.txid,control_vout:control.n,proof_vout:proof.n})+"\n");await exited;assert.equal(helper.exitCode,0);
    const fundingTx=parseTx(Buffer.from(funding.hex,"hex"));assert.equal(fundingTx.txid,decoded.txid);assert.equal(fundingTx.outputs[control.n].value,100_000_000n);assert.equal(fundingTx.outputs[proof.n].value,1_000_000n);
    writeFileSync(join(dir,"funding.json"),JSON.stringify({hex:funding.hex,txid:decoded.txid,controlVout:control.n,proofVout:proof.n,client:info.client,provider:info.provider}),{flag:"wx"});
    await rpc("sendrawtransaction",[funding.hex]);await mine();
    const checks:any[]=[],mined:any[]=[];
    const vector=(name:string)=>JSON.parse(readFileSync(join(dir,name+".json"),"utf8"));
    const reject=async(name:string,reason:RegExp)=>{const result=(await rpc("testmempoolaccept",[[vector(name).hex]]))[0];assert.equal(result.allowed,false,name);assert.match(result["reject-reason"],reason);checks.push({name,reason:result["reject-reason"]});};
    const send=async(name:string)=>{const v=vector(name),accept=(await rpc("testmempoolaccept",[[v.hex]]))[0];assert.equal(accept.allowed,true,JSON.stringify(accept));assert.equal(await rpc("sendrawtransaction",[v.hex]),v.txid);await mine();const got=await rpc("getrawtransaction",[v.txid,true]);assert.ok(got.confirmations>=1);assert.equal(got.hex,v.hex);assert.equal(got.weight,v.weight);mined.push({name,txid:v.txid,weight:v.weight,vsize:v.vsize});};
    await reject("honest-binding",/false\/empty top/);await send("false-disprove");
    await reject("provider-refund",/non-BIP68-final/);await reject("shortened-refund",/script/);await reject("same-message",/false\/empty top/);await reject("wrong-key",/script/);await reject("redirected-penalty",/script/);
    const terminal=kind==="recover-before-deadline"?"equivocation-penalty":"provider-refund";
    if(kind==="recover-before-deadline"){await send(terminal);await reject("provider-refund",/missing|spent/);}
    else {await mine(6);await send(terminal);await reject("equivocation-penalty",/missing|spent/);}
    const payout=parseTx(Buffer.from(vector(terminal).hex,"hex"));assert.equal(payout.txid,mined.find(v=>v.name===terminal).txid);assert.equal(payout.outputs.length,1);
    const address=taprootAddress(payout.outputs[0].script.subarray(2).toString("hex"),"regtest");assert.equal(address,kind==="recover-before-deadline"?info.client:info.provider);
    const metadata=JSON.parse(readFileSync(join(dir,"metadata.json"),"utf8"));assert.equal(metadata.binding_bytes,1_241_447);assert.notEqual(metadata.original_journal,metadata.alternate_journal);
    cases.push({kind,committeeExitedBeforeFunding:true,...metadata,checks,mined,payout:{name:terminal,address,sats:Number(payout.outputs[0].value),txid:payout.txid}});
    console.log(`${kind}: ${mined.length} mined, ${checks.length} rejected`);
  }
  assert.equal(await rpc("getconnectioncount"),0);report={format:"bsb/fork-equivocation-regtest/v1",generated:new Date().toISOString(),network:"regtest",core:version,policy:{acceptnonstdtxn:true,limitclustersizeKB:2000},scope:"Actual false-disprove using another journal signature from its owner, followed by setup-pinned delayed recovery. Fixed-key experiment; challenger registration and integration with a storage/fork collateral game remain unresolved.",cases};
}finally{if(helper&&helper.exitCode===null)helper.kill();if(core.exitCode===null&&!coreError){await rpc("stop").catch(()=>{});for(let i=0;i<100&&core.exitCode===null;i++)await sleep(100);if(core.exitCode===null)core.kill();}}
assert.match(readFileSync(join(root,"regtest/debug.log"),"utf8"),/Shutdown done/);writeFileSync(out,JSON.stringify({...report,nodeStopped:true},null,2)+"\n",{flag:"wx"});console.log(out);
