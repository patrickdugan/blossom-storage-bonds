// Bounded subset-bank penalty experiment. No Binohash grinding or ZK computation.
import assert from "node:assert/strict";
import {spawn,execFileSync} from "node:child_process";
import {existsSync,mkdirSync,readFileSync,writeFileSync,createWriteStream} from "node:fs";
import {createServer} from "node:net";
import {join,resolve} from "node:path";
import {createInterface} from "node:readline";
import {parseTx,taprootAddress} from "../../layer1/onchain.ts";
const opt=(n:string)=>{const i=process.argv.indexOf(`--${n}`);return i<0?undefined:process.argv[i+1];};const req=(n:string)=>{const v=opt(n);assert.ok(v,`--${n} required`);return v;};
const root=resolve(req("dir")),out=resolve(req("out")),checker=req("checker");assert.ok(!existsSync(root)&&!existsSync(out));mkdirSync(root);
const json=(p:string)=>JSON.parse(readFileSync(p,"utf8")),sleep=(ms:number)=>new Promise(r=>setTimeout(r,ms));
const reserve=createServer();await new Promise<void>(r=>reserve.listen(0,"127.0.0.1",r));const port=(reserve.address() as {port:number}).port;await new Promise<void>(r=>reserve.close(()=>r()));
const core=spawn(req("bitcoind"),["-regtest=1",`-datadir=${root}`,"-server=1","-txindex=1","-acceptnonstdtxn=0","-listen=0","-connect=0","-dnsseed=0","-discover=0","-persistmempool=0",`-rpcport=${port}`,"-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=bsb","-rpcpassword=bsb-regtest-only","-fallbackfee=0.00002"],{windowsHide:true,stdio:"ignore"});let coreError:Error|undefined;core.once("error",e=>{coreError=e;});
async function rpc(method:string,params:unknown[]=[],wallet=false):Promise<any>{const response=await fetch(`http://127.0.0.1:${port}${wallet?"/wallet/subset-penalty":""}`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},body:JSON.stringify({jsonrpc:"2.0",id:"subset-penalty",method,params}),signal:AbortSignal.timeout(30_000)});const v=await response.json() as any;if(v.error)throw Error(JSON.stringify(v.error));return v.result;}
let setup:ReturnType<typeof spawn>|undefined,report:any;
const admitted:any[]=[],rejected:any[]=[],mined:any[]=[];
try{
  for(const start=Date.now();;){if(coreError)throw coreError;assert.equal(core.exitCode,null);try{if((await rpc("getblockchaininfo")).chain==="regtest")break;}catch{}assert.ok(Date.now()-start<60_000);await sleep(200);}
  await rpc("createwallet",["subset-penalty"]);const mining=await rpc("getnewaddress",[],true);const mine=async()=>rpc("generatetoaddress",[1,mining]);await rpc("generatetoaddress",[101,mining]);
  const vectors=join(root,"vectors");setup=spawn(checker,["setup",vectors],{windowsHide:true,stdio:["pipe","pipe","pipe"]});const active=setup,log=createWriteStream(join(root,"setup.log"));active.stderr!.pipe(log,{end:false});
  let ok!:(v:any)=>void,bad!:(e:Error)=>void;const ready=new Promise<any>((a,b)=>{ok=a;bad=b;});const lines=createInterface({input:active.stdout!});lines.on("line",line=>{log.write(line+"\n");if(line.startsWith("BSB_SUBSET ")){const v=JSON.parse(line.slice(11));if(v.ready)ok(v);}});
  const exited=new Promise<void>((a,b)=>{active.once("error",e=>{bad(e);b(e);});active.once("close",c=>{lines.close();log.end();if(c===0)a();else{const e=Error(`setup exit ${c}`);bad(e);b(e);}});});exited.catch(()=>{});
  const info=await ready;assert.equal(info.network,"regtest");assert.equal(info.funding.length,2);
  const psbt=await rpc("walletcreatefundedpsbt",[[],Object.fromEntries(info.funding.map((address:string)=>[address,1])),0,{replaceable:false},true],true);const processed=await rpc("walletprocesspsbt",[psbt.psbt],true);const funded=await rpc("finalizepsbt",[processed.psbt]);assert.equal(funded.complete,true);const funding=await rpc("decoderawtransaction",[funded.hex]);
  const vouts=info.funding.map((address:string)=>funding.vout.find((v:any)=>v.scriptPubKey.address===address).n);active.stdin!.end(JSON.stringify({txid:funding.txid,vouts})+"\n");await exited;assert.equal(active.exitCode,0);setup=undefined;
  const run=(args:string[])=>execFileSync(checker,args,{windowsHide:true,timeout:30_000,stdio:"pipe"});
  writeFileSync(join(vectors,"funding.json"),JSON.stringify({hex:funded.hex,txid:funding.txid,vouts}),{flag:"wx"});await rpc("sendrawtransaction",[funded.hex]);await mine();
  const accept=async(name:string,v:any)=>{const a=(await rpc("testmempoolaccept",[[v.hex]]))[0];assert.equal(a.allowed,true,JSON.stringify(a));admitted.push({name,txid:a.txid,wtxid:a.wtxid});};
  const reject=async(name:string,v:any)=>{const a=(await rpc("testmempoolaccept",[[v.hex]]))[0];assert.equal(a.allowed,false,name);assert.match(a["reject-reason"],/script/i);rejected.push({name,reason:a["reject-reason"]});};
  const metadata=json(join(vectors,"metadata.json"));assert.equal(metadata.bankSize,120);assert.equal(metadata.honestRevealsPerBank,8);assert.equal(metadata.penaltyDistinctReveals,9);assert.equal(new Set(metadata.banks.flat()).size,240);
  const payouts:any[]=[];
  for(let round=0;round<2;round++){
    const prefix="round-"+round+"-",valid=json(join(vectors,prefix+"valid.json")),decoded=await rpc("decoderawtransaction",[valid.hex]),w=decoded.vin[0].txinwitness;
    assert.equal(w.length,21);assert.equal(w[18].length,128);assert.equal(w[19].length/2,metadata.measurements[round].scriptBytes);
    for(let i=0;i<9;i++){assert.equal(w[2*i].length,64);assert.equal(w[2*i+1],i===8?"":(8-i).toString(16).padStart(2,"0"));}
    const parsed=parseTx(Buffer.from(valid.hex,"hex"));assert.equal(parsed.outputs.length,1);assert.equal(parsed.outputs[0].value,99_997_000n);assert.equal(taprootAddress(parsed.outputs[0].script.subarray(2).toString("hex"),"regtest"),info.recipient);
    await accept(prefix+"valid",valid);
    for(const name of ["same-disclosure","reordered-disclosure","mixed-round","negative-index","out-of-range","wrong-preimage"]){const v=json(join(vectors,prefix+name+".json")),d=await rpc("decoderawtransaction",[v.hex]);assert.deepEqual(d.vin[0].txinwitness.slice(18),w.slice(18));assert.deepEqual(parseTx(Buffer.from(v.hex,"hex")).outputs,parsed.outputs);await reject(prefix+name,v);}
    const redirect=join(vectors,prefix+"redirected.json");run(["redirect",join(vectors,prefix+"valid.json"),mining,redirect]);await reject(prefix+"redirected",json(redirect));
    assert.equal(await rpc("sendrawtransaction",[valid.hex]),valid.txid);await mine();const actual=await rpc("getrawtransaction",[valid.txid,true]);assert.ok(actual.confirmations>=1);assert.equal(actual.hex,valid.hex);mined.push({name:prefix+"valid",txid:valid.txid,wtxid:actual.hash,weight:actual.weight,vsize:actual.vsize});payouts.push({round,txid:valid.txid,sats:99_997_000,address:info.recipient});
  }
  assert.equal(await rpc("getconnectioncount"),0);report={format:"bsb/subset-overdisclosure-regtest/v1",network:"regtest",core:(await rpc("getnetworkinfo")).subversion,presignerExitedBeforeFunding:true,policy:{acceptnonstdtxn:false,peers:0},bankSize:120,rounds:2,honestRevealsPerBank:8,penaltyDistinctReveals:9,commitmentsDistinctWithinAndAcrossRounds:true,measurements:metadata.measurements,admitted,rejected,mined,payouts,generated:new Date().toISOString(),scope:"Separate setup-fixed Taproot penalty. Nine distinct preimages from one fixed bank open a presigned fixed payout; one eight-preimage disclosure plus repetition, reordering or an entry from the other round does not. No Binohash introspection, transaction pinning, production security level, window escrow or full storage/fork integration."};
}finally{if(setup&&setup.exitCode===null)setup.kill();if(core.exitCode===null&&!coreError){await rpc("stop").catch(()=>{});for(let i=0;i<100&&core.exitCode===null;i++)await sleep(100);if(core.exitCode===null)core.kill();}}
assert.match(readFileSync(join(root,"regtest/debug.log"),"utf8"),/Shutdown done/);writeFileSync(out,JSON.stringify({...report,nodeStopped:true},null,2)+"\n",{flag:"wx"});console.log(JSON.stringify({mined:mined.length,admitted:admitted.length,rejected:rejected.length,result:out}));
