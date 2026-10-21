// Bounded signature experiment. No Binohash grinding or ZK computation.
import assert from "node:assert/strict";
import {spawn,execFileSync} from "node:child_process";
import {randomBytes} from "node:crypto";
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
async function rpc(method:string,params:unknown[]=[],wallet=false):Promise<any>{const response=await fetch(`http://127.0.0.1:${port}${wallet?"/wallet/late-parent":""}`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},body:JSON.stringify({jsonrpc:"2.0",id:"late-parent",method,params}),signal:AbortSignal.timeout(30_000)});const v=await response.json() as any;if(v.error)throw Error(JSON.stringify(v.error));return v.result;}
let setup:ReturnType<typeof spawn>|undefined,report:any;
const admitted:any[]=[],rejected:any[]=[],mined:any[]=[];
try{
  for(const start=Date.now();;){if(coreError)throw coreError;assert.equal(core.exitCode,null);try{if((await rpc("getblockchaininfo")).chain==="regtest")break;}catch{}assert.ok(Date.now()-start<60_000);await sleep(200);}
  await rpc("createwallet",["late-parent"]);const mining=await rpc("getnewaddress",[],true);const mine=async()=>rpc("generatetoaddress",[1,mining]);await rpc("generatetoaddress",[101,mining]);
  const vectors=join(root,"vectors");setup=spawn(checker,["setup",vectors],{windowsHide:true,stdio:["pipe","pipe","pipe"]});const active=setup,log=createWriteStream(join(root,"setup.log"));active.stderr!.pipe(log,{end:false});
  let ok!:(v:any)=>void,bad!:(e:Error)=>void;const ready=new Promise<any>((a,b)=>{ok=a;bad=b;});const lines=createInterface({input:active.stdout!});lines.on("line",line=>{log.write(line+"\n");if(line.startsWith("BSB_LATE_PARENT ")){const v=JSON.parse(line.slice(16));if(v.ready)ok(v);}});
  const exited=new Promise<void>((a,b)=>{active.once("error",e=>{bad(e);b(e);});active.once("close",c=>{lines.close();log.end();if(c===0)a();else{const e=Error(`setup exit ${c}`);bad(e);b(e);}});});exited.catch(()=>{});
  const info=await ready;assert.equal(info.network,"regtest");assert.equal(info.funding.length,2);
  const psbt=await rpc("walletcreatefundedpsbt",[[],Object.fromEntries(info.funding.map((address:string)=>[address,1])),0,{replaceable:false},true],true);const processed=await rpc("walletprocesspsbt",[psbt.psbt],true);const funded=await rpc("finalizepsbt",[processed.psbt]);assert.equal(funded.complete,true);const funding=await rpc("decoderawtransaction",[funded.hex]);
  const vouts=info.funding.map((address:string)=>funding.vout.find((v:any)=>v.scriptPubKey.address===address).n);active.stdin!.end(JSON.stringify({txid:funding.txid,vouts})+"\n");await exited;assert.equal(active.exitCode,0);setup=undefined;
  // Chosen only after the presigner exits. Public-only utility commands cannot sign.
  const tag=randomBytes(32);assert.notDeepEqual(tag,Buffer.alloc(32));
  const run=(args:string[])=>execFileSync(checker,args,{windowsHide:true,timeout:30_000,stdio:"pipe"});
  const parentPath=join(vectors,"parent-1.json"),latePath=join(vectors,"late-parent.json");run(["mutate",parentPath,tag.toString("hex"),latePath]);
  const before=json(parentPath),late=json(latePath),p0=parseTx(Buffer.from(before.hex,"hex")),p1=parseTx(Buffer.from(late.hex,"hex"));assert.notEqual(p0.txid,p1.txid);assert.deepEqual(p0.inputs,p1.inputs);assert.deepEqual(p0.outputs[0],p1.outputs[0]);assert.notDeepEqual(p0.outputs[1],p1.outputs[1]);
  const decoded0=await rpc("decoderawtransaction",[before.hex]),decoded1=await rpc("decoderawtransaction",[late.hex]);assert.deepEqual(decoded0.vin[0].txinwitness,decoded1.vin[0].txinwitness);assert.ok(decoded1.vin[0].txinwitness[0].endsWith("83"));
  writeFileSync(join(vectors,"funding.json"),JSON.stringify({hex:funded.hex,txid:funding.txid,vouts}),{flag:"wx"});await rpc("sendrawtransaction",[funded.hex]);await mine();
  const accept=async(name:string,v:any)=>{const a=(await rpc("testmempoolaccept",[[v.hex]]))[0];assert.equal(a.allowed,true,`${name}: ${JSON.stringify(a)}`);admitted.push({name,txid:a.txid,wtxid:a.wtxid});};
  const reject=async(name:string,v:any,reason:RegExp)=>{const a=(await rpc("testmempoolaccept",[[v.hex]]))[0];assert.equal(a.allowed,false,name);assert.match(a["reject-reason"],reason);rejected.push({name,reason:a["reject-reason"]});};
  const send=async(name:string,v:any)=>{await accept(name,v);assert.equal(await rpc("sendrawtransaction",[v.hex]),v.txid);await mine();const actual=await rpc("getrawtransaction",[v.txid,true]);assert.ok(actual.confirmations>=1);assert.equal(actual.hex,v.hex);mined.push({name,txid:v.txid,wtxid:actual.hash});};
  const metadata=json(join(vectors,"metadata.json"));
  const flags:Record<string,number>={"default":0,"all":1,"none":2,"single":3,"all-acp":129,"none-acp":130,"single-acp":131};assert.deepEqual(metadata.modes,Object.keys(flags));const modeResults:any[]=[];
  await send("fixed-parent-control",json(join(vectors,"parent-0.json")));
  for(const mode of metadata.modes){const v=json(join(vectors,`child-0-${mode}.json`)),decoded=await rpc("decoderawtransaction",[v.hex]),signature=decoded.vin[0].txinwitness[0];assert.equal(signature.length,mode==="default"?128:130);const flag=signature.length===128?0:Number.parseInt(signature.slice(-2),16);assert.equal(flag,flags[mode]);await accept("fixed-child-"+mode,v);modeResults.push({mode,signatureFlag:flag,fixedParentAccepted:true,rewiredParentRejected:true});}
  const payout=json(join(vectors,"child-0-default.json"));await send("fixed-child-default",payout);const parsed=parseTx(Buffer.from(payout.hex,"hex"));assert.equal(parsed.outputs[0].value,99_994_000n);assert.equal(taprootAddress(parsed.outputs[0].script.subarray(2).toString("hex"),"regtest"),info.recipient);
  const redirectedPath=join(vectors,"redirected-late-parent.json");run(["redirect",latePath,mining,redirectedPath]);await reject("redirected-protected-parent-output",json(redirectedPath),/script/i);
  await send("late-data-parent-reuses-setup-signature",late);
  await reject("unrewired-child-parent-missing",json(join(vectors,"child-1-default.json")),/missing|spent/);
  for(const mode of metadata.modes){const oldPath=join(vectors,`child-1-${mode}.json`),path=join(vectors,`rewired-${mode}.json`);run(["rewire",oldPath,late.txid,path]);const a=json(oldPath),b=json(path),da=await rpc("decoderawtransaction",[a.hex]),db=await rpc("decoderawtransaction",[b.hex]);assert.deepEqual(da.vin[0].txinwitness,db.vin[0].txinwitness);assert.deepEqual(parseTx(Buffer.from(a.hex,"hex")).outputs,parseTx(Buffer.from(b.hex,"hex")).outputs);assert.equal(db.vin[0].txid,late.txid);await reject("rewired-child-"+mode,b,/script/i);}
  assert.equal(await rpc("getconnectioncount"),0);report={format:"bsb/late-parent-successor-regtest/v1",network:"regtest",core:(await rpc("getnetworkinfo")).subversion,presignerExitedBeforeFunding:true,tagChosenAfterPresignerExit:true,parentSignatureReused:true,successorSignaturesUnchanged:true,modeCount:metadata.modes.length,modes:metadata.modes,modeResults,parentTxids:{presigned:before.txid,late:late.txid},generated:new Date().toISOString(),admitted,rejected,mined,payout:{txid:payout.txid,address:info.recipient,sats:99_994_000},scope:"Parent SINGLE|ANYONECANPAY admits late output data while fixing output 0, but all seven pre-existing Taproot successor signature modes reject the changed parent outpoint. No Binohash, candidate-proof validation, chain-work comparison, or full fork protocol."};
}finally{if(setup&&setup.exitCode===null)setup.kill();if(core.exitCode===null&&!coreError){await rpc("stop").catch(()=>{});for(let i=0;i<100&&core.exitCode===null;i++)await sleep(100);if(core.exitCode===null)core.kill();}}
assert.match(readFileSync(join(root,"regtest/debug.log"),"utf8"),/Shutdown done/);writeFileSync(out,JSON.stringify({...report,nodeStopped:true},null,2)+"\n",{flag:"wx"});console.log(JSON.stringify({mined:mined.length,admitted:admitted.length,rejected:rejected.length,result:out}));
