// Standalone bounded direct-header dispute; no RISC Zero/Groth16 proof generation.
import assert from "node:assert/strict";
import {spawn,execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {existsSync,mkdirSync,readFileSync,writeFileSync,createWriteStream} from "node:fs";
import {createServer} from "node:net";
import {join,resolve} from "node:path";
import {createInterface} from "node:readline";
import {HeaderChain,REGTEST,compactToTarget,workOf} from "../../layer1/headerchain.ts";
import {parseTx,taprootAddress} from "../../layer1/onchain.ts";
const opt=(n:string)=>{const i=process.argv.indexOf(`--${n}`);return i<0?undefined:process.argv[i+1];};const req=(n:string)=>{const v=opt(n);assert.ok(v,`--${n} required`);return v;};
const root=resolve(req("dir")),out=resolve(req("out")),checker=req("checker");assert.ok(!existsSync(root)&&!existsSync(out));mkdirSync(root);
const json=(p:string)=>JSON.parse(readFileSync(p,"utf8")),pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
const reserve=createServer();await new Promise<void>(r=>reserve.listen(0,"127.0.0.1",r));const port=(reserve.address() as {port:number}).port;await new Promise<void>(r=>reserve.close(()=>r()));
const core=spawn(req("bitcoind"),["-regtest=1",`-datadir=${root}`,"-server=1","-txindex=1","-acceptnonstdtxn=1","-limitclustersize=2000","-listen=0","-connect=0","-dnsseed=0","-discover=0","-persistmempool=0",`-rpcport=${port}`,"-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=bsb","-rpcpassword=bsb-regtest-only","-fallbackfee=0.00002"],{windowsHide:true,stdio:"ignore"});let coreError:Error|undefined;core.once("error",e=>{coreError=e;});
async function rpc(method:string,params:unknown[]=[],wallet=false):Promise<any>{const response=await fetch(`http://127.0.0.1:${port}${wallet?"/wallet/rebuttal":""}`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},body:JSON.stringify({jsonrpc:"2.0",id:"rebuttal",method,params}),signal:AbortSignal.timeout(60_000)});const v=await response.json() as any;if(v.error)throw Error(JSON.stringify(v.error));return v.result;}
const sha=(v:Buffer)=>createHash("sha256").update(v).digest();const sha2=(v:Buffer)=>sha(sha(v));
const cases:any[]=[];let previousStrongCounter:string|undefined;let producer:ReturnType<typeof spawn>|undefined,report:any;
try{
 for(const start=Date.now();;){if(coreError)throw coreError;assert.equal(core.exitCode,null);try{if((await rpc("getblockchaininfo")).chain==="regtest")break;}catch{}assert.ok(Date.now()-start<60_000);await pause(200);}
 await rpc("createwallet",["rebuttal"]);const mining=await rpc("getnewaddress",[],true);const mine=async(n=1)=>rpc("generatetoaddress",[n,mining]);await mine(169);
 for(const kind of ["stronger-counterbranch","honest-extension","silent-provider","unchallenged","equivocated-original","funding-timeout"]){
  const dir=join(root,kind);mkdirSync(dir);const vectors=join(dir,"vectors"),anchorHeight=await rpc("getblockcount"),anchorHash=await rpc("getbestblockhash"),anchorHeader=await rpc("getblockheader",[anchorHash]);
  const times=[];for(let h=anchorHeight-10;h<=anchorHeight;h++)times.push((await rpc("getblockheader",[await rpc("getblockhash",[h])])).time);
  const anchor={network:"regtest",height:anchorHeight,hash:anchorHash,hashInternal:Buffer.from(anchorHash,"hex").reverse().toString("hex"),times,work:BigInt("0x"+anchorHeader.chainwork).toString(),maxTime:anchorHeader.time+7200};const anchorFile=join(dir,"anchor.json");writeFileSync(anchorFile,JSON.stringify(anchor));
  producer=spawn(checker,["serve",vectors,anchorFile],{windowsHide:true,stdio:["pipe","pipe","pipe"]});const active=producer,log=createWriteStream(join(dir,"setup.log"));active.stderr!.pipe(log,{end:false});
  let readyOk!:(v:any)=>void,readyBad!:(e:Error)=>void,presignedOk!:()=>void;const ready=new Promise<any>((a,b)=>{readyOk=a;readyBad=b;}),presigned=new Promise<void>(a=>{presignedOk=a;});
  let claimOk!:()=>void;const claimReady=new Promise<void>(a=>{claimOk=a;});
  const lines=createInterface({input:active.stdout!});lines.on("line",line=>{log.write(line+"\n");if(line.startsWith("BSB_REBUTTAL ")){const v=JSON.parse(line.slice(13));if(v.ready)readyOk(v);if(v.presigned)presignedOk();if(v.claimReady)claimOk();}});
  const exited=new Promise<void>((a,b)=>{active.once("error",e=>{readyBad(e);b(e);});active.once("close",code=>{lines.close();log.end();if(code===0)a();else{const e=Error(`producer exit ${code}`);readyBad(e);b(e);}});});exited.catch(()=>{});
  const info=await ready;assert.equal(info.network,"regtest");
  const p=await rpc("walletcreatefundedpsbt",[[],{[info.funding]:1},0,{replaceable:false},true],true),signed=await rpc("walletprocesspsbt",[p.psbt],true),fund=await rpc("finalizepsbt",[signed.psbt]);assert.equal(fund.complete,true);const funded=await rpc("decoderawtransaction",[fund.hex]),vout=funded.vout.find((v:any)=>v.scriptPubKey.address===info.funding).n;
  active.stdin!.write(JSON.stringify({txid:funded.txid,vout})+"\n");await presigned;
  const prefix=[];for(let h=0;h<=anchorHeight;h++)prefix.push(await rpc("getblockheader",[await rpc("getblockhash",[h]),false]));writeFileSync(join(dir,"checkpoint-headers.json"),JSON.stringify(prefix));
  const original={headers:[] as string[],hashes:[] as string[],work:""};let alternate:{headers:string[];hashes:string[];work:string};let responseHeaders:string[]=[];const responseCount=kind==="honest-extension"?3:2;
  const raw=(name:string)=>json(join(vectors,name+".json"));const run=(args:string[])=>execFileSync(checker,args,{windowsHide:true,timeout:120_000,stdio:"pipe",maxBuffer:1024*1024});
  const admitted:any[]=[],rejected:any[]=[],mined:any[]=[],payouts:any[]=[];
  const accept=async(name:string,v:any)=>{const a=(await rpc("testmempoolaccept",[[v.hex]]))[0];assert.equal(a.allowed,true,`${kind}/${name}: ${JSON.stringify(a)}`);admitted.push({name,txid:a.txid,wtxid:a.wtxid});};
  const reject=async(name:string,v:any,why=/script|non-BIP68-final|non-final|missing|spent/i)=>{const a=(await rpc("testmempoolaccept",[[v.hex]]))[0];assert.equal(a.allowed,false,`${kind}/${name}`);assert.match(a["reject-reason"],why);rejected.push({name,reason:a["reject-reason"]});};
  const send=async(name:string,v:any)=>{await accept(name,v);assert.equal(await rpc("sendrawtransaction",[v.hex]),v.txid);await mine();const a=await rpc("getrawtransaction",[v.txid,true]);assert.ok(a.confirmations>=1);assert.equal(a.hex,v.hex);assert.ok(a.weight<=4_000_000);mined.push({name,txid:v.txid,wtxid:a.hash,weight:a.weight,vsize:a.vsize});return a;};
  const payout=async(name:string,v:any,who:string,sats:number)=>{await send(name,v);const t=parseTx(Buffer.from(v.hex,"hex"));assert.equal(t.outputs.length,1);assert.equal(t.outputs[0].value,BigInt(sats));assert.equal(taprootAddress(t.outputs[0].script.subarray(2).toString("hex"),"regtest"),who);payouts.push({name,txid:v.txid,address:who,sats});};
  const make=(which:string,headers:string[],name:string)=>{const path=join(dir,name+"-headers.json"),dest=join(vectors,name+".json");writeFileSync(path,JSON.stringify(headers),{flag:"wx"});run([which,vectors,path,dest]);return json(dest);};
  const redirect=(v:string,name:string)=>{const p=join(vectors,name+".json");run(["redirect",join(vectors,v+".json"),mining,p]);return json(p);};
  const mature=async(txid:string,window=6)=>{const h=(await rpc("getrawtransaction",[txid,true])).blockhash;const start=(await rpc("getblockheader",[h])).height,now=await rpc("getblockcount");if(now<start+window-1)await mine(start+window-1-now);};
  await rpc("setmocktime",[anchorHeader.time+10]);writeFileSync(join(vectors,"funding.json"),JSON.stringify({hex:fund.hex,txid:funded.txid,vout}));await rpc("sendrawtransaction",[fund.hex]);const fundBlock=(await mine())[0];original.hashes.push(fundBlock);original.headers.push(await rpc("getblockheader",[fundBlock,false]));
  if(kind==="funding-timeout"){
   active.stdin!.end(JSON.stringify({noClaim:true})+"\n");await exited;producer=undefined;
   await reject("early-funding-timeout",raw("fund-timeout"));const now=await rpc("getblockcount"),deadline=anchorHeight+60;if(now<deadline)await mine(deadline-now);
   await reject("redirected-funding-timeout",redirect("fund-timeout","redirected-funding-timeout"));await payout("funding-timeout",raw("fund-timeout"),info.client,99_997_000);
   writeFileSync(join(dir,"branches.json"),JSON.stringify({original,alternate:null,responseHeaders:[]}));assert.equal(await rpc("getconnectioncount"),0);cases.push({kind,anchorHeight,anchorHash,providerResponseHeaders:0,maxCandidateHeaders:3,workPerValidatedHeader:"2",committeeDroppedBeforeFunding:true,providerMessagesSigned:false,providerExitedBeforeTimeout:true,leafBytes:raw("metadata").leafBytes,admitted,rejected,mined,payouts});console.log(JSON.stringify({case:kind,mined:mined.length,rejected:rejected.length}));continue;
  }
  active.stdin!.write(JSON.stringify({claimHeader:original.headers[0]})+"\n");await claimReady;
  await reject("early-funding-timeout",raw("fund-timeout"));const claim=raw("claim");await send("claim",claim);const claimBlock=await rpc("getbestblockhash");original.hashes.push(claimBlock);original.headers.push(await rpc("getblockheader",[claimBlock,false]));original.work=BigInt("0x"+(await rpc("getblockchaininfo")).chainwork).toString();
  // The committee is gone; only the provider's unused WOTS key remains in RAM.
  await rpc("invalidateblock",[original.hashes[0]]);assert.equal(await rpc("getbestblockhash"),anchorHash);
  const altHeaders:string[]=[],altHashes:string[]=[];for(let i=0;i<3;i++){await rpc("setmocktime",[anchorHeader.time+20+i]);const h=(await mine())[0];altHashes.push(h);altHeaders.push(await rpc("getblockheader",[h,false]));}
  const altChain=new HeaderChain(REGTEST);altChain.ingest(0,Buffer.from(prefix.concat(altHeaders).join(""),"hex"),anchor.maxTime);const altWork=BigInt("0x"+(await rpc("getblockchaininfo")).chainwork);assert.equal(altChain.totalWork,altWork);assert.equal(altChain.tip,altHashes[2]);alternate={headers:altHeaders,hashes:altHashes,work:altWork.toString()};
  await rpc("invalidateblock",[alternate.hashes[0]]);await rpc("reconsiderblock",[original.hashes[0]]);assert.equal(await rpc("getbestblockhash"),original.hashes[1]);assert.equal((await rpc("getrawtransaction",[claim.txid,true])).confirmations,1);assert.notEqual(alternate.hashes[0],original.hashes[0]);await rpc("setmocktime",[anchorHeader.time+40]);
  await reject("early-unchallenged-refund",raw("unchallenged"));
  if(kind==="unchallenged"){
   active.stdin!.end(JSON.stringify({noResponse:true})+"\n");await exited;producer=undefined;
   await mature(claim.txid);await payout("unchallenged-refund",raw("unchallenged"),info.provider,99_197_000);
  }else{
   await reject("opening-does-not-diverge",make("challenge",original.headers.slice(0,2),"same-seed-opening"));const opening=make("challenge",alternate.headers.slice(0,2),"challenge");await reject("redirected-opening-challenge",redirect("challenge","redirected-opening"));await send("permissionless-valid-fork-challenge",opening);await reject("early-silence-timeout",raw("silence"));
   if(kind==="silent-provider"){
    active.stdin!.end(JSON.stringify({noResponse:true})+"\n");await exited;producer=undefined;
    await mature(raw("challenge").txid);await payout("provider-silence",raw("silence"),info.client,98_397_000);
   }else{
    const responseBase=await rpc("getbestblockhash");original.hashes.push(responseBase);original.headers.push(await rpc("getblockheader",[responseBase,false]));original.work=BigInt("0x"+(await rpc("getblockchaininfo")).chainwork).toString();const originalChain=new HeaderChain(REGTEST);originalChain.ingest(0,Buffer.from(prefix.concat(original.headers).join(""),"hex"),anchor.maxTime);assert.equal(originalChain.totalWork,BigInt(original.work));
    responseHeaders=(kind==="equivocated-original"?alternate:original).headers.slice(0,responseCount);active.stdin!.end(JSON.stringify({responseHeaders,deliberateEquivocation:kind==="equivocated-original"})+"\n");await exited;assert.equal(active.exitCode,0);producer=undefined;
    if(kind!=="equivocated-original")await reject("response-does-not-extend-original",make("response",alternate.headers.slice(0,responseCount),"unrelated-response"));
    await reject("response-count-mismatch",make("response",original.headers.slice(0,responseCount===3?2:3),"count-mismatch"));
    const response=raw("response");await send("provider-response",response);await reject("early-provider-refund",raw("refund"));
    const meta=raw("metadata"),claimWitness=(await rpc("getrawtransaction",[claim.txid,true])).vin[0].txinwitness,responseWitness=(await rpc("getrawtransaction",[response.txid,true])).vin[0].txinwitness;
    assert.deepEqual(claimWitness.slice(0,meta.originalSignatureItems),meta.originalSignature);assert.deepEqual(responseWitness.slice(0,meta.countSignatureItems),meta.countSignature);assert.deepEqual(responseWitness.slice(meta.countSignatureItems,meta.countSignatureItems+meta.originalSignatureItems),meta.responseOriginalSignature);
    if(kind==="equivocated-original"){
     await reject("redirected-equivocation",redirect("equivocation","redirected-equivocation"));await payout("original-equivocation",raw("equivocation"),info.client,97_550_000);
    }else{
     await reject("weaker-candidate",make("counter",alternate.headers.slice(0,1),"weaker"));
     await reject("equal-work-candidate",make("counter",alternate.headers.slice(0,responseCount),"equal"));
     await reject("same-seed-branch",make("counter",original.headers,"same-seed"));
     if(kind==="stronger-counterbranch"){
      const invalid=Buffer.from(alternate.headers[2],"hex");invalid.writeUInt32LE(0x207ffffe,72);await reject("wrong-difficulty",make("counter",[...alternate.headers.slice(0,2),invalid.toString("hex")],"wrong-bits"));
      const target=compactToTarget(0x207fffff)!;
      const headerNumber=(b:Buffer)=>BigInt("0x"+Buffer.from(sha2(b)).reverse().toString("hex"));
      const remine=(b:Buffer,valid:boolean)=>{for(let nonce=0;nonce<10000;nonce++){b.writeUInt32LE(nonce,76);if((headerNumber(b)<=target)===valid)return b.toString("hex");}throw Error("regtest nonce bound");};
      const badPow=Buffer.from(alternate.headers[2],"hex");await reject("invalid-proof-of-work",make("counter",[...alternate.headers.slice(0,2),remine(badPow,false)],"bad-pow"));
      const mtp=[...times.slice(2),...alternate.headers.slice(0,2).map(h=>Buffer.from(h,"hex").readUInt32LE(68))].sort((a,b)=>a-b)[5];
      const staleTime=Buffer.from(alternate.headers[2],"hex");staleTime.writeUInt32LE(mtp,68);await reject("timestamp-at-median",make("counter",[...alternate.headers.slice(0,2),remine(staleTime,true)],"bad-mtp"));
      const version=Buffer.from(alternate.headers[2],"hex");version.writeUInt32LE(3,0);await reject("obsolete-version",make("counter",[...alternate.headers.slice(0,2),remine(version,true)],"bad-version"));
      const strong=make("counter",alternate.headers,"stronger");previousStrongCounter=join(vectors,"stronger.json");
      for(const [name,index] of [["invented-response-work",0],["unrelated-original-key",meta.countSignatureItems]] as const){const path=join(vectors,name+".json");run(["break-witness",join(vectors,"stronger.json"),String(index),path]);await reject(name,json(path));}
await reject("redirected-counter",redirect("stronger","redirected-counter"));await payout("stronger-candidate-after-weaker-attempts",strong,info.client,95_600_000);
     }else{
      assert.ok(previousStrongCounter);make("counter",alternate.headers,"honest-counter-template");const replayPath=join(vectors,"replayed-old-count.json");run(["replay-count",join(vectors,"honest-counter-template.json"),previousStrongCounter,replayPath]);await reject("old-graph-underreported-work-replay",json(replayPath));
      await mature(response.txid);await payout("honest-extension-refund",raw("refund"),info.provider,97_597_000);
     }
    }
   }
  }
  writeFileSync(join(dir,"branches.json"),JSON.stringify({original,alternate,responseHeaders}));assert.equal(await rpc("getconnectioncount"),0);cases.push({kind,anchorHeight,anchorHash,providerResponseHeaders:responseHeaders.length,maxCandidateHeaders:3,workPerValidatedHeader:workOf(compactToTarget(0x207fffff)!).toString(),providerMessagesSelectedAfterPresigning:true,candidateChosenAfterCommitteePresigning:true,committeeDroppedBeforeFunding:true,providerResponseSignedAfterOpeningConfirmed:responseHeaders.length>0,providerExitedBeforeResponseBroadcast:true,leafBytes:raw("metadata").leafBytes,admitted,rejected,mined,payouts});
  console.log(JSON.stringify({case:kind,mined:mined.length,rejected:rejected.length}));
 }
 report={format:"bsb/bounded-provider-rebuttal-regtest/v1",network:"regtest",core:(await rpc("getnetworkinfo")).subversion,policy:{acceptnonstdtxn:true,limitclustersizeKB:2000,peers:0},maxHeaders:3,seed:"first header after the pinned checkpoint",cases,generated:new Date().toISOString(),scope:"Complete standalone transaction paths for a bounded direct-header counterbranch contest. Exact work under pinned regtest target, verified public fork challenge, provider branch response, outsider counterbranch, fixed payouts and timeout/equivocation paths. Direct verification of bounded challenger branches is still required; this does not solve long-chain optimistic challenge-input binding, candidate-set rebuttal or Groth16 admission. The no-more-proofs gate remains closed."};
}finally{if(producer&&producer.exitCode===null)producer.kill();if(core.exitCode===null&&!coreError){await rpc("stop").catch(()=>{});for(let i=0;i<100&&core.exitCode===null;i++)await pause(100);if(core.exitCode===null)core.kill();}}
assert.match(readFileSync(join(root,"regtest/debug.log"),"utf8"),/Shutdown done/);writeFileSync(out,JSON.stringify({...report,nodeStopped:true},null,2)+"\n",{flag:"wx"});console.log(JSON.stringify({cases:cases.length,mined:cases.flatMap(c=>c.mined).length,rejected:cases.flatMap(c=>c.rejected).length,result:out}));
