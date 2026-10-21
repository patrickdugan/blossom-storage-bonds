// Full storage graph on a new, loopback-only Core regtest node. No public network or faucet.
// node zk/bitvm-check/graph-regtest.ts --bitcoind <installed binary> --checker <bsb-storage-graph>
//   --partials <checked verifier cache> --assertions <checked assertions> --dir <new directory> --out <new result.json>
import assert from "node:assert/strict";
import { verifyGraphPayouts } from "./graph-payouts.ts";
import { prepareAdmissionCarriers } from "./admission-carriers.ts";
import { spawn } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
const opt=(name:string)=>{const i=process.argv.indexOf(`--${name}`);return i<0?undefined:process.argv[i+1];};
const req=(name:string)=>{const value=opt(name);if(!value)throw Error(`--${name} is required`);return value;};
const dir=resolve(req("dir")),out=resolve(req("out"));
if(existsSync(dir)||existsSync(out))throw Error("refusing to reuse test data or results");
const corePath=req("bitcoind"),checker=req("checker"),partials=resolve(req("partials")),assertions=resolve(req("assertions"));
const journal=process.argv.includes("--journal");
const repo=resolve(dirname(fileURLToPath(import.meta.url)),"../..");
const sleep=(ms:number)=>new Promise(r=>setTimeout(r,ms));
const server=createServer();await new Promise<void>((ok,bad)=>{server.once("error",bad);server.listen(0,"127.0.0.1",ok);});
const port=(server.address() as {port:number}).port;await new Promise<void>(r=>server.close(()=>r()));
mkdirSync(dir);
const core=spawn(corePath,["-regtest=1",`-datadir=${dir}`,"-server=1","-txindex=1","-listen=0","-connect=0","-dnsseed=0","-discover=0","-acceptnonstdtxn=1","-limitclustersize=2000","-persistmempool=0",`-rpcport=${port}`,"-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=bsb","-rpcpassword=bsb-regtest-only","-fallbackfee=0.00002"],{windowsHide:true,stdio:"ignore"});
let spawnError:Error|undefined;core.once("error",e=>{spawnError=e;});
async function rpc(method:string,params:unknown[]=[],wallet=false):Promise<any>{
  const response=await fetch(`http://127.0.0.1:${port}${wallet?"/wallet/graph":""}`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},body:JSON.stringify({jsonrpc:"2.0",id:"graph",method,params}),signal:AbortSignal.timeout(120_000)});
  const data=await response.json() as {result:any,error:any};if(data.error)throw Error(`${method}: ${JSON.stringify(data.error)}`);return data.result;
}
const results:any[]=[];let setup:ReturnType<typeof spawn>|undefined;
try{
  for(const started=Date.now();;){if(spawnError)throw spawnError;if(core.exitCode!==null)throw Error(`Core exited ${core.exitCode}`);try{if((await rpc("getblockchaininfo")).chain==="regtest")break;}catch{}if(Date.now()-started>60_000)throw Error("Core startup timed out");await sleep(200);}
  assert.equal((await rpc("getblockchaininfo")).chain,"regtest");
  const version=(await rpc("getnetworkinfo")).subversion;
  await rpc("createwallet",["graph"]);const mining=await rpc("getnewaddress",[],true);await rpc("generatetoaddress",[101,mining]);
  const mine=async(n:number)=>{if(n>0)await rpc("generatetoaddress",[n,mining]);};
  const mineTo=async(height:number)=>mine(Math.max(0,height-await rpc("getblockcount")));
  const kinds=(opt("scenarios")??(journal?"no-kickoff,no-challenge,silence,honest,wrong-term,wrong-journal,corrupt-proof,burn-marker":"no-kickoff,no-challenge,silence,honest,wrong-term,corrupt-proof,burn-marker")).split(",");
  if(opt("admission-checker"))assert.ok(journal && kinds.length===1 && kinds[0]==="honest","admission carrier regression requires --journal --scenarios honest");
  for(const kind of kinds){
    let admission:Awaited<ReturnType<typeof prepareAdmissionCarriers>>|undefined;
    const graphDir=join(dir,`graph-${kind}`),log=createWriteStream(join(dir,`setup-${kind}.log`),{flags:"wx"});
    let readyOk!:(v:any)=>void,readyBad!:(e:Error)=>void,completeOk!:(v:any)=>void,completeBad!:(e:Error)=>void;
    let sawReady=false,sawComplete=false;
    const ready=new Promise<any>((ok,bad)=>{readyOk=ok;readyBad=bad;});
    const complete=new Promise<any>((ok,bad)=>{completeOk=ok;completeBad=bad;});
    // Register a rejection observer while the first handshake stage is still pending.
    complete.catch(()=>undefined);
    setup=spawn(checker,[join(repo,"results","bitvm2-spike.json"),join(repo,"results","bitvm2-spike-groth16"),partials,assertions,kind,graphDir,...(journal?["--journal"]:[])],{windowsHide:true,stdio:["pipe","pipe","pipe"]});
    const active=setup;active.stderr!.pipe(log,{end:false});
    const lines=createInterface({input:active.stdout!});
    lines.on("line",line=>{log.write(line+"\n");if(line.startsWith("BSB_GRAPH ")){try{const event=JSON.parse(line.slice(10));if(event.ready){sawReady=true;readyOk(event);}if(event.complete){sawComplete=true;completeOk(event);}}catch(e){readyBad(e as Error);completeBad(e as Error);}}});
    const exited=new Promise<void>((ok,bad)=>{active.once("error",bad);active.once("close",(code)=>{if(code===0&&sawReady&&sawComplete)ok();else bad(Error(`graph setup ${kind} exited ${code}; inspect its log`));});});
    exited.catch(e=>{readyBad(e);completeBad(e);});
    const meta=await ready;assert.equal(meta.network,"regtest");
    // Obtain a signed, fixed txid but do not broadcast until graph setup and presigning finish.
    const psbt=await rpc("walletcreatefundedpsbt",[[],{[meta.funding_address]:1},0,{replaceable:false},true],true);
    const signed=await rpc("walletprocesspsbt",[psbt.psbt],true);const funding=await rpc("finalizepsbt",[signed.psbt]);assert.equal(funding.complete,true);
    const decoded=await rpc("decoderawtransaction",[funding.hex]);const coin=decoded.vout.find((v:any)=>v.scriptPubKey.address===meta.funding_address);assert.ok(coin);
    active.stdin!.end(JSON.stringify({network:"regtest",txid:decoded.txid,vout:coin.n,sats:100_000_000,height:await rpc("getblockcount")})+"\n");
    const finished=await complete;await exited;lines.close();log.end();setup=undefined;
    const graph=JSON.parse(readFileSync(finished.file,"utf8"));assert.equal(graph.network,"regtest");assert.equal(graph.groth16_leaves,364);assert.equal(graph.commitments,journal?382:381);assert.equal(graph.journal_binding,journal);
    await rpc("sendrawtransaction",[funding.hex]);await mine(1);
    const record:any={scenario:kind,checks:[],mined:[],disproveLeaf:graph.disprove_leaf,commitments:graph.commitments,journalBinding:graph.journal_binding,claimedTermJournal:graph.claimed_term_journal};
    const tx=(name:string)=>JSON.parse(readFileSync(graph.transactions[name].file,"utf8"));
    const testHex=async(hex:string)=>(await rpc("testmempoolaccept",[[hex]]))[0];
    const reject=async(name:string,reason:RegExp,hex=tx(name).hex)=>{const r=await testHex(hex);assert.equal(r.allowed,false,`${kind}: ${name} accepted unexpectedly`);assert.match(String(r["reject-reason"]),reason);record.checks.push({name,rejected:true,reason:r["reject-reason"]});};
    const send=async(name:string)=>{const t=tx(name);const r=await testHex(t.hex);assert.equal(r.allowed,true,`${kind}: ${name}: ${JSON.stringify(r)}`);assert.equal(await rpc("sendrawtransaction",[t.hex]),t.txid);await mine(1);const mined=await rpc("getrawtransaction",[t.txid,true]);assert.ok(mined.confirmations>=1);record.mined.push({name,txid:t.txid,vsize:t.vsize,feeSats:t.fee_sats});return mined;};
    if(kind==="no-kickoff"){
      await reject("kickoff-timeout",/non-final/);await mineTo(graph.kickoff_deadline);await send("kickoff-timeout");
    }else{
      await reject("kickoff",/non-final/);await mineTo(graph.term_end);
      if(opt("admission-checker"))admission=await prepareAdmissionCarriers({rpc,mine,graphDir,graph,record,checker:opt("admission-checker")!,fundingTxid:decoded.txid,fundingVout:coin.n});
      await send("kickoff");
      if(kind==="no-challenge"){
        await reject("unchallenged-refund",/non-BIP68-final/);await mine(graph.challenge_blocks);await send("unchallenged-refund");
      }else{
        if(admission)await admission.rejectAt("challenge");
        await send("challenge");
        await reject("assert-timeout",/non-BIP68-final/);
        if(kind==="silence"){
          await mine(graph.assert_blocks);await send("assert-timeout");await send("slots-timeout");
        }else{
          await reject("assert-final",/missing|spent/);
          await reject("skipped-commitment",/script/,JSON.parse(readFileSync(join(graphDir,"skipped-commitment.json"),"utf8")).hex);
          await send("assert-commit-0");
          if(journal)await reject("skipped-journal",/script/,JSON.parse(readFileSync(join(graphDir,"skipped-journal.json"),"utf8")).hex);
          await send("assert-commit-1");if(admission)await admission.rejectAt("assert-final");await send("assert-final");
          await reject("refund",/non-BIP68-final/);
          if(kind==="honest"){
            await reject("slash",/script/);await mine(graph.dispute_blocks);if(admission)await admission.rejectAt("refund");await send("refund");if(admission)await admission.finish(tx("refund").txid);
          }else if(kind==="burn-marker"){
            await send("marker-burn");await mine(graph.dispute_blocks);await reject("refund",/missing|spent/);await reject("final-timeout",/non-final/);await mineTo(graph.final_deadline);await send("final-timeout");
          }else{
            if(kind==="corrupt-proof")assert.notEqual(graph.disprove_leaf,364,"corrupt intermediates must use a real Groth16 leaf");
            await reject("redirected-slash",/script/,JSON.parse(readFileSync(join(graphDir,"redirected-slash.json"),"utf8")).hex);
            await send("slash");await reject("refund",/missing|spent/);
          }
        }
      }
    }
    record.client=meta.client_address;record.provider=meta.provider_address;
    results.push(record);console.log(`${kind}: ${record.mined.length} graph transactions mined; ${record.checks.length} invalid/early spends rejected`);
  }
  verifyGraphPayouts(results,dir);
  mkdirSync(dirname(out),{recursive:true});writeFileSync(out,JSON.stringify({payoutVerification:"independent transaction decoder; exact txids accepted and mined by Core",generated:new Date().toISOString(),network:"regtest",core:version,policy:{acceptnonstdtxn:true,limitclustersizeKB:2000},scope:journal?"Journal-linked storage graph using the fixed phase-6 proof and real verifier leaves. Fresh-chain lifecycle and heavier-fork enforcement remain separate.":"storage graph using the fixed phase-6 proof and real verifier leaves; heavier-chain challenge and fresh-chain proof generation remain",cases:results},null,2)+"\n",{flag:"wx"});
  console.log(`wrote ${out}`);
}finally{
  if(setup&&setup.exitCode===null)setup.kill();
  if(core.exitCode===null&&!spawnError){await rpc("stop").catch(()=>undefined);for(let i=0;i<100&&core.exitCode===null;i++)await sleep(100);if(core.exitCode===null)core.kill();}
}
