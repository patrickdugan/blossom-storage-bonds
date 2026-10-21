// A fresh, loopback-only Core regtest node. Tests the real Taproot witness for the storage binding
// leaf; no signet, external peers, faucet or real funds. The large script requires nonstandard policy.
// Windows + existing WSL build:
// node zk/bitvm-check/binding-regtest.ts --bitcoind <bitcoind.exe> --wsl-checker <Linux binary> --dir <new directory> --out <result.json>
// A native build can use --checker <binary> instead. Existing directories are refused.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const opt = (name: string) => { const i=process.argv.indexOf(`--${name}`); return i < 0 ? undefined : process.argv[i+1]; };
const required = (name: string) => { const value=opt(name); if (!value) throw new Error(`--${name} is required`); return value; };
const dir=resolve(required("dir"));
if (existsSync(dir)) throw new Error("refusing to reuse a test datadir");
const bitcoind=required("bitcoind"), native=opt("checker"), wsl=opt("wsl-checker");
if (!!native === !!wsl) throw new Error("choose exactly one of --checker and --wsl-checker");
const output=resolve(required("out"));
if (existsSync(output)) throw new Error("refusing to overwrite results");
const fixture=resolve(dirname(fileURLToPath(import.meta.url)),"../../results/bitvm2-spike.json");
const linuxPath = (path: string) => {
  const match=/^([a-z]):[\\/](.*)$/i.exec(path);
  if (!match) throw new Error("WSL checker expects an absolute Windows drive path");
  return `/mnt/${match[1].toLowerCase()}/${match[2].replaceAll("\\","/")}`;
};
const checker = (args: string[]) => {
  const converted=args.map(a => /^[a-z]:[\\/]/i.test(a) ? linuxPath(a) : a);
  const result=native ? execFileSync(native,args,{windowsHide:true,timeout:120_000,encoding:"utf8"})
    : execFileSync("wsl.exe",["-d",opt("distro") ?? "Ubuntu-24.04","-u","root","--exec",wsl!,...converted],{windowsHide:true,timeout:120_000,encoding:"utf8"});
  return JSON.parse(result.trim().split("\n").pop()!);
};
const sleep = (ms: number) => new Promise(r=>setTimeout(r,ms));
const reserve=createServer();
await new Promise<void>((ok,bad)=>{reserve.once("error",bad); reserve.listen(0,"127.0.0.1",ok);});
const port=(reserve.address() as {port:number}).port;
await new Promise<void>((ok,bad)=>reserve.close(error=>error ? bad(error) : ok()));
mkdirSync(dir);
const core=spawn(bitcoind,["-regtest=1",`-datadir=${dir}`,"-server=1","-txindex=1","-listen=0","-connect=0","-dnsseed=0","-discover=0","-acceptnonstdtxn=1","-limitclustersize=2000","-persistmempool=0",`-rpcport=${port}`,"-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=bsb","-rpcpassword=bsb-regtest-only","-fallbackfee=0.00002"],{windowsHide:true,stdio:"ignore"});
let startupError: Error | undefined;
core.once("error",error=>{startupError=error;});
async function rpc(method: string, params: unknown[]=[], wallet=false): Promise<any> {
  const response=await fetch(`http://127.0.0.1:${port}${wallet ? "/wallet/binding" : ""}`,{
    method:"POST",headers:{Authorization:"Basic "+Buffer.from("bsb:bsb-regtest-only").toString("base64")},
    body:JSON.stringify({jsonrpc:"2.0",id:"binding",method,params}),signal:AbortSignal.timeout(20_000),
  });
  const value=await response.json() as {result:any,error:any};
  if(value.error) throw new Error(`${method}: ${JSON.stringify(value.error)}`);
  return value.result;
}
const cases: any[]=[];
try {
  for(const start=Date.now();;){
    if(startupError) throw startupError;
    if(core.exitCode!==null) throw new Error(`Core exited ${core.exitCode}; inspect the fresh datadir`);
    try { if((await rpc("getblockchaininfo")).chain === "regtest") break; } catch { /* startup */ }
    if(Date.now()-start>60_000) throw new Error("Core startup timed out");
    await sleep(200);
  }
  assert.equal((await rpc("getblockchaininfo")).chain,"regtest");
  const version=(await rpc("getnetworkinfo")).subversion;
  await rpc("createwallet",["binding"]);
  const destination=await rpc("getnewaddress",[],true);
  await rpc("generatetoaddress",[101,destination]);
  for(const kind of ["honest","wrong-public","wrong-tip","wrong-work","wrong-term"]){
    const prepared=join(dir,`${kind}.json`);
    const info=checker(["prepare",fixture,kind,prepared]);
    const funding=await rpc("sendtoaddress",[info.address,1],true);
    await rpc("generatetoaddress",[1,destination]);
    const funded=await rpc("getrawtransaction",[funding,true]);
    const vout=funded.vout.find((v:any)=>v.scriptPubKey.address===info.address);
    assert.ok(vout,"funding output exists");
    const spendPath=join(dir,`${kind}-spend.json`);
    checker(["spend",prepared,funding,String(vout.n),"100000000",destination,spendPath]);
    const spend=JSON.parse(readFileSync(spendPath,"utf8"));
    const acceptance=(await rpc("testmempoolaccept",[[spend.hex]]))[0];
    if(kind==="honest") {
      assert.equal(acceptance.allowed,false,"an honest binding must not be slashable");
      assert.match(String(acceptance["reject-reason"]),/script/);
    } else {
      assert.equal(acceptance.allowed,true,JSON.stringify(acceptance));
      assert.equal(await rpc("sendrawtransaction",[spend.hex]),spend.txid);
      await rpc("generatetoaddress",[1,destination]);
      assert.ok((await rpc("getrawtransaction",[spend.txid,true])).confirmations>=1);
    }
    cases.push({kind,allowed:acceptance.allowed,expected:kind!=="honest",rejectReason:acceptance["reject-reason"],txid:spend.txid,scriptBytes:spend.script_bytes,vsize:spend.vsize,weight:spend.weight,feeSats:spend.fee_sats,mined:kind!=="honest"});
    console.log(`${kind}: ${acceptance.allowed ? "accepted and mined" : "correctly rejected"}`);
  }
  const report={generated:new Date().toISOString(),network:"regtest",core:version,policy:{acceptnonstdtxn:true,limitclustersizeKB:2000},scope:"isolated real Taproot storage-binding leaf; not a complete storage bond graph, proof regeneration, or chain-work challenge",cases};
  mkdirSync(dirname(output),{recursive:true});
  writeFileSync(output,JSON.stringify(report,null,2)+"\n",{flag:"wx"});
  console.log(`wrote ${output}`);
} finally {
  if(core.exitCode===null && !startupError){
    await rpc("stop").catch(()=>undefined);
    for(let i=0;i<100 && core.exitCode===null;i++) await sleep(100);
    if(core.exitCode===null) core.kill();
  }
}
