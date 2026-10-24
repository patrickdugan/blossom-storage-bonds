// Read-only signed Bitcoin settlement observer for future A/B signet/testnet4 tests.
// This checks the full confirmed witness, input/output graph, fees and active
// block identity using a *trusted Bitcoin Core node*. It does NOT establish
// Filecoin validity, FROST honesty, authorized storage outcomes or key custody.
import { createHash } from 'node:crypto';
import { readFile, open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const fail=(message)=>{throw new Error(message);};
const expect=(value,message)=>{if(!value)fail(message);};
const hex64=(text)=>typeof text==='string'&&/^[0-9a-f]{64}$/i.test(text);
const hexScript=(text)=>typeof text==='string'&&text.length%2===0&&
  /^[0-9a-f]+$/i.test(text)&&text.length<=20000;
const outpoint=(text)=>{
  expect(typeof text==='string','expected outpoint string');
  const m=/^([0-9a-f]{64}):(\d+)$/i.exec(text);
  expect(m&&Number.isSafeInteger(Number(m[2]))&&Number(m[2])<=0xffffffff,
    'invalid Bitcoin outpoint '+text);
  return m[1].toLowerCase()+':'+Number(m[2]);
};
function sats(value) {
  expect((typeof value==='number'||typeof value==='string')&&Number.isFinite(Number(value)),
    'invalid Bitcoin amount');
  const str=Number(value).toFixed(8),[whole,part]=str.split('.');
  expect(Number(value)>=0 && Number(value)<=21_000_000,'Bitcoin money range');
  const n=BigInt(whole)*100_000_000n+BigInt(part);
  expect(n<=2_100_000_000_000_000n,'Bitcoin satoshi overflow');
  return n;
}
const satNumber=v=>{const n=sats(v);return Number(n);};
const hash256=bytes=>{
  const once=createHash('sha256').update(bytes).digest();
  return createHash('sha256').update(once).digest();
};
const wtxidFromHex=raw=> {
  expect(typeof raw==='string'&&raw.length>0&&raw.length%2===0&&/^[0-9a-f]+$/i.test(raw),
    'invalid raw witness transaction hex');
  return Buffer.from(hash256(Buffer.from(raw,'hex'))).reverse().toString('hex');
};
const readOut=(tx,vout)=>{
  expect(Array.isArray(tx.vout)&&Number.isInteger(vout)&&vout>=0&&vout<tx.vout.length,
    'missing Bitcoin output');
  const o=tx.vout[vout];
  expect(o&&o.n===vout&&hexScript(o.scriptPubKey?.hex),'invalid Bitcoin output identity');
  return o;
};
const same=(a,b)=>a.toLowerCase()===b.toLowerCase();

function manifestCheck(m) {
  expect(m&&m.schema==='bsb-ab-testnet-receipt-v1','invalid testnet manifest version');
  expect(['signet','testnet4'].includes(m.network),'only signet and testnet4 allowed');
  expect(['A-sentinel','B-layertree'].includes(m.backend),'unknown A/B backend');
  expect(Number.isInteger(m.minimum_confirmations)&&m.minimum_confirmations>=1&&
    m.minimum_confirmations<=1000,'invalid minimum confirmation depth');
  expect(Array.isArray(m.transactions)&&m.transactions.length>0&&
    m.transactions.length<=100,'missing real signed transactions');
  const txids=new Set();
  for(const t of m.transactions) {
    expect(hex64(t.txid)&&hex64(t.wtxid),'must pin real txid and signed wtxid');
    expect(!txids.has(t.txid.toLowerCase()),'duplicate transaction ID');
    txids.add(t.txid.toLowerCase());
    expect(typeof t.role==='string'&&/^(fund|challenge|response|forfeit|refund|refresh|payout|fee-child)$/.test(t.role),
      'unknown transaction role');
    expect(Array.isArray(t.inputs)&&t.inputs.length>0&&t.inputs.length<=100,
      'manifest must specify the exact required consumed inputs');
    expect(t.inputs.every(x=>typeof x==='string'),'malformed input set');
    const inputSet=t.inputs.map(outpoint);
    expect(new Set(inputSet).size===inputSet.length,'repeated input outpoint');
    expect(t.exact_inputs===true,'every input set must be explicitly pinned');
    expect(Array.isArray(t.outputs)&&t.outputs.length>0&&t.outputs.length<=100,
      'manifest must specify relevant output scripts and values');
    expect(t.exact_outputs===true,'every output must be explicitly accounted for');
    const indices=new Set();
    for(const o of t.outputs) {
      expect(Number.isInteger(o.vout)&&o.vout>=0&&o.vout<=0xffffffff&&!indices.has(o.vout),
        'duplicate or invalid output index');
      indices.add(o.vout);
      expect(hexScript(o.script_pubkey_hex),'invalid expected scriptPubKey');
      expect(Number.isSafeInteger(o.sats)&&o.sats>=0,
        'invalid expected output satoshis');
    }
  }
  return m;
}

export async function observe(m, view) {
  manifestCheck(m);
  const info=await view.rpc('getblockchaininfo',[]);
  expect(info.chain===m.network,'Bitcoin Core network differs from planned A/B chain');
  expect(info.initialblockdownload===false,'Bitcoin Core still in initial sync');
  const observed=[];
  for(const record of m.transactions) {
    const tx=await view.rpc('getrawtransaction',[record.txid,true]);
    expect(tx&&same(tx.txid,record.txid)&&hex64(tx.hash),
      'Bitcoin Core returned wrong transaction or wtxid field');
    expect(wtxidFromHex(tx.hex)===record.wtxid.toLowerCase() &&
      same(tx.hash,record.wtxid),'signed witness differs from independently saved transaction');
    expect(Number.isInteger(tx.confirmations)&&tx.confirmations>=m.minimum_confirmations,
      'insufficient active-chain confirmations');
    expect(hex64(tx.blockhash),'transaction lacks a confirmed block');
    const block=await view.rpc('getblockheader',[tx.blockhash,true]);
    expect(block&&block.hash===tx.blockhash&&
      Number.isInteger(block.height)&&block.confirmations>=m.minimum_confirmations,
      'claim block is not verified on active chain');
    const active=await view.rpc('getblockhash',[block.height]);
    expect(same(active,tx.blockhash),'transaction belongs to stale Bitcoin branch');

    const spent=tx.vin.map(x=>{
      expect(hex64(x.txid)&&Number.isInteger(x.vout)&&x.vout>=0,
        'coinbase input or invalid prevout');
      return outpoint(x.txid+':'+x.vout);
    });
    expect(spent.length===record.inputs.length &&
      spent.every(v=>record.inputs.map(outpoint).includes(v)),
      'confirmed input set differs from signed intent');
    expect(tx.vout.length===record.outputs.length,'confirmed output count differs from terms');
    for(const expected of record.outputs) {
      const o=readOut(tx,expected.vout);
      expect(same(o.scriptPubKey.hex,expected.script_pubkey_hex) &&
        satNumber(o.value)===expected.sats,
        'confirmed output script or satoshi amount differs from agreement');
    }

    let inputValue=0n;
    for(const coin of spent) {
      const [parent,index]=coin.split(':');
      const parentTx=await view.rpc('getrawtransaction',[parent,true]);
      expect(parentTx&&same(parentTx.txid,parent),'missing trusted parent transaction');
      inputValue+=sats(readOut(parentTx,Number(index)).value);
    }
    const outputValue=tx.vout.reduce((sum,o)=>sum+sats(o.value),0n);
    const fee=inputValue-outputValue;
    expect(fee>=0n && fee<=BigInt(Number.MAX_SAFE_INTEGER),
      'invalid fee funding or value creation');
    expect(Number.isInteger(tx.vsize)&&tx.vsize>0,
      'Bitcoin Core omitted confirmed virtual size');
    observed.push({
      role:record.role,txid:tx.txid,wtxid:tx.hash,
      inputs:spent,outputs:tx.vout.map(o=>({
        vout:o.n,sats:satNumber(o.value),script_pubkey_hex:o.scriptPubKey.hex,
      })),blockhash:tx.blockhash,height:block.height,
      confirmations:tx.confirmations,
      vsize:tx.vsize,fee_sats:Number(fee),
      fee_rate_sat_vb:Number(fee)/tx.vsize,
    });
  }
  return {
    schema:'bsb-ab-testnet-observation-v1',backend:m.backend,network:m.network,
    trustedBitcoinCore:true,witnessBound:true,activeChainChecked:true,
    transactionCount:observed.length,transactions:observed,
    totalVbytes:observed.reduce((n,t)=>n+t.vsize,0),
    totalFeeSats:observed.reduce((n,t)=>n+t.fee_sats,0),
    claimAuthorizationVerified:false,storageFaultValidityVerified:false,
    realFrostAuthorizationChecked:false,
    // A script execution requires verified full Bitcoin consensus; the node
    // is authoritative only for its own accepted active chain.
    independentConsensusReimplementation:false,
    comparisonRequiresMatchingTestnetScenarios:true,
  };
}
export function bitcoinCli(binary,{network,datadir}) {
  expect(['signet','testnet4'].includes(network),'invalid Bitcoin network');
  expect(typeof binary==='string'&&binary.length>0,'missing trusted bitcoin-cli');
  return {
    rpc(method,params) {
      const argv=['-chain='+network];
      if(datadir)argv.push('-datadir='+datadir);
      argv.push(method,...params.map(x=>typeof x==='boolean'?String(x):String(x)));
      const p=spawnSync(binary,argv,{
        encoding:'utf8',shell:false,timeout:20_000,maxBuffer:8*1024*1024,
      });
      expect(!p.error && p.status===0, 'trusted Bitcoin Core RPC failed '+method+': '+
        String(p.stderr||p.error||'').slice(0,500));
      try{return JSON.parse(p.stdout);}
      catch{throw new Error('Bitcoin Core RPC returned non-JSON for '+method);}
    },
  };
}
export async function main(argv=process.argv.slice(2)) {
  let manifestFile=null,cli=null,datadir=null,out=null;
  for(let i=0;i<argv.length;i++) {
    const flag=argv[i],value=argv[++i];
    expect(value,'missing value after '+flag);
    if(flag==='--manifest')manifestFile=value;
    else if(flag==='--bitcoin-cli')cli=value;
    else if(flag==='--datadir')datadir=value;
    else if(flag==='--out')out=value;
    else fail('unknown read-only observation option '+flag);
  }
  expect(manifestFile&&cli,'usage: observe.mjs --manifest JSON --bitcoin-cli PATH [--datadir PATH] [--out JSON]');
  const manifest=JSON.parse(await readFile(resolve(manifestFile),'utf8'));
  manifestCheck(manifest);
  const result=await observe(manifest,bitcoinCli(cli,{
    network:manifest.network,datadir:datadir?resolve(datadir):null,
  }));
  const serialized=JSON.stringify(result,null,2)+'\n';
  if(out) {
    const f=await open(resolve(out),'wx',0o600);
    try {await f.writeFile(serialized);await f.sync();}
    finally {await f.close();}
  } else process.stdout.write(serialized);
}
if(process.argv[1] && import.meta.url===new URL('file://'+resolve(process.argv[1])).href) {
  main().catch(error=>{console.error(error.message);process.exitCode=1;});
}
