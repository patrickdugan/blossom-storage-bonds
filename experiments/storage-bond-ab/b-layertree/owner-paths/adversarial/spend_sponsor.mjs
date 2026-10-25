#!/usr/bin/env node
/**
 * Real Bitcoin Core funding sabotage. An adverse (formerly online)
 * fee sponsor spends SPECIFIC precommitted 10k-sat fee UTXOs AFTER the
 * FROST signer process has already disappeared, rendering corresponding
 * frozen BIP341 signed exits invalid even though the bonded 100k remains.
 *
 * Regtest-only, expendable sponsor wallet. Never sends on public networks.
 */
import {readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
const insist=(v,reason)=>{if(!v)throw Error(reason);};
const h64=s=>typeof s==='string'&&/^[0-9a-f]{64}$/i.test(s);
const hash=x=>createHash('sha256').update(x).digest('hex');
const sats=x=>Math.round(Number(x)*100_000_000);
function rpc(exe,dir,method,args=[],wallet=null){
  const cmd=['-regtest','-datadir='+dir];
  if(wallet)cmd.push('-rpcwallet='+wallet);
  cmd.push(method,...args.map(x=>typeof x==='object'?JSON.stringify(x):String(x)));
  const res=spawnSync(exe,cmd,{
    encoding:'utf8',shell:false,timeout:30_000,maxBuffer:8_000_000});
  insist(!res.error&&res.status===0,
    'Bitcoin '+method+' failed: '+String(res.stderr||res.error).slice(0,600));
  if(!res.stdout.trim())return null;
  try{return JSON.parse(res.stdout);}catch{return res.stdout.trim();}
}
const outpoint=str=>{
  const m=/^([0-9a-f]{64}):([0-9]+)$/i.exec(str);
  insist(m&&Number.isSafeInteger(Number(m[2])),'bad sponsor outpoint');
  return {txid:m[1],vout:Number(m[2])};
};
const targets=(x,mode)=>{
  const g=x.generations?.[2];
  insist(g && g.generation===2,'sponsor sabotage must target the live generation');
  switch(mode){
    case 'alice-first':return [g.branches.alice.first];
    case 'both-first':return [g.branches.alice.first,g.branches.bob.first];
    case 'bob-second':return [g.branches.alice.second];
    default:throw Error('unsupported sabotaged fee input mode '+mode);
  }
};
export async function sabotage({binary,datadir,dir,sha256,mode,out}){
  insist(h64(sha256),'requires original signed-export SHA256');
  const bytes=await readFile(resolve(dir,'owner-frozen.json'));
  const receipt=(await readFile(resolve(dir,'owner-frozen.sha256'),'utf8')).trim();
  insist(hash(bytes)===sha256 &&receipt===sha256,
    'the signed FROST export was substituted after signing');
  const manifest=JSON.parse(bytes);
  insist(manifest.schema==='bsb-frost-owner-branch-prepared-v1'&&
    manifest.network==='disposable-regtest-only' &&
    manifest.latestGeneration===2 &&
    manifest.maliciousQuorumControl?.bitcoinMempoolAcceptsConflictingTheft===true,
    'not a valid FROST owner-first frozen manifest');
  const node=(name,args=[],wallet=null)=>rpc(binary,datadir,name,args,wallet);
  insist(node('getblockchaininfo').chain==='regtest','refusing sponsor sabotage outside regtest');
  const wallets=node('listwallets');
  insist(wallets.includes('sponsor')&&wallets.includes('miner') &&
    wallets.includes('alice')&&wallets.includes('bob'),
    'adversarial sponsor must have its disposable wallet loaded before shutdown');
  const spendList=targets(manifest,mode);
  const actual=[];
  for(const item of spendList){
    const original=outpoint(item.sponsorInput);
    const source=node('gettxout',[original.txid,original.vout]);
    insist(source&&sats(source.value)===10_000,
      'selected sponsor UTXO was not originally live and independently funded');
    const address=node('getnewaddress',[],'miner');
    const raw=node('createrawtransaction',[
      [original],{[address]:0.00009},
    ]);
    const signed=node('signrawtransactionwithwallet',[raw],'sponsor');
    insist(signed.complete===true &&typeof signed.hex==='string',
      'malicious sponsor did not fully sign its own fee coin');
    const decoded=node('decoderawtransaction',[signed.hex]);
    insist(decoded.vin.length===1 &&
      decoded.vin[0].txid===original.txid&&
      decoded.vin[0].vout===original.vout &&
      decoded.vout.length===1 &&
      sats(decoded.vout[0].value)===9_000,
      'sponsor sabotage tried to spend beneficiary funds or an unexpected input');
    const trial=node('testmempoolaccept',[[signed.hex]]);
    insist(trial.length===1&&trial[0].allowed===true,
      'hostile sponsor did not construct a Bitcoin-valid conflicting input spend');
    const txid=node('sendrawtransaction',[signed.hex]);
    insist(txid===decoded.txid,'Bitcoin signed sponsor sabotage mismatch');
    node('generatetoaddress',[1,manifest.minerAddress]);
    const confirmed=node('getrawtransaction',[txid,true]);
    insist(confirmed.confirmations>=1&&
      node('gettxout',[original.txid,original.vout])===null,
      'sponsor coin was not irreversibly consumed on regtest');
    actual.push({
      sabotagedOutpoint:item.sponsorInput,
      independentFeeInputSats:10_000,
      theftDoesNotSpendPooledPrincipal:true,
      sabotageTxid:txid,
      confirmations:confirmed.confirmations,
      feePaidFromSponsorSats:1_000,
      nonreplayableForOriginalFrozenBip341Sighash:true
    });
  }
  const result={
    schema:'bsb-frost-sponsored-outpoint-sabotage-regtest-v1',
    mode,network:'regtest',frozenManifestSha256:sha256,
    signerProcessAlreadyExited:true,
    allSabotagedSponsorCoinsOriginallyLive:true,
    maliciousSpendSignedBySponsorWalletOnly:true,
    storageCollateralNotSpentBySabotage:true,
    onchainConflicts:actual,
    disallowsReplacementFeeInputWithoutNewFrostSignature:true,
    redispatchableToOtherPresignedBranchIfItsSponsorLive:mode==='alice-first',
    allFirstOwnerPathsBlocked:mode==='both-first',
    secondOwnerPathSabotaged:mode==='bob-second',
    securityImplication:'A valid frozen Bitcoin sighash binds its exact sponsor input; sponsor spending that UTXO breaks recovery without touching bonded principal.'
  };
  const fd=await open(out,'wx',0o600);
  try{await fd.writeFile(JSON.stringify(result,null,2)+'\n');await fd.sync();}
  finally{await fd.close();}
  console.log(JSON.stringify({mode,confirmedSponsorSabotageTxids:actual.map(x=>x.sabotageTxid),
    frozenPrincipalUntouched:true,signerAlreadyStopped:true}));
  return result;
}
async function main(args){
  const a={};
  for(let i=0;i<args.length;i++){
    const k=args[i],v=args[++i];insist(v,'option '+k+' missing argument');
    if(k==='--bitcoin-cli')a.binary=resolve(v);
    else if(k==='--datadir')a.datadir=resolve(v);
    else if(k==='--frozen-dir')a.dir=resolve(v);
    else if(k==='--sha256')a.sha256=v;
    else if(k==='--mode')a.mode=v;
    else if(k==='--out')a.out=resolve(v);
    else throw Error('unknown sponsor sabotage option '+k);
  }
  insist(a.binary&&a.datadir&&a.dir&&a.sha256&&a.mode&&a.out,
    'required bitcoin-cli/datadir/frozen-dir/sha256/mode/out');
  return sabotage(a);
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error('Real sponsor sabotage failed:',e.message);process.exitCode=1;});
}
