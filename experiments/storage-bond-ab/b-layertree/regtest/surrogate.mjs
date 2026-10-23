#!/usr/bin/env node
/**
 * Real funded Bitcoin Core regtest B-surrogate: P2WSH 2-of-3 CHECKMULTISIG.
 * NOT FROST, NOT Sapio MID, NOT a Filecoin proof verifier.
 * Demonstrates externally sponsored refresh and both honest and malicious
 * threshold-authorized payouts under actual Bitcoin Script consensus.
 */
import { createECDH, createHash, randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { scenario, challenge } from '../../shared/scenario.mjs';

const VALUE=100_000, SPONSOR=50_000, FEE=3_000;
const need=(v,s)=>{if(!v)throw Error(s);};
const btc=n=>{need(Number.isSafeInteger(n)&&n>=0,'invalid satoshis');return n/100_000_000;};
const sats=n=>Math.round(Number(n)*100_000_000);
const sha256=b=>createHash('sha256').update(b).digest();
const dhash=b=>sha256(sha256(b));
function b58(data) {
  const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n=BigInt('0x'+data.toString('hex')),text='';
  while(n>0n){text=alphabet[Number(n%58n)]+text;n/=58n;}
  for(const v of data){if(v!==0)break;text='1'+text;}
  return text;
}
function genSigner(){
  const e=createECDH('secp256k1');e.generateKeys();
  const body=Buffer.concat([Buffer.from([0xef]),e.getPrivateKey(),Buffer.from([1])]);
  return {pub:e.getPublicKey('hex','compressed'),
    wif:b58(Buffer.concat([body,dhash(body).subarray(0,4)]))};
}
function bitcoinCli(binary,dir,method,args=[],wallet=null) {
  const flags=['-regtest','-datadir='+dir];
  if(wallet)flags.push('-rpcwallet='+wallet);
  const params=args.map(x=>typeof x==='object'?JSON.stringify(x):String(x));
  const p=spawnSync(binary,[...flags,method,...params],{
    shell:false,encoding:'utf8',timeout:30000,maxBuffer:6_000_000});
  need(!p.error&&p.status===0,method+' failed: '+String(p.stderr||p.error).slice(0,1000));
  try{return JSON.parse(p.stdout);}catch{return p.stdout.trim();}
}
function outpointFrom(tx,script,amount) {
  const matches=tx.vout.filter(o=>sats(o.value)===amount&&
    o.scriptPubKey.hex.toLowerCase()===script.toLowerCase());
  need(matches.length===1,'amount/script missing or duplicated in confirmed output');
  return {txid:tx.txid,vout:matches[0].n,sats:amount,script};
}
function verifyOutputs(tx,expected) {
  need(tx.vout.length===expected.length,'unaccounted actual transaction output');
  const used=new Set();
  for(const want of expected) {
    const match=tx.vout.find(o=>sats(o.value)===want.sats &&
      o.scriptPubKey.hex.toLowerCase()===want.script.toLowerCase()&&!used.has(o.n));
    need(match,'payout/fee/commitment changed from independently pinned terms');
    used.add(match.n);
  }
}
function signTwoOfThree(rpc,principal,sponsor,outputs,priv,witnessScript) {
  const prevs=[{txid:principal.txid,vout:principal.vout,scriptPubKey:principal.script,
    witnessScript,amount:btc(principal.sats)}];
  const inputs=[{txid:principal.txid,vout:principal.vout},
    {txid:sponsor.txid,vout:sponsor.vout}];
  const unsigned=rpc('createrawtransaction',[inputs,outputs]);
  const first=rpc('signrawtransactionwithkey',[unsigned,[priv[0]],prevs]);
  need(!first.complete,'one federation key unexpectedly satisfied 2-of-3');
  const sponsorSigned=rpc('signrawtransactionwithwallet',[first.hex], 'sponsor');
  need(!sponsorSigned.complete,'fee sponsor substituted for second federation signature');
  const second=rpc('signrawtransactionwithkey',[sponsorSigned.hex,[priv[1]],prevs]);
  need(second.complete,'two federation keys and fee sponsor failed to complete transaction');
  return {hex:second.hex,underSigned:sponsorSigned.hex};
}
function verdict(rpc,hex) {
  const r=rpc('testmempoolaccept',[[hex]]);
  need(Array.isArray(r)&&r.length===1,'bad Bitcoin mempool verdict');return r[0];
}
function witnessAttack(rpc,raw) {
  const orig=rpc('decoderawtransaction',[raw]);
  const signatures=orig.vin[0].txinwitness;
  need(Array.isArray(signatures),'missing SegWit signature witness');
  const sig=signatures.find(x=>x.length>=136&&x.length<=148);
  need(sig&&raw.includes(sig),'missing real multisig witness signature');
  const changed=sig.slice(0,-2)+(sig.endsWith('00')?'01':'00');
  const altered=raw.replace(sig,changed);
  const other=rpc('decoderawtransaction',[altered]);
  need(orig.txid===other.txid&&orig.hash!==other.hash,
    'witness-only tampering affected txid or left wtxid unchanged');
  const rejected=verdict(rpc,altered);
  need(!rejected.allowed,'Bitcoin Core accepted corrupted same-txid witness');
  return {sameTxid:true,differentWtxid:true,coreRejected:true};
}
function feeOf(tx,inputs) {
  return inputs.reduce((v,n)=>v+n,0)-tx.vout.reduce((v,o)=>v+sats(o.value),0);
}
function confirm(rpc,id,depth=1) {
  const tx=rpc('getrawtransaction',[id,true]);
  need(tx.confirmations>=depth,'signed transaction not confirmed');
  const block=rpc('getblockheader',[tx.blockhash,true]);
  need(rpc('getblockhash',[block.height])===tx.blockhash,'not active Bitcoin block');
  return {txid:tx.txid,wtxid:tx.hash,blockhash:tx.blockhash,
    confirmations:tx.confirmations,height:block.height,vsize:tx.vsize,
    outputs:tx.vout.map(o=>({vout:o.n,sats:sats(o.value),
      script_pubkey_hex:o.scriptPubKey.hex}))};
}
async function run(opts) {
  const work=await mkdtemp(join(tmpdir(),'bsb-federated-regtest-'));
  const dir=join(work,'node');
  await mkdir(dir,{recursive:true,mode:0o700});
  const port=23000+(randomBytes(2).readUInt16BE()%12000);
  const cfg=['regtest=1','server=1','txindex=1','fallbackfee=0.00002',
    '[regtest]','rpcport='+port,'rpcbind=127.0.0.1',
    'rpcallowip=127.0.0.1','listen=0',''].join('\n');
  await writeFile(join(dir,'bitcoin.conf'),cfg,{mode:0o600});
  const child=spawn(opts.bitcoind,['-datadir='+dir,'-printtoconsole=0'],{
    stdio:['ignore','ignore','ignore']});
  const rpc=(method,args=[],wallet=null)=>bitcoinCli(opts.bitcoinCli,dir,method,args,wallet);
  try {
    let ready=false;
    for(let i=0;i<120;i++){
      if(child.exitCode!==null)throw Error('Bitcoin Core stopped during startup');
      try{ready=rpc('getblockchaininfo').chain==='regtest';if(ready)break;}catch{}
      await delay(100);
    }
    need(ready,'disposable Bitcoin Core failed to initialize');
    for(const wallet of ['miner','sponsor','alice','bob'])rpc('createwallet',[wallet]);
    const miningAddress=rpc('getnewaddress',[],'miner');
    rpc('generatetoaddress',[101,miningAddress]);
    const sponsorAddress=rpc('getnewaddress',[],'sponsor');
    const aliceAddress=rpc('getnewaddress',[],'alice');
    const bobAddress=rpc('getnewaddress',[],'bob');
    const sponsorScript=rpc('validateaddress',[sponsorAddress]).scriptPubKey;
    const aliceScript=rpc('validateaddress',[aliceAddress]).scriptPubKey;
    const bobScript=rpc('validateaddress',[bobAddress]).scriptPubKey;
    const keys=Array.from({length:3},genSigner);
    const vault=rpc('createmultisig',[2,keys.map(k=>k.pub),'bech32']);
    need(vault.redeemScript&&vault.address,'could not construct 2-of-3');
    const vaultScript=rpc('validateaddress',[vault.address]).scriptPubKey;
    need(/^0020[0-9a-f]{64}$/i.test(vaultScript),'expected native P2WSH');
    const txfund=rpc('sendtoaddress',[vault.address,btc(VALUE)],'miner');
    const txsponsor=rpc('sendtoaddress',[sponsorAddress,btc(SPONSOR)],'miner');
    rpc('generatetoaddress',[6,miningAddress]);
    let locked=outpointFrom(rpc('getrawtransaction',[txfund,true]),vaultScript,VALUE);
    let sponsor=outpointFrom(rpc('getrawtransaction',[txsponsor,true]),sponsorScript,SPONSOR);
    const commonCase=scenario('storage-fault');
    const terms=commonCase.terms;
    need(terms[0].stake===60000&&terms[1].stake===40000,'shared A/B scenario changed');
    need(terms.every(t=>t.challengeBlocks===6),'shared A/B challenge interval changed');
    const actualFault=challenge(commonCase.events.find(e=>
      e.kind==='proof'&&e.id==='alice'&&e.epoch===2));
    need(actualFault.verified===false&&actualFault.witness.response===null,
      'A/B reference Merkle proof did not establish a genuine sampled storage fault');
    const fraudulentCase=scenario('false-fault');
    const fraudulentClaim=challenge(fraudulentCase.events.find(e=>
      e.kind==='proof'&&e.id==='alice'&&e.epoch===2));
    need(fraudulentClaim.verified===true&&fraudulentClaim.assertedVerdict==='fault',
      'false-fault attack must conflict with actually valid Blossom Merkle openings');
    const commit1=sha256(Buffer.from(JSON.stringify(terms))).toString('hex');
    const refreshOutputs=[{[vault.address]:btc(VALUE)},
      {[sponsorAddress]:btc(SPONSOR-FEE)},{data:commit1}];
    const refresh=signTwoOfThree(rpc,locked,sponsor,refreshOutputs,
      [keys[0].wif,keys[1].wif],vault.redeemScript);
    need(!verdict(rpc,refresh.underSigned).allowed,
      'one signer plus sponsor unexpectedly refreshed shared carrier');
    need(verdict(rpc,refresh.hex).allowed,'authorized carrier refresh not Bitcoin-valid');
    const refreshTx=rpc('decoderawtransaction',[refresh.hex]);
    verifyOutputs(refreshTx,[{script:vaultScript,sats:VALUE},
      {script:sponsorScript,sats:SPONSOR-FEE},{script:'6a20'+commit1,sats:0}]);
    need(feeOf(refreshTx,[VALUE,SPONSOR])===FEE,
      'external fee sponsor did not preserve entire 100k principal');
    const rid=rpc('sendrawtransaction',[refresh.hex]);
    rpc('generatetoaddress',[1,miningAddress]);
    const refreshed=confirm(rpc,rid);
    const rawRefreshed=rpc('getrawtransaction',[rid,true]);
    locked=outpointFrom(rawRefreshed,vaultScript,VALUE);
    sponsor=outpointFrom(rawRefreshed,sponsorScript,SPONSOR-FEE);

    // A malicious quorum can direct all money away from Alice and Bob.
    // Test in mempool without ever broadcasting this attacker transaction.
    const thief=rpc('getnewaddress',[],'miner');
    const thiefScript=rpc('validateaddress',[thief]).scriptPubKey;
    const badRoot=sha256(Buffer.from('fabricated-fault|'+fraudulentClaim.evidenceHash))
      .toString('hex');
    const stolen=signTwoOfThree(rpc,locked,sponsor,
      [{[thief]:btc(VALUE)},{[sponsorAddress]:btc(SPONSOR-2*FEE)},{data:badRoot}],
      [keys[0].wif,keys[1].wif],vault.redeemScript);
    need(!verdict(rpc,stolen.underSigned).allowed,
      'single signer produced an admissible arbitrary payout');
    need(verdict(rpc,stolen.hex).allowed,
      '2-of-3 did not demonstrate missing recipient enforcement');
    const forgedTx=rpc('decoderawtransaction',[stolen.hex]);
    verifyOutputs(forgedTx,[{script:thiefScript,sats:VALUE},
      {script:sponsorScript,sats:SPONSOR-2*FEE},{script:'6a20'+badRoot,sats:0}]);
    const tampering=witnessAttack(rpc,stolen.hex);

    // Broadcast only the honest settlement to two separate Core wallets.
    const goodRoot=sha256(Buffer.from('Alice60000|Bob40000')).toString('hex');
    const good=signTwoOfThree(rpc,locked,sponsor,
      [{[aliceAddress]:btc(60000)},{[bobAddress]:btc(40000)},
        {[sponsorAddress]:btc(SPONSOR-2*FEE)},{data:goodRoot}],
      [keys[0].wif,keys[2].wif],vault.redeemScript);
    need(verdict(rpc,good.hex).allowed,'honest 60/40 split not Bitcoin-valid');
    const goodTx=rpc('decoderawtransaction',[good.hex]);
    verifyOutputs(goodTx,[{script:aliceScript,sats:60000},{script:bobScript,sats:40000},
      {script:sponsorScript,sats:SPONSOR-2*FEE},{script:'6a20'+goodRoot,sats:0}]);
    need(feeOf(goodTx,[VALUE,SPONSOR-FEE])===FEE,
      'settlement fee shaved from recipient principal');
    const gid=rpc('sendrawtransaction',[good.hex]);
    rpc('generatetoaddress',[6,miningAddress]);
    const settled=confirm(rpc,gid,6);
    const alice=outpointFrom(rpc('getrawtransaction',[gid,true]),aliceScript,60000);
    const bob=outpointFrom(rpc('getrawtransaction',[gid,true]),bobScript,40000);
    need(rpc('gettxout',[alice.txid,alice.vout])!==null&&
      rpc('gettxout',[bob.txid,bob.vout])!==null,
      'Alice or Bob payout not unspent on Bitcoin Core');
    const result={
      schema:'bsb-ab-federation-surrogate-core-regtest-v1',
      kind:'actual-funded-2of3-P2WSH-surrogate-NOT-FROST',
      chain:'regtest',networkConfirmed:true,
      threshold:{total:3,required:2,oneSignerRejected:true,
        dishonestQuorumOutputAcceptedByCore:true,honestQuorumOutputConfirmed:true},
      securityLimits:{frostSigned:false,sapioMidPolicyEnforced:false,
        filecoinFaultProofVerified:false,clientPayoutScriptEnforced:false,
        bitcoinConsensusAccepted:true},
      principalSats:VALUE,initialSponsorSats:SPONSOR,
      challengeWindow:{modelBlocks:6,bitcoinConsensusEnforced:false},
      refresh:{...refreshed,rootCommitment:commit1,principalLockedSats:VALUE,sponsorFeeSats:FEE},
      dishonestPayout:{testmempoolacceptAllowed:true,broadcast:false,
        referenceStorageProofPasses:true,
        fraudulentlyAssertedFault:true,
        independentReferenceProofHash:fraudulentClaim.evidenceHash,
        redirectedValueSats:VALUE,wouldPayScript:thiefScript,
        txid:forgedTx.txid,wtxid:forgedTx.hash,witnessTamperingRejected:tampering},
      honestPayout:{...settled,
        independentlyVerifiedFaultDetected:true,
        independentReferenceProofHash:actualFault.evidenceHash,
        aliceOutpoint:alice.txid+':'+alice.vout,
        bobOutpoint:bob.txid+':'+bob.vout,aliceSats:60000,bobSats:40000,sponsorFeeSats:FEE},
      observedVbytes:{refresh:refreshed.vsize,payout:settled.vsize},
      totalSponsorFeesSats:FEE*2,
    };
    if(opts.outDir){
      await mkdir(opts.outDir,{recursive:true,mode:0o700});
      await writeFile(join(opts.outDir,'p2wsh-surrogate.json'),
        JSON.stringify(result,null,2)+'\n',{mode:0o600,flag:'wx'});
    }
    return result;
  } finally {
    try{rpc('stop');}catch{}
    await Promise.race([new Promise(done=>child.once('exit',done)),delay(4000)]);
    if(child.exitCode===null)child.kill('SIGKILL');
    await rm(work,{force:true,recursive:true,maxRetries:3});
  }
}
async function main() {
  const args=process.argv.slice(2);let bitcoind=null,bitcoinCli=null,outDir=null;
  for(let i=0;i<args.length;i++){
    const opt=args[i],value=args[++i];need(value,'missing value after '+opt);
    if(opt==='--bitcoind')bitcoind=resolve(value);
    else if(opt==='--bitcoin-cli')bitcoinCli=resolve(value);
    else if(opt==='--out')outDir=resolve(value);
    else throw Error('unsupported option '+opt);
  }
  need(bitcoind&&bitcoinCli,'use --bitcoind /path --bitcoin-cli /path [--out path]');
  console.log(JSON.stringify(await run({bitcoind,bitcoinCli,outDir}),null,2));
}
main().catch(err=>{console.error('B P2WSH funded regtest failed:',err.message);process.exitCode=1;});
