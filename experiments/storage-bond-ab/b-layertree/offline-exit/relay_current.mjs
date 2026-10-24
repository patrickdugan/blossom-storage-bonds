#!/usr/bin/env node
/**
 * Public Bitcoin Core regtest *relay*, NO signing API, NO FROST libraries.
 * Accepts only the SHA256-pinned, already signed current generation of a
 * three-generation 100k 2-of-3 Taproot full-split recovery export.
 *
 * A or B may independently publish this SAME joint full-split transaction.
 * This is not two independent unilateral claims, and does not prevent an
 * active malicious quorum from racing an alternative keypath transaction.
 */
import {readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';

const assert=(ok,msg)=>{if(!ok)throw Error(msg);};
const h64=value=>typeof value==='string'&&/^[0-9a-f]{64}$/i.test(value);
const digest=data=>createHash('sha256').update(data).digest('hex');
const sats=n=>{
  const d=Number(n);
  assert(Number.isFinite(d)&&d>=0&&d<=21000000,'invalid Bitcoin amount');
  return Math.round(d*100_000_000);
};
const splitOutpoint=str=>{
  const m=/^([a-f0-9]{64}):(\d+)$/i.exec(String(str));
  assert(m&&Number.isSafeInteger(Number(m[2]))&&Number(m[2])<=0xffffffff,
    'bad fully bound Bitcoin input outpoint');
  return {txid:m[1].toLowerCase(),vout:Number(m[2])};
};
function cli(binary,datadir,method,args=[]){
  const p=spawnSync(binary,['-regtest','-datadir='+datadir,method,
    ...args.map(x=>typeof x==='object'?JSON.stringify(x):String(x))],{
      encoding:'utf8',shell:false,timeout:30000,maxBuffer:10_000_000,
    });
  assert(!p.error&&p.status===0,
    'Bitcoin Core '+method+' failed: '+String(p.stderr||p.error||'').slice(0,350));
  const str=p.stdout.trim();
  if(str==='')return null;
  try{return JSON.parse(str);}catch{return str;}
}
const outMatches=(tx,claims)=>{
  assert(Array.isArray(tx.vout)&&tx.vout.length===claims.length,
    'signed exit has missing or extra destination outputs');
  claims.forEach((spec,index)=>{
    const o=tx.vout[index];
    assert(o.n===index&&sats(o.value)===spec.sats&&
      o.scriptPubKey?.hex?.toLowerCase()===spec.script.toLowerCase(),
      'signed output script, index or amount differs from the frozen agreement');
  });
};
function txInfo(raw,node){
  assert(typeof raw==='string'&&raw.length%2===0&&
    /^(?:[a-f0-9]{2})+$/i.test(raw),'missing immutable signed raw SegWit transaction');
  const decoded=node('decoderawtransaction',[raw]);
  assert(h64(decoded.txid)&&h64(decoded.hash),'Bitcoin Core missing txid/wtxid');
  return decoded;
}
function signedChainAudit(records,node){
  for(let i=0;i<records.length;i++){
    const r=records[i];
    const decoded=txInfo(r.exitSignedHex,node);
    assert(decoded.txid===r.exitTxid&&decoded.hash===r.exitWtxid,
      'saved signed FROST witness bytes changed after original freeze');
    assert(r.generation===i&&Number.isInteger(r.exitVsize)&&
      r.exitVsize===decoded.vsize,
      'saved generation index or virtual size altered');
    assert(decoded.vin?.length===2 &&
      decoded.vin[0].txid+':'+decoded.vin[0].vout===r.carrierBefore &&
      decoded.vin[1].txid+':'+decoded.vin[1].vout===r.sponsorBefore,
      'recovery exit input ancestry differs from signed original');
    assert(decoded.vin[0].txinwitness?.length===1 &&
      decoded.vin[0].txinwitness[0]?.length===128 &&
      decoded.vin[1].txinwitness?.length>0,
      'recovery exit lacks actual BIP340 FROST or sponsor signature');
    assert(r.carrierScriptPubkeyHex?.startsWith('5120')&&
      r.carrierScriptPubkeyHex.length===68 &&
      Number.isSafeInteger(r.sponsorInputSats)&&r.sponsorInputSats>3000,
      'carrier or sponsor input not bound to frozen script');
    assert(r.independentSponsorFeeSats===3000 &&
      r.sponsorChangeSats===r.sponsorInputSats-3000,
      'fee could be shaved from beneficiary principal');
    assert(Array.isArray(r.exitOutputs)&&r.exitOutputs.length===4,
      'incomplete full-split exit output list');
    outMatches(decoded,r.exitOutputs);
    assert(r.exitOutputs[0].sats===60000&&r.exitOutputs[1].sats===40000&&
      r.exitOutputs[0].script!==r.exitOutputs[1].script&&
      r.exitOutputs[2].sats===r.sponsorChangeSats &&
      r.exitOutputs[3].sats===0 &&
      r.exitOutputs[3].script==='6a20'+r.applicationCommitment,
      'signed exit does not pay both distinct beneficiaries and sponsor');
    const prevs=[splitOutpoint(r.carrierBefore),splitOutpoint(r.sponsorBefore)];
    const previousValue=prevs.map((p,k)=>{
      const tx=node('getrawtransaction',[p.txid,true]);
      assert(tx.txid===p.txid&&tx.vout?.[p.vout]?.n===p.vout,
        'frozen parent outpoint transaction unavailable');
      const output=tx.vout[p.vout];
      assert(output.scriptPubKey.hex.toLowerCase()===
        (k===0?r.carrierScriptPubkeyHex:r.sponsorScriptPubkeyHex).toLowerCase(),
        'frozen ancestor output belongs to another spend authority');
      return sats(output.value);
    });
    const paid=decoded.vout.reduce((sum,v)=>sum+sats(v.value),0);
    assert(previousValue[0]===100000&&previousValue[1]===r.sponsorInputSats&&
      previousValue[0]+previousValue[1]-paid===3000,
      'a carrier amount or third-party signer fee is incorrect');
    if(i+1<records.length){
      const next=records[i+1],ref=r.refreshBroadcast;
      assert(ref && h64(ref.txid)&&h64(ref.wtxid),
        'missing signed generation transition ancestry');
      const parent=node('getrawtransaction',[ref.txid,true]);
      const refresh=txInfo(ref.signedHex,node);
      assert(refresh.txid===ref.txid&&refresh.hash===ref.wtxid&&
        parent.txid===ref.txid&&parent.hash===ref.wtxid&&
        parent.confirmations>=1,
        'pre-outage signed refresh is not Bitcoin confirmed');
      assert(refresh.vin?.length===2 &&
        refresh.vin[0].txid+':'+refresh.vin[0].vout===r.carrierBefore &&
        refresh.vin[1].txid+':'+refresh.vin[1].vout===r.sponsorBefore,
        'refresh ancestry differs from original signed evidence');
      assert(next.carrierBefore===ref.txid+':0 &&
        next.sponsorBefore===ref.txid+':1 &&
        next.sponsorInputSats===r.sponsorInputSats-3000,
        'generation continuity or sponsor fee ledger is broken');
      const prior=splitOutpoint(r.carrierBefore);
      assert(node('gettxout',[prior.txid,prior.vout])===null,
        'Bitcoin still considers stale generation carrier spendable');
      const stale=node('testmempoolaccept',[[r.exitSignedHex]]);
      assert(stale.length===1 && stale[0].allowed!==true,
        'old signed generation exit was unexpectedly accepted on current chain');
    }else{
      assert(r.refreshBroadcast===null,
        'final generation unexpectedly references another refresh');
      const p=splitOutpoint(r.carrierBefore),s=splitOutpoint(r.sponsorBefore);
      assert(node('gettxout',[p.txid,p.vout])!==null &&
        node('gettxout',[s.txid,s.vout])!==null,
        'current signed exit has stale or already-spent input');
      const trial=node('testmempoolaccept',[[r.exitSignedHex]]);
      assert(trial.length===1&&trial[0].allowed===true,
        'current generation pre-signed exit is not Bitcoin mempool valid');
    }
  }
}
export async function run({binary,datadir,dir,expectedSha,publisher,outFile}){
  assert(['alice','bob'].includes(publisher),'publisher must be alice or bob');
  assert(h64(expectedSha),'frozen manifest hash must come from former signer session');
  const base=resolve(dir);
  const payload=await readFile(base+'/sealed-exits.json');
  const hash=digest(payload);
  const separatelySaved=(await readFile(base+'/sealed-exits.sha256','utf8')).trim();
  assert(hash===expectedSha.toLowerCase() && hash===separatelySaved,
    'signed immutable export changed since FROST signers disappeared');
  const exportData=JSON.parse(payload.toString('utf8'));
  assert(exportData.schema==='bsb-frost-frozen-offline-exit-v1'&&
    exportData.chain==='regtest' &&
    exportData.sighashType==='BIP341-SIGHASH_DEFAULT'&&
    exportData.principalSats===100000 &&
    exportData.aliceEntitlementSats===60000 &&
    exportData.bobEntitlementSats===40000 &&
    exportData.requiredFinalGeneration===2 &&
    exportData.dealerProcessMustDisappearBeforeBroadcast===true &&
    exportData.signerPrivateSharesInThisExport===false &&
    exportData.allWalletSignaturesAlreadyFrozen===true &&
    exportData.sapioOracleRequiredForPublication===false &&
    exportData.limits?.jointPreSignedFullSplitRatherThanSeparateClaims===true &&
    exportData.limits?.eachHolderHasUnilateralClaimingScriptPath===false &&
    exportData.limits?.activeMaliciousQuorumTheftResistance===false &&
    exportData.maliciousQuorumNegativeControl?.bitcoinMempoolWouldAcceptConflictingSpend===true &&
    exportData.maliciousQuorumNegativeControl?.broadcast===false,
    'missing original pre-signed full-split proof or safety classification');
  assert(Array.isArray(exportData.snapshots)&&exportData.snapshots.length===3,
    'three signed consecutive generations were not frozen');
  const node=(method,args=[])=>cli(binary,datadir,method,args);
  assert(node('getblockchaininfo').chain==='regtest',
    'refusing non-regtest signed recovery publication');
  const wallets=node('listwallets');
  assert(Array.isArray(wallets)&&!wallets.includes('sponsor')&&
    !wallets.includes('alice')&&!wallets.includes('bob'),
    'signing wallet still loaded: offline recovery proof invalid');
  signedChainAudit(exportData.snapshots,node);
  const current=exportData.snapshots[2];
  const txid=node('sendrawtransaction',[current.exitSignedHex]);
  assert(txid===current.exitTxid,
    'Bitcoin broadcast a transaction other than the fully pre-signed exit');
  node('generatetoaddress',[6,exportData.minerAddress]);
  const confirmed=node('getrawtransaction',[txid,true]);
  assert(confirmed.txid===current.exitTxid&&
    confirmed.hash===current.exitWtxid&&
    confirmed.hex.toLowerCase()===current.exitSignedHex.toLowerCase()&&
    confirmed.confirmations>=6,
    'Bitcoin confirmed different signature bytes or no final settlement');
  const block=node('getblockheader',[confirmed.blockhash,true]);
  assert(node('getblockhash',[block.height])===confirmed.blockhash,
    'Bitcoin confirmed a stale fork instead of the active chain');
  current.exitOutputs.slice(0,2).forEach((o,index)=>{
    const utxo=node('gettxout',[txid,index]);
    assert(utxo!==null&&utxo.confirmations>=6&&
      sats(utxo.value)===o.sats &&
      utxo.scriptPubKey.hex.toLowerCase()===o.script.toLowerCase(),
      'offline recovery did not leave full beneficiary amount independently owned');
  });
  for(const old of exportData.snapshots.slice(0,2)){
    const req=splitOutpoint(old.carrierBefore);
    assert(node('gettxout',[req.txid,req.vout])===null,
      'stale generation coin revived after offline recovery');
    const invalid=node('testmempoolaccept',[[old.exitSignedHex]]);
    assert(invalid.length===1&&invalid[0].allowed!==true,
      'stale exit was accepted after fresh generation settlement');
  }
  const original=splitOutpoint(current.carrierBefore);
  assert(node('gettxout',[original.txid,original.vout])===null,
    'current carrier was still spendable after signed holder recovery');
  const result={
    schema:'bsb-frost-service-dead-fullsplit-regtest-v1',
    network:'regtest',
    frozenExportSha256:hash,
    publishedBy:publisher,
    executableContainsFrostSigning:false,
    loadedSignerOrHolderWallets:false,
    allFrostSigningCompletedBeforeBroadcast:true,
    onlineSapioOracleInvoked:false,
    preSignedGenerations:3,
    previousGenerationExitsRejected:2,
    liveCarrierGeneration:2,
    independentExternalFeeAlreadySignedSats:3000,
    retainedPrincipalSats:100000,
    beneficiaries:{alice:{payoutSats:60000,script:current.exitOutputs[0].script},
      bob:{payoutSats:40000,script:current.exitOutputs[1].script}},
    jointFullSplitCanBePublishedByEitherHolder:true,
    independentIndividualCarrierClaimsProven:false,
    activeMaliciousQuorumResistanceProven:false,
    signedExitTxid:current.exitTxid,
    signedExitWtxid:current.exitWtxid,
    signedBytesUnmodified:true,
    confirmationBlockhash:confirmed.blockhash,
    confirmations:confirmed.confirmations,
    actualVbytes:confirmed.vsize,
    sponsorPaysFeeWithoutWalletOnline:true,
    restrictions:{nativeSapioMIDCovenant:false,
      independentHolderExitInTwoTransactions:false,
      perGenerationSignedAncestryFrozen:true,
      latestOnlyConfirmed:true,
      allSignersStoppedAsEnforcedByRunner:true,
      noPublicTestnetSpends:true},
  };
  const fd=await open(resolve(outFile),'wx',0o600);
  try{await fd.writeFile(JSON.stringify(result,null,2)+'\n');await fd.sync();}
  finally{await fd.close();}
  return result;
}
async function main(){
  const args=process.argv.slice(2);
  let binary=null,datadir=null,dir=null,expectedSha=null,publisher=null,outFile=null;
  for(let i=0;i<args.length;i++){
    const option=args[i],value=args[++i];
    assert(value,'missing offline worker CLI value');
    if(option==='--bitcoin-cli')binary=resolve(value);
    else if(option==='--datadir')datadir=resolve(value);
    else if(option==='--frozen-dir')dir=resolve(value);
    else if(option==='--sha256')expectedSha=value;
    else if(option==='--publisher')publisher=value;
    else if(option==='--output')outFile=resolve(value);
    else throw Error('unknown offline recovery option: '+option);
  }
  assert(binary&&datadir&&dir&&expectedSha&&publisher&&outFile,
    'requires bitcoin-cli, datadir, frozen-dir, sha256, publisher, output');
  console.log(JSON.stringify(await run({binary,datadir,dir,expectedSha,publisher,outFile}),null,2));
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main().catch(error=>{console.error('Signer-free recovery failed:',error.message);process.exitCode=1;});
}
