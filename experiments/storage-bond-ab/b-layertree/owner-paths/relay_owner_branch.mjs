#!/usr/bin/env node
/**
 * NO-SIGNER OWNER-FIRST recovery worker. Each of Alice/Bob has a separately
 * pre-signed first exit from the current pooled P2TR carrier, plus the other
 * holder's pre-signed second exit from the winner's successor. Anyone with
 * the bytes can relay either path: no owner-exclusive signature is implied.
 *
 * The signer, sponsor and owner wallets are absent while this file runs.
 * Pre-signed transactions are already FROST/BIP341 and sponsor authorized.
 * This is NOT Byzantine security against an active two-share quorum.
 */
import {readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';

const must=(x,why)=>{if(!x)throw Error(why);};
const h64=x=>typeof x==='string'&&/^[0-9a-f]{64}$/i.test(x);
const sha=b=>createHash('sha256').update(b).digest('hex');
const sat=n=>{must(Number.isFinite(Number(n)),'bad value');return Math.round(Number(n)*1e8);};
const point=encoded=>{
  const m=/^([a-f0-9]{64}):([0-9]+)$/i.exec(String(encoded));
  must(m&&Number.isSafeInteger(Number(m[2]))&&Number(m[2])<=0xffffffff,
    'invalid signed Bitcoin outpoint');
  return {txid:m[1],vout:Number(m[2])};
};
export function bitcoinCli(executable,datadir){
  must(executable.startsWith('/')&&datadir.startsWith('/'),'require absolute Bitcoin Core paths');
  return (method,args=[])=>{
    const res=spawnSync(executable,['-regtest','-datadir='+datadir,method,
      ...args.map(x=>typeof x==='object'?JSON.stringify(x):String(x))],{
      encoding:'utf8',shell:false,timeout:30_000,maxBuffer:8_000_000,
    });
    must(!res.error&&res.status===0,
      'Bitcoin '+method+' failed: '+String(res.stderr||res.error).slice(0,250));
    if(res.stdout.trim()==='')return null;
    try{return JSON.parse(res.stdout);}catch{return res.stdout.trim();}
  };
}
function decode(node,rec){
  must(rec && h64(rec.txid)&&h64(rec.wtxid)&&typeof rec.signedHex==='string'&&
    /^(?:[0-9a-f]{2})+$/i.test(rec.signedHex),'signed Bitcoin raw transaction missing');
  const tx=node('decoderawtransaction',[rec.signedHex]);
  must(tx.txid===rec.txid&&tx.hash===rec.wtxid&&
    tx.vsize===rec.vsize&&Array.isArray(tx.vin)&&tx.vin.length===2 &&
    tx.vin[0].txinwitness?.length===1&&
    tx.vin[0].txinwitness[0].length===128&&
    tx.vin[1].txinwitness?.length>0,
    'Bitcoin Core decoded a different FROST witness, txid or fee signature');
  const spends=tx.vin.map(i=>i.txid+':'+i.vout);
  must(spends[0]===rec.principalInput&&spends[1]===rec.sponsorInput,
    'frozen FROST spend references a substituted Bitcoin input');
  must(Array.isArray(rec.exactOutputs)&&rec.exactOutputs.length===tx.vout.length,
    'unaccounted or missing signed Bitcoin recipient outputs');
  rec.exactOutputs.forEach((o,i)=>{
    const actual=tx.vout[i];
    must(o.vout===i&&actual.n===i&&
      sat(actual.value)===o.sats&&
      actual.scriptPubKey.hex.toLowerCase()===o.script.toLowerCase(),
      'signed frozen transaction changed payout script, output order or value');
  });
  must(rec.externalSponsorFeeSats===3000,'frozen recovery fee must be sponsor funded');
  return tx;
}
function sponsorValue(node,spend){
  const input=point(spend.sponsorInput);
  const tx=node('getrawtransaction',[input.txid,true]);
  must(tx.txid===input.txid&&tx.vout?.[input.vout]?.n===input.vout,
    'frozen independent sponsor outpoint not in trusted Core history');
  const sponsor=tx.vout[input.vout];
  must(sat(sponsor.value)===10_000 &&
    sponsor.scriptPubKey.hex===spend.exactOutputs.find(o=>o.sats===7000)?.script,
    'frozen sponsor UTXO mismatched actual output or signing policy');
  return 10_000;
}
function outputs(node,rec,principal){
  const tx=decode(node,rec);
  const fee=sponsorValue(node,rec);
  const outSum=tx.vout.reduce((n,o)=>n+sat(o.value),0);
  must(principal+fee-outSum===3000,
    'principal lost value, or sponsor did not pay the 3000 satoshis');
  return tx;
}
function checkManifest(p,node,desired){
  must(p.schema==='bsb-frost-owner-branch-prepared-v1'&&
    p.network==='disposable-regtest-only' &&
    p.real2of3TaprootThresholdSignatures===true &&
    p.signerProcessMustDieBeforeRelay===true &&
    p.threeIndependentGenerationStates===true &&
    p.allSponsoredInputsIndependentlyConfirmed===true &&
    p.allSignatureBytesFrozenBeforeBroadcast===true &&
    p.signingSharesSavedToDisk===false &&
    p.fundedPrincipalSats===100000 &&p.aliceSats===60000&&p.bobSats===40000 &&
    p.latestGeneration===2&&p.sponsorFeePerTransactionSats===3000&&
    p.maliciousQuorumControl.bitcoinMempoolAcceptsConflictingTheft===true &&
    p.maliciousQuorumControl.broadcast===false &&
    p.caveats.maliciousQuorumCanSignTheftOrWrongRoot===true &&
    p.caveats.holderExclusiveCarrierSignature===false &&
    p.caveats.sapioMidEnforcedOnBitcoin===false,
    'frozen owner-specific branch claim overstates security');
  must(h64(p.sourcePdpEvidenceHash),'invalid reference PDP SHA256');
  must(/^0014[0-9a-f]{40}$/i.test(p.holderPayoutScripts?.alice)&&
    /^0014[0-9a-f]{40}$/i.test(p.holderPayoutScripts?.bob)&&
    p.holderPayoutScripts.alice!==p.holderPayoutScripts.bob,
    'owner output scripts do not belong to two distinct disposable wallets');
  must(Array.isArray(p.generations)&&p.generations.length===3 &&
    ['alice','bob'].includes(desired),'wrong generation or first publisher');
  const usedSponsor=new Set();
  for(const [i,g] of p.generations.entries()){
    must(g.generation===i &&
      /^5120[0-9a-f]{64}$/i.test(g.carrierScriptPubkeyHex),
      'missing distinct frozen Bitcoin P2TR carrier');
    for(const [firstName,secondName,firstValue,secondValue] of [
      ['alice','bob',60000,40000],['bob','alice',40000,60000],
    ]){
      const branch=g.branches?.[firstName];
      must(branch?.firstPaysOwner===firstName&&
        branch.secondPaysOther===secondName&&
        branch.ownerGetsSats===firstValue&&branch.otherGetsSats===secondValue &&
        branch.remainderAfterFirstSats===secondValue&&
        branch.sameOriginalCarrier===g.carrierBefore,
        'holder branch does not preserve both first/remainder entitlements');
      const first=branch.first,second=branch.second;
      outputs(node,first,100000);
      outputs(node,second,secondValue);
      must(first.principalInput===g.carrierBefore &&
        second.principalInput===first.txid+':0' &&
        branch.descendantCarrier===second.principalInput &&
        first.exactOutputs.length===4 &&
        second.exactOutputs.length===3 &&
        first.exactOutputs[0].script===g.carrierScriptPubkeyHex &&
        first.exactOutputs[0].sats===secondValue &&
        first.exactOutputs[1].script===p.holderPayoutScripts[firstName] &&
        first.exactOutputs[1].sats===firstValue &&
        second.exactOutputs[0].script===p.holderPayoutScripts[secondName] &&
        second.exactOutputs[0].sats===secondValue &&
        branch.independentSecondExternalFeeAlreadySigned===true,
        'first exit or other-holder successor spends wrong principal or payouts');
      for(const r of [first,second]){
        must(!usedSponsor.has(r.sponsorInput),'sponsor UTXO reused by another branch');
        usedSponsor.add(r.sponsorInput);
      }
    }
    if(i<2){
      const ref=g.refreshBroadcast;
      outputs(node,ref,100000);
      must(ref.principalInput===g.carrierBefore&&
        ref.exactOutputs[0].script===g.carrierScriptPubkeyHex&&
        ref.exactOutputs[0].sats===100000 &&
        p.generations[i+1].carrierBefore===ref.txid+':0',
        'previous signed refresh is not bound to next carrier generation');
      must(!usedSponsor.has(ref.sponsorInput),'refresh reused recovery sponsor UTXO');
      usedSponsor.add(ref.sponsorInput);
      const confirmed=node('getrawtransaction',[ref.txid,true]);
      must(confirmed.txid===ref.txid&&confirmed.hash===ref.wtxid&&confirmed.confirmations>=1,
        'frozen carrier refresh was not published and confirmed');
      const old=point(g.carrierBefore);
      must(node('gettxout',[old.txid,old.vout])===null,
        'prior generation carrier is still live after refresh');
      for(const owner of ['alice','bob']){
        const signed=g.branches[owner].first.signedHex;
        const verdict=node('testmempoolaccept',[[signed]]);
        must(verdict?.length===1&&verdict[0].allowed!==true,
          'prior generation first owner exit accepted after refresh');
      }
    }else{
      must(g.refreshBroadcast===null,'current generation has unexpected unsigned refresh');
      const current=point(g.carrierBefore);
      must(node('gettxout',[current.txid,current.vout])!==null,
        'current P2TR carrier not spendable before owner-first exit');
      for(const owner of ['alice','bob']){
        const signed=g.branches[owner].first.signedHex;
        const verdict=node('testmempoolaccept',[[signed]]);
        must(verdict?.length===1&&verdict[0].allowed===true,
          'one of two owner-first frozen Bitcoin exits invalid before settlement');
      }
    }
  }
  must(usedSponsor.size===14,'not all 14 confirmed fee UTXOs have distinct binding');
}
export async function run({binary,datadir,dir,sha256,first,out}) {
  must(h64(sha256),'expected separate pre-signer SHA256 receipt commitment');
  const bytes=await readFile(resolve(dir,'owner-frozen.json'));
  const saved=(await readFile(resolve(dir,'owner-frozen.sha256'),'utf8')).trim();
  must(sha(bytes)===sha256&&saved===sha256,'frozen FROST witness export changed after signing');
  const manifest=JSON.parse(bytes);
  const node=bitcoinCli(binary,datadir);
  must(node('getblockchaininfo').chain==='regtest','refusing non-regtest publication');
  const wallets=node('listwallets');
  must(Array.isArray(wallets)&&wallets.length===1&&wallets[0]==='miner',
    'holder, oracle or sponsor signing wallet is still online');
  checkManifest(manifest,node,first);
  const current=manifest.generations[2];
  const winner=current.branches[first],loser=current.branches[first==='alice'?'bob':'alice'];
  const firstTx=node('sendrawtransaction',[winner.first.signedHex]);
  must(firstTx===winner.first.txid,'Bitcoin first exit signed bytes or txid differ');
  node('generatetoaddress',[1,manifest.minerAddress]);
  const firstConfirmed=node('getrawtransaction',[firstTx,true]);
  must(firstConfirmed.hash===winner.first.wtxid&&firstConfirmed.confirmations>=1,
    'owner-specific first exit not Bitcoin confirmed');
  const alternate=node('testmempoolaccept',[[loser.first.signedHex]]);
  must(alternate?.length===1&&alternate[0].allowed!==true,
    'opposing owner first spend is simultaneously Bitcoin valid');
  const remainder=point(winner.second.principalInput);
  must(node('gettxout',[remainder.txid,remainder.vout])!==null,
    'other holder successor was lost after first owner exit');
  const secondTrial=node('testmempoolaccept',[[winner.second.signedHex]]);
  must(secondTrial?.length===1&&secondTrial[0].allowed===true,
    'other owner pre-signed claim cannot redeem remainder after first exit');
  const secondTx=node('sendrawtransaction',[winner.second.signedHex]);
  must(secondTx===winner.second.txid,'Bitcoin second owner exit txid not frozen');
  node('generatetoaddress',[6,manifest.minerAddress]);
  const secondConfirmed=node('getrawtransaction',[secondTx,true]);
  must(secondConfirmed.hash===winner.second.wtxid&&
    secondConfirmed.confirmations>=6,
    'other beneficiary exit not confirmed with original frozen witness bytes');
  for(const [owner,txid,index,value]of [
    [first,firstTx,1,winner.ownerGetsSats],
    [winner.secondPaysOther,secondTx,0,winner.otherGetsSats],
  ]){
    const coin=node('gettxout',[txid,index]);
    must(coin!==null&&coin.confirmations>=6&&
      sat(coin.value)===value&&
      coin.scriptPubKey.hex===manifest.holderPayoutScripts[owner],
      'Bitcoin current owner claim has wrong immutable payout script or sats');
  }
  for(const g of manifest.generations.slice(0,2)){
    for(const branch of ['alice','bob']){
      const old=node('testmempoolaccept',[[g.branches[branch].first.signedHex]]);
      must(old.length===1&&!old[0].allowed,'revived stale signed owner exit');
    }
  }
  must(node('gettxout',[remainder.txid,remainder.vout])===null,
    'remainder FROST carrier not spent after second beneficiary recovery');
  const result={
    schema:'bsb-frost-owner-specific-signer-dead-regtest-v1',
    network:'regtest',firstPublisher:first,secondBeneficiary:winner.secondPaysOther,
    sourcePdpEvidenceHash:manifest.sourcePdpEvidenceHash,
    frozenManifestSha256:sha256,
    originalSigningProcessGone:true,ownerAndFeeSigningWalletsUnloaded:true,
    individualFirstClaimPublishedWithoutOnlineFederation:true,
    otherBeneficiaryPreSignedSecondClaimConfirmed:true,
    preSignedGenerations:3,priorGenerationFirstExitsRejected:4,
    currentGenerationConflictingFirstRejected:true,
    independentlyConfirmedOutputs:{
      alice:{sats:60000,script:manifest.holderPayoutScripts.alice},
      bob:{sats:40000,script:manifest.holderPayoutScripts.bob}
    },
    currentCarrierPrincipalSats:100000,
    externalSponsorFeesSats:6000,
    firstExit:{txid:firstTx,wtxid:winner.first.wtxid,
      vbytes:firstConfirmed.vsize,confirmations:firstConfirmed.confirmations},
    secondExit:{txid:secondTx,wtxid:winner.second.wtxid,
      vbytes:secondConfirmed.vsize,confirmations:secondConfirmed.confirmations},
    signedBytesUntouched:true,
    securityBoundaries:{
      eitherHolderCouldPublishOwnFirstExit:true,
      otherHolderCanClaimAfterCompetingFirstExit:true,
      noOtherHolderSignatureNeededAfterFreeze:true,
      firstExitDoesNotRequireOtherHolderOnline:true,
      anyoneWithSignedBytesCanRelay:true,
      oneConflictingFirstExitMustWin:true,
      preSigningRequiresTrustedTwoShareFrostQuorum:true,
      noOwnerExclusiveBitcoinKeyForCarrier:true,
      activeMaliciousQuorumCanStillSteal:true,
      bitcoinScriptEnforcesMidPolicy:false,
      indefiniteRefreshCoverage:false,
      filecoinStorageFaultEnforcedByBitcoin:false,
    }
  };
  const fd=await open(out,'wx',0o600);
  try{await fd.writeFile(JSON.stringify(result,null,2)+'\n');await fd.sync();}
  finally{await fd.close();}
  return result;
}
async function main(args){
  const opts={};
  for(let i=0;i<args.length;i++){
    const k=args[i],v=args[++i];
    must(v,'missing argument value after '+k);
    if(k==='--bitcoin-cli')opts.binary=resolve(v);
    else if(k==='--datadir')opts.datadir=resolve(v);
    else if(k==='--frozen-dir')opts.dir=resolve(v);
    else if(k==='--sha256')opts.sha256=v;
    else if(k==='--first')opts.first=v;
    else if(k==='--output')opts.out=resolve(v);
    else throw Error('unrecognized no-signer owner exit argument '+k);
  }
  must(opts.binary&&opts.datadir&&opts.dir&&opts.sha256&&opts.first&&opts.out,
    'requires --bitcoin-cli --datadir --frozen-dir --sha256 --first --output');
  console.log(JSON.stringify(await run(opts),null,2));
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error('Owner-first frozen relay rejected:',e.message);process.exitCode=1;});
}
