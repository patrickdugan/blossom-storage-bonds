#!/usr/bin/env node
/**
 * Fee-independent FROST-v3/P2A Bitcoin Core package recovery worker.
 *
 * NO FROST crate or oracle: only frozen one-input BIP341 Taproot parents.
 * AFTER signer process exits, external fee wallets fund two distinct
 * 1-parent/1-child TRUC packages, one for each beneficiary in either order.
 * If a chosen child-fee UTXO is spent, construct a DIFFERENT child,
 * using a fresh third-party UTXO without changing the signed parent.
 *
 * This does not defeat malicious 2-of-3 FROST keypath theft; it is bounded
 * signer-offline liveness against FIXED-SPONSOR-UTXO griefing.
 */
import {readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
const required=(x,msg)=>{if(!x)throw Error(msg);};
const h64=s=>typeof s==='string'&&/^[0-9a-f]{64}$/i.test(s);
const sha256=raw=>createHash('sha256').update(raw).digest('hex');
const sats=x=>{
  const n=Number(x);
  required(Number.isFinite(n)&&n>=0&&n<=21_000_000,'invalid Bitcoin amount');
  return Math.round(n*100_000_000);
};
const outpoint=s=>{
  const m=/^([a-f0-9]{64}):([0-9]+)$/i.exec(String(s));
  required(m&&Number.isSafeInteger(Number(m[2])),'bad frozen Bitcoin outpoint');
  return {txid:m[1],vout:Number(m[2])};
};
export function rpc(binary,dir,method,args=[],wallet=null){
  const options=['-regtest','-datadir='+dir];
  if(wallet)options.push('-rpcwallet='+wallet);
  const p=spawnSync(binary,[...options,method,...args.map(x=>
    typeof x==='object'?JSON.stringify(x):String(x))],{
    shell:false,encoding:'utf8',timeout:30_000,maxBuffer:8_000_000,
  });
  required(!p.error&&p.status===0,'Bitcoin Core '+method+': '+String(p.stderr||p.error).slice(0,600));
  const raw=p.stdout.trim();
  if(!raw)return null;
  try{return JSON.parse(raw);}catch{return raw;}
}
const money=n=>{required(Number.isSafeInteger(n)&&n>=0,'bad sats to BTC');return Number((n/1e8).toFixed(8));};
export function decode(node,raw){
  const tx=node('decoderawtransaction',[raw]);
  required(tx&&h64(tx.txid)&&h64(tx.hash),'bad signed Bitcoin witness transaction');
  return tx;
}
function verifyParent(node,r,carrierSats){
  required(r?.version===3&&r.parentMinerFeeSats===0&&
    r.feeInputsSignedByFrost===false&&r.sighashType==='BIP341-SIGHASH_DEFAULT'&&
    r.anchorScript==='51024e73',
    'P2A parent unexpectedly carries a static fee signer or wrong sighash');
  const tx=decode(node,r.signedHex);
  required(tx.txid===r.txid&&tx.hash===r.wtxid&&
    tx.version===3&&tx.vsize===r.vsize&&tx.vin.length===1 &&
    tx.vin[0].txinwitness?.length===1 &&
    tx.vin[0].txinwitness[0].length===128 &&
    tx.vin[0].txid+':'+tx.vin[0].vout===r.carrierInput &&
    tx.vout.length===r.outputAgreement.length &&
    tx.vout[r.anchorIndex]?.scriptPubKey?.hex==='51024e73' &&
    sats(tx.vout[r.anchorIndex].value)===0,
    'presigned BIP341 FROST P2TR parent differs from frozen signed witness');
  for(const [i,expected]of r.outputAgreement.entries()){
    const o=tx.vout[i];
    required(o.n===i&&expected.vout===i&&
      sats(o.value)===expected.sats&&
      o.scriptPubKey.hex.toLowerCase()===expected.script.toLowerCase(),
      'fee-independent parent changed beneficiary amount or successor script');
  }
  const total=tx.vout.reduce((n,o)=>n+sats(o.value),0);
  required(total===carrierSats&&r.carrierOutputSats===carrierSats,
    'zero-fee FROST parent fails exact principal conservation');
  return tx;
}
export function verifyFrozen(manifest,node){
  required(manifest.schema==='bsb-frost-v3-p2a-frozen-v1'&&
    manifest.network==='disposable-regtest-only'&&
    manifest.realFrostThreshold==='2-of-3-secp256k1-tr-3.0.0'&&
    manifest.bitcoinTransactionVersion===3&&
    manifest.feeIndependentSignedParents===true&&
    manifest.frostWitnessCommittedToExternalFeeUtxo===false&&
    manifest.allPreSignedParentsZeroMinerFee===true&&
    manifest.zeroValueAnchorScriptPubkeyHex==='51024e73'&&
    manifest.principalSats===100000&&manifest.aliceSats===60000&&
    manifest.bobSats===40000&&manifest.currentGeneration===2&&
    manifest.signerProcessMustTerminateBeforeP2aChildCreated===true&&
    manifest.originalFrostPrivateSharesSerialized===false&&
    manifest.onlineSapioOracleRequiredForRelay===false &&
    manifest.scopeLimits?.midCovenantEnforcedByBitcoin===false &&
    manifest.scopeLimits?.futureUnattendedRefreshWithDynamicSponsorProven===false&&
    manifest.maliciousActiveQuorumControl?.bitcoinMempoolAcceptsCompetingTheft===true &&
    manifest.maliciousActiveQuorumControl.broadcast===false,
    'P2A signed manifest overstates security, omits principal, or uses static fee');
  const rows=manifest.generations;
  required(rows?.length===3&&h64(manifest.sourceBlossomReferencePdpHash),
    'three signed root generations not frozen with shared PDP evidence');
  for(const [i,row] of rows.entries()){
    required(row.generation===i&&/^5120[a-f0-9]{64}$/i.test(row.carrierScriptPubkeyHex),
      'wrong current Bitcoin Taproot carrier');
    for(const [first,other,a,b]of [
      ['alice','bob',60000,40000],['bob','alice',40000,60000],
    ]){
      const path=row.branches[first];
      required(path?.firstReceivesSats===a&&path.secondReceivesSats===b &&
        path.otherOwner===other&&path.noFeeInputsInEitherFrostSignature===true,
        'missing correct pre-signed second-owner entitlement branch');
      const signedFirst=verifyParent(node,path.first,100000);
      verifyParent(node,path.second,b);
      required(path.first.carrierInput===row.carrierBefore&&
        path.first.anchorIndex===2 &&
        path.first.outputAgreement[0].sats===b &&
        path.first.outputAgreement[0].script===row.carrierScriptPubkeyHex &&
        path.first.outputAgreement[1].sats===a &&
        path.first.outputAgreement[1].script===manifest.beneficiaryScripts[first] &&
        path.second.anchorIndex===1 &&
        path.second.carrierInput===path.first.txid+':0' &&
        path.second.outputAgreement[0].sats===b &&
        path.second.outputAgreement[0].script===manifest.beneficiaryScripts[other] &&
        signedFirst.vout[0].scriptPubKey.hex===row.carrierScriptPubkeyHex &&
        path.descendantOutpoint===path.first.txid+':0',
        'owner-first P2A recovery links wrong output or descendant');
    }
    if(i<2){
      const ref=row.refreshBroadcast;
      required(ref&&h64(ref.txid)&&h64(ref.wtxid)&&
        rows[i+1].carrierBefore===ref.txid+':0',
        'pre-shutdown refresh failed to produce next signed generation');
      const old=node('getrawtransaction',[ref.txid,true]);
      required(old.txid===ref.txid&&old.hash===ref.wtxid&&old.confirmations>=1,
        'preoutage generation refresh missing from Bitcoin active chain');
      const spend=outpoint(row.carrierBefore);
      required(node('gettxout',[spend.txid,spend.vout])===null,
        'obsolete carrier still spendable after fresh generation');
    }else{
      required(row.refreshBroadcast===null,'unexpected unsigned future refresh');
      const current=outpoint(row.carrierBefore);
      const coin=node('gettxout',[current.txid,current.vout]);
      required(coin&&sats(coin.value)===100000 &&
        coin.scriptPubKey.hex===row.carrierScriptPubkeyHex,
        'current generation has no confirmed spendable Bitcoin carrier');
    }
  }
}
export function fundNewFeeCoin(node,wallet,minerAddress){
  // Wallet created only in the no-FROST worker, not during pre-signing.
  node('createwallet',[wallet]);
  const address=node('getnewaddress',[],wallet);
  const script=node('validateaddress',[address]).scriptPubKey;
  const txid=node('sendtoaddress',[address,money(100000)],'miner');
  node('generatetoaddress',[1,minerAddress]);
  const parent=node('getrawtransaction',[txid,true]);
  const hits=parent.vout.filter(o=>sats(o.value)===100000 &&
    o.scriptPubKey.hex===script);
  required(parent.confirmations>=1&&hits.length===1,
    'new third-party fee wallet not independently confirmed');
  return {wallet,address,script,point:{txid,vout:hits[0].n},value:100000};
}
export function feeChild(node,parent,feeCoin,feeSats=5000){
  required(Number.isSafeInteger(feeSats)&&feeSats>=1000&&feeSats<feeCoin.value,
    'fee child must explicitly price its Bitcoin Core v3 package');
  // createrawtransaction defaults to v2; set exact 4-byte LE version to 3
  // BEFORE signing to meet Bitcoin Core TRUC package policy.
  const recipient=node('getnewaddress',[],feeCoin.wallet);
  const raw=node('createrawtransaction',[
    [{txid:parent.txid,vout:parent.anchorIndex},
      {txid:feeCoin.point.txid,vout:feeCoin.point.vout}],
    {[recipient]:money(feeCoin.value-feeSats)},
  ]);
  required(typeof raw==='string'&&/^0[23]000000/i.test(raw),
    'Bitcoin Core created an unexpected base tx version for CPFP');
  const unsigned='03000000'+raw.slice(8);
  const signed=node('signrawtransactionwithwallet',[
    unsigned,[{txid:parent.txid,vout:parent.anchorIndex,
      scriptPubKey:'51024e73',amount:money(0)}],
  ],feeCoin.wallet);
  required(typeof signed.hex==='string',
    'Bitcoin Core external fee wallet did not return complete child witness');
  const decoded=decode(node,signed.hex);
  required(decoded.version===3&&decoded.vin.length===2&&decoded.vout.length===1 &&
    decoded.vin[0].txid===parent.txid &&
    decoded.vin[0].vout===parent.anchorIndex &&
    decoded.vin[1].txid===feeCoin.point.txid&&
    decoded.vin[1].vout===feeCoin.point.vout &&
    decoded.vin[1].txinwitness?.length>0 &&
    sats(decoded.vout[0].value)===feeCoin.value-feeSats,
    'external child tries to alter BIP341 parent or does not fully sign fee input');
  // Parent P2A contributes zero. Entire explicitly selected package fee comes
  // from the new, independently chosen 100k-sat external fee UTXO.
  required(feeCoin.value-sats(decoded.vout[0].value)===feeSats,
    'CPFP child does not account for the entire real package fee');
  return {raw:signed.hex,txid:decoded.txid,wtxid:decoded.hash,
    vsize:decoded.vsize,feeOutpoint:feeCoin.point.txid+':'+feeCoin.point.vout,
    feeWallet:feeCoin.wallet,minerFeeSats:feeSats};
}
function sabotageSelectedFeeCoin(node,chosen,minerAddress){
  const doomed=chosen.point;
  const original=node('gettxout',[doomed.txid,doomed.vout]);
  required(original&&sats(original.value)===100000,
    'candidate child fee UTXO was unavailable before sabotage');
  const unsigned=node('createrawtransaction',[
    [doomed],{[minerAddress]:money(99000)},
  ]);
  const signed=node('signrawtransactionwithwallet',[unsigned],chosen.wallet);
  required(signed.complete===true,'adversarial fee payer did not sign its own UTXO');
  const spent=decode(node,signed.hex);
  required(spent.vin.length===1 &&
    spent.vin[0].txid===doomed.txid&&spent.vin[0].vout===doomed.vout &&
    sats(spent.vout[0].value)===99000,
    'sponsor sabotage consumed carrier or other unrelated funds');
  const txid=node('sendrawtransaction',[signed.hex]);
  required(txid===spent.txid,'unexpected sponsor sabotage Bitcoin txid');
  node('generatetoaddress',[1,minerAddress]);
  required(node('gettxout',[doomed.txid,doomed.vout])===null,
    'first fee UTXO was not spent before alternate CPFP was made');
  return txid;
}
function publishParentAndChild(node,manifest,parent,step,attack){
  const parentRaw=parent.signedHex;
  const originalHash=parent.wtxid;
  let rejectedOriginalChild=null,maliciousFeeSpent=null;
  if(attack){
    const doomed=fundNewFeeCoin(node,'doomed-fee-'+step,manifest.minerAddress);
    const badChild=feeChild(node,parent,doomed);
    maliciousFeeSpent=sabotageSelectedFeeCoin(node,doomed,manifest.minerAddress);
    // Prior candidate can no longer support the zero-fee FROST parent.
    const conflict=node('testmempoolaccept',[
      [parentRaw,badChild.raw]]);
    required(conflict?.length===2&&conflict.some(v=>v.allowed!==true),
      'child with previously spent fee coin still accepted as a live Bitcoin package');
    rejectedOriginalChild=badChild.txid;
  }
  const valid=fundNewFeeCoin(node,'live-fee-'+step,manifest.minerAddress);
  const child=feeChild(node,parent,valid);
  const dec=decode(node,parentRaw);
  required(dec.txid===parent.txid&&dec.hash===originalHash,
    'fresh fee payer caused a different FROST-signed parent transaction');
  const aggregateRate=5000/(parent.vsize+child.vsize);
  required(aggregateRate>5,
    'dynamic CPFP child provided insufficient effective sat/vbyte package fee');
  const result=node('submitpackage',[[parentRaw,child.raw]]);
  required(result?.package_msg==='success',
    'real Bitcoin Core v3 P2A package rejected: '+JSON.stringify(result).slice(0,600));
  const mempool=node('getrawmempool');
  required(mempool.includes(parent.txid)&&mempool.includes(child.txid),
    'P2A package response omitted one actual unconfirmed Bitcoin transaction');
  node('generatetoaddress',[1,manifest.minerAddress]);
  const parentConfirmed=node('getrawtransaction',[parent.txid,true]);
  const childConfirmed=node('getrawtransaction',[child.txid,true]);
  required(parentConfirmed.hash===originalHash&&parentConfirmed.confirmations>=1 &&
    childConfirmed.hash===child.wtxid&&childConfirmed.confirmations>=1,
    'Bitcoin Core did not confirm both exact TRUC package witnesses');
  return {parent:parent.txid,wtxid:originalHash,parentRawUnmodified:true,
    parentVbytes:parentConfirmed.vsize,parentConfirmations:parentConfirmed.confirmations,
    child:child.txid,childWtxid:child.wtxid,childVbytes:childConfirmed.vsize,
    childConfirmations:childConfirmed.confirmations,
    freshChosenFeeInput:child.feeOutpoint,
    externalFeeSats:5000,
    effectivePackageFeeRateSatVb:aggregateRate,
    oldCandidateFeeInputSpent:attack,
    oldChildInvalidatedBySpentFeeCoin:attack,
    oldChildTxid:rejectedOriginalChild,
    sponsorSabotageTxid:maliciousFeeSpent,
    dynamicSponsorAfterSignerDeath:true,
  };
}
export async function run({binary,datadir,dir,sha256,first,attackStep,out}){
  required(['alice','bob'].includes(first),'unknown first holder');
  required(['first','second','none'].includes(attackStep),'unknown P2A fee attack stage');
  const signedBytes=await readFile(resolve(dir,'p2a-frozen.json'));
  const originalSeal=(await readFile(resolve(dir,'p2a-frozen.sha256'),'utf8')).trim();
  required(h64(sha256)&&originalSeal===sha256.toLowerCase() &&
    globalSha(signedBytes)===sha256.toLowerCase(),
    'presigner frozen recovery material was modified or rolled back');
  const manifest=JSON.parse(signedBytes);
  const node=(m,a=[],w=null)=>rpc(binary,datadir,m,a,w);
  required(node('getblockchaininfo').chain==='regtest',
    'refusing any chain other than disposable Bitcoin Core regtest');
  required(JSON.stringify(node('listwallets'))===JSON.stringify(['miner']),
    'FROST, sponsor or beneficiary wallet remained online during P2A relay');
  verifyFrozen(manifest,node);
  const unsignedFeeParent=manifest.generations[2].branches[first].first;
  const alone=node('testmempoolaccept',[[unsignedFeeParent.signedHex]]);
  required(alone?.length===1&&alone[0].allowed!==true,
    'unfunded zero-fee v3 parent was unexpectedly acceptable without a CPFP child');
  // Provide an actual freshly funded CPFP child to EACH obsolete
  // owner-first parent. The Bitcoin package must still reject these
  // stale principal outpoints, independently of child fee availability.
  let staleP2aPackagesRejected=0;
  for(const old of manifest.generations.slice(0,2)){
    for(const candidate of ['alice','bob']){
      const expired=old.branches[candidate].first;
      const fee=fundNewFeeCoin(node,
        'stale-fee-g'+old.generation+'-'+candidate,manifest.minerAddress);
      const replacement=feeChild(node,expired,fee);
      const verdict=node('testmempoolaccept',[
        [expired.signedHex,replacement.raw]]);
      required(verdict?.length===2&&verdict.some(x=>x.allowed!==true),
        'a stale carrier generation was accepted with an independent P2A fee child');
      staleP2aPackagesRejected++;
    }
  }
  const path=manifest.generations[2].branches[first],losing=
    manifest.generations[2].branches[first==='alice'?'bob':'alice'];
  // No fee sponsor input in any signed parent. The first payer can
  // intentionally spend an initial candidate fee coin without affecting
  // the parent transaction's BIP341 witness or transaction ID.
  const firstPackage=publishParentAndChild(node,manifest,path.first,'first',
    attackStep==='first');
  const competitor=node('testmempoolaccept',[[losing.first.signedHex]]);
  required(competitor?.length===1&&competitor[0].allowed!==true,
    'opposing first-order carrier exit remained valid after winner confirmed');
  const rem=outpoint(path.second.carrierInput);
  const survivor=node('gettxout',[rem.txid,rem.vout]);
  required(survivor&&sats(survivor.value)===(first==='alice'?40000:60000),
    'other beneficiary output failed to remain in pre-signed P2TR successor');
  const secondPackage=publishParentAndChild(node,manifest,path.second,'second',
    attackStep==='second');
  node('generatetoaddress',[6,manifest.minerAddress]);
  const confirmedFirst=node('getrawtransaction',[path.first.txid,true]),
    confirmedSecond=node('getrawtransaction',[path.second.txid,true]);
  required(confirmedFirst.confirmations>=6&&confirmedSecond.confirmations>=6,
    'signed first and second owner P2A parents not six-deep');
  const firstOwnerValue=first==='alice'?60000:40000,
    secondOwnerValue=100000-firstOwnerValue;
  const finalFirst=node('gettxout',[path.first.txid,1]),
    finalSecond=node('gettxout',[path.second.txid,0]);
  required(finalFirst&&finalSecond &&
    sats(finalFirst.value)===firstOwnerValue&&
    sats(finalSecond.value)===secondOwnerValue &&
    finalFirst.scriptPubKey.hex===manifest.beneficiaryScripts[first] &&
    finalSecond.scriptPubKey.hex===manifest.beneficiaryScripts[path.otherOwner],
    'P2A CPFP changed original owner entitlements');
  const proof={
    schema:'bsb-frost-p2a-fee-independent-recovery-v1',
    network:'regtest',presignerProcessAlreadyExited:true,
    publisherFirst:first,publisherSecond:path.otherOwner,
    selectedFeeSabotageStage:attackStep,externalSignedManifestSha256:sha256,
    frozenGenerations:3,staleGenerationCarriersNotSpendable:true,
    staleGenerationsWithNewFeeChildrenRejected:staleP2aPackagesRejected,
    zeroFeeStandaloneParentRejectedByCore:true,
    sourcePdpEvidenceHash:manifest.sourceBlossomReferencePdpHash,
    firstPackage,secondPackage,
    sixConfirmationPayouts:{
      aliceSats:60000,bobSats:40000,principalSats:100000,
      minerFeesPaidByExternalChildrenSats:10000,
    },
    parentTxidStableAfterFeeReplacement:true,
    FROSTKeypathResignedDuringRelay:false,
    feeProviderCreatedAfterSignerDeath:true,
    originalBondFeeSponsorWalletAvailable:false,
    otherHolderOnlineForPublication:false,
    independentOwnerFirstClaimBranch:true,
    independentBitcoinCarrierOwnerKey:false,
    maliciousTwoShareQuorumTheftStillPossible:true,
    otherRequiredProperties:{
      bitcoinCoreAcceptedRealTrucOneParentOneChild:true,
      zeroFeeParentSignedWithExactBeneficiaryScripts:true,
      zeroValueP2AAnchorScript:'51024e73',
      refreshingLaterWithoutNewFrostWitnessesSafe:false,
      actualSapioMidConstrainedByBitcoin:false,
      packageDeliveryAndFeeAvailabilityGuaranteed:false,
      filecoinFaultProvenOnBitcoin:false,
    },
  };
  const fd=await open(out,'wx',0o600);
  try{await fd.writeFile(JSON.stringify(proof,null,2)+'\n');await fd.sync();}
  finally{await fd.close();}
  return proof;
}
function globalSha(b){return createHash('sha256').update(b).digest('hex');}
async function main(args){
  const r={};
  for(let i=0;i<args.length;i++){
    const k=args[i],v=args[++i];required(v,'missing '+k+' argument');
    if(k==='--bitcoin-cli')r.binary=resolve(v);
    else if(k==='--datadir')r.datadir=resolve(v);
    else if(k==='--frozen-dir')r.dir=resolve(v);
    else if(k==='--sha256')r.sha256=v;
    else if(k==='--first')r.first=v;
    else if(k==='--attack-step')r.attackStep=v;
    else if(k==='--out')r.out=resolve(v);
    else throw Error('unknown P2A recovery option '+k);
  }
  required(r.binary&&r.datadir&&r.dir&&r.sha256&&r.first&&r.attackStep&&r.out,
    'requires bitcoin-cli datadir frozen-dir sha256 first attack-step out');
  const proof=await run(r);
  console.log(JSON.stringify(proof,null,2));
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error('P2A zero-fee parent recovery failed:',e.message);process.exitCode=1;});
}
