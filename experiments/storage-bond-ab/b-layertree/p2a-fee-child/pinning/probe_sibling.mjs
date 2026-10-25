#!/usr/bin/env node
/**
 * P2A/TRUC mempool pinning adversarial control on actual Bitcoin Core 30.3.
 *
 * A stranger with a newly funded UTXO attaches their own v3 P2A child
 * to the FROST-signed, zero-fee owner exit parent *before* the intended
 * relay does. Check whether a separate fee payer can evict that child
 * through actual Bitcoin Core RBF, without ANY new FROST signing.
 *
 * Also test a rival child paying more than the relayer's fixed budget:
 * a cheaper replacement must fail, while the incumbent package remains
 * independently valid and confirms (not a complete custody loss).
 *
 * This is local regtest mempool POLICY at one node, NOT global P2P relay,
 * package pinning impossibility, Byzantine FROST safety or mainnet proof.
 */
import {readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {
  rpc,verifyFrozen,decode,fundNewFeeCoin,feeChild,
} from '../relay_dynamic.mjs';

const ensure=(ok,why)=>{if(!ok)throw Error(why);};
const hex64=v=>typeof v==='string'&&/^[a-f0-9]{64}$/i.test(v);
const digest=b=>createHash('sha256').update(b).digest('hex');
const money=n=>{
  const v=Number(n);
  ensure(Number.isFinite(v)&&v>=0&&v<=21000000,'bad Bitcoin amount');
  return Math.round(v*100_000_000);
};
const point=s=>{
  const m=/^([a-f0-9]{64}):([0-9]+)$/i.exec(String(s));
  ensure(m&&Number.isSafeInteger(Number(m[2])),'invalid Bitcoin UTXO outpoint');
  return {txid:m[1],vout:Number(m[2])};
};
function has(node,txid){return node('getrawmempool').includes(txid);}
function fullNodeState(node,parent,txid){
  const src=node('getmempoolentry',[parent.txid]);
  const child=node('getmempoolentry',[txid]);
  ensure(src.vsize===parent.vsize && child.vsize>0,
    'missing actual Bitcoin Core v3 parent/child mempool entries');
  ensure(Array.isArray(child.depends)&&child.depends.includes(parent.txid),
    'adversarial child not associated with the intended parent');
  return {parentVbytes:src.vsize,childVbytes:child.vsize,
    parentDescendants:src.descendantcount,
    childAncestors:child.ancestorcount,
    mempoolMinFeeBtcKvB:node('getmempoolinfo').mempoolminfee};
}
function validOutput(node,txid,vout,sats,script){
  const coin=node('gettxout',[txid,vout]);
  ensure(coin && coin.confirmations>=6 &&
    money(coin.value)===sats&&coin.scriptPubKey?.hex===script,
    'confirmed Bitcoin Core owner payout script, amount or depth mismatch');
}
function independentFeeCandidate(node,manifest,parent,role,sats){
  const fund=fundNewFeeCoin(node,role,manifest.minerAddress);
  const child=feeChild(node,parent,fund,sats);
  ensure(child.feeWallet===role&&child.minerFeeSats===sats,
    'P2A child does not bind independent fee wallet and exact fee');
  return child;
}
function ordinaryPackage(node,manifest,parent,step){
  const candidate=independentFeeCandidate(node,manifest,parent,
    'ordinary-CPFP-'+step,5000);
  const original=decode(node,parent.signedHex);
  const result=node('submitpackage',[[parent.signedHex,candidate.raw]]);
  ensure(result?.package_msg==='success',
    'normal v3/P2A funded recovery unexpectedly failed');
  ensure(has(node,parent.txid)&&has(node,candidate.txid),
    'Bitcoin Core failed to place both ordinary transactions in mempool');
  ensure(decode(node,parent.signedHex).hash===original.hash,
    'ordinary CPFP changed frozen parent witness');
  return {parent:parent.txid,oldChild:null,newChild:candidate.txid,
    initialChildFeeSats:0,finalChildFeeSats:5000,
    mempoolReplacementOccurred:false,replacementBudgetExceeded:false,
    afterSigningFrostInvoked:false};
}
function attackedPackage(node,manifest,parent,step,pinKind){
  const low=pinKind==='low';
  const incumbentFee=low?1200:12000;
  const rival=independentFeeCandidate(node,manifest,parent,
    'untrusted-P2A-child-'+step,incumbentFee);
  const honest=independentFeeCandidate(node,manifest,parent,
    'honest-P2A-child-'+step,5000);
  ensure(rival.feeOutpoint!==honest.feeOutpoint,
    'rival and honest fee sponsor share input UTXO');
  const original=decode(node,parent.signedHex);
  const submitted=node('submitpackage',[[parent.signedHex,rival.raw]]);
  ensure(submitted?.package_msg==='success',
    'attacker child could not attach to zero-fee parent in real Bitcoin Core');
  ensure(has(node,parent.txid)&&has(node,rival.txid),
    'attacker never occupied the P2A mempool child slot');
  const prior=fullNodeState(node,parent,rival.txid);
  let replaced=false,hostError=null;
  try{
    const txid=node('sendrawtransaction',[honest.raw]);
    ensure(txid===honest.txid,'Bitcoin Core accepted a different replacement child');
    replaced=true;
  }catch(error){
    hostError=String(error.message).slice(0,500);
  }
  const unchanged=decode(node,parent.signedHex);
  ensure(unchanged.txid===original.txid&&unchanged.hash===original.hash,
    'competing fee sponsor modified signed FROST parent bytes');
  if(low){
    ensure(replaced&&has(node,honest.txid)&&!has(node,rival.txid)&&has(node,parent.txid),
      'low-fee adversarial P2A child was not evicted by independent higher-fee sponsor');
    fullNodeState(node,parent,honest.txid);
  }else{
    ensure(!replaced&&has(node,rival.txid)&&!has(node,honest.txid) &&
      has(node,parent.txid),
      'honest lower fee unexpectedly replaced higher fee child in mempool');
    // A high-fee incumbent can be unreplaceable for this limited budget,
    // but remains valid and can itself pay for the owner's parent.
    ensure(Boolean(hostError),'Core did not return explicit insufficient replacement error');
  }
  return {
    parent:parent.txid,
    oldChild:rival.txid,newChild:low?honest.txid:null,
    acceptedChild:low?honest.txid:rival.txid,
    initialChildFeeSats:incumbentFee,
    attemptedReplacementFeeSats:5000,
    finalChildFeeSats:low?5000:incumbentFee,
    oldChildStillInMempool:!low,
    mempoolReplacementOccurred:low,
    replacementBudgetExceeded:!low,
    higherFeeCandidateMempoolAccepted:low,
    honestLowerFeeRejected:!low,
    expectedSingleTRUCChildAfterReplacement:true,
    parentTxidUnmodified:true,parentWtxidUnmodified:true,
    incumbentBefore:prior,
    rejectionDetail:hostError,
    afterSigningFrostInvoked:false,
  };
}
function confirmed(node,manifest,parent,childTxid,step){
  node('generatetoaddress',[1,manifest.minerAddress]);
  const original=decode(node,parent.signedHex);
  const chain=node('getrawtransaction',[parent.txid,true]);
  const child=node('getrawtransaction',[childTxid,true]);
  ensure(chain.confirmations>=1&&child.confirmations>=1 &&
    chain.txid===original.txid&&chain.hash===original.hash &&
    child.txid===childTxid&&
    !has(node,childTxid)&&!has(node,parent.txid),
    'Bitcoin did not mine exact frozen FROST P2A parent with accepted mempool child');
  return {step,parentTxid:chain.txid,parentWtxid:chain.hash,
    confirmedChildTxid:child.txid,confirmedChildWtxid:child.hash,
    parentVbytes:chain.vsize,childVbytes:child.vsize,
    parentBlockhash:chain.blockhash,childBlockhash:child.blockhash,
    bitcoinConfirmedBoth:true};
}
export async function run({binary,datadir,dir,sha,first,pinStep,pinKind,out}){
  ensure(['alice','bob'].includes(first)&&['first','second'].includes(pinStep)&&
    ['low','high'].includes(pinKind),'invalid pinning scenario');
  const frozen=await readFile(resolve(dir,'p2a-frozen.json'));
  const saved=(await readFile(resolve(dir,'p2a-frozen.sha256'),'utf8')).trim();
  ensure(hex64(sha)&&digest(frozen)===sha.toLowerCase()&&saved===sha.toLowerCase(),
    'the FROST-signed parent witness or independent SHA256 seal changed');
  const manifest=JSON.parse(frozen.toString('utf8'));
  const node=(method,args=[],wallet=null)=>rpc(binary,datadir,method,args,wallet);
  ensure(node('getblockchaininfo').chain==='regtest',
    'no public Bitcoin network may be used for pinning research');
  ensure(JSON.stringify(node('listwallets'))===JSON.stringify(['miner']),
    'original FROST/sponsor/owner wallet still loaded during pinning');
  verifyFrozen(manifest,node);
  const branch=manifest.generations[2].branches[first],
    opposite=manifest.generations[2].branches[first==='alice'?'bob':'alice'];
  ensure(branch&&opposite&&manifest.principalSats===100000,
    'no suitable frozen three-generation two-owner recovery graph');
  const observations=[];
  for(const [step,parent] of [['first',branch.first],['second',branch.second]]){
    const isPinned=pinStep===step;
    // Funding coins are mined BEFORE publishing any zero-fee parent.
    // Never mine while a malicious child is resident or it would
    // prematurely confirm and invalidate the pinning experiment.
    const attempt=isPinned?attackedPackage(node,manifest,parent,step,pinKind):
      ordinaryPackage(node,manifest,parent,step);
    const liveChild=attempt.acceptedChild??attempt.newChild;
    ensure(hex64(liveChild),'no Bitcoin-valid fee-paying child survived');
    observations.push({...attempt,...confirmed(node,manifest,parent,liveChild,step)});
    if(step==='first'){
      const oppositeCandidate=node('testmempoolaccept',[[opposite.first.signedHex]]);
      ensure(oppositeCandidate?.length===1&&oppositeCandidate[0].allowed!==true,
        'conflicting alternative owner-first was not invalidated by confirmation');
      const rem=point(branch.second.carrierInput);
      const live=node('gettxout',[rem.txid,rem.vout]);
      ensure(live&&money(live.value)===(first==='alice'?40000:60000),
        'first owner did not preserve other holder entire successor P2TR entitlement');
    }
  }
  node('generatetoaddress',[6,manifest.minerAddress]);
  const firstTx=branch.first,secondTx=branch.second;
  const firstCoin=node('getrawtransaction',[firstTx.txid,true]);
  const secondCoin=node('getrawtransaction',[secondTx.txid,true]);
  ensure(firstCoin.confirmations>=6&&secondCoin.confirmations>=6,
    'both owner release transactions not confirmed to depth six');
  const firstSats=first==='alice'?60000:40000;
  validOutput(node,firstTx.txid,1,firstSats,manifest.beneficiaryScripts[first]);
  validOutput(node,secondTx.txid,0,100000-firstSats,
    manifest.beneficiaryScripts[branch.otherOwner]);
  const result={
    schema:'bsb-frost-p2a-mempool-sibling-pinning-v1',
    network:'regtest',
    signingCompletedBeforeAdversarialMempoolInteractions:true,
    originalSignersAndSponsorWalletUnavailable:true,
    independentPreconfirmedFeeWalletsAfterSignerDeath:true,
    chosenOwnerFirst:first,adversarialStep:pinStep,pinningMode:pinKind,
    frozenSha256:sha,sourcePdpEvidenceHash:manifest.sourceBlossomReferencePdpHash,
    ownerPayoutsSats:{alice:60000,bob:40000},
    originalPrincipalPreservedSats:100000,
    allOwnersFinalConfirmationDepthAtLeast6:true,
    experiments:observations,
    maliciousActive2of3QuorumStillCanSteal:true,
    noNativeSapioMidCovenant:true,
    globalP2PPackagePropagationVerified:false,
    guaranteedResistanceToAllPinning:false,
    boundedLocalTrucSiblingEvictionTest:true,
    replacementLimitedByActualBitcoinCoreFees:true,
  };
  const file=await open(resolve(out),'wx',0o600);
  try{await file.writeFile(JSON.stringify(result,null,2)+'\n');await file.sync();}
  finally{await file.close();}
  return result;
}
async function main(args){
  const x={};
  for(let i=0;i<args.length;i++){
    const flag=args[i],value=args[++i];ensure(value,'missing '+flag+' option value');
    if(flag==='--bitcoin-cli')x.binary=resolve(value);
    else if(flag==='--datadir')x.datadir=resolve(value);
    else if(flag==='--frozen-dir')x.dir=resolve(value);
    else if(flag==='--sha256')x.sha=value;
    else if(flag==='--first')x.first=value;
    else if(flag==='--pin-step')x.pinStep=value;
    else if(flag==='--pin-kind')x.pinKind=value;
    else if(flag==='--out')x.out=resolve(value);
    else throw Error('unrecognized pinning argument '+flag);
  }
  ensure(x.binary&&x.datadir&&x.dir&&x.sha&&x.first&&x.pinStep&&x.pinKind&&x.out,
    'missing independent P2A pinning regtest arguments');
  console.log(JSON.stringify(await run(x),null,2));
}
if(process.argv[1]&&import.meta.url==='file://'+resolve(process.argv[1])){
  main(process.argv.slice(2)).catch(e=>{console.error('Real TRUC sibling control failed:',e.message);process.exitCode=1;});
}
