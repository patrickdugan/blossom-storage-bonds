#!/usr/bin/env node
/**
 * Genuine opportunistic 1p1c P2P relay experiment on TWO distinct Bitcoin
 * Core 30.3 regtest nodes, with separate mempools and different fee floors.
 *
 * FROST signs zero-fee v3 Taproot parents in a separate stopped process.
 * This observer creates fee children after the signer is gone; it NEVER
 * signs the P2TR parent, invokes Sapio or modifies frozen recovery bytes.
 *
 * Record P2P arrival BEFORE any receiver-side RPC submission; if Bitcoin
 * Core cannot propagate a qualifying package, record failure of automatic
 * relay and test explicit receiver submission separately. A local success
 * is NOT worldwide relay / fee availability / anti-pinning proof.
 */
import {readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {setTimeout as sleep} from 'node:timers/promises';
import {rpc,decode,verifyFrozen,fundNewFeeCoin,feeChild} from '../relay_dynamic.mjs';

const ensure=(ok,msg)=>{if(!ok)throw Error(msg);};
const h64=x=>typeof x==='string'&&/^[0-9a-f]{64}$/i.test(x);
const sha256=b=>createHash('sha256').update(b).digest('hex');
const sats=n=>{
  const x=Number(n);
  ensure(Number.isFinite(x)&&x>=0&&x<=21_000_000,'invalid Bitcoin value');
  return Math.round(x*1e8);
};
const outpoint=raw=>{
  const m=/^([a-f0-9]{64}):(\d+)$/i.exec(String(raw));
  ensure(m&&Number.isSafeInteger(Number(m[2])),'invalid previous Bitcoin UTXO');
  return {txid:m[1],vout:Number(m[2])};
};
const hasPair=(node,parent,child)=>{
  const pool=node('getrawmempool');
  ensure(Array.isArray(pool),'unexpected Bitcoin Core mempool response');
  return pool.includes(parent)&&pool.includes(child);
};
const pairState=(node,parent,child)=>{
  const mempool=node('getrawmempool');
  return {parent:mempool.includes(parent),child:mempool.includes(child),
    mempoolSize:mempool.length};
};
const syncTip=async(origin,peer,limit=45)=>{
  for(let i=0;i<limit;i++){
    const first=origin('getbestblockhash');
    if(peer('getbestblockhash')===first&&origin('getblockcount')===peer('getblockcount'))
      return origin('getblockcount');
    await sleep(250);
  }
  throw Error('receiver peer failed to synchronize active Bitcoin Core block tip');
};
const waitMempool=async(peer,parent,child,limit=50)=>{
  for(let i=0;i<limit;i++){
    if(hasPair(peer,parent,child))return {propagated:true,polls:i+1};
    await sleep(400);
  }
  return {propagated:false,polls:limit};
};
function trySubmit(node,parentHex,childHex){
  try{
    const r=node('submitpackage',[[parentHex,childHex]]);
    return {rpcError:false,packageMsg:r?.package_msg??null,
      accepted:r?.package_msg==='success',result:r};
  }catch(e){
    return {rpcError:true,accepted:false,message:String(e.message).slice(0,650)};
  }
}
function confirmOnBoth(origin,peer,parentId,childId,expectedParentWtxid,
  expectedChildWtxid){
  const o=origin('getrawtransaction',[parentId,true]),
    c=origin('getrawtransaction',[childId,true]);
  ensure(o?.confirmations>=1&&c?.confirmations>=1 &&
    o.hash===expectedParentWtxid&&c.hash===expectedChildWtxid,
    'source miner did not confirm the frozen parent and chosen child');
  const p=peer('getrawtransaction',[parentId,true]),
    q=peer('getrawtransaction',[childId,true]);
  ensure(p.confirmations>=1&&q.confirmations>=1 &&
    p.hash===expectedParentWtxid&&q.hash===expectedChildWtxid &&
    p.blockhash===o.blockhash&&q.blockhash===c.blockhash,
    'peer node failed to independently validate and confirm both witnesses');
  return {parentVbytes:o.vsize,childVbytes:c.vsize,sourceConfirmations:o.confirmations,
    peerConfirmations:p.confirmations,
    matchingParentBlockhash:o.blockhash===p.blockhash,
    matchingChildBlockhash:c.blockhash===q.blockhash};
}
async function proveStep(origin,peer,manifest,parent,step,kind) {
  // Fund and CONFIRM both fee candidates before publishing any parent.
  // Otherwise mining the second wallet UTXO may accidentally confirm the
  // first parent, concealing genuine P2P mempool behavior.
  const originalCoin=fundNewFeeCoin(origin,'tx-p2p-low-'+kind+'-'+step,
    manifest.minerAddress);
  const bumpedCoin=fundNewFeeCoin(origin,'tx-p2p-bump-'+kind+'-'+step,
    manifest.minerAddress);
  const lowChild=feeChild(origin,parent,originalCoin,5000);
  const highChild=feeChild(origin,parent,bumpedCoin,15000);
  const tip=await syncTip(origin,peer);
  const originallyFrozen=decode(origin,parent.signedHex);
  ensure(originallyFrozen.txid===parent.txid&&originallyFrozen.hash===parent.wtxid,
    'signed FROST input bytes changed before independent P2P test');
  const originMempool=origin('getrawmempool'),peerMempool=peer('getrawmempool');
  ensure(originMempool.length===0&&peerMempool.length===0,
    'P2P test must begin without an unaccounted parent/child in either mempool');
  const initial=origin('submitpackage',[[parent.signedHex,lowChild.raw]]);
  ensure(initial?.package_msg==='success'&&
    hasPair(origin,parent.txid,lowChild.txid),
    'origin node did not accept valid 5000-sat FROST P2A package');
  // P2P-only observation. No RPC has yet inserted the parent/child into
  // the receiving node. Report whether Core's opportunistic 1p1c works.
  const observedInitial=await waitMempool(peer,parent.txid,lowChild.txid,50);
  const firstView=pairState(peer,parent.txid,lowChild.txid);
  let floorTooHigh=false,receiverInitialDirect=null,explicitFallback=false,
    replacement=null;
  let chosen=lowChild;
  if(kind==='low'){
    if(!observedInitial.propagated){
      receiverInitialDirect=trySubmit(peer,parent.signedHex,lowChild.raw);
      // Do not claim automatic P2P delivery if only manual local RPC worked.
      ensure(receiverInitialDirect.accepted&&hasPair(peer,parent.txid,lowChild.txid),
        'peer accepted neither low-floor opportunistic 1p1c nor explicit known-good package');
      explicitFallback=true;
    }
  }else{
    // This receiver's 25 sat/vB policy must reject 5000 sats over the
    // aggregate vbytes. It may have the child in orphanage; mempool is
    // the only authoritative accepted-transaction observation.
    ensure(!observedInitial.propagated&&!hasPair(peer,parent.txid,lowChild.txid),
      'high-fee-floor receiver unexpectedly accepted low-feerate package');
    floorTooHigh=true;
    receiverInitialDirect=trySubmit(peer,parent.signedHex,lowChild.raw);
    ensure(!receiverInitialDirect.accepted&&!hasPair(peer,parent.txid,lowChild.txid),
      'explicit high-floor receiver accepted underpriced parent/child package');
    const substitute=origin('sendrawtransaction',[highChild.raw]);
    ensure(substitute===highChild.txid &&
      hasPair(origin,parent.txid,highChild.txid)&&
      !hasPair(origin,parent.txid,lowChild.txid),
      'source node could not RBF-replace low-fee child with high-fee child');
    const observedHigh=await waitMempool(peer,parent.txid,highChild.txid,50);
    if(!observedHigh.propagated){
      const explicit=trySubmit(peer,parent.signedHex,highChild.raw);
      ensure(explicit.accepted&&hasPair(peer,parent.txid,highChild.txid),
        'higher-fee package was not admitted to receiver by P2P or explicit submission');
      explicitFallback=true;
    }
    replacement={
      originalLowFeeChildRejectedAtHighFloor:true,
      originalLowFeeChildTxid:lowChild.txid,
      dynamicHighFeeChildTxid:highChild.txid,
      highFeeChildAmountSats:15000,
      highFeeP2PObservedBeforeExplicitSubmission:observedHigh.propagated,
      highFeePeerCheckPolls:observedHigh.polls,
      lowFeePeerDirectSubmissionRejected:true,
      lowFeeDirectResult:receiverInitialDirect?.rpcError?
        {error:receiverInitialDirect.message}:
        {packageMsg:receiverInitialDirect?.packageMsg},
    };
    chosen=highChild;
  }
  const finalState=pairState(peer,parent.txid,chosen.txid);
  ensure(finalState.parent&&finalState.child,
    'receiver lacks a validated, mempool-resident parent/child pair before confirmation');
  const parentWtxid=decode(origin,parent.signedHex).hash;
  ensure(parentWtxid===originallyFrozen.hash,
    'later fee inputs modified the original FROST-signed BIP341 parent');
  origin('generatetoaddress',[1,manifest.minerAddress]);
  await syncTip(origin,peer);
  const confirmed=confirmOnBoth(origin,peer,parent.txid,chosen.txid,
    parent.wtxid,chosen.wtxid);
  return {
    step,receiverFloor:kind,
    receiverHeightBefore:tip,
    originSubmittedLowFeePackage:true,
    originalFrostParentTxidUnchanged:true,
    originalFrostParentWtxidUnchanged:true,
    initialP2PObservation:observedInitial,
    receiverBeforeExplicitPackage:firstView,
    receiverInitialDirectlyChecked:receiverInitialDirect!==null,
    lowFeeBelowReceiverFloor:floorTooHigh,
    secondFeeChildReplacement:replacement,
    explicitReceiverSubmitpackageFallback:explicitFallback,
    acceptedFinalChildTxid:chosen.txid,
    finalChildFeeSats:chosen.minerFeeSats,
    aggregateFeeRateSatsVb:chosen.minerFeeSats/(parent.vsize+chosen.vsize),
    acceptedAfterPeerPolicyChecked:finalState,
    confirmation:confirmed,
  };
}
export async function run({bitcoinCli,originDir,peerDir,manifestDir,
  frozenSha256,first,kind,out}){
  ensure(['alice','bob'].includes(first)&&['low','high'].includes(kind),
    'invalid receiver policy experiment');
  ensure(h64(frozenSha256),'signer source hash must be precommitted');
  const bytes=await readFile(resolve(manifestDir,'p2a-frozen.json'));
  const saved=(await readFile(resolve(manifestDir,'p2a-frozen.sha256'),'utf8')).trim();
  ensure(sha256(bytes)===frozenSha256&&saved===frozenSha256,
    'signed FROST transaction export or external pre-shutdown hash substituted');
  const manifest=JSON.parse(bytes.toString('utf8'));
  const origin=(m,args=[],wallet=null)=>rpc(bitcoinCli,originDir,m,args,wallet);
  const peer=(m,args=[],wallet=null)=>rpc(bitcoinCli,peerDir,m,args,wallet);
  ensure(origin('getblockchaininfo').chain==='regtest'&&
    peer('getblockchaininfo').chain==='regtest',
    'never conduct this experiment on public Bitcoin');
  ensure(JSON.stringify(origin('listwallets'))===JSON.stringify(['miner']) &&
    peer('listwallets').length===0,
    'FROST or sponsor wallets remained online, or passive peer has signing keys');
  verifyFrozen(manifest,origin);
  const peerInfo=peer('getpeerinfo'),sourcePeers=origin('getpeerinfo');
  ensure(peerInfo.length>=1&&sourcePeers.length>=1,
    'Bitcoin Core nodes are not physically connected over P2P');
  const floorSatsVb=Number(peer('getnetworkinfo').relayfee)*1e8/1000;
  ensure(Math.abs(floorSatsVb-(kind==='low'?2:25))<0.001,
    'receiving Bitcoin node does not have the declared minimum relay fee policy');
  await syncTip(origin,peer);
  const selected=manifest.generations[2].branches[first];
  const rows=[];
  rows.push(await proveStep(origin,peer,manifest,selected.first,'first',kind));
  const competing=manifest.generations[2].branches[first==='alice'?'bob':'alice'];
  // Only the branch on the actual mined first-spend ancestry can proceed.
  const stale=peer('testmempoolaccept',[[competing.first.signedHex]]);
  ensure(stale.length===1&&stale[0].allowed!==true,
    'competing first-owner branch unexpectedly valid after first payout mined');
  const successor=outpoint(selected.second.carrierInput);
  const coin=peer('gettxout',[successor.txid,successor.vout]);
  ensure(coin&&sats(coin.value)===(first==='alice'?40000:60000),
    'second holder successor UTXO missing on peer validated Bitcoin chain');
  rows.push(await proveStep(origin,peer,manifest,selected.second,'second',kind));
  origin('generatetoaddress',[6,manifest.minerAddress]);
  await syncTip(origin,peer);
  for(const [owner,txid,n,expected]of [
    [first,selected.first.txid,1,first==='alice'?60000:40000],
    [selected.otherOwner,selected.second.txid,0,first==='alice'?40000:60000],
  ]){
    const coinPeer=peer('gettxout',[txid,n]),coinOrigin=origin('gettxout',[txid,n]);
    ensure(coinPeer&&coinOrigin&&coinPeer.confirmations>=6&&coinOrigin.confirmations>=6&&
      sats(coinPeer.value)===expected&&
      coinPeer.scriptPubKey.hex===manifest.beneficiaryScripts[owner],
      'receiver did not confirm the full correct owner entitlement to six-block depth');
  }
  const proof={
    schema:'bsb-frost-p2a-two-node-opportunistic-relay-v1',
    network:'two-physically-connected-disposable-regtest-nodes',
    bitcoinCoreVersion:origin('getnetworkinfo').subversion,
    originalP2TRFrostSignersTerminatedBeforePeerObservations:true,
    originalSponsorAliceAndBobSigningWalletsUnloaded:true,
    nodeSeparation:{
      nodeAProvidesSignedPackageAndMines:true,
      nodeBPassivelyReceivesWithoutSigningWallets:true,
      p2pConnectionConfirmed:true,independentMempools:true,
      separateBitcoinCoreProcesses:true,
      receiverMinRelayFeeSatsVb:floorSatsVb,
    },
    initialSignedManifestSha256:frozenSha256,
    ownerFirst:first,receiverPolicy:kind,
    sourceBlossomPdpEvidenceHash:manifest.sourceBlossomReferencePdpHash,
    actualPeerObservations:rows,
    totalPresignedPrincipalSats:100000,
    fullBeneficiaryPayoutsConfirmed:{alice:60000,bob:40000},
    signedFrostParentsUnchangedAcrossPeerAndFeePolicy:true,
    opportunisticP2PPropagationAllSteps:rows.every(x=>
      (x.secondFeeChildReplacement?
        x.secondFeeChildReplacement.highFeeP2PObservedBeforeExplicitSubmission:
        x.initialP2PObservation.propagated)),
    receiverLocalRpcFallbackNeeded:rows.some(x=>
      x.explicitReceiverSubmitpackageFallback),
    claimBoundaries:{
      directP2pObservationBeforeReceiverRpcSubmission:true,
      noFrostResigningOrNewSapioOracleCall:true,
      testedOnlyTwoNodesAtFixedRelayFeeFloors:true,
      worldwidePropagationGuaranteed:false,
      completeMempoolAntiPinningProven:false,
      activeTwoOfThreeQuorumCanStillSteal:true,
      futureUnattendedRefreshProven:false,
      receiptDeliveryAndRollbackProtectionProven:false,
      FilecoinFaultProofBitcoinEnforced:false,
    },
  };
  const fd=await open(out,'wx',0o600);
  try{await fd.writeFile(JSON.stringify(proof,null,2)+'\n');await fd.sync();}
  finally{await fd.close();}
  return proof;
}
async function main(args){
  const p={};
  for(let i=0;i<args.length;i++){
    const k=args[i],v=args[++i];ensure(v,'missing '+k+' argument');
    if(k==='--bitcoin-cli')p.bitcoinCli=resolve(v);
    else if(k==='--origin-dir')p.originDir=resolve(v);
    else if(k==='--peer-dir')p.peerDir=resolve(v);
    else if(k==='--frozen-dir')p.manifestDir=resolve(v);
    else if(k==='--sha256')p.frozenSha256=v;
    else if(k==='--first')p.first=v;
    else if(k==='--receiver-policy')p.kind=v;
    else if(k==='--out')p.out=resolve(v);
    else throw Error('unknown Bitcoin P2P test argument '+k);
  }
  ensure(p.bitcoinCli&&p.originDir&&p.peerDir&&p.manifestDir&&
    p.frozenSha256&&p.first&&p.kind&&p.out,
    'missing signed parent, origin and receiver regtest options');
  console.log(JSON.stringify(await run(p),null,2));
}
if(process.argv[1]&&import.meta.url==='file://'+resolve(process.argv[1])){
  main(process.argv.slice(2)).catch(e=>{console.error('Two-node FROST P2A P2P test:',e.message);process.exitCode=1;});
}
