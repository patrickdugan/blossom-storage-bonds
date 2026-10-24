#!/usr/bin/env node
/** Service-dead zero-fee FROST P2TR parent + relay-funded v3 P2A child. */
import {readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {bitcoin,need,point,sats,amount,decodedParent,child,submit} from './core.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function confirmed(node,id,n=1){
  const tx=node('getrawtransaction',[id,true]);
  need(tx.txid===id&&tx.confirmations>=n,
    'Bitcoin Core did not confirm expected FROST/P2A spend');
  const block=node('getblockheader',[tx.blockhash,true]);
  need(node('getblockhash',[block.height])===tx.blockhash,
    'Bitcoin FROST/P2A result belongs to stale regtest chain');
  return tx;
}
function original(node,rec,principal){
  const decoded=decodedParent(node,rec,principal);
  const op=point(rec.carrierBefore);
  const funded=node('getrawtransaction',[op.txid,true]);
  need(funded.txid===op.txid&&
    sats(funded.vout?.[op.vout]?.value)===principal&&
    funded.vout[op.vout].scriptPubKey.hex.startsWith('5120'),
    'frozen one-input FROST parent does not reference correct P2TR amount');
  return decoded;
}
function currentDAG(m,node){
  need(m.schema==='bsb-frost-truc-p2a-presigned-dag-v1'&&
    m.network==='regtest'&&
    m.realFrostBip341TaprootKeypath===true &&
    m.onlyOneInputPerPresignedParent===true &&
    m.zeroParentFeeSats===0&&
    m.zeroValueAnchorScriptHex==='51024e73'&&
    m.generationCount===3&&m.latestGeneration===2&&
    m.originalPrincipalSats===100000&&
    m.entitlementsSats?.alice===60000&&
    m.entitlementsSats?.bob===40000&&
    m.allFrostSharesRemainInSignerProcess===true &&
    m.onlineSapioOracleRequiredToRelay===false &&
    m.activeMaliciousTwoShareQuorumCouldRedirect===true &&
    m.experimentalMidRulesBitcoinEnforced===false &&
    m.differentFeePayerCanFundSameParent===true &&
    m.relayMustProvideFreshValidChild===true,
    'not a pinned BIP341 v3/P2A signer-dead recovery export');
  const generations=m.snapshots;
  need(Array.isArray(generations)&&generations.length===3,
    'not exactly three prevout generations');
  for(let i=0;i<3;i++){
    const g=generations[i];
    need(g.generation===i&&g.principalSats===100000&&
      g.carrierScriptPubkeyHex===m.principalCarrierScript,
      'generation index or source script altered');
    for(const [first,second,value,otherValue] of [
      ['alice','bob',60000,40000],['bob','alice',40000,60000]
    ]){
      const b=g.branches?.[first];
      need(b?.firstOwner===first&&b.otherOwner===second&&
        b.firstSats===value&&b.otherSats===otherValue&&
        b.feeInputsBoundIntoParent===false,
        'frozen owner-first branch class changed');
      const a=original(node,b.first,100000),follow=decodedParent(node,b.second,otherValue);
      need(b.first.carrierBefore===g.carrierBefore &&
        b.second.carrierBefore===b.first.txid+':0'&&
        a.vout.length===3&&follow.vout.length===2&&
        sats(a.vout[0].value)===otherValue&&
        a.vout[0].scriptPubKey.hex===m.principalCarrierScript&&
        sats(a.vout[1].value)===value&&
        a.vout[1].scriptPubKey.hex===m.beneficiaryScripts[first]&&
        sats(follow.vout[0].value)===otherValue&&
        follow.vout[0].scriptPubKey.hex===m.beneficiaryScripts[second],
        'presigned owner split lost counterparty principal or signed descendant');
    }
    if(i<2){
      const refresh=g.refreshBroadcast;
      const parent=original(node,refresh?.parent,100000);
      need(parent.vout.length===2&&
        sats(parent.vout[0].value)===100000 &&
        parent.vout[0].scriptPubKey.hex===m.principalCarrierScript &&
        refresh?.actualBitcoinCoreSubmitpackageSuccess===true&&
        refresh.childFeeSats===3000 &&
        generations[i+1].carrierBefore===parent.txid+':0',
        'signed generation refresh was not P2A package-funded');
      confirmed(node,refresh.parent.txid,1);
      confirmed(node,refresh.childTxid,1);
      const old=point(g.carrierBefore);
      need(node('gettxout',[old.txid,old.vout])===null,
        'old carrier still unspent after Bitcoin refresh');
    }else need(g.refreshBroadcast===null,'current generation should not refresh');
  }
  const cur=point(generations[2].carrierBefore);
  const u=node('gettxout',[cur.txid,cur.vout]);
  need(u&&sats(u.value)===100000,
    'current FROST carrier no longer available for presigned recovery');
  return generations[2];
}
function stealCandidateFee(node,parent,m){
  const old=point(m.legacyCandidateConfirmedOutpoint);
  const unspent=node('gettxout',[old.txid,old.vout]);
  need(unspent&&sats(unspent.value)===10000,
    'legacy candidate fee UTXO not independently confirmed');
  const proposed=child(node,parent,'legacyfee');
  need(proposed.feeCoin.txid===old.txid&&
    proposed.feeCoin.vout===old.vout,
    'originally proposed fixed fee candidate not bound to intended legacy UTXO');
  const destination=node('getnewaddress',[],'miner');
  const raw=node('createrawtransaction',[[old],{[destination]:amount(9000)}]);
  const signed=node('signrawtransactionwithwallet',[raw], 'legacyfee');
  need(signed.complete===true,'legacy fee adversary could not sign its own UTXO');
  const decoded=node('decoderawtransaction',[signed.hex]);
  need(decoded.vin.length===1&&decoded.vin[0].txid===old.txid&&
    decoded.vin[0].vout===old.vout,
    'fee adversary attempted to spend carrier instead of its fee coin');
  const txid=node('sendrawtransaction',[signed.hex]);
  need(txid===decoded.txid,'Bitcoin broadcast an unexpected legacy-fee sabotage');
  node('generatetoaddress',[1,m.minerAddress]);
  confirmed(node,txid,1);
  need(node('gettxout',[old.txid,old.vout])===null,
    'legacy candidate fee UTXO did not become unspendable');
  const proposedFee=point(proposed.feeCoin.txid+':'+proposed.feeCoin.vout);
  need(node('gettxout',[proposedFee.txid,proposedFee.vout])===null,
    'stale child still has a valid original funding input');
  return {legacyFeeCandidateSpent:true,originalCandidateChildTxid:proposed.tx.txid,
    sabotageTxid:txid,originallySelectedInput:old.txid+':'+old.vout};
}
function publish(node,record,principal,miner){
  const parent=decodedParent(node,record,principal);
  const fee=child(node,parent,'relayfee');
  need(fee.feeCoin.wallet===undefined,
    'unrecognized fee wallet ownership metadata');
  const before=record.signedHex;
  submit(node,parent,fee);
  need(record.signedHex===before,'dynamic CPFP mutated frozen FROST parent');
  node('generatetoaddress',[1,miner]);
  const one=confirmed(node,parent.txid,1),two=confirmed(node,fee.tx.txid,1);
  need(one.hash===record.wtxid&&two.hash===fee.tx.hash,
    'Bitcoin confirmed different parent/child witness bytes');
  return {parent:one,feeChild:two,feeCoin:fee.feeCoin,
    signedParentUnchanged:true,feeSats:fee.childFeeSats,
    totalVbytes:parent.vsize+fee.tx.vsize};
}
export async function recover({binary,datadir,dir,sha256,first,out}){
  need(['alice','bob'].includes(first)&&/^[0-9a-f]{64}$/i.test(sha256),
    'explicit owner ordering and pre-shutdown manifest digest required');
  const originalBytes=await readFile(resolve(dir,'p2a-frozen.json'));
  const expected=(await readFile(resolve(dir,'p2a-frozen.sha256'),'utf8')).trim();
  need(sha(originalBytes)===sha256&&expected===sha256,
    'presigned recovery manifest changed or was rolled back since freeze');
  const manifest=JSON.parse(originalBytes);
  const node=bitcoin(binary,datadir);
  need(node('getblockchaininfo').chain==='regtest',
    'refusing P2A experiment on public Bitcoin network');
  const loaded=node('listwallets');
  need(Array.isArray(loaded)&&loaded.includes('miner')&&
    loaded.includes('relayfee')&&loaded.includes('legacyfee')&&
    !loaded.includes('refreshfee')&&
    !loaded.includes('alice')&&!loaded.includes('bob'),
    'FROST pre-signing/owner wallet remained available during recovery');
  const g=currentDAG(manifest,node);
  const branch=g.branches[first],loser=g.branches[first==='alice'?'bob':'alice'];
  const parentBefore=branch.first.signedHex;
  const sabotage=stealCandidateFee(node,decodedParent(node,branch.first,100000),manifest);
  const firstProof=publish(node,branch.first,100000,manifest.minerAddress);
  need(branch.first.signedHex===parentBefore,'post-sponsor FROST parent bytes changed');
  const loserPoint=point(g.carrierBefore);
  need(node('gettxout',[loserPoint.txid,loserPoint.vout])===null,
    'frozen other-first carrier was not consumed by winner');
  const secondProof=publish(node,branch.second,branch.otherSats,manifest.minerAddress);
  node('generatetoaddress',[5,manifest.minerAddress]);
  const firstFinal=confirmed(node,branch.first.txid,6);
  const secondFinal=confirmed(node,branch.second.txid,6);
  for(const [name,txid,index,value] of [
    [first,branch.first.txid,1,branch.firstSats],
    [branch.otherOwner,branch.second.txid,0,branch.otherSats]
  ]){
    const utxo=node('gettxout',[txid,index]);
    need(utxo&&utxo.confirmations>=6&&sats(utxo.value)===value&&
      utxo.scriptPubKey.hex===manifest.beneficiaryScripts[name],
      'signed v3/P2A relay failed independent Bitcoin beneficiary payout');
  }
  need(firstProof.feeCoin.txid!==sabotage.originallySelectedInput.split(':')[0],
    'fresh CPFP child reused hostile sponsor input');
  need(sats(firstFinal.vout[0].value)===branch.otherSats&&
    sats(secondFinal.vout[0].value)===branch.otherSats,
    'other beneficiary successor value changed');
  const result={
    schema:'bsb-frost-p2a-dynamic-fee-offline-regtest-v1',
    network:'regtest',firstOwner:first,secondOwner:branch.otherOwner,
    sourcePdpEvidenceHash:manifest.sourceBlossomPdpEvidenceHash,
    preShutdownFrozenSha256:sha256,
    realBip341FrostSignature:true,
    fROSTSignerProcessExitedBeforeFundingChildren:true,
    sponsorWalletFromSigningPhaseNotLoaded:true,
    dynamicFeePayerWalletUsedOnlyForV3Children:true,
    inputBoundIntoFrozenFrostParents:false,
    sameFrostParentBeforeAndAfterFeeSabotage:true,
    priorCandidateSponsorSpend: sabotage,
    firstParent:{txid:branch.first.txid,wtxid:branch.first.wtxid,
      confirmations:firstFinal.confirmations,vbytes:firstFinal.vsize},
    secondParent:{txid:branch.second.txid,wtxid:branch.second.wtxid,
      confirmations:secondFinal.confirmations,vbytes:secondFinal.vsize},
    firstChild:{txid:firstProof.feeChild.txid,wtxid:firstProof.feeChild.hash,
      feeSats:firstProof.feeSats,vbytes:firstProof.feeChild.vsize},
    secondChild:{txid:secondProof.feeChild.txid,wtxid:secondProof.feeChild.hash,
      feeSats:secondProof.feeSats,vbytes:secondProof.feeChild.vsize},
    beneficiaryPaymentsSats:{alice:60000,bob:40000},
    feeIndependentThirdPartyPaysSats:6000,
    bitcoinMinedTwoOneParentOneChildPackages:true,
    signerAbsentDuringRecovery:true,
    activeMaliciousFrostQuorumCanStillSteal:true,
    fixedSponsorOutpointLivenessAttackDefeatedForTheseParents:true,
    requiresSomeIndependentFeePayer:true,
    bitcoinConsensusEnforcesSapioMid:false,
    permissionlessFilecoinFaultProof:false,
    indefinitelySafeRefreshesProven:false,
  };
  const file=await open(out,'wx',0o600);
  try{await file.writeFile(JSON.stringify(result,null,2)+'\n');await file.sync();}
  finally{await file.close();}
  return result;
}
async function main(args){
  const config={};
  for(let i=0;i<args.length;i++){
    const k=args[i],v=args[++i];need(v,'missing option value after '+k);
    if(k==='--bitcoin-cli')config.binary=resolve(v);
    else if(k==='--datadir')config.datadir=resolve(v);
    else if(k==='--frozen-dir')config.dir=resolve(v);
    else if(k==='--sha256')config.sha256=v;
    else if(k==='--first')config.first=v;
    else if(k==='--out')config.out=resolve(v);
    else throw Error('unknown P2A relay option '+k);
  }
  need(config.binary&&config.datadir&&config.dir&&config.sha256&&
    config.first&&config.out,'complete no-FROST relay arguments required');
  console.log(JSON.stringify(await recover(config),null,2));
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error('FROST v3 P2A relay:',e.message);process.exitCode=1;});
}
