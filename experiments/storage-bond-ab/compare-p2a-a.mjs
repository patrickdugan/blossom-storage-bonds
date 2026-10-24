#!/usr/bin/env node
// A = original funded two-holder Taproot sentinel.
// B = two separately confirmed FROST zero-fee v3/P2A recovery orderings.
// Genuine Bitcoin Core receipts only; NOT a matched workload or safety winner.
import {readFile,open} from 'node:fs/promises';
import {resolve} from 'node:path';
const requireFact=(v,m)=>{if(!v)throw Error(m);};
const sha=x=>typeof x==='string'&&/^[a-f0-9]{64}$/i.test(x);
export function compare(a,aliceFirst,bobFirst){
  requireFact(a?.kind==='matched-capital-A-real-Taproot-regtest-NOT-matched-proof-epochs' &&
    a.principalSats===100000&&a.aliceInitialSats===60000&&
    a.bobInitialSats===40000&&a.independentTaprootBonds===2 &&
    a.originalTerminalFeeShavedSatsPerBond===1000,
    'A original Taproot principal or terminal fee policy changed');
  for(const [owner,sats,payout] of [
    ['alice',60000,59000],['bob',40000,39000]]){
    const evidence=a.results?.[owner];
    requireFact(evidence?.checks>=21&&evidence.failed===0&&
      evidence.csvBlocks===6&&evidence.impliedSingleTerminalReceiptSats===payout&&
      Array.isArray(evidence.sizes)&&evidence.sizes.length>=7&&
      evidence.sizes.every(x=>Number.isInteger(x.vsize)&&x.vsize>0),
      'A real Bitcoin Core checks or six-block CSV timing missing for '+owner);
  }
  const ref=a.sharedPdpEvidence;
  const source=ref?.holderFixtures?.alice?.referenceEvidenceHashes?.[1];
  requireFact(ref?.classification===
    'COMMON-MERKLE-WITNESS-BITCOIN-SCRIPT-NOT-PROVIDER-ERASURE'&&
    ref.sourceWitnessesBoundToCoreSignedTransactions===true&&
    ref.productionStorageNonavailabilityProven===false&&
    ref.realBitcoinCsvDelayBlocks===6&&
    ref.epochsAndFeePoliciesFullyMatchedToB===false&&
    ref.holderFixtures.alice.pdpVerdicts.join(',')==='pass,fault,pass'&&
    ref.holderFixtures.bob.pdpVerdicts.join(',')==='pass,pass,pass'&&sha(source),
    'A original signed Taproot commitments not tied to genuine shared PDP');
  for(const [owner,r] of [['alice',aliceFirst],['bob',bobFirst]]){
    requireFact(r?.schema==='bsb-frost-p2a-dynamic-fee-offline-regtest-v1' &&
      r.network==='regtest'&&r.firstOwner===owner&&
      r.secondOwner!=='undefined' &&
      r.sourcePdpEvidenceHash===source&&sha(r.preShutdownFrozenSha256)&&
      r.realBip341FrostSignature===true&&
      r.fROSTSignerProcessExitedBeforeFundingChildren===true&&
      r.inputBoundIntoFrozenFrostParents===false &&
      r.sameFrostParentBeforeAndAfterFeeSabotage===true &&
      r.priorCandidateSponsorSpend?.legacyFeeCandidateSpent===true&&
      r.bitcoinMinedTwoOneParentOneChildPackages===true&&
      r.beneficiaryPaymentsSats?.alice===60000&&
      r.beneficiaryPaymentsSats?.bob===40000&&
      r.firstParent?.confirmations>=6&&r.secondParent?.confirmations>=6&&
      r.firstChild?.feeSats===3000&&r.secondChild?.feeSats===3000&&
      Number.isInteger(r.firstChild.vbytes)&&r.firstChild.vbytes>0&&
      Number.isInteger(r.secondChild.vbytes)&&r.secondChild.vbytes>0&&
      r.feeIndependentThirdPartyPaysSats===6000&&
      r.activeMaliciousFrostQuorumCanStillSteal===true&&
      r.bitcoinConsensusEnforcesSapioMid===false&&
      r.permissionlessFilecoinFaultProof===false &&
      r.indefinitelySafeRefreshesProven===false,
      'B real P2A Bitcoin evidence, sponsor independence or source PDP mismatch for '+owner);
    for(const which of ['firstParent','secondParent']){
      requireFact(sha(r[which].txid)&&sha(r[which].wtxid)&&
        Number.isInteger(r[which].vbytes)&&r[which].vbytes>0,
        'B actual parent vsize or signed wtxid missing');
    }
  }
  requireFact(aliceFirst.preShutdownFrozenSha256!==bobFirst.preShutdownFrozenSha256 &&
    aliceFirst.firstParent.txid!==bobFirst.firstParent.txid,
    'B two independent disposable Bitcoin histories have duplicate identities');
  return {
    schema:'bsb-a-sentinel-vs-b-frost-p2a-observed-regtest-v1',
    chain:'two-independent-project-fixtures-on-Bitcoin-Core-30.3',
    matchedStartingPrincipal:true,amountSats:100000,
    matchedSourceBlossomReferencePdpHash:true,
    sharedSourcePdpHash:source,
    protocolWorkloadMatched:false,
    internalScriptAuthorityEquivalent:false,
    exactBeneficiaryAmountsAtFirstUnilateralExitEquivalent:false,
    overallBitcoinTransactionCostRatioValid:false,
    securityScoreWinnerSupported:false,
    actualFeePolicy:{
      A:'historical Taproot sentinel, 1000 sats deducted per unilateral terminal payout',
      B:'zero-fee FROST parent with independent v3/P2A child, 3000 sats per package',
      directlyComparable:false
    },
    actualCoreMeasurements:{
      A:{
        twoSeparateBonds:true,originalChecksPassed:
          a.results.alice.checks+a.results.bob.checks,
        csvBlocks:6,
        referenceTransactionSizes:{
          alice:a.results.alice.sizes.map(x=>({name:x.tx,vbytes:x.vsize})),
          bob:a.results.bob.sizes.map(x=>({name:x.tx,vbytes:x.vsize}))
        }
      },
      B:{
        twoDifferentFirstOwnerOrderings:true,
        confirmedFrostParents:4,confirmedFreshP2aChildren:4,
        previousFeeCandidateCoinsSpentAfterSignerDeath:2,
        eachOwnerReceivedFullAgreedPrincipal:true,
        measured:{
          aliceFirst:{
            parentsVbytes:aliceFirst.firstParent.vbytes+aliceFirst.secondParent.vbytes,
            childrenVbytes:aliceFirst.firstChild.vbytes+aliceFirst.secondChild.vbytes,
            relayTimeSponsorFeesSats:6000
          },
          bobFirst:{
            parentsVbytes:bobFirst.firstParent.vbytes+bobFirst.secondParent.vbytes,
            childrenVbytes:bobFirst.firstChild.vbytes+bobFirst.secondChild.vbytes,
            relayTimeSponsorFeesSats:6000
          }
        },
        staticCommittedSponsorInputInFrostParent:false,
        liveFeeWalletRequiredToPublish:true,
        liveFrostSignerRequiredToPublish:false
      }
    },
    threats:{
      allFrostSignersDisappearWithCurrentFrozenDAG:'B confirmed recovery if external fee UTXO is available',
      originalSponsorFeeInputSpent:'B recovers with alternate payer in both observed histories',
      maliciousActiveTwoShareFrostQuorum:'B can still authorize theft; NOT protected',
      unavailableCurrentFrozenDAG:'both protocols need retained valid evidence',
      FilecoinAbsentPoStConsensusVerification:'not demonstrated'
    },
    nextGate:'matched adversarial sponsor outage and 1P1C pinning on signet, then independent holder witness distribution and hostile quorum enforcement analysis'
  };
}
async function main(args){
  const p={};
  for(let i=0;i<args.length;i++){
    const flag=args[i],value=args[++i];requireFact(value,'missing comparison argument '+flag);
    if(flag==='--a')p.a=resolve(value);
    else if(flag==='--b-alice')p.alice=resolve(value);
    else if(flag==='--b-bob')p.bob=resolve(value);
    else if(flag==='--out')p.out=resolve(value);
    else throw Error('unrecognized comparison option '+flag);
  }
  requireFact(p.a&&p.alice&&p.bob&&p.out,
    'requires --a --b-alice --b-bob --out file');
  const [a,alice,bob]=await Promise.all([p.a,p.alice,p.bob]
    .map(x=>readFile(x,'utf8').then(JSON.parse)));
  const checked=compare(a,alice,bob);
  const f=await open(p.out,'wx',0o600);
  try{await f.writeFile(JSON.stringify(checked,null,2)+'\n');await f.sync();}
  finally{await f.close();}
  console.log(JSON.stringify({matchedCapital:true,matchedSource:true,
    trulyComparableFeeRatio:false,safetyWinner:false,
    confirmedBRecoveryParents:4,confirmedBRecoveryP2aChildren:4},null,2));
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error('A-vs-B P2A evidence:',e.message);process.exitCode=1;});
}
