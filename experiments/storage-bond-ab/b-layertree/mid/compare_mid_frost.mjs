#!/usr/bin/env node
/**
 * Joint evidence report for two DIFFERENT signing authorities.
 * Sapio's compiled MID guest + online oracle has signed synthetic 60k/40k
 * sequential exits. A funded Bitcoin P2TR 2-of-3 FROST keypath has signed
 * physically different actual carrier/beneficiary scripts.
 *
 * This is a DIFFERENTIAL CONTROL TEST, not proof that the MID guest governs
 * the P2TR FROST output. An OP_RETURN state commitment is not a covenant.
 */
import {readFile,open} from 'node:fs/promises';
import {resolve} from 'node:path';
const PIN='34363851a11d0f2b3ddb27c050537c1a2e5b7e9b';
const must=(ok,why)=>{if(!ok)throw Error(why)};
const h64=x=>typeof x==='string'&&/^[0-9a-f]{64}$/i.test(x);
export function compareMidFrost(mid,oracle,btc){
  must(mid?.schema==='bsb-sapio-pinned-mid-exit-verified-v1'&&
    mid.sapioRevision===PIN&&
    mid.actualCompiledOracleGuestTransitions===2&&
    mid.witnessTransactionIdsRehashed===true&&
    mid.bitcoinCoreConfirmed===false&&
    mid.bitcoinConsensusEnforcedMid===false&&
    mid.sameBitcoinCarrierAsFundedFrost===false&&
    mid.storagePdpEvidenceBoundToMidRoot===false&&
    mid.onlineOracleRequired===true&&
    mid.unilateralExitDuringTotalOracleOutageProven===false&&
    mid.syntheticPayoutSats?.alice===60_000&&
    mid.syntheticPayoutSats?.bob===40_000&&
    mid.merkleSumSequenceSats?.join(',')==='100000,40000,0'&&
    h64(mid.canonicalRootHashes?.[0])&&
    h64(mid.canonicalRootHashes?.[1])&&
    h64(mid.canonicalRootHashes?.[2])&&
    /^5120[a-f0-9]{64}$/i.test(mid.physicalMidCarrierScriptPubkeyHex),
    'signed MID guest real vector provenance, root sequence or trust limits incorrect');
  must(oracle?.schema==='bsb-ab-pinned-sapio-mid-oracle-scope-v1'&&
    oracle.sapioRevision===PIN&&
    oracle.testsPassed?.length===4&&
    oracle.actualCompiledMidEmulationGuestExercised===true&&
    oracle.onlineSapioOracleStillRequired===true&&
    oracle.bitcoinConsensusEnforcesExperimentalMid===false&&
    oracle.historicalVoucherReplayAttackReproduced===true&&
    oracle.realFrostThresholdIntegratedWithMid===false&&
    oracle.sourceWitnessBoundIntoSapioMidTransition===false&&
    oracle.sameRootAsBBitcoinFrostCarrierProven===false&&
    h64(oracle.referenceBlossomPdpEvidenceHash),
    'pinned MID oracle regressions or input-data caveats missing');
  must(btc?.schema==='bsb-ab-p2tr-real-frost-regtest-v1'&&
    btc.chain==='regtest'&&
    btc.capitalSats===100_000&&btc.aliceSats===60_000&&btc.bobSats===40_000&&
    btc.signatures==='real-BIP341-sighash-P2TR-TapTweak'&&
    btc.missingSecondShareRejected===true&&
    btc.sharedPdpEvidenceHash===oracle.referenceBlossomPdpEvidenceHash&&
    btc.independentFeeSponsorSats===50_000&&
    btc.sponsorTotalFeesSats===6_000,
    'real confirmed BIP341 FROST principal or shared reference PDP mismatch');
  const b=btc.stateCommitmentBypass;
  must(b?.bitcoinMempoolAccepted===true&&b.broadcast===false&&
    b.realTwoOfThreeFrostTaprootSignature===true&&
    b.alicePayoutSatsUnchanged===60_000&&
    b.bobPayoutSatsUnchanged===40_000&&
    b.originalRecipientScriptsUnchanged===true&&
    b.bitcoinChecksStateRootSemantics===false&&
    b.scriptPathCovenantCannotConstrainThisKeypath===true&&
    h64(b.legitimateApplicationCommitment)&&
    h64(b.maliciousApplicationCommitment)&&
    b.legitimateApplicationCommitment!==b.maliciousApplicationCommitment,
    'missing real Bitcoin FROST state-only root corruption counterexample');
  must(btc.refresh?.outputs?.[0]?.sats===100_000&&
    btc.payout?.outputs?.[0]?.sats===60_000&&
    btc.payout?.outputs?.[1]?.sats===40_000&&
    btc.refresh.outputs[0].script_pubkey_hex==='5120'+btc.p2trTweakedOutputKey,
    'funded FROST signed tx does not commit matching collateral');
  must(btc.honestTwoSharePayout?.confirmed===true&&
    btc.honestTwoSharePayout.sixConfirmations===true&&
    btc.beneficiaryRedemptions?.actualBitcoinCoreConfirmed===true&&
    btc.beneficiaryRedemptions.alice?.reclaimedSats===59_000&&
    btc.beneficiaryRedemptions.bob?.reclaimedSats===39_000&&
    btc.limits?.realSapioMidCovenant===false&&
    btc.limits?.realLayerTreeRefresh===false&&
    btc.limits?.independentHolderExitWithoutFederation===false&&
    btc.limits?.realFrostAcrossNetworkPeers===false&&
    btc.limits?.publicTestnetSpend===false,
    'FROST custody status or native MID claim overstated');
  must(mid.physicalMidCarrierScriptPubkeyHex!==
      btc.refresh.outputs[0].script_pubkey_hex,
    'real MID and FROST share a carrier script unexpectedly; needs NEW verification');
  return {
    schema:'bsb-ab-mid-frost-authorization-differential-v1',
    network:'disposable-regtest-plus-synthetic-Sapio-guest',
    pinnedSapioCommit:PIN,
    initialCollateralMatched:true,
    beneficiaryValuesMatched:true,
    sourcePdpReferenceHashMatchedInExternalReport:true,
    oracleMidHashCryptographicallyBoundIntoBitcoinCarrier:false,
    samePhysicalBitcoinCarrier:false,
    midCarrierScriptPubkeyHex:mid.physicalMidCarrierScriptPubkeyHex,
    frostCarrierScriptPubkeyHex:btc.refresh.outputs[0].script_pubkey_hex,
    midpointMerkleSumSats:mid.merkleSumSequenceSats,
    midRootHashes:mid.canonicalRootHashes,
    beneficiaryReleasePattern:{
      sapio:'sequential-owner-EXIT-60k-then-40k-online-oracle',
      frost:'one-2-of-3-authorized-60k-40k-split',
      sameAuthorizationTransaction:false,
      ownerOnlyExitFromFrostCarrier:false,
    },
    adversarial:{
      realFrostQuorumCanSignAlternativeCommitmentWithSamePayouts:true,
      actualBitcoinMempoolAcceptedThatAlternative:true,
      maliciousAlternativeBroadcast:false,
      pinnedSapioMidGuestRejectedOutputMutationsWithNewOwnerSignatures:true,
      historicalSapioVoucherReplayAttackExists:true,
    },
    proofStatus:{
      realP2trBitcoinBip341Confirmed:true,
      realSapioMidCompiledOracleGuestExecuted:true,
      bitcoinConsensusEnforcesMid:false,
      realFrostKeypathGovernedByMid:false,
      offlineHolderRecoveryWithoutOracleOrFederation:false,
      auditedRealFilecoinPoStProof:false,
      comparableFeeOrSecurityWinner:false
    },
    nextGate:'Exact MID policy and real BTC carrier share one restrictive script, or freeze independently spendable signed exit paths before all signing services disappear'
  };
}
async function main(args){
  must(args.length===6&&args[0]==='--mid'&&args[2]==='--oracle'&&
    args[4]==='--frost',
    'usage: compare-mid-frost.mjs --mid VERIFIED.json --oracle ORACLE.json --frost FROST.json');
  const [mid,oracle,frost]=await Promise.all([args[1],args[3],args[5]]
    .map(p=>readFile(resolve(p),'utf8').then(JSON.parse)));
  process.stdout.write(JSON.stringify(compareMidFrost(mid,oracle,frost),null,2)+'\n');
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error(e.message);process.exitCode=1;});
}
