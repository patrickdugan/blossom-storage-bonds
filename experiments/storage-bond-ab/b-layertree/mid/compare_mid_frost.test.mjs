import test from 'node:test';
import assert from 'node:assert/strict';
import {compareMidFrost} from './compare_mid_frost.mjs';
const H=s=>s.repeat(64);
function fixture(){
  const mid={
    schema:'bsb-sapio-pinned-mid-exit-verified-v1',
    sapioRevision:'34363851a11d0f2b3ddb27c050537c1a2e5b7e9b',
    actualCompiledOracleGuestTransitions:2,
    witnessTransactionIdsRehashed:true,
    bitcoinCoreConfirmed:false,bitcoinConsensusEnforcedMid:false,
    sameBitcoinCarrierAsFundedFrost:false,
    storagePdpEvidenceBoundToMidRoot:false,
    onlineOracleRequired:true,
    unilateralExitDuringTotalOracleOutageProven:false,
    syntheticPayoutSats:{alice:60_000,bob:40_000},
    merkleSumSequenceSats:[100_000,40_000,0],
    canonicalRootHashes:[H('a'),H('b'),H('c')],
    physicalMidCarrierScriptPubkeyHex:'5120'+H('d')
  };
  const oracle={
    schema:'bsb-ab-pinned-sapio-mid-oracle-scope-v1',
    sapioRevision:mid.sapioRevision,
    testsPassed:['two_members_exit','owner_negative','replay','durable_lineage'],
    actualCompiledMidEmulationGuestExercised:true,
    onlineSapioOracleStillRequired:true,
    bitcoinConsensusEnforcesExperimentalMid:false,
    historicalVoucherReplayAttackReproduced:true,
    realFrostThresholdIntegratedWithMid:false,
    sourceWitnessBoundIntoSapioMidTransition:false,
    sameRootAsBBitcoinFrostCarrierProven:false,
    referenceBlossomPdpEvidenceHash:H('e')
  };
  const fro={
    schema:'bsb-ab-p2tr-real-frost-regtest-v1',
    chain:'regtest',capitalSats:100_000,aliceSats:60_000,bobSats:40_000,
    signatures:'real-BIP341-sighash-P2TR-TapTweak',
    missingSecondShareRejected:true,
    sharedPdpEvidenceHash:H('e'),
    independentFeeSponsorSats:50_000,sponsorTotalFeesSats:6_000,
    p2trTweakedOutputKey:H('f'),
    stateCommitmentBypass:{
      bitcoinMempoolAccepted:true,broadcast:false,
      realTwoOfThreeFrostTaprootSignature:true,
      alicePayoutSatsUnchanged:60_000,bobPayoutSatsUnchanged:40_000,
      originalRecipientScriptsUnchanged:true,
      bitcoinChecksStateRootSemantics:false,
      scriptPathCovenantCannotConstrainThisKeypath:true,
      legitimateApplicationCommitment:H('1'),
      maliciousApplicationCommitment:H('2')
    },
    refresh:{outputs:[{sats:100_000,script_pubkey_hex:'5120'+H('f')}]},
    payout:{outputs:[{sats:60_000},{sats:40_000}]},
    honestTwoSharePayout:{confirmed:true,sixConfirmations:true},
    beneficiaryRedemptions:{
      actualBitcoinCoreConfirmed:true,
      alice:{reclaimedSats:59_000},bob:{reclaimedSats:39_000}
    },
    limits:{
      realSapioMidCovenant:false,realLayerTreeRefresh:false,
      independentHolderExitWithoutFederation:false,
      realFrostAcrossNetworkPeers:false,publicTestnetSpend:false
    }
  };
  return {mid,oracle,fro};
}
test('real oracle and Bitcoin FROST paths share only economic amounts, not authorization',()=>{
  const f=fixture(),r=compareMidFrost(f.mid,f.oracle,f.fro);
  assert.equal(r.initialCollateralMatched,true);
  assert.equal(r.officiallyEquivalent,false);
  assert.equal(r.samePhysicalBitcoinCarrier,false);
  assert.equal(r.proofStatus.bitcoinConsensusEnforcesMid,false);
  assert.equal(r.adversarial.realFrostQuorumCanSignAlternativeCommitmentWithSamePayouts,true);
  assert.equal(r.proofStatus.offlineHolderRecoveryWithoutOracleOrFederation,false);
});
test('reject forged MID source commitment or false onchain MID consensus',()=>{
  let f=fixture();f.mid.bitcoinConsensusEnforcedMid=true;
  assert.throws(()=>compareMidFrost(f.mid,f.oracle,f.fro),/MID guest real vector/);
  f=fixture();f.oracle.bitcoinConsensusEnforcesExperimentalMid=true;
  assert.throws(()=>compareMidFrost(f.mid,f.oracle,f.fro),/MID oracle regressions/);
  f=fixture();f.fro.limits.realSapioMidCovenant=true;
  assert.throws(()=>compareMidFrost(f.mid,f.oracle,f.fro),/FROST custody/);
});
test('reject wrong PDP evidence and mismatched 60k/40k conservation',()=>{
  let f=fixture();f.fro.sharedPdpEvidenceHash=H('0');
  assert.throws(()=>compareMidFrost(f.mid,f.oracle,f.fro),/PDP mismatch/);
  f=fixture();f.mid.merkleSumSequenceSats=[100000,39999,0];
  assert.throws(()=>compareMidFrost(f.mid,f.oracle,f.fro),/MID guest real vector/);
  f=fixture();f.fro.payout.outputs[0].sats=59999;
  assert.throws(()=>compareMidFrost(f.mid,f.oracle,f.fro),/funded FROST signed tx/);
});
test('FROST quorum cannot claim restrictive root policy after Bitcoin accepts wrong root',()=>{
  let f=fixture();f.fro.stateCommitmentBypass.bitcoinChecksStateRootSemantics=true;
  assert.throws(()=>compareMidFrost(f.mid,f.oracle,f.fro),/root corruption/);
  f=fixture();f.fro.stateCommitmentBypass.maliciousApplicationCommitment=H('1');
  assert.throws(()=>compareMidFrost(f.mid,f.oracle,f.fro),/root corruption/);
});
