import test from 'node:test';
import assert from 'node:assert/strict';
import {compareFrostFunded} from './compare-frost-funded.mjs';

const H=n=>String(n).repeat(64);
const fault=H('a');
const sizes=Array.from({length:8},(_,i)=>({tx:'case-'+i,vsize:153+i}));
function records(){
  const a={
    kind:'matched-capital-A-real-Taproot-regtest-NOT-matched-proof-epochs',
    bitcoinScriptConfirmed:true,principalSats:100_000,
    aliceInitialSats:60_000,bobInitialSats:40_000,
    independentTaprootBonds:2,originalTerminalFeeShavedSatsPerBond:1_000,
    results:{
      alice:{checks:21,failed:0,csvBlocks:6,
        impliedSingleTerminalReceiptSats:59_000,sizes},
      bob:{checks:21,failed:0,csvBlocks:6,
        impliedSingleTerminalReceiptSats:39_000,sizes},
    },
    sharedPdpEvidence:{
      classification:'COMMON-MERKLE-WITNESS-BITCOIN-SCRIPT-NOT-PROVIDER-ERASURE',
      sourceWitnessesBoundToCoreSignedTransactions:true,
      productionStorageNonavailabilityProven:false,
      epochsAndFeePoliciesFullyMatchedToB:false,
      realBitcoinCsvDelayBlocks:6,
      holderFixtures:{
        alice:{pdpVerdicts:['pass','fault','pass'],
          referenceEvidenceHashes:[H('1'),fault,H('2')],
          commitmentHashes:[H('3'),H('4'),H('5')]},
        bob:{pdpVerdicts:['pass','pass','pass'],
          referenceEvidenceHashes:[H('6'),H('7'),H('8')],
          commitmentHashes:[H('9'),H('b'),H('c')]},
      },
    },
  };
  const b={
    schema:'bsb-ab-p2tr-real-frost-regtest-v1',
    chain:'regtest',cryptography:'frost-secp256k1-tr 3.0.0',
    signatures:'real-BIP341-sighash-P2TR-TapTweak',
    capitalSats:100_000,aliceSats:60_000,bobSats:40_000,
    sponsorTotalFeesSats:6_000,independentFeeSponsorSats:50_000,
    sharedPdpEvidenceHash:fault,p2trGroupKey:H('d'),
    p2trTweakedOutputKey:H('e'),missingSecondShareRejected:true,
    separateSignerSharesInDifferentProcesses:false,trustedDealerSimulated:true,
    maliciousTwoShareRedirect:{
      validBitcoinMempoolSpend:true,broadcast:false,
      redirectedPrincipalSats:100_000,
      sameTxidWitnessMutationRejected:true,
      conflictingAlternativeRejectedAfterHonestConfirmation:true,
      sourceBlossomStorageEvidenceHash:fault,
    },
    stateCommitmentBypass:{
      bitcoinMempoolAccepted:true,broadcast:false,
      realTwoOfThreeFrostTaprootSignature:true,
      alicePayoutSatsUnchanged:60_000,bobPayoutSatsUnchanged:40_000,
      sponsorFeeUnchangedSats:3_000,originalRecipientScriptsUnchanged:true,
      bitcoinChecksStateRootSemantics:false,
      scriptPathCovenantCannotConstrainThisKeypath:true,
      legitimateApplicationCommitment:H('1'),
      maliciousApplicationCommitment:H('2'),
      txid:H('3'),wtxid:H('4')
    },
    honestTwoSharePayout:{confirmed:true,sixConfirmations:true,
      postSignatureOutputTamperRejected:true,
      aliceOutpoint:H('3')+':0',bobOutpoint:H('3')+':1'},
    preSettlementCustodyChecks:{
      payoutsNotYetReleased:true,noBip341FrostSignature:true,
      sponsorAlreadySignedItsOnlyInput:true,
      ownerOnlyCarrierSpendRejected:{alice:true,bob:true},
      unilateralCarrierRecoveryProven:false,
    },
    beneficiaryRedemptions:{
      actualBitcoinCoreConfirmed:true,
      noFrostSigningRoundNeededAfterSplit:true,
      noSponsorInputUsed:true,crossSigningBlocked:true,
      walletsSeparatelyKeyed:true,
      provesPreSplitFederationFreeExit:false,
      combinedBeneficiaryWalletFeesSats:2_000,
      alice:{
        originalPayoutOutpoint:H('3')+':0',originalValueSats:60_000,
        reclaimedSats:59_000,ownerWalletFeeSats:1_000,
        rawTransaction:{txid:H('a'),wtxid:H('b'),confirmations:6,
          vsize:110,outputs:[{sats:59_000,script_pubkey_hex:'0014'+'11'.repeat(20)}]},
      },
      bob:{
        originalPayoutOutpoint:H('3')+':1',originalValueSats:40_000,
        reclaimedSats:39_000,ownerWalletFeeSats:1_000,
        rawTransaction:{txid:H('c'),wtxid:H('d'),confirmations:6,
          vsize:110,outputs:[{sats:39_000,script_pubkey_hex:'0014'+'22'.repeat(20)}]},
      },
    },
    refresh:{txid:H('1'),wtxid:H('2'),vsize:253,confirmations:7,
      outputs:[{sats:100_000},{sats:47_000},{sats:0}]},
    payout:{txid:H('3'),wtxid:H('4'),vsize:272,confirmations:6,
      outputs:[{sats:60_000},{sats:40_000},{sats:44_000},{sats:0}]},
    limits:{bitcoinCoreBip341AndP2TRKeyPathAccepted:true,
      realSapioMidCovenant:false,realLayerTreeRefresh:false,
      realFrostAcrossNetworkPeers:false,blossomPdpVerifiedByBitcoin:false,
      filecoinFaultVerifiedByBitcoin:false,
      independentHolderExitWithoutFederation:false,publicTestnetSpend:false,
      preSettlementCarrierExitByEitherHolder:false,
      independentHolderSpendAfterQuorumSettlement:true},
  };
  return {a,b};
}
test('actual A/B FROST receipt is capital/evidence matched but NOT security comparable',()=>{
  const {a,b}=records(),r=compareFrostFunded(a,b);
  assert.equal(r.matchedCapital,true);
  assert.equal(r.realFrostBip341,true);
  assert.equal(r.matchedSourcePdpEvidence,true);
  assert.equal(r.matchedFullScenarios,false);
  assert.equal(r.feesComparable,false);
  assert.equal(r.securityRankPermitted,false);
  assert.equal(r.A.actualBitcoinCoreScriptTests,42);
  assert.equal(r.A.actualCsvDelayBlocks,6);
  assert.equal(r.B.physicalRefreshVbytes,253);
  assert.equal(r.B.physicalPayoutVbytes,272);
  assert.equal(r.holderIndependentExitOnBProven,false);
  assert.equal(r.holderIndependentPostSettlementSpendProven,true);
  assert.equal(r.B.postSettlementIndependentWalletRedemptions.alice.redeemedSats,59_000);
  assert.equal(r.B.postSettlementIndependentWalletRedemptions.bob.redeemedSats,39_000);
});
test('prevent a cryptographically valid but mismatched Alice storage fault statement',()=>{
  const {a,b}=records();b.sharedPdpEvidenceHash=H('0');
  assert.throws(()=>compareFrostFunded(a,b),/same PDP proof/);
  const x=records();x.a.sharedPdpEvidence.holderFixtures.alice.pdpVerdicts[1]='pass';
  assert.throws(()=>compareFrostFunded(x.a,x.b),/A source Merkle/);
});
test('do not mislabel one-process trusted dealer FROST as independently held shares',()=>{
  const {a,b}=records();b.separateSignerSharesInDifferentProcesses=true;
  assert.throws(()=>compareFrostFunded(a,b),/adversarial safeguards/);
  const x=records();x.b.limits.realFrostAcrossNetworkPeers=true;
  assert.throws(()=>compareFrostFunded(x.a,x.b),/incorrect consensus/);
});
test('require real Bitcoin-confirmed outputs, correct sponsor fees and malicious-quorum result',()=>{
  const a=records(),b=records(),c=records(),d=records();
  a.b.payout.confirmations=0;
  assert.throws(()=>compareFrostFunded(a.a,a.b),/missing confirmed physical FROST transaction/);
  b.b.payout.outputs[1].sats=39_999;
  assert.throws(()=>compareFrostFunded(b.a,b.b),/preserved bonded capital/);
  c.b.sponsorTotalFeesSats=7000;
  assert.throws(()=>compareFrostFunded(c.a,c.b),/separately sponsored/);
  d.b.maliciousTwoShareRedirect.validBitcoinMempoolSpend=false;
  assert.throws(()=>compareFrostFunded(d.a,d.b),/adversarial safeguards/);
});
test('deny promotion of B result to onchain MID or fully verified PDP',()=>{
  const p=records();p.b.limits.realSapioMidCovenant=true;
  assert.throws(()=>compareFrostFunded(p.a,p.b),/incorrect consensus/);
  const x=records();x.b.limits.blossomPdpVerifiedByBitcoin=true;
  assert.throws(()=>compareFrostFunded(x.a,x.b),/incorrect consensus/);
});
test('A 144-block CSV or missing true Taproot checks invalidate fairness claims',()=>{
  const a=records();a.a.results.alice.csvBlocks=144;
  assert.throws(()=>compareFrostFunded(a.a,a.b),/A actual Bitcoin Core/);
  const b=records();b.a.results.alice.failed=1;
  assert.throws(()=>compareFrostFunded(b.a,b.b),/A actual Bitcoin Core/);
});
test('completed honest settlement must disable malicious double spend before evidence accepted',()=>{
  const {a,b}=records();b.maliciousTwoShareRedirect.conflictingAlternativeRejectedAfterHonestConfirmation=false;
  assert.throws(()=>compareFrostFunded(a,b),/adversarial safeguards/);
});

test('beneficiary PSBT confirmations never establish an earlier unilateral carrier exit',()=>{
  const r=records();
  r.b.preSettlementCustodyChecks.ownerOnlyCarrierSpendRejected.alice=false;
  assert.throws(()=>compareFrostFunded(r.a,r.b),/pre-settlement unilateral/);
  const x=records();
  x.b.limits.preSettlementCarrierExitByEitherHolder=true;
  assert.throws(()=>compareFrostFunded(x.a,x.b),/pre-settlement unilateral/);
});
test('reject false beneficiary custody, cross-wallet signing and repeated Bitcoin spends',()=>{
  const p=records();p.b.beneficiaryRedemptions.crossSigningBlocked=false;
  assert.throws(()=>compareFrostFunded(p.a,p.b),/post-settlement wallet custody/);
  const q=records();q.b.beneficiaryRedemptions.alice.rawTransaction.confirmations=0;
  assert.throws(()=>compareFrostFunded(q.a,q.b),/independent beneficiary wallet spend/);
  const r=records();r.b.beneficiaryRedemptions.bob.rawTransaction.txid=
    r.b.beneficiaryRedemptions.alice.rawTransaction.txid;
  assert.throws(()=>compareFrostFunded(r.a,r.b),/not independent/);
  const t=records();t.b.beneficiaryRedemptions.alice.originalPayoutOutpoint=H('0')+':0';
  assert.throws(()=>compareFrostFunded(t.a,t.b),/independent beneficiary wallet spend/);
});

test('two real FROST shares may sign a different opaque root without changing payouts',()=>{
  const {a,b}=records();
  const verified=compareFrostFunded(a,b);
  assert.equal(verified.opaqueStateRootBypassDemonstratedOnBitcoin,true);
  assert.equal(verified.B.thresholdSignedWrongStateRootMempoolValid,true);
  assert.equal(verified.onchainMidCovenantProven,false);
  const same=records();
  same.b.stateCommitmentBypass.maliciousApplicationCommitment=
    same.b.stateCommitmentBypass.legitimateApplicationCommitment;
  assert.throws(()=>compareFrostFunded(same.a,same.b),/root-only bypass/);
  const stolen=records();
  stolen.b.stateCommitmentBypass.alicePayoutSatsUnchanged=59_999;
  assert.throws(()=>compareFrostFunded(stolen.a,stolen.b),/root-only bypass/);
  const bypass=records();
  bypass.b.stateCommitmentBypass.bitcoinChecksStateRootSemantics=true;
  assert.throws(()=>compareFrostFunded(bypass.a,bypass.b),/root-only bypass/);
});
