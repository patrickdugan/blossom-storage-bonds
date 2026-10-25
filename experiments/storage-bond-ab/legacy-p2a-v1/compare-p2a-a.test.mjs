import test from 'node:test';
import assert from 'node:assert/strict';
import {compare} from './compare-p2a-a.mjs';
const hash=x=>x.repeat(64);
function fixtures(){
  const reference=hash('a');
  const a={
    kind:'matched-capital-A-real-Taproot-regtest-NOT-matched-proof-epochs',
    principalSats:100000,aliceInitialSats:60000,bobInitialSats:40000,
    independentTaprootBonds:2,originalTerminalFeeShavedSatsPerBond:1000,
    results:{
      alice:{checks:21,failed:0,csvBlocks:6,impliedSingleTerminalReceiptSats:59000,
        sizes:Array.from({length:8},(_,i)=>({tx:'A-'+i,vsize:200+i}))},
      bob:{checks:21,failed:0,csvBlocks:6,impliedSingleTerminalReceiptSats:39000,
        sizes:Array.from({length:8},(_,i)=>({tx:'B-'+i,vsize:200+i}))}
    },
    sharedPdpEvidence:{
      classification:'COMMON-MERKLE-WITNESS-BITCOIN-SCRIPT-NOT-PROVIDER-ERASURE',
      sourceWitnessesBoundToCoreSignedTransactions:true,
      productionStorageNonavailabilityProven:false,
      realBitcoinCsvDelayBlocks:6,
      epochsAndFeePoliciesFullyMatchedToB:false,
      holderFixtures:{
        alice:{referenceEvidenceHashes:[hash('0'),reference,hash('1')],
          pdpVerdicts:['pass','fault','pass']},
        bob:{referenceEvidenceHashes:[hash('2'),hash('3'),hash('4')],
          pdpVerdicts:['pass','pass','pass']}
      }
    }
  };
  const receipt=owner=>({
    schema:'bsb-frost-p2a-dynamic-fee-offline-regtest-v1',
    network:'regtest',firstOwner:owner,secondOwner:owner==='alice'?'bob':'alice',
    sourcePdpEvidenceHash:reference,
    preShutdownFrozenSha256:hash(owner==='alice'?'5':'6'),
    realBip341FrostSignature:true,
    fROSTSignerProcessExitedBeforeFundingChildren:true,
    inputBoundIntoFrozenFrostParents:false,
    sameFrostParentBeforeAndAfterFeeSabotage:true,
    priorCandidateSponsorSpend:{legacyFeeCandidateSpent:true},
    bitcoinMinedTwoOneParentOneChildPackages:true,
    beneficiaryPaymentsSats:{alice:60000,bob:40000},
    firstParent:{txid:hash(owner==='alice'?'7':'8'),wtxid:hash('a'),
      vbytes:220,confirmations:7},
    secondParent:{txid:hash(owner==='alice'?'9':'b'),wtxid:hash('c'),
      vbytes:195,confirmations:6},
    firstChild:{txid:hash('d'),wtxid:hash('e'),
      vbytes:162,feeSats:3000},
    secondChild:{txid:hash('f'),wtxid:hash('0'),
      vbytes:162,feeSats:3000},
    feeIndependentThirdPartyPaysSats:6000,
    activeMaliciousFrostQuorumCanStillSteal:true,
    bitcoinConsensusEnforcesSapioMid:false,
    permissionlessFilecoinFaultProof:false,
    indefinitelySafeRefreshesProven:false
  });
  return {a,alice:receipt('alice'),bob:receipt('bob')};
}
test('receipts match 100k and PDP without turning incomparable transaction sizes into a score',()=>{
  const x=fixtures(),v=compare(x.a,x.alice,x.bob);
  assert.equal(v.matchedStartingPrincipal,true);
  assert.equal(v.matchedSourceBlossomReferencePdpHash,true);
  assert.equal(v.protocolWorkloadMatched,false);
  assert.equal(v.overallBitcoinTransactionCostRatioValid,false);
  assert.equal(v.securityScoreWinnerSupported,false);
  assert.equal(v.actualCoreMeasurements.B.confirmedFrostParents,4);
  assert.equal(v.actualCoreMeasurements.B.measured.aliceFirst.childrenVbytes,324);
});
test('fail closed if FROST parent suddenly commits a sponsor input',()=>{
  const x=fixtures();x.bob.inputBoundIntoFrozenFrostParents=true;
  assert.throws(()=>compare(x.a,x.alice,x.bob),/B real P2A Bitcoin evidence/);
});
test('reject missing actual beneficiary confirmation and parent vbytes',()=>{
  const x=fixtures();x.alice.secondParent.confirmations=0;
  assert.throws(()=>compare(x.a,x.alice,x.bob),/B real P2A Bitcoin evidence/);
  const y=fixtures();y.bob.firstParent.vbytes=0;
  assert.throws(()=>compare(y.a,y.alice,y.bob),/actual parent vsize/);
});
test('reject broken source Merkle hash or forged storage nonavailability claim',()=>{
  const x=fixtures();x.bob.sourcePdpEvidenceHash=hash('e');
  assert.throws(()=>compare(x.a,x.alice,x.bob),/PDP mismatch/);
  const y=fixtures();y.a.sharedPdpEvidence.productionStorageNonavailabilityProven=true;
  assert.throws(()=>compare(y.a,y.alice,y.bob),/A original signed Taproot/);
});
test('reject A terminal fee changes and unsafe fee-equivalence inference',()=>{
  const x=fixtures();x.a.results.alice.impliedSingleTerminalReceiptSats=60000;
  assert.throws(()=>compare(x.a,x.alice,x.bob),/A real Bitcoin Core checks/);
  const y=fixtures();y.bob.activeMaliciousFrostQuorumCanStillSteal=false;
  assert.throws(()=>compare(y.a,y.alice,y.bob),/B real P2A Bitcoin evidence/);
});
