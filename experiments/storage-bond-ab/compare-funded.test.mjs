import test from 'node:test';
import assert from 'node:assert/strict';
import { compare } from './compare-funded.mjs';

const checks=()=>Array.from({length:21},(_,i)=>({check:'Core test '+i,pass:true}));
const sizes=()=>Array.from({length:8},(_,i)=>({tx:'case-'+i,vsize:153+i}));
function A() {
  return {
    kind:'matched-capital-A-real-Taproot-regtest-NOT-matched-proof-epochs',
    principalSats:100_000,aliceInitialSats:60_000,bobInitialSats:40_000,
    independentTaprootBonds:2,originalTerminalFeeShavedSatsPerBond:1000,
    results:{
      alice:{checks:21,failed:0,sizes:sizes(),impliedSingleTerminalReceiptSats:59_000},
      bob:{checks:21,failed:0,sizes:sizes(),impliedSingleTerminalReceiptSats:39_000},
    },
  };
}
function B() {
  return {
    schema:'bsb-ab-federation-surrogate-core-regtest-v1',
    kind:'actual-funded-2of3-P2WSH-surrogate-NOT-FROST',
    chain:'regtest',networkConfirmed:true,
    principalSats:100_000,initialSponsorSats:50_000,
    refresh:{principalLockedSats:100_000},
    honestPayout:{aliceSats:60_000,bobSats:40_000},
    threshold:{oneSignerRejected:true,dishonestQuorumOutputAcceptedByCore:true,
      honestQuorumOutputConfirmed:true},
    dishonestPayout:{broadcast:false,referenceStorageProofPasses:true,
      fraudulentlyAssertedFault:true,witnessTamperingRejected:{coreRejected:true}},
    totalSponsorFeesSats:6000,observedVbytes:{refresh:300,payout:319},
    securityLimits:{frostSigned:false,sapioMidPolicyEnforced:false,
      filecoinFaultProofVerified:false},
  };
}
test('equal capital is not falsely called matched economic evidence',()=>{
  const r=compare(A(),B());
  assert.equal(r.matchedCapital,true);
  assert.equal(r.matchedFullScenarios,false);
  assert.equal(r.feeComparisonPermitted,false);
  assert.equal(r.securityRankPermitted,false);
  assert.equal(r.A.checksPassed,42);
  assert.equal(r.B.externalSponsorFeeSats,6000);
  assert.equal(r.A.originalTerminalFeeShavedSatsPerBond,1000);
  assert.equal(r.B.trueFrost,false);
});
test('historical 1BTC fixture is not capital matched',()=>{
  const a={bond_sats:100_000_000,failed:0,checks:checks(),sizes:sizes()};
  assert.equal(compare(a,B()).matchedCapital,false);
});
test('A receipt cannot silently omit half its Taproot checks',()=>{
  const a=A();a.results.bob.checks=20;
  assert.throws(()=>compare(a,B()),/Core checks/);
});
test('B cannot hide valid proof when quorum fabricates fault',()=>{
  const b=B();b.dishonestPayout.referenceStorageProofPasses=false;
  assert.throws(()=>compare(A(),b),/negative controls/);
});
test('B must preserve full 100k principal and independent sponsor fees',()=>{
  const b=B();b.totalSponsorFeesSats=7000;
  assert.throws(()=>compare(A(),b),/fee or security classification/);
  const v=B();v.refresh.principalLockedSats=99_000;
  assert.throws(()=>compare(A(),v),/principal or entitlement mismatch/);
});
test('security label cannot be upgraded to FROST without review',()=>{
  const b=B();b.securityLimits.frostSigned=true;
  assert.throws(()=>compare(A(),b),/fee or security classification/);
});
