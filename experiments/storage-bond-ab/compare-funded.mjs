#!/usr/bin/env node
/**
 * Combine ALREADY CAPTURED funded regtest receipts without hiding mismatches.
 * A is currently historical 1BTC Taproot sentinel, B a 100k-sat pooled P2WSH
 * 2-of-3 surrogate. These are NOT a matched testnet experiment or equal trust.
 */
import {readFile,open} from 'node:fs/promises';
import {resolve} from 'node:path';

const insist=(x,m)=>{if(!x)throw Error(m);};
const count=r=>r.checks.filter(x=>x.pass===true).length;
export function compare(a,b) {
  insist(a && b,'two independent Core receipts required');
  const matched=a.kind==='matched-capital-A-real-Taproot-regtest-NOT-matched-proof-epochs';
  let aFacts;
  if(matched) {
    insist(a.principalSats===100_000&&a.aliceInitialSats===60_000&&
      a.bobInitialSats===40_000&&a.independentTaprootBonds===2&&
      a.originalTerminalFeeShavedSatsPerBond===1_000,
      'capital-matched A witness/fee policy changed');
    for(const [name,expected] of [['alice',60_000],['bob',40_000]]) {
      const trial=a.results?.[name];
      insist(trial&&trial.checks>=21&&trial.failed===0&&
        Array.isArray(trial.sizes)&&trial.sizes.length>=7,
        'capital-matched A reference failed Core checks');
      insist(trial.impliedSingleTerminalReceiptSats===expected-1_000,
        'A unilateral terminal fee amount changed');
    }
    aFacts={
      aggregateBondSats:a.principalSats,checksPassed:a.results.alice.checks+a.results.bob.checks,
      checksFailed:a.results.alice.failed+a.results.bob.failed,
      twoIndependentBonds:true,
      originalTerminalFeeShavedSatsPerBond:1_000,
      coreMeasuredSamples:{
        alice:Object.fromEntries(a.results.alice.sizes.map(x=>[x.tx,x.vsize])),
        bob:Object.fromEntries(a.results.bob.sizes.map(x=>[x.tx,x.vsize])),
      },
    };
  } else {
    insist(a.bond_sats===100_000_000,'expected historical 1-BTC sentinel report');
    insist(a.failed===0&&Array.isArray(a.checks)&&a.checks.length>=21&&
      a.checks.every(r=>r.pass===true),'sentinel full-node regression failed');
    insist(Array.isArray(a.sizes)&&a.sizes.length>=7&&a.sizes.every(s=>
      Number.isInteger(s.vsize)&&s.vsize>0&&typeof s.tx==='string'),
      'sentinel metrics missing');
    aFacts={aggregateBondSats:a.bond_sats,checksPassed:count(a),
      checksFailed:a.failed,twoIndependentBonds:false,
      coreMeasuredSamples:Object.fromEntries(a.sizes.map(x=>[x.tx,x.vsize]))};
  }
  insist(b.schema==='bsb-ab-federation-surrogate-core-regtest-v1'&&
    b.kind==='actual-funded-2of3-P2WSH-surrogate-NOT-FROST'&&
    b.chain==='regtest'&&b.networkConfirmed===true,
    'expected genuine Bitcoin Core B surrogate report');
  insist(b.principalSats===100_000&&b.initialSponsorSats===50_000&&
    b.honestPayout.aliceSats===60_000&&b.honestPayout.bobSats===40_000&&
    b.refresh.principalLockedSats===100_000,'B principal or entitlement mismatch');
  insist(b.threshold.oneSignerRejected===true&&
    b.threshold.dishonestQuorumOutputAcceptedByCore===true&&
    b.threshold.honestQuorumOutputConfirmed===true&&
    b.dishonestPayout.broadcast===false&&
    b.dishonestPayout.referenceStorageProofPasses===true&&
    b.dishonestPayout.fraudulentlyAssertedFault===true&&
    b.dishonestPayout.witnessTamperingRejected.coreRejected===true,
    'missing B threshold or fraudulent-storage negative controls');
  insist(b.totalSponsorFeesSats===6_000&&
    b.securityLimits.frostSigned===false&&
    b.securityLimits.sapioMidPolicyEnforced===false&&
    b.securityLimits.filecoinFaultProofVerified===false,
    'misleading B fee or security classification');
  return {
    schema:'bsb-ab-core-heterogeneous-evidence-v1',
    network:'regtest',matchedCapital:matched,matchedFullScenarios:false,
    feeComparisonPermitted:false,securityRankPermitted:false,
    note:matched?
      'Both begin with 100k sats but A has two separate Taproot bonds, distinct challenge events and terminal fees deducted from collateral. B is pooled P2WSH multisig, NOT FROST or MID. Do not present a transaction-fee winner.':
      'A is one historical 1BTC Taproot/Schnorr sentinel; B is 100k P2WSH multisig, NOT FROST or MID. Do not report byte figures as a cost ratio.',
    A:{
      ...aFacts,
      consensusSpendTypes:[
        'BIP341-Taproot-presigned-script','BIP112-CSV',
        'BIP65-CLTV','TRUC-P2A-CPFP','MuSig2-keypath',
      ],
      realIndependentStorageVerdict:false,
      matched60k40k:matched,
    },
    B:{
      carrierBondSats:b.principalSats,clientEntitlementsSats:{alice:60_000,bob:40_000},
      coreMeasuredVbytes:b.observedVbytes,
      externalSponsorFeeSats:b.totalSponsorFeesSats,
      singleSignerRejection:true,
      twoSignerWrongPayoutBitcoinValid:true,
      wrongPayoutBroadcast:false,
      validBlossomProofFalselyClaimedFault:true,
      sameTxidWitnessMutationRejected:true,
      trueFrost:false,trueSapioMid:false,
    },
    nextAcceptanceGate:'Fund two independent A Taproot bonds at 60k and 40k, rerun B with matched scenarios, isolate fees and actual signer availability, then repeat on signet.',
  };
}
async function main(){
  const argv=process.argv.slice(2);let a,b,out;
  for(let i=0;i<argv.length;i++) {
    const k=argv[i],v=argv[++i];insist(v,'missing value after '+k);
    if(k==='--a')a=v;else if(k==='--b')b=v;else if(k==='--out')out=v;
    else throw Error('unknown option '+k);
  }
  insist(a&&b,'usage: compare-funded.mjs --a original-A.json --b B-surrogate.json [--out PATH]');
  const reports=await Promise.all([a,b].map(x=>readFile(resolve(x),'utf8').then(JSON.parse)));
  const result=JSON.stringify(compare(...reports),null,2)+'\n';
  if(out){const f=await open(resolve(out),'wx',0o600);
    try{await f.writeFile(result);await f.sync();}finally{await f.close();}
  } else process.stdout.write(result);
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main().catch(e=>{console.error(e.message);process.exitCode=1;});
}
