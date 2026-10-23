#!/usr/bin/env node
// Bitcoin Core evidence comparison for two independent Taproot A bonds and
// one funded, real FROST 2-of-3 P2TR B carrier. The capital and original
// PDP witness hashes match. The Script policy, stakeholder rights and fee
// arrangements still differ: a security or efficiency winner is PROHIBITED.
import {readFile,open} from 'node:fs/promises';
import {resolve} from 'node:path';

const insist=(truth,why)=>{if(!truth)throw Error(why);};
const h64=s=>typeof s==='string'&&/^[0-9a-f]{64}$/i.test(s);
const eHashes=(e)=>e?.referenceEvidenceHashes;

export function compareFrostFunded(a,b) {
  insist(a?.kind==='matched-capital-A-real-Taproot-regtest-NOT-matched-proof-epochs' &&
    a.bitcoinScriptConfirmed===true && a.principalSats===100_000 &&
    a.aliceInitialSats===60_000 && a.bobInitialSats===40_000 &&
    a.independentTaprootBonds===2,
    'missing capital-matched authentic A Taproot evidence');
  insist(a.originalTerminalFeeShavedSatsPerBond===1_000,
    'A terminal funding policy changed');
  for(const [holder,value] of [['alice',60_000],['bob',40_000]]){
    const result=a.results?.[holder];
    insist(result && result.checks>=21 && result.failed===0 &&
      result.csvBlocks===6 &&
      result.impliedSingleTerminalReceiptSats===value-1_000 &&
      Array.isArray(result.sizes)&&result.sizes.length>=7,
      'A actual Bitcoin Core Script execution or CSV policy incomplete');
  }
  const pdp=a.sharedPdpEvidence;
  insist(pdp?.classification==='COMMON-MERKLE-WITNESS-BITCOIN-SCRIPT-NOT-PROVIDER-ERASURE' &&
    pdp.sourceWitnessesBoundToCoreSignedTransactions===true &&
    pdp.productionStorageNonavailabilityProven===false &&
    pdp.epochsAndFeePoliciesFullyMatchedToB===false &&
    pdp.realBitcoinCsvDelayBlocks===6,
    'A PDP->BIP341 witness evidence invalid');
  const alice=pdp.holderFixtures?.alice, bob=pdp.holderFixtures?.bob;
  insist(alice?.pdpVerdicts?.join(',')==='pass,fault,pass' &&
    bob?.pdpVerdicts?.join(',')==='pass,pass,pass' &&
    eHashes(alice)?.length===3 && eHashes(bob)?.length===3 &&
    eHashes(alice).every(h64) && eHashes(bob).every(h64) &&
    alice.commitmentHashes?.length===3 &&
    bob.commitmentHashes?.length===3 &&
    h64(alice.referenceEvidenceHashes[1]),
    'A source Merkle witness sample missing or corrupted');

  insist(b?.schema==='bsb-ab-p2tr-real-frost-regtest-v1' &&
    b.chain==='regtest' && b.cryptography==='frost-secp256k1-tr 3.0.0' &&
    b.signatures==='real-BIP341-sighash-P2TR-TapTweak' &&
    b.capitalSats===100_000 && b.aliceSats===60_000 &&
    b.bobSats===40_000 && b.sponsorTotalFeesSats===6_000 &&
    b.independentFeeSponsorSats===50_000,
    'B is not the capital-matched, separately sponsored real FROST Bitcoin receipt');
  insist(b.sharedPdpEvidenceHash===alice.referenceEvidenceHashes[1] &&
    b.maliciousTwoShareRedirect?.sourceBlossomStorageEvidenceHash===
      alice.referenceEvidenceHashes[1],
    'actual A signed sentinel witness and B FROST settlement do not refer to same PDP proof');
  insist(h64(b.p2trGroupKey) && h64(b.p2trTweakedOutputKey) &&
    b.missingSecondShareRejected===true &&
    b.separateSignerSharesInDifferentProcesses===false &&
    b.trustedDealerSimulated===true &&
    b.maliciousTwoShareRedirect?.validBitcoinMempoolSpend===true &&
    b.maliciousTwoShareRedirect?.broadcast===false &&
    b.maliciousTwoShareRedirect?.redirectedPrincipalSats===100_000 &&
    b.maliciousTwoShareRedirect?.sameTxidWitnessMutationRejected===true &&
    b.maliciousTwoShareRedirect?.conflictingAlternativeRejectedAfterHonestConfirmation===true &&
    b.honestTwoSharePayout?.confirmed===true &&
    b.honestTwoSharePayout?.sixConfirmations===true &&
    b.honestTwoSharePayout?.postSignatureOutputTamperRejected===true,
    'real BIP341 FROST quorum or adversarial safeguards incomplete');
  const limits=b.limits;
  insist(limits?.bitcoinCoreBip341AndP2TRKeyPathAccepted===true &&
    limits?.realSapioMidCovenant===false &&
    limits?.realLayerTreeRefresh===false &&
    limits?.realFrostAcrossNetworkPeers===false &&
    limits?.blossomPdpVerifiedByBitcoin===false &&
    limits?.filecoinFaultVerifiedByBitcoin===false &&
    limits?.independentHolderExitWithoutFederation===false &&
    limits?.publicTestnetSpend===false,
    'incorrect consensus, custody or Filecoin security classification');
  for(const name of ['refresh','payout']) {
    const tx=b[name];
    insist(h64(tx?.txid) && h64(tx?.wtxid) &&
      Number.isSafeInteger(tx.vsize)&&tx.vsize>0 &&
      Number.isInteger(tx.confirmations)&&tx.confirmations>=1 &&
      Array.isArray(tx.outputs)&&tx.outputs.length>=3,
      'missing confirmed physical FROST transaction witness or size');
  }
  insist(b.payout.confirmations>=6 &&
    b.payout.outputs.some(o=>o.sats===60_000) &&
    b.payout.outputs.some(o=>o.sats===40_000) &&
    b.refresh.outputs.some(o=>o.sats===100_000),
    'B real Bitcoin outputs fail preserved bonded capital accounting');
  return {
    schema:'bsb-ab-actual-frost-core-comparison-v1',network:'regtest',
    matchedCapital:true,matchedSourcePdpEvidence:true,realFrostBip341:true,
    matchedFullScenarios:false,feesComparable:false,
    securityRankPermitted:false,
    holderIndependentExitOnBProven:false,
    onchainMidCovenantProven:false,
    distinction:'BIP341 FROST can authorize malicious outputs; Bitcoin does not check storage verdict or LayerTree state',
    A:{
      principalSats:100_000,independentBonds:2,
      actualBitcoinCoreScriptTests:a.results.alice.checks+a.results.bob.checks,
      actualCsvDelayBlocks:6,terminalFeeShavedSatsPerBond:1_000,
      referencePdpFaultHash:alice.referenceEvidenceHashes[1],
      cryptographicallyProvenDataUnavailability:false,
    },
    B:{
      actualFrostThresholdSchnorr:true,
      recipientOutputsSats:{alice:60_000,bob:40_000},
      physicalRefreshVbytes:b.refresh.vsize,
      physicalPayoutVbytes:b.payout.vsize,
      sponsorFeeSats:6_000,
      maliciousThresholdPayoutBitcoinValid:true,
      maliciousThresholdPayoutBroadcast:false,
      independentPeers:false,productionConsensusPolicy:false,
    },
    nextGates:[
      'Run both under identical storage-proof epoch schedule and fee funding',
      'Execute actual Sapio MID transition and verify all Taproot spend paths',
      'Distribute authenticated FROST shares and nonce commitments across processes',
      'Prove unilateral participant exits without a responsive signer federation',
      'Only then stage equal-value disposable Signet trials',
    ]
  };
}
async function main() {
  let a=null,b=null,out=null,args=process.argv.slice(2);
  for(let i=0;i<args.length;i++){
    const flag=args[i],value=args[++i];
    insist(value,'missing option value');
    if(flag==='--a')a=value;
    else if(flag==='--b')b=value;
    else if(flag==='--out')out=value;
    else throw Error('unknown comparison option '+flag);
  }
  insist(a&&b,'usage: compare-frost-funded.mjs --a A-MATCHED.json --b B-FROST.json [--out NEW-PATH]');
  const [aa,bb]=await Promise.all([a,b].map(file=>
    readFile(resolve(file),'utf8').then(JSON.parse)));
  const raw=JSON.stringify(compareFrostFunded(aa,bb),null,2)+'\n';
  if(out){
    const file=await open(resolve(out),'wx',0o600);
    try{await file.writeFile(raw);await file.sync();}
    finally{await file.close();}
  }else process.stdout.write(raw);
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main().catch(e=>{console.error(e.message);process.exitCode=1;});
}
