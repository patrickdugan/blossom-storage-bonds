// A: Existing single-client Taproot sentinel prototype.
// Uses the repository's SHA256 sentinel commitments, BIP340 test signatures,
// and limited tapscript interpreter. Witnesses here use STAND-IN sighashes;
// funded Bitcoin transactions live in regtest/ and are an independent stage.
import { keyFromSeed } from '../../../model/schnorr.ts';
import {
  challengeLeaf, respondLeaf, forfeitLeaf, refundLeaf,
  runTapscript, sign, digest, isStandardTapscriptStack,
} from '../../../model/storage_bonds.ts';

const insist = (value,why) => {if (!value) throw new Error(why);};
const ctx = (label,height,age=0) => ({ digest:digest(label), lockTime:height, age });
const verified = (script,witness,label,height,age=0) => {
  const answer = runTapscript(script,witness,ctx(label,height,age));
  insist(answer.ok,'reference tapscript rejected: '+(answer.why||'unknown'));
};
export function makeSentinelBackend(scenario) {
  const positions = new Map(scenario.terms.map(t=>[t.id, {
    terms:t, status:'armed', lastEpoch:t.startEpoch-1, challengeAt:null,
    sentinel:null, response:null, payment:null,
    provider:keyFromSeed('ab-script-provider-'+t.id),
    client:keyFromSeed('ab-script-client-'+t.id),
  }]));
  const metrics={
    logicalRefreshRequests:0, physicalCarrierRefreshes:0,
    onchainStepsModeled:0, scriptValidations:0, challengeCount:0,
    honestResponses:0, providerRefunds:0, clientForfeits:0,
    feeEstimateSource:'Blossom docs/design.md regtest measured example sizes; per-event estimates',
    fixedFundingVbytes:154*positions.size, modeledExtraVbytes:0,
    feeRateSatVbIllustrative:5,
    externalFeeSponsorProven:false,
  };
  const checks=[];
  function step(event,evidence) {
    if(event.kind==='refresh') {
      metrics.logicalRefreshRequests++;
      return {meaning:'individual sentinel bonds retain existing UTXOs',bitcoinSpend:false};
    }
    const p=positions.get(event.id);
    insist(p,'unknown client bond '+event.id);
    if(event.kind==='proof') {
      insist(evidence && evidence.id===event.id && evidence.epoch===event.epoch,
        'missing matching independent PDP evidence');
      insist(event.epoch===p.lastEpoch+1 && event.epoch<=p.terms.endEpoch,
        'stale or skipped proof epoch');
      insist(p.status==='armed','challenged bond cannot take a new proof');
      // Model A consumes the *actual* SHA256/Merkle verifier verdict,
      // never the federation's purported "fault" string.
      if(evidence.verified) {
        p.lastEpoch=event.epoch;
        return {pdp:'valid',storageBytesChecked:true,
          claimedByFederation:evidence.assertedVerdict,acceptedFault:false};
      }
      const label='ab-challenge-'+p.terms.id+'-'+event.epoch;
      const script=challengeLeaf(p.client,p.provider,evidence.witness.sentinel.s);
      verified(script,[evidence.witness.sentinel.r,
        sign(p.provider,label),sign(p.client,label)],label,event.height);
      metrics.scriptValidations++;
      metrics.challengeCount++;
      metrics.onchainStepsModeled++;
      metrics.modeledExtraVbytes+=187+153;
      const replyLabel='ab-respond-'+p.terms.id+'-'+event.epoch;
      const response=evidence.witness.response;
      if(response) {
        insist(response.length===80 && isStandardTapscriptStack([response]),
          'nonstandard sentinel witness');
        verified(respondLeaf(p.provider,p.client,evidence.witness.sentinel.h),
          [response,sign(p.client,replyLabel),sign(p.provider,replyLabel)],
          replyLabel,event.height+1);
        metrics.scriptValidations++;
        metrics.honestResponses++;
        metrics.onchainStepsModeled++;
        metrics.modeledExtraVbytes+=203+153;
        p.lastEpoch=event.epoch;
        return {pdp:'invalid',challenge:'answered',amountPreserved:p.terms.stake};
      }
      // Permanent negative test: a guessed incorrect preimage does not work.
      const forged=Buffer.concat([evidence.witness.sentinel.r, Buffer.alloc(64)]);
      const failure=runTapscript(
        respondLeaf(p.provider,p.client,evidence.witness.sentinel.h),
        [forged,sign(p.client,replyLabel),sign(p.provider,replyLabel)],
        ctx(replyLabel,event.height+1));
      insist(!failure.ok,'missing stored window unexpectedly passed sentinel commitment');
      metrics.scriptValidations++;
      p.lastEpoch=event.epoch;
      p.challengeAt=event.height;
      p.status='challenged';
      return {pdp:'invalid',challenge:'pending',scriptWrongAnswerRejected:true,
        deadline:event.height+p.terms.challengeBlocks};
    }
    insist(event.kind==='settle','unknown sentinel action');
    insist(!p.payment,'bond already settled');
    let winner;
    if(event.winner==='client') {
      insist(p.status==='challenged' && p.challengeAt!==null,
        'client forfeit needs an actual pending challenge');
      const age=event.height-p.challengeAt;
      const label='ab-forfeit-'+p.terms.id+'-'+p.lastEpoch;
      verified(forfeitLeaf(p.client,p.terms.challengeBlocks),
        [sign(p.client,label)],label,event.height,age);
      metrics.clientForfeits++;
      winner='client';
    } else if(event.winner==='provider') {
      insist(p.status==='armed' && p.lastEpoch>=p.terms.endEpoch,
        'provider refund requires successful service through full term');
      insist(event.height>p.terms.refundHeight,
        'provider refund lacks contextual finality margin');
      const label='ab-refund-'+p.terms.id;
      verified(refundLeaf(p.provider,p.terms.refundHeight),
        [sign(p.provider,label)],label,event.height);
      metrics.providerRefunds++;
      winner='provider';
    } else throw new Error('unknown settlement claimant');
    metrics.scriptValidations++;
    metrics.onchainStepsModeled++;
    metrics.modeledExtraVbytes+=138;
    // Actual unilateral signer can choose another destination; script only
    // authenticates disposition. This is NOT exact recipient enforcement.
    p.payment={winner,amount:p.terms.stake,
      defaultScript:winner==='client'?p.terms.clientScript:p.terms.providerScript,
      outputEnforcedByScript:false,at:event.height};
    p.status='closed';
    checks.push({holder:p.terms.id,...p.payment});
    return {payout:{holder:p.terms.id,winner,amount:p.payment.amount},
      scriptAuthorized:true,recipientScriptEnforced:false};
  }
  function report() {
    const positionsOut=[...positions].map(([id,p])=>({
      id,status:p.status,stake:p.terms.stake,epoch:p.lastEpoch,
      challengedAt:p.challengeAt,payout:p.payment,
    }));
    return {backend:'A-sentinel',execution:'bitcoin-script-reference-interpreter',
      chain:'unfunded-simulation',settlements:checks,
      collateralAtStart:[...positions.values()].reduce((s,p)=>s+p.terms.stake,0),
      unresolvedSats:positionsOut.filter(p=>p.status!=='closed').reduce((s,p)=>s+p.stake,0),
      metrics:{...metrics,estimatedVbytes:metrics.fixedFundingVbytes+metrics.modeledExtraVbytes,
        illustrativeFeesSats:(metrics.fixedFundingVbytes+metrics.modeledExtraVbytes)*
          metrics.feeRateSatVbIllustrative},
      remaining:positionsOut,
      trust:{scriptPredicateModeled:true,actualBip341SighashVerified:false,
        bitcoinNodeConfirmed:false,clientCanExitWithoutFederation:true,
        requiresPreSignedSuccessors:true,exactRecipientBoundByScript:false,
        storageMerkleProofLocallyVerified:true},
    };
  }
  return {step,report};
}
