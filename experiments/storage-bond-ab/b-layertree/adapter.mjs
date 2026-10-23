// B: Shared L3 carrier prototype with labeled (NONCRYPTOGRAPHIC) quorum.
// Wraps the existing LayerTree overlay economic model. A threshold signer
// is assumed to authorize refresh/proof/settlement; Bitcoin does not execute
// this program's Filecoin/Blossom semantics without a real covenant/oracle.
import { genesis, refresh, observe, payout } from '../../../model/layertree_bond_overlay.mjs';
import { carrier } from '../shared/scenario.mjs';

export function makeLayerTreeBackend(scenario) {
  let state=genesis({outpoint:scenario.initialCarrier,
    signers:scenario.federation,threshold:scenario.threshold,terms:scenario.terms});
  const metrics={logicalRefreshRequests:0,physicalCarrierRefreshesModeled:0,
    quorumAuthorizationsModeled:0,claimedProofEvents:0,
    acceptedFalseFaults:0,settlementTransitions:0,
    externalFeeBudgetSatsConfigured:0,bitcoinFeeVbytesMeasured:null,
    mockThresholdSignatureCount:0};
  const payments=[];
  let index=0;
  function nextOutpoint(kind) {
    return carrier(kind+'|'+scenario.name+'|'+index+'|'+state.carrier.outpoint+
      '|'+state.root);
  }
  function voters(event) {return event.voters ?? scenario.voters;}
  function withVote(event) {return voters(event);}
  function step(event,evidence) {
    index++;
    const voted=withVote(event);
    if(event.kind==='refresh') {
      metrics.logicalRefreshRequests++;
      const to=nextOutpoint('refresh');
      const result=refresh(state,{
        kind:'refresh',before:state.root,from:state.carrier.outpoint,
        to,generation:state.carrier.generation+1,value:state.carrier.value,
        externalFee:event.externalFee,
      },voted);
      state=result;
      metrics.physicalCarrierRefreshesModeled++;
      metrics.quorumAuthorizationsModeled++;
      metrics.mockThresholdSignatureCount+=voted.length;
      metrics.externalFeeBudgetSatsConfigured+=event.externalFee;
      return {refresh:{carrier:state.carrier.outpoint,generation:state.carrier.generation},
        principal:state.carrier.value,voters:voted.slice(),
        bitcoinTransactionAuthenticated:false};
    }
    const terms=state.bonds.find(b=>b.terms.id===event.id)?.terms;
    if(!terms)throw new Error('unknown bond ID');
    if(event.kind==='proof') {
      if(!evidence || evidence.id!==event.id || evidence.epoch!==event.epoch) {
        throw new Error('missing common storage evidence');
      }
      const claimed=evidence.assertedVerdict;
      const fraudulent=claimed==='fault' && evidence.verified;
      const next=observe(state,{
        kind:'observe',before:state.root,id:event.id,deal:terms.deal,
        sector:terms.sector,proofKind:terms.proofKind,epoch:event.epoch,
        verdict:claimed,checkpoint:evidence.checkpoint,
        evidenceHash:evidence.evidenceHash,
        finalizedEpoch:evidence.finalizedEpoch,bitcoinHeight:event.height,
      },voted);
      state=next;metrics.claimedProofEvents++;
      metrics.quorumAuthorizationsModeled++;
      metrics.mockThresholdSignatureCount+=voted.length;
      if(fraudulent)metrics.acceptedFalseFaults++;
      return {assertedByFederation:claimed,
        referencePdpVerdict:evidence.verified?'pass':'fault',
        falseFaultAccepted:fraudulent,
        authenticatedStorageEvidence:false,
        checkpointAuthenticated:false};
    }
    if(event.kind!=='settle')throw new Error('unknown LayerTree action');
    const remaining=state.carrier.value-terms.stake;
    const next= payout(state,{
      kind:'settle',before:state.root,id:event.id,
      from:state.carrier.outpoint, height:event.height,
      winner:event.winner,value:terms.stake,
      script:event.winner==='client'?terms.clientScript:terms.providerScript,
      remaining,to:remaining===0?null:nextOutpoint('settle'),
    },voted);
    state=next;
    metrics.settlementTransitions++;
    metrics.quorumAuthorizationsModeled++;
    metrics.mockThresholdSignatureCount+=voted.length;
    const receipt={holder:event.id,winner:event.winner,amount:terms.stake,
      scriptApprovedByEconomicModel:true,scriptEnforcedByBitcoin:false,
      settledAt:event.height};
    payments.push(receipt);
    return {payout:receipt,remainingCollateral:state.carrier.value,
      thresholdOracleNeeded:true,bitcoinTransactionAuthenticated:false};
  }
  function report() {
    return {backend:'B-layertree',execution:'federation-labeled-state-transition-model',
      chain:'unfunded-simulation',settlements:payments.slice(),
      collateralAtStart:scenario.terms.reduce((sum,t)=>sum+t.stake,0),
      unresolvedSats:state.carrier.value,metrics:{...metrics},
      remaining:state.bonds.map(b=>({
        id:b.terms.id,stake:b.terms.stake,lastEpoch:b.lastEpoch,
        challengedAt:b.challenge?b.challenge.deadline-b.terms.challengeBlocks:null,
        payout:b.closed,
      })),
      carrier:{...state.carrier,stateRoot:state.root},
      trust:{scriptPredicateModeled:false,bitcoinNodeConfirmed:false,
        thresholdVotesCryptographicallyVerified:false,
        clientCanExitWithoutFederation:false,
        requiresPreSignedSuccessors:false,exactRecipientBoundByBitcoin:false,
        storageMerkleProofLocallyVerified:false,
        filecoinCheckpointVerified:false,
        maliciousThresholdCanRedirect:true},
    };
  }
  return {step,report};
}
