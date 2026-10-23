/**
 * Alternate protocol SPECIFICATION: one existential counterexample to a
 * frozen provider claim. It does not use a mutable journal cursor.
 *
 * Exact chain work, Bitcoin inclusion anchoring, transaction binding, and
 * payout controls are EXTERNAL ORACLES. This is not a Bitcoin Script verifier.
 */
import {createHash} from 'node:crypto';
const MAX=(1n<<256n)-1n;
const hash=s=>createHash('sha256').update(s).digest('hex');
const in256=x=>typeof x==='bigint'&&x>=0n&&x<=MAX;
const validRoot=x=>typeof x==='string'&&/^[0-9a-f]{64}$/i.test(x);
export function frozenClaim({claimId,tipHash,work,cutoff,disputeDeadline,collateralOutpoint}){
  if(typeof claimId!=='string'||!claimId||!validRoot(tipHash)||!in256(work)||
     !Number.isSafeInteger(cutoff)||cutoff<1||!Number.isSafeInteger(disputeDeadline)||disputeDeadline<=cutoff||
     !/^[0-9a-f]{64}:[0-9]+$/.test(collateralOutpoint)) throw new TypeError('invalid claim fields');
  return Object.freeze({claimId,tipHash:tipHash.toLowerCase(),work,cutoff,disputeDeadline,collateralOutpoint,
    commitment:hash('BSB/CLAIM/V1\0'+JSON.stringify([claimId,tipHash.toLowerCase(),work.toString(),cutoff,disputeDeadline,collateralOutpoint]))});
}
export function forkCertificate({id,tipHash,work,inclusionHeight,referenceClaim}){
  if(typeof id!=='string'||!id||!validRoot(tipHash)||!in256(work)||
     !Number.isSafeInteger(inclusionHeight)||inclusionHeight<1||!validRoot(referenceClaim))
    throw new TypeError('invalid certificate fields');
  return Object.freeze({id,tipHash:tipHash.toLowerCase(),work,inclusionHeight,referenceClaim,
    digest:hash('BSB/COUNTEREXAMPLE/V1\0'+JSON.stringify([id,tipHash.toLowerCase(),work.toString(),inclusionHeight,referenceClaim]))});
}
export function validateExistentialRefutation({claim,certificate,minedHeight,
    verifiedExactWork=false,verifiedAnchor=false,transactionBound=false,fixesPayouts=false}){
  // A desired future BitVM verification predicate, not current Script consensus.
  if(!Number.isSafeInteger(minedHeight)||minedHeight<1)throw new TypeError('invalid confirmation height');
  if(minedHeight>claim.disputeDeadline)return {allowed:false,reason:'dispute deadline passed'};
  if(certificate.referenceClaim!==claim.commitment)return {allowed:false,reason:'wrong provider claim'};
  if(certificate.inclusionHeight>claim.cutoff)return {allowed:false,reason:'certificate after cutoff'};
  if(minedHeight<certificate.inclusionHeight)return {allowed:false,reason:'certificate not yet confirmed'};
  if(!verifiedAnchor)return {allowed:false,reason:'no verified Bitcoin inclusion commitment'};
  if(!verifiedExactWork)return {allowed:false,reason:'missing genuine header linkage and exact chain-work proof'};
  if(!transactionBound)return {allowed:false,reason:'certificate not bound to Bitcoin spend'};
  if(!fixesPayouts)return {allowed:false,reason:'output amounts or recipients unconstrained'};
  if(certificate.work<=claim.work)return {allowed:false,reason:'counterexample not strictly stronger'};
  return {allowed:true,reason:'stronger existential counterexample'};
}
export class RefutationContest {
  constructor(claim) {this.claim=claim;this.spent=false;this.winner=null;this.history=[];}
  submit({certificate,minedHeight,verifiedExactWork=false,verifiedAnchor=false,transactionBound=false,fixesPayouts=false}){
    if(this.spent)return {accepted:false,reason:'collateral already spent'};
    const result=validateExistentialRefutation({claim:this.claim,certificate,minedHeight,
      verifiedExactWork,verifiedAnchor,transactionBound,fixesPayouts});
    this.history.push(Object.freeze({cert:certificate.id,minedHeight,...result}));
    if(result.allowed){this.spent=true;this.winner=certificate.id;}
    return {accepted:result.allowed,reason:result.reason};
  }
  providerRefund(height){
    if(!Number.isSafeInteger(height)||height<1)throw new TypeError('invalid height');
    if(this.spent)return {accepted:false,reason:'collateral already spent'};
    if(height<=this.claim.disputeDeadline)return {accepted:false,reason:'provider refund timelocked'};
    this.spent=true;this.winner='provider';return {accepted:true,reason:'uncontested claim'};
  }
}
