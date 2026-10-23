import test from 'node:test';
import assert from 'node:assert/strict';
import {frozenClaim,forkCertificate,validateExistentialRefutation,RefutationContest} from './stateless_refutation.mjs';
const OUTPOINT='bb'.repeat(32)+':0';
const C=frozenClaim({claimId:'claim-1',tipHash:'11'.repeat(32),work:120n,cutoff:20,disputeDeadline:30,collateralOutpoint:OUTPOINT});
const cert=(id,work,at=20)=>forkCertificate({id,tipHash:'22'.repeat(32),work:BigInt(work),inclusionHeight:at,referenceClaim:C.commitment});
const strong=cert('strong-151',151,20),weak=cert('weak-100',100,10),equal=cert('tie-120',120,19);
const proof=(certificate,minedHeight=21)=>({certificate,minedHeight,verifiedExactWork:true,verifiedAnchor:true,transactionBound:true,fixesPayouts:true});
test('R01: permissionless valid stronger certificate slashes collateral',()=>{
  const a=new RefutationContest(C);assert.equal(a.submit(proof(strong)).accepted,true);
});
test('R02: weak first challenge is rejected, stronger challenger remains open',()=>{
  const a=new RefutationContest(C);assert.equal(a.submit(proof(weak)).accepted,false);
  assert.equal(a.submit(proof(strong)).accepted,true);
});
test('R03: an equal-work conflicting fork does not slash by strict work rule',()=>{
  const a=new RefutationContest(C);assert.equal(a.submit(proof(equal)).accepted,false);
  assert.equal(a.submit(proof(strong)).accepted,true);
});
test('R04: unverifiable high-work fake cannot seize collateral',()=>{
  const a=new RefutationContest(C);const p={...proof(strong),verifiedExactWork:false};
  assert.equal(a.submit(p).accepted,false);
});
test('R05: unauthenticated certificate cannot be substituted',()=>{
  const a=new RefutationContest(C);assert.equal(a.submit({...proof(strong),transactionBound:false}).accepted,false);
});
test('R06: unconstrained payout recipients invalidate challenger branch',()=>{
  const a=new RefutationContest(C);assert.equal(a.submit({...proof(strong),fixesPayouts:false}).accepted,false);
});
test('R07: certificate anchored after cutoff is ineligible',()=>{
  const a=new RefutationContest(C);assert.equal(a.submit(proof(cert('late-200',200,21))).accepted,false);
});
test('R08: previously anchored certificate can refute during grace window',()=>{
  const a=new RefutationContest(C);assert.equal(a.submit(proof(strong,30)).accepted,true);
});
test('R09: proof mined after dispute deadline is too late',()=>{
  const a=new RefutationContest(C);assert.equal(a.submit(proof(strong,31)).accepted,false);
});
test('R10: provider refund locked throughout dispute deadline',()=>{
  const a=new RefutationContest(C);for(const h of [1,20,30])assert.equal(a.providerRefund(h).accepted,false);
});
test('R11: provider may refund only after unchallenged deadline',()=>{
  const a=new RefutationContest(C);a.submit(proof(weak));assert.equal(a.providerRefund(31).accepted,true);
});
test('R12: successful challenger consumes collateral and defeats refund',()=>{
  const a=new RefutationContest(C);a.submit(proof(strong));assert.equal(a.providerRefund(31).accepted,false);
});
test('R13: only one successful challenger can consume collateral',()=>{
  const a=new RefutationContest(C);a.submit(proof(strong));
  assert.equal(a.submit(proof(cert('stronger-200',200))).accepted,false);
  assert.equal(a.winner,'strong-151');
});
test('R14: a weaker challenger cannot prevent a later stronger one',()=>{
  const a=new RefutationContest(C);for(let i=0;i<10;i++)a.submit(proof(cert('weak-'+i,119)));
  assert.equal(a.submit(proof(strong,30)).accepted,true);
});
test('R15: validator uses 256-bit BigInts beyond float precision',()=>{
  const huge=(1n<<200n)+7n;
  const c=frozenClaim({claimId:'big',tipHash:'11'.repeat(32),work:huge,
    cutoff:20,disputeDeadline:30,collateralOutpoint:OUTPOINT});
  const x=forkCertificate({id:'big-more',tipHash:'22'.repeat(32),work:huge+1n,inclusionHeight:20,referenceClaim:c.commitment});
  assert.equal(validateExistentialRefutation({claim:c,...proof(x)}).allowed,true);
});
test('R16: forgery referring to another claim is rejected',()=>{
  const a=new RefutationContest(C);
  const certOther=forkCertificate({id:'strong',tipHash:'22'.repeat(32),work:200n,inclusionHeight:20,referenceClaim:'aa'.repeat(32)});
  assert.equal(a.submit(proof(certOther)).accepted,false);
});
test('R17: verified certificate with no transaction binding cannot slash',()=>{
  const a=new RefutationContest(C);const p=proof(strong);
  assert.equal(a.submit({...p,transactionBound:false}).reason,'certificate not bound to Bitcoin spend');
});
test('R18: no mutable cursor needed in this ideal model',()=>{
  const a=new RefutationContest(C);assert.equal(Object.hasOwn(a,'cursor'),false);
  assert.equal(a.submit(proof(strong)).accepted,true);
});
test('R19: claimed publication height without SPV anchor proof is insufficient',()=>{
  const a=new RefutationContest(C);
  assert.equal(a.submit({...proof(strong),verifiedAnchor:false}).accepted,false);
});
test('R20: a refutation cannot be mined before certificate confirmation',()=>{
  const a=new RefutationContest(C);
  assert.equal(a.submit(proof(strong,19)).reason,'certificate not yet confirmed');
});
test('R21: frozen claims are immutable and hash-bound',()=>{
  assert.equal(Object.isFrozen(C),true);
  assert.equal(Object.isFrozen(strong),true);
  const altered=frozenClaim({claimId:'claim-1',tipHash:'11'.repeat(32),work:121n,cutoff:20,disputeDeadline:30,collateralOutpoint:OUTPOINT});
  assert.notEqual(C.commitment,altered.commitment);
  assert.equal(validateExistentialRefutation({claim:altered,...proof(strong)}).allowed,false);
});
test('R22: a certificate confirmed exactly at cutoff may refute',()=>{
  const a=new RefutationContest(C);
  assert.equal(a.submit(proof(strong,20)).accepted,true);
});
