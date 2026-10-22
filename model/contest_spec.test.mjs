import test from 'node:test';
import assert from 'node:assert/strict';
import {ContestSpecification,certificateDigest} from './contest_spec.mjs';
const cert=(id,work,height,hex)=>({id,work:BigInt(work),height,headerRoot:hex.repeat(64)});
const weak=cert('weak',100,10,'a');
const strong=cert('strong',151,20,'b');
const tie=cert('tie',151,19,'c');
const create=()=>new ContestSpecification({admissionEnd:20,responseBlocks:5});
const submit=(c,candidate,verifiedExactWork=true)=>c.submit(candidate,{confirmedHeight:candidate.height,verifiedExactWork});

test('S01: stronger certificate arriving at cutoff supersedes earlier weak challenge',()=>{
  const c=create(); submit(c,weak); submit(c,strong);
  assert.deepEqual(c.freeze(21).required,[certificateDigest(strong)]);
  assert.equal(c.payout(21),'locked');
});
test('S02: late stronger challenge is excluded from cutoff',()=>{
  const c=create();submit(c,weak);c.freeze(21);
  assert.throws(()=>submit(c,strong),/closed/);
});
test('S03: invalid high-work certificate is rejected by external exact-work oracle',()=>{
  const c=create();submit(c,weak);
  assert.throws(()=>submit(c,cert('fake',999,18,'d'),false),/invalid/);
  assert.equal(c.strongest()[0].id,'weak');
});
test('S04: two different equally strong forks require separate responses',()=>{
  const c=create();submit(c,weak);submit(c,strong);submit(c,tie);c.freeze(21);
  assert.equal(c.strongest().length,2);
  c.rebut({id:strong.id,digest:certificateDigest(strong),proofMatchesCertificate:true,height:22});
  assert.equal(c.payout(22),'locked');
  c.rebut({id:tie.id,digest:certificateDigest(tie),proofMatchesCertificate:true,height:23});
  assert.equal(c.payout(23),'provider');
});
test('S05: provider cannot answer the earlier weaker certificate in place of stronger',()=>{
  const c=create();submit(c,weak);submit(c,strong);c.freeze(21);
  assert.throws(()=>c.rebut({id:weak.id,digest:certificateDigest(weak),proofMatchesCertificate:true,height:22}),/not bound/);
});
test('S06: provider cannot substitute digest for the admitted strong certificate',()=>{
  const c=create();submit(c,strong);c.freeze(21);
  assert.throws(()=>c.rebut({id:strong.id,digest:certificateDigest(weak),proofMatchesCertificate:true,height:22}),/not bound/);
});
test('S07: timely verified response to the actual strongest certificate releases provider',()=>{
  const c=create();submit(c,strong);c.freeze(21);
  c.rebut({id:strong.id,digest:certificateDigest(strong),proofMatchesCertificate:true,height:23});
  assert.equal(c.payout(23),'provider');
});
test('S08: uncontested provider refund after admission cutoff',()=>{
  const c=create();assert.equal(c.payout(19),'locked');c.freeze(21);
  assert.equal(c.payout(21),'provider');
});
test('S09: unanswered challenge eventually forfeits bond after response window',()=>{
  const c=create();submit(c,strong);c.freeze(21);
  assert.equal(c.payout(26),'locked');
  assert.equal(c.payout(27),'forfeit');
});
test('S10: no refund while admission open even if provider claims no challenges',()=>{
  const c=create();assert.equal(c.payout(20),'locked');
});
test('S11: freeze at last admission height fails',()=>{
  const c=create();assert.throws(()=>c.freeze(20),/cutoff/);
});
test('S12: journal root is deterministic across challenge arrival order',()=>{
  const a=create(),b=create();[weak,strong,tie].forEach(x=>submit(a,x));
  [tie,weak,strong].forEach(x=>submit(b,x));
  assert.equal(a.freeze(21).journalRoot,b.freeze(21).journalRoot);
});
test('S13: same certificate ID with conflicting work is rejected',()=>{
  const c=create();submit(c,strong);
  assert.throws(()=>submit(c,cert('strong',152,20,'b')),/equivocation/);
});
test('S14: weaker certificate admitted later does not erase higher work',()=>{
  const c=create();submit(c,strong);submit(c,weak);
  assert.equal(c.strongest()[0].id,'strong');
});
test('S15: fabricated successful rebuttal proof cannot unlock provider payout',()=>{
  const c=create();submit(c,strong);c.freeze(21);
  assert.throws(()=>c.rebut({id:strong.id,digest:certificateDigest(strong),proofMatchesCertificate:false,height:21}),/invalid/);
  assert.equal(c.payout(25),'locked');
});
test('S16: stale or provider-selected journal root cannot authorize payout',()=>{
  const c=create();submit(c,strong);c.freeze(21);
  c.rebut({id:strong.id,digest:certificateDigest(strong),proofMatchesCertificate:true,height:22});
  assert.equal(c.payout(22,'a'.repeat(64)),'locked');
});
test('S17: work uses BigInt so integers beyond JS safe precision preserve ordering',()=>{
  const c=create(),huge=2n**120n;
  const first=cert('large',huge,9,'a');const second=cert('larger',huge+1n,20,'b');
  submit(c,first);submit(c,second);assert.equal(c.strongest()[0].id,'larger');
});
test('S18: proof outside allowed answer window is rejected even if correct',()=>{
  const c=create();submit(c,strong);c.freeze(21);
  assert.throws(()=>c.rebut({id:strong.id,digest:certificateDigest(strong),proofMatchesCertificate:true,height:27}),/outside window/);
});
