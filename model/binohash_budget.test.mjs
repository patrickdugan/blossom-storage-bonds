import test from 'node:test';
import assert from 'node:assert/strict';
import {estimateBinohashBudget,mustSplitEnforcement} from './binohash_budget.mjs';
test('B01: paper canonical two-round t=8 formula uses 199 of 201 opcodes',()=>{
  const x=estimateBinohashBudget({});
  assert.equal(x.totalOps,199);
  assert.equal(x.remainingOps,2);
  assert.equal(x.withinOpcodeBudget,true);
});
test('B02: ordinary n=120 t=8 script-size estimate reproduces 8028 bytes',()=>{
  const x=estimateBinohashBudget({});
  assert.equal(x.roughScriptBytes,8028);
  assert.equal(x.fitsP2SH,false);
  assert.equal(x.withinScriptBudget,true);
});
test('B03: adding three standalone enforcing opcodes breaches illustrative budget',()=>{
  const x=estimateBinohashBudget({extraOps:3});
  assert.equal(x.totalOps,202);
  assert.equal(x.withinOpcodeBudget,false);
  assert.equal(mustSplitEnforcement(3),true);
});
test('B04: a separate 199-opcode carrier leaves only 2 spare opcode slots',()=>{
  assert.equal(mustSplitEnforcement(2),false);
  assert.equal(mustSplitEnforcement(3),true);
});
test('B05: Appendix D formula at r=2,t=10 totals 203, needs optimization',()=>{
  const p=estimateBinohashBudget({rounds:2,pool:90,selections:10,polyglot:true});
  assert.equal(p.totalOps,203);
  assert.equal(p.withinOpcodeBudget,false);
});
test('B06: Appendix D polyglot at t=9 formula stays within op budget',()=>{
  const p=estimateBinohashBudget({rounds:2,pool:90,selections:9,polyglot:true});
  assert.equal(p.totalOps,185);
  assert.equal(p.withinOpcodeBudget,true);
});
test('B07: n=120 t=8 two-round nonce entropy is about 79 bits',()=>{
  const p=estimateBinohashBudget({});
  assert.ok(p.nonceEntropyBits>78);
  assert.ok(p.nonceEntropyBits<81);
});
test('B08: reducing pool size shrinks combinatorial nonce entropy',()=>{
  assert.ok(estimateBinohashBudget({pool:90}).nonceEntropyBits < estimateBinohashBudget({pool:120}).nonceEntropyBits);
});
test('B09: invalid parameters fail early',()=>{
  assert.throws(()=>estimateBinohashBudget({selections:121}),RangeError);
  assert.throws(()=>estimateBinohashBudget({extraOps:-1}),RangeError);
});
