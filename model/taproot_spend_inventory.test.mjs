import test from 'node:test';
import assert from 'node:assert/strict';
import {auditTaprootSources,loadSource} from './taproot_spend_inventory.mjs';

test('AI01: source inventory distinguishes demo MuSig2 from agent NUMS',()=>{
  const v=auditTaprootSources();
  assert.equal(v.schema,'bsb/taproot-source-inventory/v1');
  assert.match(v.configurations.demo.internalKey,/MuSig2/);
  assert.match(v.configurations.agent.internalKey,/NUMS/);
  assert.equal(v.configurations.agent.keypath,'assumed unavailable');
  assert.equal(v.configurations.demo.liveLeaves.join(','),'challenge,refund');
});
test('AI02: final live bond has only refund leaf and presigned chain has P2A fees',()=>{
  const v=auditTaprootSources();
  assert.deepEqual(v.configurations.agent.finalLiveLeaves,['refund']);
  assert.match(v.parentFee,/CPFP child/);
  assert.equal(v.bondAmountSats,100000000);
});
test('AI03: payment channel is a separate NUMS script with two exits',()=>{
  const v=auditTaprootSources();
  assert.deepEqual(v.configurations.channel.liveLeaves,
    ['joint cooperative script','client CLTV refund']);
});
test('AI04: failing closed when the final refund-only leaf is altered',()=>{
  const path='regtest/src/common.rs';
  const bad=loadSource(path).replace('bonds.push(state(secp, internal, &[&refund]));',
    'bonds.push(state(secp, internal, &[&forfeit]));');
  assert.notEqual(bad,loadSource(path));
  assert.throws(()=>auditTaprootSources({[path]:bad}),/final live refund-only state/);
});
test('AI05: failing closed when agent switches away from its NUMS internal key',()=>{
  const path='regtest/src/bin/bond.rs',raw=loadSource(path);
  const bad=raw.replace('build_chain(secp, nums(), &d.p','build_chain(secp, me.x, &d.p');
  assert.notEqual(bad,raw);
  assert.throws(()=>auditTaprootSources({[path]:bad}),/agent loaded bond uses NUMS/);
});
test('AI06: failing closed if the signature no longer hashes all prevouts',()=>{
  const path='regtest/src/common.rs',raw=loadSource(path);
  const bad=raw.replace('taproot_script_spend_signature_hash(0, &Prevouts::All(&[prev.clone()]), lh, TapSighashType::Default)',
    'taproot_script_spend_signature_hash(0, &Prevouts::One(0, &prev), lh, TapSighashType::Default)');
  assert.notEqual(bad,raw);
  assert.throws(()=>auditTaprootSources({[path]:bad}),/script-path Default sighash/);
});
test('AI07: failing closed if the channel payer split forgets its fee',()=>{
  const path='regtest/src/bin/bond.rs',raw=loadSource(path);
  const bad=raw.replace('ch.capacity - Amount::from_sat(paid) - CHAN_FEE',
    'ch.capacity - Amount::from_sat(paid)');
  assert.notEqual(bad,raw);
  assert.throws(()=>auditTaprootSources({[path]:bad}),/payment split conserves/);
});
test('AI08: an additional unknown Rust bond command requires review',()=>{
  const path='regtest/src/bin/bond.rs',raw=loadSource(path);
  const bad=raw.replace('Some("bond-status") =>','Some("bond-escape") => json!({}),\n        Some("bond-status") =>');
  assert.notEqual(bad,raw);
  assert.throws(()=>auditTaprootSources({[path]:bad}),/bond agent commands/);
});
test('AI09: code-level inventory never asserts consensus-exhaustiveness',()=>{
  const v=auditTaprootSources();
  assert.match(v.disclaimer,/NOT consensus coverage/);
  assert.equal(v.agentCommands.length,8);
});
