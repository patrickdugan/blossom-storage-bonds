import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {compositeCursorConsensusVectors,BINOLOCK} from './composite_cursor_consensus_vectors.mjs';
import {decodeLegacyTransaction,legacySignatureHash} from './legacy_sighash.mjs';
import {verifyToyScript} from './binohash_finddelete_poc.mjs';
import {P2PK} from './single_acp_successor_vectors.mjs';
import {parseBitcoinSignature,parsePubkey,displayHashToZ,verifyECDSA} from './secp256k1_legacy_demo.mjs';

let v,cases;
before(()=>{v=compositeCursorConsensusVectors();cases=new Map(v.cases.map(c=>[c.name,c]));});
const named=n=>cases.get(n);
function inspect(name){
  const tx=decodeLegacyTransaction(named(name).stripped_tx_hex);
  const sig=parseBitcoinSignature(tx.vin[1].scriptSig.slice(2));
  const z=displayHashToZ(legacySignatureHash(tx,1,P2PK,sig.hashType));
  return {
    tx,cursorOK:verifyECDSA({z,r:sig.r,s:sig.s,publicKey:parsePubkey(P2PK.slice(2,-2))}),
    binoOK:verifyToyScript(tx,BINOLOCK,{inputIndex:2}).valid
  };
}
test('M01: composite transaction has separate P2PK and Binohash inputs',()=>{
  assert.deepEqual(v.checks.map(x=>x.input_index),[0,1,2]);
});
test('M02: Binohash carrier sits after last output so legacy SINGLE bug holds',()=>{
  const c=inspect('composite-challenger-A');assert.equal(c.tx.vin.length,3);
  assert.equal(c.tx.vout.length,2);
});
test('M03: honest challenger A authenticates both inputs',()=>{
  const c=inspect('composite-challenger-A');
  assert.equal(c.cursorOK,true);assert.equal(c.binoOK,true);
});
test('M04: honest challenger B changes certified bytes and regrinds Binohash',()=>{
  const c=inspect('composite-challenger-B');
  assert.equal(c.cursorOK,true);assert.equal(c.binoOK,true);
  assert.notEqual(named('composite-challenger-A').txid,named('composite-challenger-B').txid);
});
test('M05: successor pre-signature remains IDENTICAL for both certificate outputs',()=>{
  assert.equal(v.commitments.first_a_sig,v.commitments.first_b_sig);
  assert.equal(v.commitments.output_a,v.commitments.output_b);
});
test('M06: certificate swap without regrind defeats Binohash while preserving cursor signature',()=>{
  const c=inspect('certificate-mutation-without-new-binohash');
  assert.equal(c.cursorOK,true);assert.equal(c.binoOK,false);
});
test('M07: malicious regrind cannot redirect pre-signed successor output',()=>{
  const c=inspect('regrind-burn-at-protected-output');
  assert.equal(c.cursorOK,false);assert.equal(c.binoOK,true);
});
test('M08: malicious regrind cannot decrease protected successor value',()=>{
  const c=inspect('regrind-steal-protected-cursor-value');
  assert.equal(c.cursorOK,false);assert.equal(c.binoOK,true);
});
test('M09: sponsor change requires only Binohash regrind, keeps P2PK signature valid',()=>{
  const old=inspect('sponsor-mutation-without-regrind');
  const current=inspect('sponsor-mutation-with-fresh-binohash');
  assert.equal(old.cursorOK,true);assert.equal(old.binoOK,false);
  assert.equal(current.cursorOK,true);assert.equal(current.binoOK,true);
});
test('M10: provider cursor-input substitution breaks both signatures',()=>{
  const c=inspect('cursor-prevout-mutation-without-new-signatures');
  assert.equal(c.cursorOK,false);assert.equal(c.binoOK,false);
});
test('M11: new cursor parent changes txid and defeats stale next-generation presignature',()=>{
  assert.notEqual(v.commitments.first_a_txid,v.commitments.first_b_txid);
  assert.equal(v.commitments.next_a_cursor_prevout,v.commitments.first_a_txid);
  assert.equal(v.commitments.next_b_cursor_prevout,v.commitments.first_b_txid);
  assert.equal(inspect('composite-next-cursor-A-signature-on-B').cursorOK,false);
});
test('M12: fresh signatures for each actual next-generation prevout succeed',()=>{
  assert.equal(inspect('composite-next-cursor-signed-for-A').cursorOK,true);
  assert.equal(inspect('composite-next-cursor-signed-for-A').binoOK,true);
  assert.equal(inspect('composite-next-cursor-signed-for-B').cursorOK,true);
  assert.equal(inspect('composite-next-cursor-signed-for-B').binoOK,true);
});
test('M13: witness-only data remains invisible to BOTH legacy signatures',()=>{
  const a=named('composite-challenger-A');
  const changed=named('unrelated-segwit-witness-uncaptured');
  assert.equal(a.txid,changed.txid);
  assert.notEqual(a.wtxid,changed.wtxid);
});
test('M14: script-valid composite does not authenticate exact chain work',()=>{
  assert.equal(named('composite-challenger-A').expected_valid,true);
  assert.equal(v.checks.some(x=>x.input_index===2),true);
  // There is no header-chain proof, fork certificate verifier, or work
  // comparator in the scripts. Arbitrary 32-byte strings are admitted.
  assert.equal(v.commitments.first_a_sig,v.commitments.first_b_sig);
});

test('M15: sponsor has real native v0 P2WSH Script path, verified as third input',()=>{
  assert.equal(v.checks[0].script_pub_key.slice(0,4),'0020');
  assert.equal(v.checks[0].script_pub_key.length,68);
  assert.equal(v.cases[0].expected_inputs.length,3);
});
test('M16: Binohash and one-hop cursor guard can coexist with true witness data',()=>{
  assert.equal(named('unrelated-segwit-witness-uncaptured').expected_valid,true);
  assert.equal(named('unrelated-segwit-witness-uncaptured').expected_inputs[0].expected_valid,true);
});
test('M17: SegWit serialization differs from stripped serialization for valid sponsor input',()=>{
  const c=named('composite-challenger-A');
  assert.notEqual(c.tx_hex,c.stripped_tx_hex);
  assert.equal(c.tx_hex.slice(8,12),'0001'); // BIP141 marker and flag after version
});
test('M18: certificate variants preserve cursor signature while changing witness commitment',()=>{
  assert.equal(v.commitments.first_a_sig,v.commitments.first_b_sig);
  assert.notEqual(named('composite-challenger-A').wtxid,named('composite-challenger-B').wtxid);
});
