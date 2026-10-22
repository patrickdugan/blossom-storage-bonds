import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import {linkedCursorConsensusVectors} from './binohash_linked_cursor_vectors.mjs';
import {decodeLegacyTransaction} from './legacy_sighash.mjs';
import {transactionId,serializeTransaction} from './txid_admission.mjs';

let data,byName;
before(()=>{
  data=linkedCursorConsensusVectors();
  byName=new Map(data.cases.map(c=>[c.name,c]));
});
const named=n=>byName.get(n);
test('LC01: fixture creates two successive script-locked outputs',()=>{
  assert.equal(data.chain.successor_script_pub_key,data.script_pub_key);
  assert.equal(data.chain.honest_script_pub_key,data.script_pub_key);
});
test('LC02: second honest spend uses actual J0 txid as input outpoint',()=>{
  assert.equal(data.chain.honest_successor_prevout,data.chain.parent_txid);
});
test('LC03: third honest spend uses J1 txid as input outpoint',()=>{
  assert.equal(data.chain.later_successor_prevout,data.chain.first_successor_txid);
});
test('LC04: malicious spend competes for same previous J0 output',()=>{
  assert.equal(data.chain.malicious_successor_prevout,data.chain.honest_successor_prevout);
});
test('LC05: malicious output destroys the prescribed cursor script',()=>{
  assert.ok(data.chain.malicious_script_pub_key.startsWith('6a20'));
  assert.notEqual(data.chain.malicious_script_pub_key,data.script_pub_key);
});
test('LC06: separate Binohash grind yields distinct txids and two valid scripts',()=>{
  assert.notEqual(data.chain.malicious_alternative_txid,data.chain.first_successor_txid);
  assert.equal(named('malicious-challenger-burns-J1').expected_valid,true);
  assert.equal(named('honest-cursor-J1-rearms-script').expected_valid,true);
});
test('LC07: changing output after Binohash signature makes script invalid',()=>{
  assert.equal(named('unreground-output-replacement-is-rejected').expected_valid,false);
  assert.notEqual(named('unreground-output-replacement-is-rejected').txid,data.chain.first_successor_txid);
});
test('LC08: changing input outpoint after Binohash signature makes script invalid',()=>{
  assert.equal(named('unreground-parent-prevout-substitution-is-rejected').expected_valid,false);
});
test('LC09: two witness-only certificate variants have same txid',()=>{
  const a=named('witness-only-certificate-A-passes');
  const b=named('witness-only-certificate-B-passes');
  assert.equal(a.txid,b.txid);
});
test('LC10: two witness-only certificate variants have different wtxids',()=>{
  const a=named('witness-only-certificate-A-passes');
  const b=named('witness-only-certificate-B-passes');
  assert.notEqual(a.wtxid,b.wtxid);
});
test('LC11: witness-only certificates preserve the same signed transaction fields',()=>{
  assert.equal(named('witness-only-certificate-A-passes').txid,data.chain.first_successor_txid);
  assert.equal(named('witness-only-certificate-B-passes').txid,data.chain.first_successor_txid);
});
test('LC12: all Script test cases carry the same fixed locking script',()=>{
  assert.equal(data.cases.length,8);
  assert.ok(data.script_pub_key.length>1000);
  assert.ok(data.cases.every(c=>c.tx_hex.length>200));
});
