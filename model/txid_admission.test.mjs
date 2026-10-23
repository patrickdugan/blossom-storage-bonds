import test from 'node:test';
import assert from 'node:assert/strict';
import {
  compactSize, serializeTransaction, transactionId, witnessTransactionId,
  transactionFixture, signedDescendant, descendantReferencesParent
} from './txid_admission.mjs';

// Byte-level Bitcoin serialization checks. We do not execute Script or signatures.
test('T01: witness-only mutation changes wtxid while preserving txid', () => {
  const old = transactionFixture({witness:['01']});
  const modified = transactionFixture({witness:['02']});
  assert.equal(transactionId(old), transactionId(modified));
  assert.notEqual(witnessTransactionId(old), witnessTransactionId(modified));
});
test('T02: legacy scriptSig changes txid (Binohash spends cannot freely mutate it)', () => {
  const old = transactionFixture({scriptSig:'0101'});
  const modified = transactionFixture({scriptSig:'0102'});
  assert.notEqual(transactionId(old), transactionId(modified));
});
test('T03: dynamic output certificate commitment changes txid', () => {
  const low = transactionFixture({outputScript:'6a20'+'11'.repeat(32)});
  const high = transactionFixture({outputScript:'6a20'+'22'.repeat(32)});
  assert.notEqual(transactionId(low), transactionId(high));
});
test('T04: a presigned descendant is broken by its parent scriptSig mutation', () => {
  const parent = transactionFixture({scriptSig:'0101'});
  const child = signedDescendant(transactionId(parent));
  assert.equal(descendantReferencesParent(child,parent),true);
  const changed = transactionFixture({scriptSig:'0102'});
  assert.equal(descendantReferencesParent(child,changed),false);
});
test('T05: a presigned descendant survives a parent witness-only mutation', () => {
  const parent = transactionFixture({witness:['01']});
  const child = signedDescendant(transactionId(parent));
  const changed = transactionFixture({witness:['03']});
  assert.equal(descendantReferencesParent(child,changed),true);
  assert.notEqual(witnessTransactionId(parent),witnessTransactionId(changed));
});
test('T06: output relocation of a journal commitment breaks presigned child', () => {
  const parent = transactionFixture({outputScript:'6a20'+'11'.repeat(32)});
  const child = signedDescendant(transactionId(parent));
  const changed = transactionFixture({outputScript:'6a20'+'22'.repeat(32)});
  assert.equal(descendantReferencesParent(child,changed),false);
});
test('T07: a Binohash-style legacy carrier makes a dynamically modified terminal tx acceptable for off-chain graph modelling', () => {
  const parent = transactionFixture({scriptSig:'0101'});
  const mutated = transactionFixture({scriptSig:'0102'});
  // No descendant is presigned against this parent. The txid change alone
  // does not break a *downstream* contract. Script safety remains unproven.
  assert.notEqual(transactionId(parent),transactionId(mutated));
});
test('T08: fully witness-free tx has same txid and wtxid', () => {
  const tx = transactionFixture({witness:[]});
  assert.equal(transactionId(tx),witnessTransactionId(tx));
});
test('T09: output amount or locktime mutation changes signed transaction identity', () => {
  const tx = transactionFixture();
  assert.notEqual(transactionId(tx),transactionId({...tx,lockTime:43}));
  assert.notEqual(transactionId(tx),transactionId(transactionFixture({outputSats:75001n})));
});
test('T10: varint boundaries are encoded canonically', () => {
  assert.equal(compactSize(252).toString('hex'),'fc');
  assert.equal(compactSize(253).toString('hex'),'fdfd00');
  assert.equal(compactSize(65535).toString('hex'),'fdffff');
  assert.equal(compactSize(65536).toString('hex'),'fe00000100');
  assert.equal(compactSize(4294967296n).toString('hex'),'ff0000000001000000');
});
test('T11: Bitcoin witness marker appears only in serialization with nonempty witness', () => {
  const tx=transactionFixture({witness:['01']});
  assert.equal(serializeTransaction(tx).subarray(4,6).toString('hex'),'01'+'11');
  assert.equal(serializeTransaction(tx,true).subarray(4,6).toString('hex'),'0001');
});
test('T12: malformed hex and oversized integers are rejected before hashing', () => {
  const bad = transactionFixture({scriptSig:'xx'});
  assert.throws(()=>transactionId(bad),TypeError);
  assert.throws(()=>compactSize(-1),RangeError);
});
