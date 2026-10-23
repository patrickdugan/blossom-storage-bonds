// ADR-015 unit checks for the independent tapscript-vector verdicts (no Rust or Core needed).
import test from 'node:test';
import assert from 'node:assert/strict';
import { hash256, hasOpSuccess } from './verify_admission_vectors.mjs';

const GENESIS = Buffer.from('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c', 'hex');
const BLOCK1 = Buffer.from('010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299', 'hex');

test('AV01: real block 1 links to the real genesis hash', () => {
  assert.equal(Buffer.from(hash256(GENESIS)).reverse().toString('hex'),
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
  assert.ok(BLOCK1.subarray(4, 36).equals(hash256(GENESIS)));
});

test('AV02: a header is exactly the 80-byte standard tapscript item limit', () => {
  assert.equal(GENESIS.length, 80);
});

test('AV03: OP_CAT (0x7e) and OP_SUCCESS80 are OP_SUCCESSx in tapscript; push data is skipped', () => {
  assert.equal(hasOpSuccess(Buffer.from([0x7e])), true);
  assert.equal(hasOpSuccess(Buffer.from([0x50])), true);
  assert.equal(hasOpSuccess(Buffer.from([0x01, 0x7e, 0x87])), false, '0x7e inside a push is data');
  assert.equal(hasOpSuccess(Buffer.from([0xa8, 0x20, ...new Array(32).fill(0x7e), 0x87])), false);
  assert.equal(hasOpSuccess(Buffer.from([0xac])), false, 'OP_CHECKSIG is ordinary');
});

test('AV04: OP_CHECKSIGADD (0xba) is ordinary, 0xbb is OP_SUCCESS187', () => {
  assert.equal(hasOpSuccess(Buffer.from([0xba])), false);
  assert.equal(hasOpSuccess(Buffer.from([0xbb])), true);
});
