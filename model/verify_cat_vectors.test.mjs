// ADR-016 unit checks for the independent header-chain verdict (no Rust or Core needed).
import test from 'node:test';
import assert from 'node:assert/strict';
import { hash256 } from './verify_admission_vectors.mjs';
import { REGTEST_GENESIS, REGTEST_TARGET, isStrongerFork } from './verify_cat_vectors.mjs';

const BITS = Buffer.from('ffff7f20', 'hex');
const le = (b) => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));

function mine(prev, i, wantPow = true) {
  const version = Buffer.from('00000020', 'hex');
  const tail = Buffer.alloc(36, i + 1);
  for (let nonce = 0; ; nonce++) {
    const nb = Buffer.alloc(4); nb.writeUInt32LE(nonce);
    const hash = hash256(Buffer.concat([version, prev, tail, BITS, nb]));
    if ((le(hash) <= REGTEST_TARGET) === wantPow) return { version, tail, nonce: nb, hash };
  }
}
function items(chain) {
  const out = [];
  for (const h of [...chain].reverse()) out.push(h.hash.subarray(29), h.hash.subarray(0, 29), h.nonce, h.tail, h.version);
  return out;
}
function chainOf(n) {
  const c = []; let prev = REGTEST_GENESIS;
  for (let i = 0; i < n; i++) { const h = mine(prev, i); c.push(h); prev = h.hash; }
  return c;
}

test('CV01: the regtest genesis hash is the known constant', () => {
  assert.equal(Buffer.from(REGTEST_GENESIS).reverse().toString('hex'), '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206');
});

test('CV02: linked mined headers from genesis are a stronger fork of exactly n', () => {
  const c = chainOf(5);
  assert.equal(isStrongerFork(items(c), 5), true);
  assert.equal(isStrongerFork(items(c), 4), false, 'count must equal n');
  assert.equal(isStrongerFork(items(c.slice(0, 4)), 5), false);
});

test('CV03: a header above the target, or an unlinked header, is rejected', () => {
  const c = chainOf(3);
  const weak = mine(c[1].hash, 9, false);
  assert.equal(isStrongerFork(items([c[0], c[1], weak]), 3), false);
  const other = mine(Buffer.alloc(32, 0x33), 2);
  assert.equal(isStrongerFork(items([c[0], c[1], other]), 3), false);
});

test('CV04: forged limbs and shifted field sizes are rejected', () => {
  const c = chainOf(2);
  const it = items(c);
  it[it.length - 5] = Buffer.alloc(3);
  assert.equal(isStrongerFork(it, 2), false);
  const it2 = items(c);
  const top = it2.length - 1;
  it2[top] = Buffer.concat([it2[top], it2[top - 1].subarray(0, 1)]);
  it2[top - 1] = it2[top - 1].subarray(1);
  assert.equal(isStrongerFork(it2, 2), false);
});
