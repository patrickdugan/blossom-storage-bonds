// ADR-016: an independent design verdict for the OP_CAT refutation vectors, recomputed from the
// serialized transaction with Bitcoin's own rules. The leaf's Script semantics play no part here:
// - every header rebuilt from the witness fields is 80 bytes with nBits 0x207fffff;
// - each header's prev field is the regtest genesis hash or the previous header's hash;
// - each hash is <= the regtest target (the real consensus rule, as a 256-bit integer);
// - there are exactly N headers, so the fork is stronger than the frozen claim of N-1;
// - output 0 pays the intended client.
// It does not check the setup signature; Core does that. A Script bug that accepted a non-chain would
// show up as a disagreement with the generator's `design_ok`.
// Usage: node model/verify_cat_vectors.mjs vectors.json
import { readFileSync } from 'node:fs';
import { hash256, parseTx } from './verify_admission_vectors.mjs';

export const REGTEST_GENESIS = Buffer.from('0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206', 'hex').reverse();
export const REGTEST_TARGET = 0x7fffffn << 232n;
const BITS = Buffer.from('ffff7f20', 'hex');
const le = (b) => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));

/** Rebuild the header chain from witness items (bottom to top; per header: hi, lo, nonce, tail, version). */
export function headersFromItems(items) {
  if (items.length % 5 !== 0) return null;
  const hs = [];
  for (let i = items.length - 5; i >= 0; i -= 5) {
    const [hi, lo, nonce, tail, version] = items.slice(i, i + 5);
    if (version.length !== 4 || tail.length !== 36 || nonce.length !== 4 || lo.length !== 29 || hi.length !== 3) return null;
    hs.push({ version, tail, nonce, limbs: Buffer.concat([lo, hi]) });
  }
  return hs;
}

/** True when the items form exactly `n` linked headers from the checkpoint, each meeting the target. */
export function isStrongerFork(items, n, checkpoint = REGTEST_GENESIS) {
  const hs = headersFromItems(items);
  if (!hs || hs.length !== n) return false;
  let prev = checkpoint;
  for (const h of hs) {
    const header = Buffer.concat([h.version, prev, h.tail, BITS, h.nonce]);
    const hash = hash256(header);
    if (!hash.equals(h.limbs)) return false;
    if (le(hash) > REGTEST_TARGET) return false;
    prev = hash;
  }
  return true;
}

// ADR-017 freeze-graph cases carry a check kind:
// - fork: the ADR-016 header-chain rule for n headers, and output 0 to the client;
// - freeze: output 0 is one of the presigned freeze templates (an enumerated claim) and the setup
//   signature slot is non-empty;
// - cltv: nLockTime >= t, from the serialized bytes. Signature validity, including a wrong signer,
//   is decided by Core; the generator marks a wrong-signer case explicitly.
export function designVerdict(c, clientSpk, freeze) {
  const tx = parseTx(c.raw_hex);
  const w = tx.ins[c.input_index].witness;
  const check = c.check ?? { kind: 'fork', n: Number(/^N(\d+)\//.exec(c.name)[1]) };
  if (check.kind === 'fork') {
    if (w.length < 3) return false;
    return isStrongerFork(w.slice(0, -3), check.n) && tx.outs[0].script.equals(clientSpk);
  }
  if (check.kind === 'freeze') {
    const listed = Object.values(freeze.freeze_spks).some((s) => tx.outs[0].script.equals(Buffer.from(s, 'hex')));
    return listed && w[0].length > 0;
  }
  if (check.kind === 'cltv') return tx.lockTime >= check.t && !check.wrong_signer;
  if (check.kind === 'fork_sched') {
    if (w.length < 3) return false;
    return isScheduledFork(w.slice(0, -3), check.schedule, Buffer.from(check.checkpoint, 'hex')) && tx.outs[0].script.equals(clientSpk);
  }
  throw new Error(`unknown check ${check.kind}`);
}

/** The consensus target for compact nBits (exponent e, mantissa m): m * 256^(e-3). */
export function targetOf(bits) {
  const e = bits[3];
  const m = BigInt(bits[0] | (bits[1] << 8) | (bits[2] << 16));
  return e >= 3 ? m << BigInt(8 * (e - 3)) : m >> BigInt(8 * (3 - e));
}

/** ADR-019: exactly schedule.length linked headers from `checkpoint`, header i using nBits
 * schedule[i], each hash <= its target under the real consensus rule. Witness per header, top first:
 * version, tail, nonce, lo(e-3), m3(3), z(32-e) when e < 32. */
export function isScheduledFork(items, schedule, checkpoint) {
  let at = items.length;
  let prev = checkpoint;
  for (const bitsHex of schedule) {
    const bits = Buffer.from(bitsHex, 'hex');
    const e = bits[3];
    const take = () => { if (at === 0) throw new Error('short'); return items[--at]; };
    let version, tail, nonce, lo, m3, z;
    try {
      version = take(); tail = take(); nonce = take(); lo = take(); m3 = take(); z = e < 32 ? take() : Buffer.alloc(0);
    } catch { return false; }
    if (version.length !== 4 || tail.length !== 36 || nonce.length !== 4 || lo.length !== e - 3 || m3.length !== 3 || z.length !== 32 - e) return false;
    const hash = hash256(Buffer.concat([version, prev, tail, bits, nonce]));
    if (!hash.equals(Buffer.concat([lo, m3, z]))) return false;
    if (le(hash) > targetOf(bits)) return false;
    prev = hash;
  }
  return at === 0;
}

if (process.argv[1]?.endsWith('verify_cat_vectors.mjs')) {
  const v = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  if (v.schema !== 'bsb/cat-verifier-vectors/v1') throw new Error('wrong schema');
  const clientSpk = parseTx(v.cases.find((c) => c.name === 'N8/honest_stronger_fork').raw_hex).outs[0].script;
  let bad = 0;
  for (const c of v.cases) {
    const mine = designVerdict(c, clientSpk, v.freeze);
    if (mine !== c.design_ok) bad++;
    console.log(`${mine === c.design_ok ? 'ok' : 'FAIL'}  ${c.name.padEnd(30)} design_ok=${mine} bip347_valid=${c.bip347_valid} weight=${c.weight}`);
  }
  console.log(`independent ADR-016 verdicts (real regtest PoW rule): ${v.cases.length} cases, ${bad} disagreements`);
  if (bad) process.exit(1);
}
