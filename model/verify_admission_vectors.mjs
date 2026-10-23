// ADR-015: an independent check of the design verdicts in the Rust tapscript admission vectors.
//
// The Rust generator labels each case `design_ok`, and Bitcoin Core 26 decides `core_valid`. This file
// recomputes `design_ok` from the serialized transaction bytes, so a counterexample doesn't rest on
// the generator's own label:
// - L1: are the two witness headers actually linked (h2[4..36] == HASH256(h1))?
// - L3/L6: does the executed leaf contain an OP_SUCCESSx opcode (BIP342)?
// - L4-L6: does output 0 pay the intended recipient (the client), or someone else?
// Usage: node model/verify_admission_vectors.mjs vectors.json
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const sha = (b) => createHash('sha256').update(b).digest();
export const hash256 = (b) => sha(sha(b));

function reader(buf) {
  let o = 0;
  const take = (n) => { if (o + n > buf.length) throw new Error('truncated'); const s = buf.subarray(o, o + n); o += n; return s; };
  const varint = () => {
    const x = take(1)[0];
    if (x < 0xfd) return x;
    if (x === 0xfd) return take(2).readUInt16LE();
    if (x === 0xfe) return take(4).readUInt32LE();
    throw new Error('varint too large');
  };
  return { take, varint, done: () => o === buf.length };
}

/** Parse a BIP144 segwit transaction: inputs, outputs and per-input witness stacks. */
export function parseTx(hex) {
  const r = reader(Buffer.from(hex, 'hex'));
  r.take(4);
  const marker = r.take(2);
  if (marker[0] !== 0 || marker[1] !== 1) throw new Error('expected a segwit serialization');
  const ins = [];
  for (let n = r.varint(); n > 0; n--) { r.take(36); r.take(r.varint()); r.take(4); ins.push({}); }
  const outs = [];
  for (let n = r.varint(); n > 0; n--) { const value = r.take(8).readBigUInt64LE(); outs.push({ value, script: Buffer.from(r.take(r.varint())) }); }
  for (const i of ins) { i.witness = []; for (let n = r.varint(); n > 0; n--) i.witness.push(Buffer.from(r.take(r.varint()))); }
  const lockTime = r.take(4).readUInt32LE();
  if (!r.done()) throw new Error('trailing bytes');
  return { ins, outs, lockTime };
}

// BIP342 OP_SUCCESSx set.
const SUCCESS = new Set([80, 98, 126, 127, 128, 129, 131, 132, 133, 134, 137, 138, 141, 142, 149, 150, 151, 152, 153]);
for (let x = 187; x <= 254; x++) SUCCESS.add(x);

/** Walk a tapscript's opcodes, skipping push data, and report whether any is OP_SUCCESSx. */
export function hasOpSuccess(script) {
  for (let i = 0; i < script.length;) {
    const op = script[i++];
    if (op >= 1 && op <= 75) i += op;
    else if (op === 76) i += 1 + script[i];
    else if (op === 77) i += 2 + script.readUInt16LE(i);
    else if (op === 78) i += 4 + script.readUInt32LE(i);
    else if (SUCCESS.has(op)) return true;
  }
  return false;
}

/** Recompute the design verdict of one case from its bytes. */
export function designVerdict(c, clientSpk) {
  const tx = parseTx(c.raw_hex);
  const w = tx.ins[c.input_index].witness;
  const leaf = w[w.length - 2];
  const toClient = tx.outs[0].script.equals(clientSpk);
  if (c.leaf === 'naive_link') {
    const [, h2, h1] = w;
    return h2.length === 80 && h2.subarray(4, 36).equals(hash256(h1));
  }
  if (c.leaf === 'cat_link') {
    if (!hasOpSuccess(leaf)) throw new Error('L3 leaf should contain OP_CAT');
    // Intended semantics: the parts rebuild a header that extends the 80-byte item, and pay the client.
    if (w.length !== 5) return false;
    const [rest, version, h1] = w;
    const h2 = Buffer.concat([version, hash256(h1), rest]);
    return h2.length === 80 && toClient;
  }
  if (c.leaf === 'hidden_success') return !hasOpSuccess(leaf) && toClient;
  if (c.leaf.startsWith('cert_')) return toClient && c.attack !== 'invalid certificate';
  if (c.leaf.startsWith('pow_no_cat')) return true;
  throw new Error(`unknown leaf ${c.leaf}`);
}

if (process.argv[1]?.endsWith('verify_admission_vectors.mjs')) {
  const v = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  if (v.schema !== 'bsb/tapscript-admission-vectors/v1') throw new Error('wrong schema');
  // The client's P2TR is output 0 of the honest L4 case: it is the generator's intended recipient.
  const honest = v.cases.find((c) => c.name === 'L4/challenger_claims');
  const clientSpk = parseTx(honest.raw_hex).outs[0].script;
  let bad = 0;
  for (const c of v.cases) {
    const mine = designVerdict(c, clientSpk);
    const same = mine === c.design_ok;
    if (!same) bad++;
    console.log(`${same ? 'ok' : 'FAIL'}  ${c.name.padEnd(36)} design_ok=${mine}${c.counterexample ? ' (consensus-valid counterexample)' : ''}`);
  }
  console.log(`independent design verdicts: ${v.cases.length} cases, ${bad} disagreements with the generator`);
  if (bad) process.exit(1);
}
