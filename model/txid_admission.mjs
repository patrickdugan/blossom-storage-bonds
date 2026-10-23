/**
 * Bitcoin transaction byte-serialization lab for Binohash admission research.
 * Implements consensus txid/wtxid serialization, not Script validation,
 * signature hashing, Binohash grinding, or mempool admission.
 *
 * Inputs are raw byte strings (hex). An input's scriptSig participates in txid;
 * SegWit witness stacks do not. Outputs and locktime always participate in txid.
 */
import { createHash } from 'node:crypto';

const hash256 = (bytes) => {
  const once = createHash('sha256').update(bytes).digest();
  return createHash('sha256').update(once).digest();
};

function bytes(hex, fixedLength) {
  if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-f]*$/i.test(hex))
    throw new TypeError('expected even-length hex string');
  const b = Buffer.from(hex, 'hex');
  if (fixedLength !== undefined && b.length !== fixedLength) throw new RangeError('unexpected byte length');
  return b;
}
function unsignedLE(n, width) {
  if (typeof n !== 'bigint' && (!Number.isSafeInteger(n) || n < 0))
    throw new RangeError('invalid integer');
  let x = BigInt(n);
  if (x < 0n || x >= 1n << BigInt(width * 8)) throw new RangeError('integer overflow');
  const out = Buffer.alloc(width);
  for (let i = 0; i < width; i++) {out[i] = Number(x & 255n); x >>= 8n;}
  return out;
}
export function compactSize(n) {
  const x = BigInt(n);
  if (x < 0n || x > (1n << 64n) - 1n) throw new RangeError('compactSize overflow');
  if (x < 253n) return unsignedLE(x, 1);
  if (x <= 0xffffn) return Buffer.concat([Buffer.from([253]), unsignedLE(x, 2)]);
  if (x <= 0xffffffffn) return Buffer.concat([Buffer.from([254]), unsignedLE(x, 4)]);
  return Buffer.concat([Buffer.from([255]), unsignedLE(x, 8)]);
}
const varbytes = (b) => Buffer.concat([compactSize(b.length), b]);
const serializeInput = (i) => {
  const txid = bytes(i.prevTxid, 32);
  return Buffer.concat([Buffer.from(txid).reverse(), unsignedLE(i.prevVout, 4),
    varbytes(bytes(i.scriptSig ?? '')), unsignedLE(i.sequence ?? 0xffffffff, 4)]);
};
const serializeOutput = (o) => Buffer.concat([
  unsignedLE(o.valueSats, 8), varbytes(bytes(o.scriptPubKey))
]);
function checkedTransaction(tx) {
  if (!Array.isArray(tx.vin) || tx.vin.length < 1 || !Array.isArray(tx.vout) || tx.vout.length < 1)
    throw new RangeError('transaction must have inputs and outputs');
  for (const i of tx.vin) if (i.witness !== undefined && !Array.isArray(i.witness))
    throw new TypeError('witness must be array of hex strings');
}
export function serializeTransaction(tx, useWitness = false) {
  checkedTransaction(tx);
  const prefix = unsignedLE(tx.version ?? 2, 4);
  const inputBytes = Buffer.concat(tx.vin.map(serializeInput));
  const outputBytes = Buffer.concat(tx.vout.map(serializeOutput));
  const hasWitness = useWitness && tx.vin.some(i => i.witness?.length);
  const witnessBytes = hasWitness ? Buffer.concat(tx.vin.map(i => Buffer.concat([
    compactSize(i.witness?.length ?? 0),
    ...(i.witness ?? []).map(hex => varbytes(bytes(hex)))
  ]))) : Buffer.alloc(0);
  return Buffer.concat([
    prefix, ...(hasWitness ? [Buffer.from([0, 1])] : []),
    compactSize(tx.vin.length), inputBytes,
    compactSize(tx.vout.length), outputBytes,
    witnessBytes, unsignedLE(tx.lockTime ?? 0, 4)
  ]);
}
export function transactionId(tx) {
  return Buffer.from(hash256(serializeTransaction(tx))).reverse().toString('hex');
}
export function witnessTransactionId(tx) {
  return Buffer.from(hash256(serializeTransaction(tx, true))).reverse().toString('hex');
}
export function transactionFixture({scriptSig = '', witness = ['01'], outputScript = '51', outputSats = 75000n} = {}) {
  return {
    version: 2,
    vin: [{ prevTxid: '11'.repeat(32), prevVout: 0, scriptSig, sequence: 0xfffffffe, witness }],
    vout: [{ valueSats: outputSats, scriptPubKey: outputScript }],
    lockTime: 42
  };
}
export function signedDescendant(inputTxid, vout = 0) {
  return {
    version: 2,
    vin: [{ prevTxid: inputTxid, prevVout: vout, sequence: 0xfffffffe, scriptSig: '', witness: ['02'] }],
    vout: [{valueSats: 70000n, scriptPubKey: '51'}], lockTime: 0
  };
}
export function descendantReferencesParent(descendant, parent, vout = 0) {
  return descendant.vin.some(i => i.prevTxid === transactionId(parent) && i.prevVout === vout);
}
