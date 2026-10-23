/**
 * UTXO topology and transaction-ID admission laboratory.
 *
 * WARNING: The ledger deliberately assumes a boolean authorization oracle.
 * It validates outpoint consumption, transaction locktime (height mode), and
 * double-spend conflicts; it does NOT run Script, verify signatures or
 * certificates, enforce BIP68, or execute Binohash/BitVM.
 *
 * The point: separate properties provable from Bitcoin's transaction/outpoint
 * serialization from obligations that need real consensus-enforced scripts.
 */
import { createHash } from 'node:crypto';
import { transactionId } from './txid_admission.mjs';

const hash = text => createHash('sha256').update(String(text)).digest('hex');
const MAX_U64 = (1n << 64n) - 1n;
const finalSequence = 0xffffffff;
export const outpoint = (txid, vout = 0) => `${txid}:${vout}`;
export const puzzleCommitment = text => `0020${hash('BSB/ADMISSION-TEST/STATE\0' + text)}`;

export function makeTransaction({source, outputScripts, amounts, lockTime = 0, sequence = 0xfffffffe,
                                  scriptSig = '', witness = ['01'], version = 2}) {
  if (!source || !/^[a-f0-9]{64}$/.test(source.txid) || !Number.isInteger(source.vout))
    throw new TypeError('source must be a valid txid + vout');
  if (!Array.isArray(outputScripts) || !outputScripts.length || outputScripts.length !== amounts?.length)
    throw new TypeError('outputs and amounts required');
  for (const amt of amounts) if (typeof amt !== 'bigint' || amt < 0n || amt > MAX_U64)
    throw new RangeError('invalid output amount');
  return {
    version,
    vin: [{prevTxid: source.txid, prevVout: source.vout, scriptSig, witness, sequence}],
    vout: outputScripts.map((scriptPubKey, i) => ({valueSats: amounts[i], scriptPubKey})),
    lockTime
  };
}
export function spendOf(tx, vout = 0) {
  return {txid: transactionId(tx), vout};
}
export class TopologyLedger {
  constructor(seedUTXOs = []) {
    this.utxos = new Map();
    this.accepted = new Set();
    for (const item of seedUTXOs) {
      const ref = outpoint(item.txid, item.vout ?? 0);
      if (this.utxos.has(ref)) throw new Error('duplicate seed UTXO');
      this.utxos.set(ref, {amount: item.amount, scriptPubKey: item.scriptPubKey});
    }
  }
  has(source) {return this.utxos.has(outpoint(source.txid, source.vout));}
  /** `authorized` is an explicit external oracle, NEVER computed by this model. */
  apply(tx, {height, authorized, tag = 'spend'}) {
    if (authorized !== true) throw new Error(`${tag}: script authorization unverified`);
    if (!Number.isSafeInteger(height) || height <= 0) throw new RangeError('invalid height');
    if (tx.lockTime >= 500_000_000) throw new Error('timestamp locktime not simulated');
    if (tx.lockTime > 0 && tx.vin.some(v => v.sequence !== finalSequence) && tx.lockTime >= height)
      throw new Error(`${tag}: transaction not final`);
    const keys = tx.vin.map(v => outpoint(v.prevTxid, v.prevVout));
    if (new Set(keys).size !== keys.length) throw new Error(`${tag}: double-input`);
    for (const key of keys) if (!this.utxos.has(key)) throw new Error(`${tag}: missing or spent prevout ${key}`);
    const valueIn = keys.reduce((sum, key) => sum + this.utxos.get(key).amount, 0n);
    const valueOut = tx.vout.reduce((sum, output) => sum + output.valueSats, 0n);
    if (valueOut > valueIn) throw new Error(`${tag}: creates value`);
    // Consensus-inspired UTXO mechanics only; no BIP30, maturity, or script verification.
    const id = transactionId(tx);
    if (this.accepted.has(id)) throw new Error(`${tag}: duplicate transaction`);
    keys.forEach(key => this.utxos.delete(key));
    tx.vout.forEach((output, i) => this.utxos.set(outpoint(id, i), {
      amount: output.valueSats, scriptPubKey: output.scriptPubKey
    }));
    this.accepted.add(id);
    return {txid: id, fee: valueIn - valueOut, spent: keys, created: tx.vout.map((_,i)=>outpoint(id,i))};
  }
}
export function fundingFixture() {
  // The 2 seed inputs are virtual funding outpoints used solely by this lab.
  const funder = '11'.repeat(32), journalist = '22'.repeat(32);
  const ledger = new TopologyLedger([
    {txid:funder, vout:0, amount:150000n,scriptPubKey:'51'},
    {txid:journalist, vout:0,amount:10000n,scriptPubKey:'51'}
  ]);
  const fundTx = makeTransaction({source:{txid:funder,vout:0},
    outputScripts:[puzzleCommitment('bond/output')],amounts:[149000n]});
  ledger.apply(fundTx,{height:1,authorized:true,tag:'seed bond funding'});
  return {ledger, bond:spendOf(fundTx), independentUTXO:{txid:journalist,vout:0}, fundTx};
}
export function directProviderRefund(bond, lockTime = 150) {
  // The signature is an assumed successful provider-only leaf.
  return makeTransaction({source:bond,outputScripts:['51'],amounts:[148000n],
    lockTime, witness:['bb']});
}
export function independentChallenge(utxo, certificateID) {
  const data = hash(`BSB/challenge/${certificateID}`);
  return makeTransaction({source:utxo,
    outputScripts:[`6a20${data}`, '51'], amounts:[0n,9000n]});
}
export function contestChallenge(currentBond, certificateID) {
  // Covenant-style successor script is a PLACEHOLDER. Model assumes it can
  // embed a commitment, NOT that Bitcoin Script currently validates it.
  return makeTransaction({source:currentBond,
    outputScripts:[puzzleCommitment(`contest/${certificateID}`)],amounts:[148000n]});
}
export function legacyCarrierMutation(tx, changedScriptSig) {
  return {...tx, vin: tx.vin.map((i,index) => index===0 ? {...i,scriptSig:changedScriptSig} : {...i})};
}
export function witnessCarrierMutation(tx, changedWitness) {
  return {...tx, vin: tx.vin.map((i,index) => index===0 ? {...i,witness:changedWitness} : {...i})};
}
export function checkUnsignedRefundLeaves(leaves) {
  // Data-flow audit of *declared* spend paths, not a Script verifier.
  // Only paths explicitly marked 'refund' and 'provider-alone' are identified.
  const risky = leaves.filter(leaf => leaf.payout === 'provider' &&
    leaf.signers?.length===1 && leaf.signers[0]==='provider' && !leaf.mustConsumeContestState);
  return {riskyPaths:risky.map(x=>x.id), requiresProof:leaves.filter(x=>x.mustConsumeContestState).map(x=>x.id)};
}
