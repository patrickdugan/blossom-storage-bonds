/**
 * Cursor-U TXO proposal, drawn from the read-output DA chain in Binohash App. C.
 *
 * Creates serializable Bitcoin transaction TOPOLOGIES. Does not implement
 * Script, BitVM verdict enforcement, validity proofs, or Binohash grinding.
 * In particular, policyAuthorization=true is an EXTERNAL ORACLE.
 *
 * A challenge consumes the unique live journal cursor and replaces it with
 * the next cursor. Settlement must consume both the collateral and the current
 * cursor, making the previous cursor unspendable after an admitted challenge.
 * This is useful only if Bitcoin can enforce a unique valid successor cursor
 * and force all collateral exit paths to use it. Those are open obligations.
 */
import {createHash} from 'node:crypto';
import {spendOf, puzzleCommitment} from './utxo_admission_graph.mjs';
const H = (value) => createHash('sha256').update(value).digest('hex');
const isRef = ref => ref && /^[0-9a-f]{64}$/i.test(ref.txid) && Number.isInteger(ref.vout) && ref.vout >= 0;
const standardInput = ref => ({prevTxid:ref.txid,prevVout:ref.vout,scriptSig:'',sequence:0xfffffffe,witness:['01']});
const validSats = x => typeof x === 'bigint' && x >= 0n && x <= (1n<<64n)-1n;

export function cursorGenesis({source, sourceValue, initialWork = 0n}) {
  if(!isRef(source) || !validSats(sourceValue) || sourceValue<2000n || !validSats(initialWork))
    throw new TypeError('invalid journal funding data');
  const commitment = H('BSB/INITIAL-JOURNAL/TEST-ONLY\0'+initialWork);
  const tx = {
    version:2,vin:[standardInput(source)],
    vout:[{valueSats:sourceValue-1000n,scriptPubKey:puzzleCommitment(`journal/${commitment}`)}],lockTime:0
  };
  return {tx,ref:spendOf(tx),root:commitment,work:initialWork,budget:sourceValue-1000n,bestIds:[]};
}
/**
 * Builds ONE tentative journal update, consuming exactly the current cursor.
 * The model computes a digest; it does NOT prove the candidate's chainwork.
 */
export function cursorUpdate({cursor,certificateId,work,validatedWork,fee=1000n,sponsor=null,allowTies=false}) {
  if(!cursor || !isRef(cursor.ref) || typeof cursor.root !== 'string' || !validSats(cursor.budget))
    throw new TypeError('invalid journal cursor');
  if(typeof certificateId !== 'string' || !certificateId || !validSats(work)) throw new TypeError('invalid certificate');
  if(!validatedWork) throw new Error('requires external exact-work verification oracle');
  if(work < cursor.work || (work === cursor.work && !allowTies)) throw new Error('non-increasing work');
  if(work === cursor.work && (cursor.bestIds ?? []).includes(certificateId)) throw new Error('duplicate certificate');
  if(!validSats(fee) || fee<1n) throw new RangeError('invalid cursor fee');
  if (sponsor && (!isRef(sponsor.ref) || !validSats(sponsor.value) || sponsor.value < fee ||
      (sponsor.ref.txid===cursor.ref.txid && sponsor.ref.vout===cursor.ref.vout)))
    throw new RangeError('invalid sponsor input');
  if(!sponsor && fee>=cursor.budget) throw new RangeError('insufficient cursor value');
  const root = H('BSB/JOURNAL-EXTEND/TEST-ONLY\0'+JSON.stringify([cursor.root,certificateId,work.toString()]));
  const remaining=sponsor ? cursor.budget : cursor.budget-fee;
  const outputs=[{valueSats:remaining,scriptPubKey:puzzleCommitment(`journal/${root}`)}];
  if(sponsor && sponsor.value>fee) outputs.push({valueSats:sponsor.value-fee,scriptPubKey:'51'});
  const tx = {version:2,vin:[standardInput(cursor.ref),...(sponsor?[standardInput(sponsor.ref)]:[])],
    vout:outputs,lockTime:0};
  const bestIds=work>cursor.work?[certificateId]:[...(cursor.bestIds??[]),certificateId];
  return {tx,ref:spendOf(tx),root,work,budget:remaining,bestIds};
}
/**
 * Binohash-style input pinning is assumed but never executed. A true legacy
 * digest of this settlement tx must cover BOTH collateral and cursor prevouts.
 * A BitVM prover must be forced to prove that the cursor spend is canonical.
 */
export function jointSettlement({bond,cursor,bondValue,settlementHeight,fee=1000n}) {
  if(!isRef(bond) || !cursor || !isRef(cursor.ref) || !validSats(bondValue) ||
    !validSats(cursor.budget) || !Number.isInteger(settlementHeight) || settlementHeight<1)
    throw new TypeError('invalid joint settlement');
  if(!validSats(fee) || fee>=bondValue+cursor.budget) throw new RangeError('invalid settlement fee');
  const tx={version:2,vin:[standardInput(bond),standardInput(cursor.ref)],
    vout:[{valueSats:bondValue+cursor.budget-fee,scriptPubKey:'51'}],lockTime:settlementHeight};
  return {tx,boundJournalRoot:cursor.root,cursorRef:cursor.ref};
}
export function destroyCursor(cursor) {
  if(!cursor || !isRef(cursor.ref)) throw new TypeError('invalid cursor');
  // Deliberately malicious. An open anyone-can-spend connector must reject
  // this output replacement via a real Bitcoin-enforced transition rule.
  return {version:2,vin:[standardInput(cursor.ref)],
    vout:[{valueSats:0n,scriptPubKey:'6a20'+H('BURN/CURSOR') }],lockTime:0};
}
export function proposedCursorInvariants({liveCursor,settlement,history=[]}) {
  // Informational: a checklist of obligations, NOT a check of Bitcoin Script.
  const unique = history.every(record=>record.outpointsCreated?.length===1);
  return {
    referencesLiveCursor: settlement.tx.vin.some(i=>i.prevTxid===liveCursor.ref.txid && i.prevVout===liveCursor.ref.vout),
    claimsLiveRoot: settlement.boundJournalRoot===liveCursor.root,
    allUpdatesHaveOneSuccessor: unique,
    enforceableOnCurrentBitcoin: false,
    unresolved:['permissionless valid-cursor successor covenant', 'exact-work chain proof binding',
      'all-path bond refund gating', 'admission and response deadline enforcement']
  };
}
