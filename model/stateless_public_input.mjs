/**
 * Canonical 32-byte RISC Zero JOURNAL SCHEMA for a future stateless challenger.
 * The existing Phase 6 Groth16/BitVM wrapper takes a 32-byte RISC0 journal.
 * This module serializes and hashes PUBLIC INPUTS. It cannot certify real fork
 * validity, SPV inclusion, Binohash, or Bitcoin spending authorization.
 */
import {createHash} from 'node:crypto';
const SHA=(data)=>createHash('sha256').update(data).digest();
export const MAX_WORK=(1n<<256n)-1n;
export const VERSION=1;
const PREFIX=Buffer.from('BSB/STORAGE/EXISTENCE/V1\0','utf8');
function bytes32(value,label){
  if(typeof value!=='string'||!/^[0-9a-fA-F]{64}$/.test(value))throw new TypeError(`${label}: expected 32-byte hex`);
  return Buffer.from(value,'hex');
}
function uint32(n,label){
  if(!Number.isSafeInteger(n)||n<0||n>0xffffffff)throw new RangeError(`${label}: requires uint32`);
  const b=Buffer.alloc(4);b.writeUInt32BE(n);return b;
}
function work256(value,label){
  if(typeof value!=='bigint'||value<0n||value>MAX_WORK)throw new RangeError(`${label}: requires 256-bit work`);
  return Buffer.from(value.toString(16).padStart(64,'0'),'hex');
}
function outpoint(value){
  const m=/^([0-9a-f]{64}):([0-9]+)$/i.exec(value??'');
  if(!m)throw new TypeError('collateral outpoint: txid:vout expected');
  const vout=Number(m[2]);
  if(!Number.isSafeInteger(vout)||vout<0||vout>0xffffffff)throw new RangeError('collateral vout must be uint32');
  const index=Buffer.alloc(4);index.writeUInt32LE(vout);
  return Buffer.concat([Buffer.from(m[1],'hex').reverse(),index]);
}
function payoutDigest(scriptHex){
  if(typeof scriptHex!=='string'||scriptHex.length%2||!/^[0-9a-f]*$/i.test(scriptHex))
    throw new TypeError('payout script: expected hex');
  return SHA(Buffer.from(scriptHex,'hex'));
}
/**
 * Hash fields use human-display big-endian byte order; the collateral txid
 * uses Bitcoin serialization little-endian order. Heights are uint32 BE and
 * work uses unsigned uint256 BE. SHA256(domain_prefix || encoded_fields).
 */
export function serializeStatelessClaimInput({networkGenesis,claimCommitment,certificateDigest,
  certificateTip,providerWork,challengerWork,anchorBlockHash,anchorHeight,cutoff,
  disputeDeadline,collateralOutpoint,payoutScript}){
  return Buffer.concat([
    PREFIX,uint32(VERSION,'version'),bytes32(networkGenesis,'network genesis'),
    bytes32(claimCommitment,'claim commitment'),bytes32(certificateDigest,'certificate digest'),
    bytes32(certificateTip,'certificate tip'),work256(providerWork,'provider work'),
    work256(challengerWork,'challenger work'),bytes32(anchorBlockHash,'anchor block hash'),
    uint32(anchorHeight,'anchor height'),uint32(cutoff,'cutoff'),
    uint32(disputeDeadline,'dispute deadline'),outpoint(collateralOutpoint),payoutDigest(payoutScript)
  ]);
}
export function statelessJournalDigest(fields){
  return SHA(serializeStatelessClaimInput(fields));
}
/** These preconditions must be independently enforced by the eventual guest. */
export function assertPreconditions(fields){
  serializeStatelessClaimInput(fields);
  if(fields.anchorHeight>fields.cutoff)throw new Error('certificate anchored after cutoff');
  if(fields.disputeDeadline<=fields.cutoff)throw new Error('invalid dispute duration');
  if(fields.challengerWork<=fields.providerWork)throw new Error('fork not strictly stronger');
  return true;
}
/** A schema adapter, never a proof verification result. */
export function riscZeroJournalBytes(fields){
  assertPreconditions(fields);
  const b=statelessJournalDigest(fields);
  if(b.length!==32)throw new Error('unexpected RISC0 journal length');
  return b;
}
