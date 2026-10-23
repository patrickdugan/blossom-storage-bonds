/**
 * Offline *contextual* height-lock requirements corresponding to the
 * operational Blossom bond's refund (CLTV) and forfeiture (CSV) transactions.
 *
 * BIP65: OP_CLTV script checks signed nLockTime and nonfinal input sequence;
 * a height-locked transaction becomes final for block H only when H>L.
 * BIP112: CSV checks a version-2 transaction, compatible sequence type and
 * minimum sequence; BIP68 additionally requires the spent output's height.
 *
 * No chain is queried. The caller supplies the hypothetical UTXO creation
 * and candidate block heights. Time-based locks require MTP, and therefore
 * are explicitly rejected instead of being silently treated as height locks.
 *
 * This is a companion executable model, NOT a Bitcoin Core consensus oracle.
 */
export const LOCKTIME_THRESHOLD = 500_000_000;
export const SEQUENCE_FINAL = 0xffffffff;
export const SEQUENCE_DISABLE_FLAG = 0x80000000;
export const SEQUENCE_TYPE_FLAG = 0x00400000;
export const SEQUENCE_MASK = 0x0000ffff;
const validUint32=x=>Number.isInteger(x)&&x>=0&&x<=SEQUENCE_FINAL;
const validHeight=x=>Number.isSafeInteger(x)&&x>=0&&x<LOCKTIME_THRESHOLD;

export function csvScriptHeightOk({version,sequence,delay}) {
  if(!Number.isInteger(version)||version<2||!validUint32(sequence)||
     !Number.isInteger(delay)||delay<0||delay>SEQUENCE_MASK) return false;
  if((sequence & SEQUENCE_DISABLE_FLAG)!==0) return false;
  if((sequence & SEQUENCE_TYPE_FLAG)!==0) return false;
  return (sequence & SEQUENCE_MASK)>=delay;
}

/** BIP68 height-based sequence locks, conditional on a supplied confirmed
 * spent-output height. Version<2 or disabled sequence imposes no BIP68 delay
 * but does not make BIP112 OP_CSV valid. */
export function bip68HeightFinal({version,sequence,outpointHeight,candidateHeight}) {
  if(!Number.isInteger(version)||version<0||!validUint32(sequence)||
     !validHeight(outpointHeight)||!validHeight(candidateHeight))
    return false;
  if(version<2||(sequence & SEQUENCE_DISABLE_FLAG)!==0)return true;
  if((sequence & SEQUENCE_TYPE_FLAG)!==0)
    throw new RangeError('BIP68 time-based sequence requires median-time-past context');
  return outpointHeight+(sequence & SEQUENCE_MASK)<=candidateHeight;
}

export function forfeitContextOk({version,sequence,delay,outpointHeight,candidateHeight}) {
  return csvScriptHeightOk({version,sequence,delay}) &&
    bip68HeightFinal({version,sequence,outpointHeight,candidateHeight});
}

export function cltvScriptHeightOk({contractEndHeight,nLockTime,sequence}) {
  if(!validHeight(contractEndHeight)||!validHeight(nLockTime)||!validUint32(sequence))
    return false;
  return nLockTime>=contractEndHeight && sequence!==SEQUENCE_FINAL;
}

/** A height-based nLockTime L is final only at block H>L. */
export function absoluteHeightFinal({nLockTime,candidateHeight}) {
  return validHeight(nLockTime)&&validHeight(candidateHeight)&&candidateHeight>nLockTime;
}

export function refundContextOk({contractEndHeight,nLockTime,sequence,candidateHeight}) {
  return cltvScriptHeightOk({contractEndHeight,nLockTime,sequence}) &&
    absoluteHeightFinal({nLockTime,candidateHeight});
}
