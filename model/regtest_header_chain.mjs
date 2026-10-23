/**
 * Independent proof-of-work, compact target and cumulative-work validation
 * of a contiguous Bitcoin REGTEST header chain anchored to Bitcoin's
 * published regtest genesis.
 *
 * The results are still conditional on a known valid block body/UTXO set,
 * correct network rules and the claim that this is the BEST chain. No
 * amount of checking one supplied chain proves that no higher-work fork
 * exists elsewhere. The full-node audit compares our computed chainwork
 * against Core's chosen active chain and validated block bodies.
 *
 * Regtest-specific: no retargeting, 0x207fffff compact PoW target.
 * Mainnet or testnet4 would require different difficulty-transition rules.
 */
import {createHash} from 'node:crypto';

const sha=b=>createHash('sha256').update(b).digest();
const doubleSha=b=>sha(sha(b));
const HASH_MAX=(1n<<256n)-1n;
const ZERO='00'.repeat(32);
export const REGTEST_GENESIS =
  '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206';
export const REGTEST_BITS=0x207fffff;
export const REGTEST_POW_LIMIT=0x7fffffn<<232n;

const displayDigest=b=>Buffer.from(b).reverse().toString('hex');
const internalFromDisplay=hex=>Buffer.from(hex,'hex').reverse();

export function targetFromCompact(bits){
  if(!Number.isInteger(bits)||bits<0||bits>0xffffffff)
    throw Error('bits must be a 32-bit unsigned integer');
  const size=bits>>>24;
  const mantissa=bits&0x007fffff;
  if((bits&0x00800000)!==0 || mantissa===0 ||
      (mantissa>0xff&&size>33) ||
      (mantissa>0xffff&&size>32) ||
      size>34)
    throw Error('invalid compact PoW target: negative, zero or overflow');
  const shift=8n*BigInt(Math.abs(size-3));
  const target=size<=3 ? BigInt(mantissa)>>shift : BigInt(mantissa)<<shift;
  if(target<=0n||target>REGTEST_POW_LIMIT||target>HASH_MAX)
    throw Error('invalid Bitcoin REGTEST proof-of-work target');
  return target;
}

/** Core's GetBlockProof is mathematically floor(2^256 / (target+1)). */
export function blockWork(target){
  if(typeof target!=='bigint'||target<=0n||target>HASH_MAX)
    throw Error('work target out of range');
  return (HASH_MAX-target)/(target+1n)+1n;
}

export function decodeHeader(rawHex){
  if(typeof rawHex!=='string'||!(/^[0-9a-f]{160}$/i.test(rawHex)))
    throw Error('Bitcoin header must be exactly 80 bytes of hex');
  const data=Buffer.from(rawHex,'hex');
  const digest=doubleSha(data);
  return {
    rawHex:data.toString('hex'),
    version:data.readInt32LE(0),
    hash:displayDigest(digest),
    internalHash:digest,
    prevHash:displayDigest(data.subarray(4,36)),
    prevInternal:data.subarray(4,36),
    merkleRoot:displayDigest(data.subarray(36,68)),
    time:data.readUInt32LE(68),
    bits:data.readUInt32LE(72),
    nonce:data.readUInt32LE(76)
  };
}

/**
 * Records must contain the entire chain starting at height zero:
 *   [{height:0, hex:'...', hash:'...'}, ...].
 * Never silently trust the RPC-provided hash, claimed height, bits, target
 * or advertised chainwork. Check all values independently.
 */
export function verifyRegtestHeaderChain(records,opts={}){
  if(!Array.isArray(records)||records.length<2 ||
     records.length>50_000) throw Error('need complete genesis-anchored regtest headers');
  const genesis=opts.genesis??REGTEST_GENESIS;
  if(typeof genesis!=='string'||!/^[0-9a-f]{64}$/i.test(genesis))
    throw Error('bad expected chain genesis');
  let totalWork=0n;
  let previous=null;
  const seen=new Set();
  const times=[];
  const checkpoints=[];
  for(let i=0;i<records.length;i++){
    const record=records[i];
    if(!record||record.height!==i)throw Error('header heights must be sequential from genesis');
    const hd=decodeHeader(record.hex);
    if(record.hash!==undefined && record.hash.toLowerCase()!==hd.hash)
      throw Error('claimed block hash does not match serialized header');
    if(seen.has(hd.hash))throw Error('duplicate block hash in header chain');
    seen.add(hd.hash);
    if(i===0){
      if(hd.hash!==genesis.toLowerCase())
        throw Error('Bitcoin regtest genesis anchor mismatch');
      if(hd.prevHash!==ZERO)throw Error('genesis previous-block field not null');
    }else{
      if(!hd.prevInternal.equals(previous.internalHash))
        throw Error('previous header hash linkage mismatch at height '+i);
      const prev11=times.slice(Math.max(0,times.length-11)).sort((a,b)=>a-b);
      const median=prev11[Math.floor(prev11.length/2)];
      if(!(hd.time>median))
        throw Error('header timestamp fails median-time-past at height '+i);
    }
    if(hd.bits!==REGTEST_BITS)
      throw Error('unexpected regtest difficulty bits at height '+i);
    const target=targetFromCompact(hd.bits);
    if(BigInt('0x'+hd.hash)>target)
      throw Error('header proof-of-work invalid at height '+i);
    const work=blockWork(target);
    totalWork+=work;
    // Values are strings because work may exceed JS Number precision.
    if(record.chainwork!==undefined &&
       BigInt('0x'+record.chainwork)!==totalWork)
      throw Error('Core-claimed cumulative chainwork mismatch at height '+i);
    if(record.merkleRoot!==undefined && record.merkleRoot!==hd.merkleRoot)
      throw Error('header Merkle root mismatch at height '+i);
    const item={height:i,hash:hd.hash,merkleRoot:hd.merkleRoot,
      bits:hd.bits,time:hd.time,work:work.toString(),chainwork:totalWork.toString()};
    if(i===0||i===records.length-1||opts.checkpoints?.includes(i))checkpoints.push(item);
    previous=hd;
    times.push(hd.time);
  }
  const tip=previous.hash;
  if(opts.expectedTip && tip!==opts.expectedTip)
    throw Error('independently derived tip disagrees with expected tip');
  if(opts.minimumChainwork!==undefined &&
     totalWork<BigInt(opts.minimumChainwork))
    throw Error('chain is below explicitly required accumulated-work threshold');
  return {
    schema:'bsb/regtest-header-chain-work/v1',network:'regtest',
    genesis,tip,tipHeight:records.length-1,headerCount:records.length,
    cumulativeWorkDecimal:totalWork.toString(),
    cumulativeWorkHex:totalWork.toString(16),
    blockWorkAtRegtestLimit:blockWork(targetFromCompact(REGTEST_BITS)).toString(),
    checks:{genesis:true,headerLinks:true,compactTargets:true,pow:true,
      medianTimePast:true,exactBigIntChainwork:true},
    checkpoints
  };
}

/** Confirm an already authenticated Merkle/witness inclusion payload names
 * an exact header in the independently checked contiguous chain. */
export function bindInclusionToHeaderChain(inclusion,records,verified){
  if(!verified || verified.schema!=='bsb/regtest-header-chain-work/v1')
    throw Error('missing independently verified header chain');
  if(!Number.isSafeInteger(inclusion?.height)||inclusion.height<0 ||
     inclusion.height>=records.length)
    throw Error('inclusion height outside known header chain');
  const h=decodeHeader(records[inclusion.height].hex);
  if(inclusion.blockhash!==h.hash||inclusion.headerHex!==h.rawHex||
     inclusion.merkleRoot!==h.merkleRoot)
    throw Error('inclusion proof is not bound to verified header at height');
  if(inclusion.witness?.blockhash!==h.hash ||
     inclusion.witness?.blockHeaderHex!==h.rawHex)
    throw Error('witness coinbase proof not bound to verified header');
  return true;
}
