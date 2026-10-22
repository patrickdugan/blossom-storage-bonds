/**
 * Arithmetic *estimator* from Binohash (Linus, 2026), sec. 6 & Appendix D.
 * Not a compiled Script, Bitcoin Core policy result, or security proof.
 * Script limits used here are for legacy (non-SegWit) script.
 */
const LEGACY_MAX_OPS=201;
const MAX_SCRIPT_BYTES=10000;
const P2SH_MAX_REDEEM_BYTES=520;
export function estimateBinohashBudget({rounds=2,pool=120,selections=8,polyglot=false,extraOps=0}) {
  for (const x of [rounds,pool,selections,extraOps])
    if (!Number.isSafeInteger(x)||x<0) throw new RangeError('nonnegative integer parameters required');
  if(rounds<1||pool<1||selections<1||selections>pool) throw new RangeError('bad rounds, pool or subset size');
  // Section 6: pinning=13; non-polyglot rounds (11t+4), plus 2.
  // Appendix D (polyglot) changes only the per-selection term to 9t.
  const pinningOps=13;
  const extractionOps=rounds*((polyglot?9:11)*selections+4)+2;
  const totalOps=pinningOps+extractionOps+extraOps;
  const nonceEntropyBits=rounds*log2binomial(pool,selections);
  const fixedPushedData=polyglot ? rounds*pool*21 : rounds*pool*(10+21);
  // Exact ~8KB formula for ordinary n=120 t=8 r=2, rough for variants.
  const roughScriptBytes=100+fixedPushedData+rounds*(11*selections+156);
  return Object.freeze({totalOps,remainingOps:LEGACY_MAX_OPS-totalOps,
    withinOpcodeBudget:totalOps<=LEGACY_MAX_OPS,
    roughScriptBytes,withinScriptBudget:roughScriptBytes<=MAX_SCRIPT_BYTES,
    fitsP2SH:roughScriptBytes<=P2SH_MAX_REDEEM_BYTES,
    nonceEntropyBits:Number(nonceEntropyBits.toFixed(2)),
    assumptions:'paper arithmetic only; compile and inspect actual script before making consensus claims'});
}
function log2binomial(n,k) {
  let value=0;
  for(let i=1;i<=k;i++) value+=Math.log2(n-k+i)-Math.log2(i);
  return value;
}
export function mustSplitEnforcement(extraOps,estimate=estimateBinohashBudget({})) {
  if(!Number.isSafeInteger(extraOps)||extraOps<0) throw new RangeError('bad extension count');
  return extraOps>estimate.remainingOps;
}
