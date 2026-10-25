/** Abstract, non-consensus LayerTree bond/federation model. No FROST crypto or Filecoin light client. */
import {createHash} from 'node:crypto';
const H = x => createHash('sha256').update(JSON.stringify(x)).digest('hex');
const check = (ok,why) => {if (!ok) throw new Error(why);};
const op = x => typeof x === 'string' && /^[0-9a-f]{64}:[0-9]+$/i.test(x);
const sat = x => Number.isSafeInteger(x) && x >= 0 && x <= 0x7fffffff;
const clone = x => structuredClone(x);
const principal = s => s.bonds.filter(b=>!b.closed).reduce((n,b)=>n+b.terms.stake,0);
const root = s => H([s.carrier,s.usedOutpoints,s.bonds,s.usedLineages,s.signers,s.threshold]);
function verify(s) {
  check(s.carrier.value === principal(s), 'principal mismatch');
  check(s.root === root(s), 'state commitment mismatch');
  check(s.bonds.every(b=>b.termsHash===H(b.terms)), 'immutable bond terms mutated');
  check(new Set(s.usedOutpoints).size === s.usedOutpoints.length, 'reused carrier history');
}
function quorum(s,a,voters) {
  verify(s);
  check(a.before === s.root, 'stale root');
  check(Array.isArray(voters) && new Set(voters).size === voters.length, 'duplicate votes');
  check(voters.every(v=>s.signers.includes(v)), 'unknown voter');
  check(voters.length >= s.threshold, 'insufficient quorum');
  // WARNING: these are identities supplied by the test caller, not verified signatures.
}
function finish(s) { s.root=root(s); return s; }
const validTerms = t => {
  check(typeof t.id==='string' && t.id.length>0 && typeof t.provider==='string' &&
    typeof t.client==='string' && typeof t.deal==='string' && typeof t.sector==='string' &&
    typeof t.nonce==='string' && t.nonce.length>0, 'bad identifiers');
  check(sat(t.stake) && t.stake>0, 'bad collateral amount');
  check(['filecoin-windowpost','blossom-pdp'].includes(t.proofKind), 'unknown proof kind');
  check(typeof t.clientScript==='string' && /^[0-9a-f]+$/i.test(t.clientScript), 'bad client script');
  check(typeof t.providerScript==='string' && /^[0-9a-f]+$/i.test(t.providerScript), 'bad provider script');
  check(Number.isSafeInteger(t.startEpoch) && t.startEpoch>=0 &&
    Number.isSafeInteger(t.endEpoch) && t.endEpoch>t.startEpoch &&
    Number.isSafeInteger(t.refundHeight) && t.refundHeight>0 &&
    Number.isSafeInteger(t.challengeBlocks) && t.challengeBlocks>0, 'bad term');
};
export function genesis({outpoint,signers,threshold,terms}) {
  check(op(outpoint), 'bad first carrier');
  check(Array.isArray(signers) && signers.length>1 && new Set(signers).size===signers.length &&
    signers.every(x=>typeof x==='string'), 'bad signers');
  check(Number.isInteger(threshold) && threshold>=2 && threshold<=signers.length, 'bad threshold');
  check(Array.isArray(terms) && terms.length>0, 'no members');
  terms.forEach(validTerms);
  const usedLineages=terms.map(t=>t.provider+'|'+t.nonce);
  check(new Set(usedLineages).size===usedLineages.length, 'duplicate lineages');
  check(new Set(terms.map(t=>t.id)).size===terms.length, 'duplicate bond IDs');
  const bonds=terms.map(terms=>({terms:clone(terms),termsHash:H(terms),lastEpoch:terms.startEpoch-1,
    challenge:null,closed:null}));
  const s={carrier:{outpoint,generation:0,value:0},usedOutpoints:[],usedLineages,
    bonds,signers:signers.slice().sort(),threshold,root:'',bitcoinEnforced:false,
    frostSignaturesVerified:false,filecoinCheckpointVerified:false};
  s.carrier.value=principal(s);check(s.carrier.value<=0x7fffffff,'MID sum overflow');
  return finish(s);
}
const bond = (s,id) => {const b=s.bonds.find(b=>b.terms.id===id);check(b,'unknown bond');return b;};
export function refresh(s,a,voters) {
  quorum(s,a,voters);
  check(a.kind==='refresh', 'wrong transition');
  check(s.carrier.value>0 && s.carrier.outpoint!==null, 'cannot refresh closed bond carrier');
  check(a.from===s.carrier.outpoint && op(a.to) && a.to!==a.from &&
    !s.usedOutpoints.includes(a.to), 'bad carrier lineage');
  check(a.generation===s.carrier.generation+1 && a.value===principal(s), 'stale generation or value theft');
  check(Number.isSafeInteger(a.externalFee) && a.externalFee>=0, 'fee must be external');
  const n=clone(s);n.usedOutpoints.push(n.carrier.outpoint);
  n.carrier={outpoint:a.to,generation:a.generation,value:a.value};return finish(n);
}
export function observe(s,a,voters) {
  quorum(s,a,voters);
  check(a.kind==='observe', 'wrong transition');
  const n=clone(s),b=bond(n,a.id);
  check(!b.closed && !b.challenge, 'bond frozen or redeemed');
  check(a.deal===b.terms.deal && a.sector===b.terms.sector &&
    a.proofKind===b.terms.proofKind, 'wrong proof source');
  check(Number.isInteger(a.epoch) && a.epoch>b.lastEpoch && a.epoch<=b.terms.endEpoch,
    'replayed proof epoch');
  check(Number.isInteger(a.finalizedEpoch) && a.finalizedEpoch>=a.epoch &&
    /^[0-9a-f]{64}$/i.test(a.checkpoint), 'unfinalized checkpoint');
  check(['pass','fault'].includes(a.verdict) && /^[0-9a-f]{64}$/i.test(a.evidenceHash), 'bad verdict evidence');
  check(Number.isInteger(a.bitcoinHeight) && a.bitcoinHeight>=0, 'bad bitcoin height');
  if (a.verdict==='pass') check(a.epoch===b.lastEpoch+1, 'skipped storage epoch');
  b.lastEpoch=a.epoch;
  if(a.verdict==='fault') b.challenge={epoch:a.epoch,deadline:a.bitcoinHeight+b.terms.challengeBlocks,
    checkpoint:a.checkpoint,evidenceHash:a.evidenceHash};
  return finish(n);
}
export function payout(s,a,voters) {
  quorum(s,a,voters);
  check(a.kind==='settle', 'wrong transition');
  const n=clone(s),b=bond(n,a.id);
  check(!b.closed, 'double payout');
  check(a.from===s.carrier.outpoint && sat(a.value) && a.value===b.terms.stake,
    'wrong input or amount');
  check(Number.isInteger(a.height) && a.height>=0, 'invalid height');
  if(a.winner==='client') {
    check(b.challenge && a.height>=b.challenge.deadline,'unmatured or missing fault');
    check(a.script===b.terms.clientScript,'wrong client payout');
  } else if(a.winner==='provider') {
    check(!b.challenge && b.lastEpoch>=b.terms.endEpoch &&
      a.height>b.terms.refundHeight,'premature or contested refund');
    check(a.script===b.terms.providerScript,'wrong provider payout');
  } else throw new Error('unknown winner');
  b.closed={winner:a.winner,height:a.height};
  const value=principal(n);check(a.remaining===value,'underfunded successor');
  check(value===0 ? a.to===null : op(a.to) && a.to!==a.from &&
    !s.usedOutpoints.includes(a.to),'bad settlement successor');
  n.usedOutpoints.push(a.from);
  n.carrier={outpoint:a.to,generation:s.carrier.generation+1,value};
  return finish(n);
}
export function admit(s,a,voters) {
  quorum(s,a,voters);
  check(a.kind==='admit', 'wrong transition');validTerms(a.terms);
  const t=a.terms,lineage=t.provider+'|'+t.nonce;
  check(!s.usedLineages.includes(lineage) && !s.bonds.some(b=>b.terms.id===t.id),
    'historical nonce or duplicate id');
  check(s.carrier.value>0 && s.carrier.outpoint!==null, 'cannot join a closed carrier');
  check(a.from===s.carrier.outpoint && op(a.to) && a.to!==a.from &&
    !s.usedOutpoints.includes(a.to),'bad parent');
  check(sat(a.value) && a.value===principal(s)+t.stake, 'underfunded join');
  const n=clone(s);n.usedOutpoints.push(a.from);n.usedLineages.push(lineage);
  n.bonds.push({terms:clone(t),termsHash:H(t),lastEpoch:t.startEpoch-1,challenge:null,closed:null});
  n.carrier={outpoint:a.to,generation:s.carrier.generation+1,value:a.value};
  return finish(n);
}
export function compromisedThreshold(s,ids) {
  return new Set(ids.filter(id=>s.signers.includes(id))).size>=s.threshold;
}
export function bareScriptTimeoutRace({height,deadline,providerKnowsAnswer}) {
  return {clientForfeitEligible:height>=deadline,
    providerLateResponseEligible:Boolean(providerKnowsAnswer),
    consensusGuaranteesExclusiveVerdict:false};
}
