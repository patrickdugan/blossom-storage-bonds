// Phase 7C: assert the outcome of an end-to-end run from its results file. These are the claims the
// pilot rests on; CI fails if any of them stops holding.
//   node scripts/check-e2e.mjs <results.json> market|full-stack
//
// - The honest provider: bond refunded to the provider, every epoch paid.
// - The outsourcer (and the 50% deleter in market.ts): bond forfeited to the client.
// - The 10% deleter: forfeits unless sampling missed it every time. A miss is a measured outcome, not a
//   pass. It is reported as ESCAPED with the run's own detection probability, and CI accepts it only
//   when that probability leaves a real chance of escape (≥ 1% across the sampled epochs).
import { readFileSync } from 'node:fs';

const [file, kind] = process.argv.slice(2);
if (!['market', 'full-stack'].includes(kind)) throw new Error('usage: check-e2e.mjs <results.json> market|full-stack');
const r = JSON.parse(readFileSync(file, 'utf8'));
const fails = [];
const notes = [];
const by = (role) => r.summary.find((s) => s.role === role) ?? (fails.push(`no ${role} provider in results`), null);
const bondTo = (s) => s?.bond?.to;
const paid = (s) => s?.paidSats ?? s?.lightning?.paid_sats ?? s?.onchain?.paid_sats ?? 0;

const honest = by('honest');
if (bondTo(honest) !== 'provider') fails.push(`honest bond went to ${bondTo(honest)}, expected provider (refund)`);
if (kind === 'market' && honest?.failedEpochs !== 0) fails.push(`honest provider failed ${honest?.failedEpochs} epochs`);
if (kind === 'full-stack') {
  const bad = (honest?.epochs ?? []).length === 0 ? 'no epochs recorded' : null;
  if (bad) fails.push(`honest: ${bad}`);
}
if (paid(honest) <= 0) fails.push('honest provider was never paid');

for (const role of kind === 'market' ? ['outsources', 'deletes 50%'] : ['outsources']) {
  const s = by(role);
  if (bondTo(s) !== 'client') fails.push(`${role} bond went to ${bondTo(s)}, expected client (forfeit)`);
  if (paid(s) >= paid(honest)) fails.push(`${role} was paid ${paid(s)} sats, not less than the honest ${paid(honest)}`);
}

const d10 = by('deletes 10%');
if (d10) {
  if (bondTo(d10) === 'client') notes.push('deletes 10%: forfeited');
  else {
    const p = d10.p_detect_10pct_per_epoch ?? null;
    const sampled = kind === 'full-stack' ? Math.max(1, (r.params?.epochs ?? 3) - (r.params?.misbehaviourFromEpoch ?? 2) + 1) : null;
    const escape = p === null ? null : (1 - p) ** (sampled ?? 1);
    notes.push(`deletes 10%: ESCAPED (bond to ${bondTo(d10)}); per-epoch detection ${p}, escape probability over ${sampled} sampled epochs ${escape?.toFixed(4)}`);
    if (escape === null || escape < 0.01) fails.push('deletes 10% escaped although its escape probability was below 1%');
  }
}

for (const n of notes) console.log(`note: ${n}`);
for (const f of fails) console.log(`FAIL: ${f}`);
console.log(`${kind} ${file}: ${fails.length ? 'FAILED' : 'ok'} (honest paid ${paid(honest)} sats, bond to ${bondTo(honest)})`);
process.exit(fails.length ? 1 : 0);
