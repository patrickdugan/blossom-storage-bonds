# Phase 7C Pilot Readiness Report: the no-soft-fork Blossom storage market

Date: 2026-10-23. Branch `phase-7c-pilot`. Separate from `research/binohash-admission`, whose final
BLOCKED certificate-to-collateral review and draft PR #1 are unchanged. Nothing here claims OP_CAT
is active on Bitcoin.

## Recommendation: **CONDITIONAL GO**, for a small signet pilot

The existing-consensus market works end to end, reproducibly, in CI:
- Merkle PDP and public Stwo epoch proofs;
- payment over a Spilman channel, on chain with receipts, or over Lightning;
- per-deal sentinel bonds whose challenges, responses, forfeits and refunds are enforced by Bitcoin
  Core.

It survives provider crashes with its payment state intact, and every adversarial claim below has an
executable test. The GO is conditional on the five pilot conditions in §7. Mainnet value at risk is
**NO GO** until those conditions are met and a public signet pilot has run.

## 1. Commits

| Commit | What |
| --- | --- |
| `b6611ce` | Phase 7b private-signet rehearsal (local until 7C; now on the remote via this branch) |
| `46cb43d` | bond-phase RPC churn fix, merged (`776b859`) |
| `ed476a5` | native Linux prover path (`layer1/zk.ts`); end-to-end regtest CI (`.github/workflows/pilot-e2e.yml`, `scripts/ci-fetch.sh`, `scripts/check-e2e.mjs`) |
| `5594648`, `b0bfc52` | Codex's channel hardening, cherry-picked from the research branch: invoice validation, replay rejection, serialized verification |
| `747ffa0` | write-ahead payment ledgers (`layer1/ledger.ts`) in the channel and on-chain backends |
| `36f7fa7` | retrieval gate and a withholding provider; `--crash-honest`; harness RBF race; `model/pilot_economics.ts`; Phase 5 note |
| `8c79160` | deployment and recovery guide; e2e outcomes as CI annotations |

## 2. Phase 1: signet recovered and verified

b6611ce was found intact in the local worktree `blossom-storage-bonds-rehearsal` and is now pushed on
this branch. Its four fixes were reviewed in its diff:

1. **Sweep falls back to 1 sat/vB on "dust" as well as "too low".** Sound. The residual is that a
   lone 512-sat payment can be unsweepable at any rate, which is why the pilot batches on-chain
   payments (§5).
2. **The client sends one challenge at a time.** This fixes the race for the same fee coin.
   Enforcement becomes serial, which still fits easily within Δ = 144 blocks.
3. **The sweep wallet is loaded on a long-lived node, and named after the pay key off regtest.**
   Correct.
4. **Misbehaviour is injected right after the previous epoch's proofs off regtest.** Orchestration
   only; no protocol change.

**CI** (`pilot-e2e.yml`, every job on a fresh regtest node): unit and adversarial tests; the
sentinel-bond harness on Core 31.1; `market.ts` over the Spilman channel, with a provider crash and
the retrieval probe, and over Lightning (lnd v0.21.4); `full-stack.ts` paid on chain and over
Lightning, with public Stwo proofs built and proved on Linux. Outcomes are asserted from each results
file. Runs:
- 747ffa0: [run 39927920541](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39927920541), all 9 jobs green, both full-stack modes included.
- 8c79160: [run 39929671835](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39929671835), all 9 jobs green. Outcomes from the public check-run annotations:
  - **market (channel, crash + probe):** honest refunded and paid 5,120; deletes 10% and 50% and outsources forfeited; the withholder kept its bond and was paid 1,536. The honest provider was SIGKILLed at epoch 3 and restarted with 1 bond resumed.
  - **market (Lightning + probe):** the same outcomes.
  - **full stack (on chain), full stack (Lightning):** honest refunded and paid 1,536; deletes 10% and outsources forfeited.
  - **harness:** 24 checks, 0 failed.

## 3. Phase 2: adversarial results

| Attack | Executable test | Result |
| --- | --- | --- |
| Deletes 10% / 50% | `market.ts`, `full-stack.ts` (CI), `layer1.test.ts` | Forfeited on chain. The 10% deleter can escape sampling by chance (§5); CI reports an escape with its probability, never as a pass |
| Outsources to another replica | same | Forfeited; per-replica encryption makes the borrowed bytes useless |
| Withholds (keeps data, refuses downloads) | RT01, `market.ts --retrieval-probe` | **Keeps its bond: possession is all the bond enforces.** The retrieval gate stops paying it (1,536 vs the honest 5,120 sats) |
| Dishonest client plants bad sentinels | cut-and-choose tests (`bond.test.ts`, `storage_bonds.test.ts`) | Caught at setup. One planted bad sentinel survives with probability k/M |
| Client never seals | phase 7 regtest check (a challenge is refused until the provider's presignatures exist; 1c09167); deal-stage tests in `signet.test.ts`; design finding 13 | The provider signs last; an unsealed bond refunds at t_end; `--max-term` and `--uploaders` bound the griefing |
| Replayed invoice / duplicate payment | CI06, DU02, DU03, DU08, OD03, Lightning stub test | Refused, including across restarts of either party |
| Node or process crash | DU01–DU08, OD01–OD04; `market.ts --crash-honest 3` (SIGKILL) | Payment state and bonds come back from disk. The restarted honest provider passed all 10 epochs, was paid 5,120 sats and refunded |
| Interrupted settlement | DU04, DU05, OD04 | Resumed or rebroadcast byte for byte; never paid twice, never lost |
| Torn ledger write | DU06 | The partial last line is ignored; damage elsewhere stops the restart |
| Missing confirmations | signet tests (`--confs`, waits instead of mining); receipts checked at depth | Signet mode waits for depth; use 6 on signet |
| Conflicting bond spends | harness S1 (Core 31.1) | After Δ, a late Respond at the default fee loses to a mempool forfeit. **At 25 sat/vB it replaces the forfeit (package RBF) and keeps the bond.** The deadline is fee-dependent; possession is still enforced |
| Lower or skipped channel total | DU07, CR01 | Refused |
| Provider loses invoices on a crash (on chain) | OD01 | Was a real bug: pre-crash payments became unsweepable. Fixed by the invoice ledger |

## 4. Phase 3: measured costs

| Item | Measured |
| --- | --- |
| Sentinel transactions (vB) | fund 154, challenge 187 + CPFP child 153, respond 203, forfeit 138, refund 138, cooperative close 154 |
| Enforcing one sentinel | 478 vB, about 47,800 sats at 100 sat/vB |
| Epoch proof (q = 16, 3 deals) | 11.2–11.6 MB; proving 19–55 s once warm on one provider |
| Proof verification | under 20 ms in `bsb-zk`; the watchtower's 20–100 s wall time is queueing on one prover lock |
| On-chain pay per proof | 240 vB per batch of 3 payees; one 512-sat epoch at 5 sat/vB loses over 75% to fees, and batched over 30 epochs under 3% |
| Lightning pay per proof | seconds per epoch; no on-chain cost per payment over a direct channel |
| Payment latency, on chain | 1 confirmation on regtest; 3–6 on signet |

## 5. Phase 3: pilot parameters

All derived in `model/pilot_economics.ts` (EC01–EC07):
- **q = 64** per epoch, the Blake2s per-proof maximum. A 5% deleter escapes 3 epochs with p ≈ 5×10⁻⁵.
  The demo's q = 16 let a 10% deleter escape two epochs 3.4% of the time, which is exactly what the
  phase 7b rehearsal observed.
- **Daily epochs** (144 blocks): a 1% deleter escapes a 30-epoch month at q = 64 with p < 10⁻⁸.
- **Bond ≥ 100,000 sats per deal, not 1 BTC.** For small deals deterrence needs almost nothing (a few
  sats of storage saved). The floor is enforceability: about 84k sats lets the client challenge,
  CPFP and forfeit through a 100 sat/vB spike and still outbid a late responder's RBF.
- **Payment:** Lightning per epoch, or on chain batched over ≥ 30 epochs.
- **Retrieval:** proof of possession is not retrieval. Run the client's retrieval probe, and replicate
  across ≥ 2 providers in separate failure domains. A withholder still keeps its bond.

## 6. Phase 4: what protects what

| Protection | Enforced by |
| --- | --- |
| Forfeit only after a challenge plus Δ blocks of silence; refund only from t_end; challenge needs the client's signature and the right r; a response needs the right window | **Bitcoin consensus** (Core harness S1–S4) |
| Channel: 2-of-2 states, client refund after t_refund; on-chain payments spendable only with the payee's key plus the invoice tweak | **Bitcoin consensus** |
| Storage proofs (Merkle PDP, Stwo), invoice and receipt checks, header chain for receipts, retrieval probe, per-replica encryption | **Client verified** (and watchtower verified) |
| Cut and choose, the presigned chain, the sentinel count k per bond | **Setup honesty**, checked at setup; a planted bad sentinel survives with probability k/M |
| Challenge within the window, forfeit before a late RBF, watchtower attestations, relays carrying messages, the provider serving downloads | **Service availability** (client, watchtower, relays, provider) |
| Lightning routing and channel peers; fee coins for CPFP; miners including the forfeit | **Counterparties** |

Deployment and recovery: `docs/pilot/deployment.md`.

## 7. Pilot conditions (the "conditional")

1. **A restartable client loop.** `full-stack.ts` keeps its epoch and enforcement loop in memory
   (runbook §11). Payments and deal files survive a crash, but enforcement must be resumable before
   Δ expires. Until it is, an operator stands by to enforce from the deal files.
2. **A forfeit fee policy.** Broadcast at the first eligible block, at a competitive rate, and fee-bump
   while unconfirmed. Harness S1 shows a late responder can otherwise outbid it.
3. **Sentinel budget discipline.** Spend sentinels only on watchtower-attested missing or invalid
   proofs, never on retrieval failures. The market spent all k = 4 on a withholder that answered
   every one.
4. **Pilot parameters as in §5:** q = 64, daily epochs, ≥ 100k-sat bonds, the retrieval probe, ≥ 2
   replicas.
5. **Public-network gates** (runbook §8): each step of the signet pilot needs explicit approval. No
   mainnet funds.

## 8. Residual trust and limits

- **Withholding:** a provider can keep its bond while refusing service. Payment gating limits its
  income; nothing on chain punishes it.
- **Late responses:** the Δ deadline is soft against a fee bidder (S1); possession is still proven.
- **Sentinel budget:** each bond can be challenged at most k times.
- **Proof availability:** proofs are 11 MB, served by Blossom and announced on Nostr.
- **Header stand-in:** the watchtower's header chain is a replay stand-in for a header STARK
  (phase 5).
- **Pooled bonds:** public, permissionless adjudication of pooled bonds is out of scope. See
  `docs/pilot/bitvm2-pooled-bonds.md`: feasible with BitVM2 at four extra assumptions, or needs
  BIP347.

## 9. Phase 5 summary

BitVM2 can publicly adjudicate an operator-asserted pooled bond under a 1-of-n setup. It needs a
Groth16 ceremony, a miner for transactions of up to a megabyte, and a chain-work challenge, all
measured in phase 6. It is not a pilot prerequisite.

The smallest executable certificate-to-collateral construction on active consensus is a certificate
enumerated at setup with a presigned SINGLE|ANYONECANPAY payout (ADR-015 L5). An unknown certificate
needs BIP347 (ADR-016 to ADR-019, BLOCKED).
