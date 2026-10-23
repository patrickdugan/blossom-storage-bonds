# Blossom Storage Bonds Certificate-to-Collateral Enforcement Review

Date: 2026-10-23. Branch `research/binohash-admission`. Draft PR [#1](https://github.com/patrickdugan/blossom-storage-bonds/pull/1) stays a draft. Tracking: issues [#2](https://github.com/patrickdugan/blossom-storage-bonds/issues/2) and [#3](https://github.com/patrickdugan/blossom-storage-bonds/issues/3).

**Verdict: BLOCKED.**

Bitcoin Core 26 consensus cannot verify a stronger-fork certificate it didn't know at setup:
- it has no way to read a header's fields;
- it has no way to compare a hash with a target.

It also cannot bind a verdict to the payout except through a key presigned at setup. The missing enforcement primitive is **OP_CAT (BIP347)**.

**Update, ADR-016 (§7 run):** the experiment was run on Bitcoin Core 26 with a local BIP347 patch (no download). It shows that OP_CAT is *sufficient* for the scoped construction:
- one fixed tapscript leaf accepts any stronger fork of a fixed-difficulty chain, from any challenger, on real mined regtest headers;
- the leaf rejects all 10 attack classes;
- the leaf binds the payout through a presigned SINGLE|ANYONECANPAY signature;
- the spend is 19,428 WU at 151 headers.

On stock Core the same output is anyone-can-spend. The verdict therefore stays **BLOCKED**, and the exact missing primitive is BIP347 activation. The residual items are engineering: retarget-aware work, dynamic claims, timeliness via BIP141 inclusion, and a covenant in place of A5 (§7a).

## 1. Baseline and what was run

**Baseline.** CI was green on `a1a7bda` before this work:
- [Lean #39887308719](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39887308719)
- [Binohash model #39887308800](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39887308800)
- [full-node regtest #39887308682](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39887308682)

These were read from the public API, not assumed.

**Run locally on this change:**

| Check | Result |
| --- | --- |
| `node --test model/*.test.mjs` | 421/421 (417 before, plus 4 new AV tests) |
| TypeScript storage/channel tests | 33/33 |
| `bsb-admission-vectors` → `verify_admission_vectors.mjs` | 16/16 independent design verdicts agree |
| `tapscript-vectors` (Core 26, Taproot flags) | 16 cases, 0 mismatches, 5 consensus-valid counterexamples |
| `formal/CertificateAdmission.lean` | kernel-checked (Lean 4.34.1 locally; CI pins 4.15.0); 14 theorems audited by `#print axioms`: only `propext`, `Quot.sound`, `Classical.choice`; no `sorry`, `admit` or `axiom` |

CI links for the new commit are recorded in §8 after the push.

**Not run:**
- the 21-scenario regtest harness (no settlement code changed);
- mining, funding, broadcast or any proof job.

## 2. Formal security games (`formal/CertificateAdmission.lean`)

| Theorem | Class | Statement |
| --- | --- | --- |
| `client_safety` | safety (client) | With exclusive exits (A3), a sound refutation leaf (A2) and a refutation confirmed before the deadline (A4), the bond settles by refutation |
| `provider_safety` | safety (provider) | Any refutation settlement implies a timely, valid, stronger certificate. A truthful frozen claim is never forfeited |
| `provider_liveness` | liveness | With A2 and A3 and a truthful claim, a refund confirmed after the deadline settles the bond |
| `late_refutation_can_lose` | counterexample | Without A4, a timely certificate's refutation confirming at the deadline loses the race to the refund |
| `hidden_path_breaks_safety` | counterexample | Without A3, one unaudited leaf drains the bond before a valid refutation |
| `journal_ge`, `weaker_never_replaces` | specification | The ADR-001 journal ends at least at every valid timely certificate's work, and a weaker certificate never replaces a stronger one |
| `fixed_graph_misses` | impossibility (model) | For any fixed presigned graph, some timely valid certificate has no presigned successor. It is either refused, or admitted through an output the spender chooses |
| `enumerated_leaf_incomplete` | impossibility (model) | A leaf recognising only setup-enumerated certificates misses a stronger one |
| `copy_redirect` | counterexample | An output-blind leaf's accepted spend stays valid with output 0 redirected (front-running) |
| `presigned_binds` | safety (payout) | With A5, a presigned SINGLE signature fixes output 0 |
| `outsider_exists` | impossibility (model) | Chunked verification bound by setup one-time-signature keys excludes some challenger: admission is permissioned |
| `truthful_keeps_bond`, `underclaim_forfeits` | incentive | Claiming the true maximum keeps the bond, and an under-claim beaten in time forfeits. Truthful claiming is weakly dominant, given A4 |

The earlier nine modules (`Blossom`, `UTXORefinement`, `MerkleBinding`, `BitcoinInclusion`, `BitcoinWitnessBinding`, `PaymentChannel`, `PresignedParents`, `RecipientAuthority`, `ContextualFinality`) cover:
- storage-proof acceptance and Merkle-opening collision reductions;
- epoch payment authorization and no replay;
- channel monotonicity;
- collateral conservation, signer-authorized payout disposition, and CSV/CLTV contextual finality.

This review adds no theorem there and relies on them unchanged.

## 3. Assumptions

Every assumption is a hypothesis in Lean, never a postulate.

| | Assumption | Status on Bitcoin today |
| --- | --- | --- |
| A1 | `Env.valid`: PoW per header, linkage to the checkpoint, exact cumulative work, BIP141 inclusion of the certificate | Checked off chain by `model/regtest_header_chain.mjs` and `model/bitcoin_serialized_receipt.mjs` (ADR-013/014). Not checked by any Script |
| A2 | A refutation leaf sound and complete for "timely, valid, stronger than the frozen claim" | **Refuted as realisable** by Core 26 (L1, L2, L3) |
| A3 | Exclusive exits: no keypath, and no leaf beyond refute and refund | Must be audited per output. L6 is the counterexample; the keypath is NUMS in `bond.rs` |
| A4 | A refutation broadcast in time confirms before the deadline | Miner liveness, an ordinary inclusion assumption. Censorship for Δ blocks defeats it |
| A5 | Setup keys are erased; only presigned signatures exist | A trust assumption (committee, 1-of-n honest). ADR-010 shows a retained key redirects |
| A6 | SHA256 collision and second-preimage resistance; BIP340 unforgeability | Standard; folded into A1, A2 and A5. Binohash's ~84-bit grinding bound (ADR notes) is weaker, and is not used here |

## 4. Adversarial review

| Attack | Evidence | Real serialized Bitcoin tx in Core? | Result |
| --- | --- | --- | --- |
| Provider refund bypass | RB01–RB07 (`refund_bypass_consensus_vectors`), C07; Lean `late_refutation_can_lose` | yes (P2WSH, Core 26) | An old independent CLTV refund stays valid. It must be absent from the funded graph |
| Journal exhaustion | C17 (fee depletion), A16 (one-shot gate), `fixed_graph_misses` | model + Lean | A finite presigned journal can be exhausted or blocked |
| Invalid fork certificates | HC03–HC08, HC11, R04, R16 | off-chain verifier (real headers) | Rejected off chain. **On chain, L1 accepts unlinked headers** |
| Witness substitution | ADR-005, T-series, `txid_admission`, ADR-013 negative control | yes | Same txid with a different witness is caught only by BIP141 binding |
| Unrelated witness commitments | `bitcoin_serialized_receipt.test` forged-commitment case | real regtest blocks | Rejected only when bound to the raw coinbase (ADR-014) |
| Collateral payout redirection | ADR-009/010/011 vectors, **L4/witness_copied_redirect**, L5/redirect_output0 | yes (P2WSH and P2TR) | Output-blind leaves are front-runnable. A presigned SINGLE binding holds under A5 |
| Late responses | R09, ADR-010 late-race vectors, `late_refutation_can_lose` | yes (ADR-010) | Branches race after the deadline; an absolute upper deadline needs exclusive leaves |
| Competing challengers | R02, R13, R14, C20, S-series | model | One outpoint, one winner; strict-greater ordering and ties are policy |
| Signature reuse | RB03, J07, ADR-011 signer redirection | yes | A witness-only change reuses the provider signature. Cross-network reuse is stopped by the genesis binding |
| Unenumerated Taproot spend paths | `taproot_spend_inventory` (Rust drift check), **L6/hidden_leaf_drains**, **L3** OP_SUCCESS | yes (P2TR) | Every leaf is a spend path, and an OP_SUCCESS byte anywhere in a leaf makes it anyone-can-spend |

## 5. Architecture selection

| | Mutable strongest-certificate journal (ADR-001) | Stateless existential refutation (ADR-002) |
| --- | --- | --- |
| Economic commitment | The provider must rebut *every* strongest timely certificate | The provider freezes a claim; anyone holding a stronger timely certificate takes the bond. There is no rebuttal of the specific certificate |
| Script capability needed | A single-tx certificate verifier (CAT), **plus** a successor-output covenant carrying dynamic state (journal root, best work) | A single-tx certificate verifier (CAT) only |
| Without a soft fork | Impossible as a fixed graph (`fixed_graph_misses`) | BitVM2 chunking with setup-fixed committers (permissioned, `outsider_exists`) or one huge non-standard tx |
| BitVM assumptions | Committee 1-of-n, Groth16 key, challenger liveness, non-standard MB transactions (phase 6) | Same if chunked; none if CAT is available |
| Presigned transactions | A cursor chain that grows per update and breaks when the certificate bytes differ (C14) | One SINGLE\|ANYONECANPAY refutation payout per frozen claim (L5) |
| Trusted setup | Committee keys; a Groth16 phase 2 if SNARK-wrapped | Committee key for the payout signature (A5); none with a CAT covenant |
| Fee model | Every update pays fees; the cursor depletes (C17) | The challenger sponsors with ANYONECANPAY inputs (L5/sponsor_adds_fee_input) |
| Mining liveness | Every update before the cutoff, and freeze races (cutoff_race) | One refutation before the deadline (A4) |

**Selected:** stateless existential refutation. It needs strictly fewer primitives. Its cost is semantic: it replaces "rebut the submitted certificate" with "be correct about the frozen maximum". That is a change of security game, and it is stated here rather than made silently.

## 6. Minimal counterexamples and the smallest missing primitive

All of these are Core 26-verified P2TR spends (ADR-015):
1. **L1:** with only `OP_SIZE`, `OP_HASH256` and `OP_EQUAL`, a leaf meant to check "h2 extends h1" accepts an h2 whose prev-hash field points nowhere. Script can't extract bytes 4–36 of an 80-byte item.
2. **L2:** `HASH256 <target> OP_LESSTHAN` fails for every input, the real genesis header included. Arithmetic takes at most 4-byte operands, and a hash can't be split into limbs without OP_CAT to re-bind them.
3. **L3:** the OP_CAT version of the verifier is consensus-valid with an *empty* witness and any outputs. 0x7e is OP_SUCCESS126, so deploying it before BIP347 activates would hand the bond to anyone.
4. **L4:** even a sound check leaves the payout to whoever broadcasts first.
5. **L6:** an unaudited leaf beside a correct one drains the bond.

**Smallest additional primitive: OP_CAT (BIP347).** With CAT and native `OP_SHA256`, one tapscript can:
- rebuild each header as `version ‖ HASH256(previous) ‖ rest` (linkage);
- re-bind split hash limbs and compare the top limb with the target (PoW);
- verify a BIP141/BIP37 Merkle path to the certificate.

A header is exactly the 80-byte standard stack-item limit. The payout can then be bound by the presigned SINGLE|ANYONECANPAY signature (L5) or by a CAT-based covenant.

None of this CAT construction has been executed: stock Core treats it as OP_SUCCESS (L3). Two parts aren't even designed in detail yet:
- exact 256-bit work across difficulty retargets, which needs bigint limb arithmetic or per-period targets fixed at setup;
- the script size of the construction.

## 7. Next implementable experiment

Build the L3 leaf for real:
- linkage over `k` real regtest headers from a checkpoint;
- a limb comparison against the regtest target;
- a 1-of-1 SINGLE|ANYONECANPAY payout signature.

Run it against an interpreter with BIP347 active: Bitcoin Inquisition on regtest, or Core with the BIP347 patch.

The test passes when:
- honest k-header refutations are valid;
- each of L1's forgeries, an under-target header, a substituted certificate witness and a redirected output 0 are invalid;
- the transaction stays under 400k weight for k = 151.

This needs your approval to download and build Inquisition. Until then the vectors pin the boundary on stock Core.

A no-soft-fork alternative to measure alongside it: the script size of BitVM's limb-arithmetic SHA256 for one 80-byte header (from the BitVM clone used in phase 6), which bounds how many headers one non-standard transaction can verify.

## 7a. Result of the experiment (ADR-016)

See [ADR-016](cat-refutation-verifier.md). There are 13 real-transaction cases:

| Interpreter | Honest refutations | Attacks rejected | Consensus-valid counterexamples |
| --- | --- | --- | --- |
| Stock Bitcoin Core 26 | 3 valid | 0 of 10 | 10 |
| Core 26 + `research/bip347-check/bip347.patch` | 3 valid (N8, N151, sponsored) | 10 of 10 | 0 |

`model/verify_cat_vectors.mjs` recomputes every verdict with the real 256-bit regtest PoW rule and agrees on all 13. In Lean, `exactN_stronger` and `exactN_leaf_sound` connect the leaf's exact-N acceptance to A2's soundness (fixed difficulty). Both depend on no axioms.

**Next implementable experiments**, in order of value:
1. ~~Cross-check the patch against Bitcoin Inquisition's BIP347.~~ Done in [ADR-018](inquisition-crosscheck.md). Inquisition v29.4-inq's own `VerifyScript` reproduces every verdict, 41 cases with 0 mismatches:
   - with `SCRIPT_VERIFY_OP_CAT` it matches the patch;
   - without the flag it matches stock Core 26;
   - each attack fails at its intended check.
2. Add per-period targets fixed at setup, to handle mainnet retargets.
3. Add a BIP141 inclusion check of the certificate's anchor transaction inside the leaf (CAT Merkle path), for timeliness.
4. ~~Add a presigned leaf per claim value, for dynamic frozen claims.~~ Done in [ADR-017](dynamic-claim-freeze.md).

**ADR-017 (dynamic claims).** Setup presigns one freeze transaction per claim. The provider completes one at the cutoff, and a CLTV forfeit pays the client if the provider never freezes. 12 more real-transaction cases match on Core 26 + BIP347:
- only listed claims can be frozen, and only with the setup signature;
- the refund cannot come early;
- a fork equal to the claim does not refute, and any longer fork refutes through its prefix.

The whole file has 25 cases with 0 mismatches. Stock Core shows 11 counterexamples, and the BIP347 build shows 0.

## 9. Remaining items

Status after [ADR-019](pinned-difficulty-schedule.md):
- **Retargets are built** for forks on a schedule pinned at setup. Real mainnet headers 32251–32262 cross the 32256 retarget, with 0 mismatches across Core 26 + BIP347, Inquisition and the Node consensus check. Exact work is computed at setup, and `sched_leaf_sound` makes it sound. A fork that retargets differently is refused; that is a completeness limit, not a counterexample.
- **Timeliness is characterized.** `no_expiry` (Lean) proves that no Bitcoin timelock expires, and a trusted anchor needs a covenant (`fixed_graph_misses`). Timeliness therefore needs a covenant or oracle beyond OP_CAT's verifier, or it accepts the A4 race.

The original text follows for the record.

1. **Retargets (mainnet).** A header's work is `2^256 / (target + 1)` from its nBits. Exact cumulative work in one tapscript needs that 256-bit division for every header, plus the retarget rule (a timestamp difference over 2016 blocks). Either can be written with OP_CAT limb arithmetic, but neither is measured. The cheaper sound variant has the leaf pin nBits per difficulty period at setup, as ADR-016 does for one period. That admits forks only on the pinned schedule: it is sound, but incomplete for forks that retarget differently. Lean's `exactN_leaf_sound` covers the fixed-difficulty case only.
2. **Timeliness.** Bitcoin has no "valid only before height h" timelock. The refutation window is closed only by the refund spending the output after the deadline, which is A4 (`late_refutation_can_lose`). Proving that the fork *existed* by the cutoff needs an anchor: for example, the fork tip committed in a transaction confirmed on the claimed chain before the cutoff, proven in the leaf by a Merkle path, which is possible with OP_CAT. That makes the refutation depend on main-chain headers too. Header timestamps alone don't establish it, because miners choose them within the median-time-past and two-hour rules.

## 8. Commit and CI record

Commit `ba8138d`. All three workflows passed, as read from the public API:
- [Lean #39891395693](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39891395693):
  - Lean 4.15.0 kernel-checked all ten modules, including `CertificateAdmission.lean`.
  - The axiom gate passed: 14 `#print axioms` lines, standard axioms only.
  - The same run's Taproot job passed the three ADR-015 steps: generator, independent Node verdicts, and Core 26 with Taproot flags.
- [Binohash model #39891395830](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39891395830): the Node research suite, including the new AV tests, the TypeScript tests and the offline Core legacy suites.
- [Full-node regtest #39891395713](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39891395713): unchanged settlement harness, still green.

Commit `3a8c698` (ADR-016). All three workflows passed:
- [Lean #39893706998](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39893706998):
  - Lean 4.15.0: all modules, and the axiom gate with 16 theorems.
  - The Taproot job's ADR-015 steps.
  - The four ADR-016 steps: generator; independent verdicts with the real PoW rule; stock Core 26, where all 13 cases are valid; Core 26 + BIP347 patch, where the 3 honest cases are valid and the 10 attacks invalid.
- [Binohash model #39893706990](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39893706990): Node suite, 425 tests locally.
- [Full-node regtest #39893707005](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39893707005).

ADR-017 (`1561509`, docs fix `2ecff90`). The 1561509 runs were superseded by 2ecff90, which re-ran every workflow over the PR diff, and all passed:
- [Lean #39894483452](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39894483452): includes the 25-case ADR-016/017 file on stock and BIP347-patched Core 26.
- [Binohash model #39894483434](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39894483434).
- [Full-node regtest #39894483293](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39894483293).

ADR-018 (commit 1656574). All passed:
- [Lean #39907229241](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39907229241): its new job, ADR-018 Bitcoin Inquisition v29.4-inq interpreter cross-check, built Inquisition from source on the runner and reproduced every verdict with and without SCRIPT_VERIFY_OP_CAT.
- [Binohash model #39907229214](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39907229214).
- [Full-node regtest #39907229207](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39907229207).

The issues and PR could not be updated from here: comments need auth, and this flow has none. The text for #2 and #3 is below.

## Tracking issue update (text for #2 and #3)

> ADR-015 (`docs/binohash-admission/script-capability-boundary.md`) and the review (`certificate-to-collateral-enforcement-review.md`): BLOCKED on OP_CAT (BIP347).
>
> - Core 26 Taproot vectors: 16 cases, 5 consensus-valid counterexamples. Unlinked headers pass a no-CAT linkage leaf; no 256-bit target check is expressible; a CAT leaf is OP_SUCCESS (anyone-can-spend) today; an output-blind verdict can be front-run; a hidden leaf drains the bond.
> - Lean `CertificateAdmission.lean`: refutation safety, liveness and incentives are conditional on A2–A5, plus the fixed-graph journal impossibility.
> - Selected: stateless refutation with a presigned SINGLE|ACP payout.
> - ADR-016: on Core 26 with a local BIP347 patch, a one-tx OP_CAT refutation leaf accepts real stronger regtest forks (N=8, N=151 at 19,428 WU) and rejects all 10 attacks. On stock Core all 10 are valid. BIP347 activation is the exact missing primitive.
> - ADR-017: dynamic frozen claims via a presigned freeze set (25 cases total, 0 counterexamples under BIP347).
> - ADR-018: Bitcoin Inquisition v29.4-inq's interpreter reproduces all verdicts with and without its OP_CAT flag (41 cases, 0 mismatches).
> - Next: retarget-aware work and timeliness (review §9).
