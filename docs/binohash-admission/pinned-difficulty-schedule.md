# ADR-019: retargets through a pinned difficulty schedule, on real mainnet headers

Date: 2026-10-23. Status: experiment done.
- It closes ADR-016's open item 2 (retargets) for forks on the pinned schedule.
- It characterizes item 4 (timeliness) as needing a primitive beyond OP_CAT.

## Retargets

`leaf_sched` in `regtest/src/bin/cat_verifier_vectors.rs` pins one nBits per height at setup. Write a header's nBits as exponent e and mantissa m; its target is m·256^(e−3).

For each header the leaf:
1. Rebuilds the header with the pinned nBits.
2. Splits the hash into `lo(e−3) ‖ m3(3) ‖ z(32−e)`. It requires z to be all zero and 0 ≤ m3 < m, which is the consensus rule minus the measure-zero equality edge.
3. Re-binds `lo ‖ m3 ‖ z` to `HASH256` with OP_CAT.
4. Carries the hash on as the next header's prev.

Each header's exact work, 2^256/(target+1), is computed at setup for the pinned schedule and never in Script. In Lean, `schedWork_strictMono` and `sched_leaf_sound` show that exactly N scheduled headers refute a claim of N−1.

**Data.** The test uses real Bitcoin mainnet blocks 32251–32262, rooted at block 32250 (`000000002931f8c7…1719`). They were fetched from mempool.space and embedded in the generator. The generator checks the linkage and `validate_pow` for each one. nBits moves from `1d00ffff` to `1d00d86a` at block 32256, the first difficulty change.

| Case | Core 26 + BIP347 | Inquisition + OP_CAT | Design |
| --- | --- | --- | --- |
| M/honest_mainnet_retarget (12 headers, 2,159 WU) | valid | valid | ok |
| M/pinned_without_retarget | invalid (EQUALVERIFY) | invalid | refused: the completeness limit |
| M/truncated_11_of_12 | invalid (stack) | invalid | forbidden |
| M/weak_tip | invalid (mantissa OP_VERIFY) | invalid | forbidden |
| M/forged_mantissa_limb | invalid (EQUALVERIFY) | invalid | forbidden |
| M/redirect_output0 | invalid (Schnorr) | invalid | forbidden |

The vector file now has 31 cases, all agreeing across the generator, `model/verify_cat_vectors.mjs` (the real compact-target rule), stock Core 26 (16 counterexamples), Core 26 + BIP347 (0) and Inquisition in both modes.

**Limit.** A fork that retargets differently from the pinned schedule is refused (`pinned_without_retarget`). Accepting any valid retarget would mean checking the retarget rule in Script: the 2016-block timestamp span, the ×4 clamp, and the 256-bit `target × span / 1209600` product. That is OP_CAT limb arithmetic, which is possible but neither built nor measured.

## Timeliness: OP_CAT is not enough

1. **No expiry.** Every Bitcoin height condition is "not before" (CLTV, CSV). In Lean, `no_expiry` shows that no conjunction of them is valid at d and invalid at d+1. A refutation leaf therefore can't close its own window. Only the refund spend can, which is A4 (`late_refutation_can_lose`).
2. **No trusted anchor.** Proving that a fork existed by the cutoff means anchoring it to a chain the leaf trusts.
   - A chain supplied by the challenger proves nothing: heights on a self-built chain are arbitrary.
   - Anchoring to the provider's frozen tip would mean presigning one freeze per possible tip hash, and `fixed_graph_misses` rules that out without a covenant.

   So timeliness needs one of three things: a covenant that carries the provider's tip into the frozen output (CAT plus a Schnorr introspection trick, or CTV with CSFS), an oracle attestation, or the current race semantics.

## Reproduce

```bash
cargo run --locked --release --manifest-path regtest/Cargo.toml --bin bsb-cat-verifier-vectors > /tmp/adr016.json
node model/verify_cat_vectors.mjs /tmp/adr016.json
bash research/bip347-check/prepare.sh && cargo run --release --manifest-path research/bip347-check/Cargo.toml < /tmp/adr016.json
bash research/inquisition-check/run.sh /tmp/adr015.json /tmp/adr016.json /tmp/inq-work
```
