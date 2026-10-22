# Lean formalization: Blossom storage proofs and payment mechanics

Status: **kernel-checked safety theorems about an abstract storage/payment protocol**, with explicit cryptographic assumptions and an unproved Bitcoin consensus refinement boundary. This work is on the draft `research/binohash-admission` branch.

## Scope and exact source mapping

The original `model/storage_bonds.ts` has two economic layers:

1. **Pay per proof.** The client supplies a fresh nonce, computes sampled 4 KiB ciphertext-chunk indices, verifies supplied Merkle chunk paths against the agreed root, then pays that epoch through Lightning.
2. **Sentinel collateral.** The provider locks a pre-signed Taproot bond at state `Bond_i`. A client challenge reveals a salted sentinel secret and consumes `Bond_i` to `Challenged_i`. A correct provider preimage response spends `Challenged_i` to the *next live* `Bond_(i+1)`. After a CSV delay, a missing response allows client forfeiture. The provider may refund a still-live `Bond_i` after the term-end CLTV condition, subject to all actual spend paths.

The current Lean files:

- [`formal/Blossom.lean`](../../formal/Blossom.lean): the state machine, deal/root-bound epoch proof prerequisite, replay-resistant paid-epoch ledger, sentinel rounds, bond accounting and miner fees.
- [`formal/UTXORefinement.lean`](../../formal/UTXORefinement.lean): bond prevout identity, consumed outpoints, output scripts, payout amounts, fees, witness/timelock predicates and forward simulation over arbitrary transaction histories.
- [`formal/MerkleBinding.lean`](../../formal/MerkleBinding.lean): an unconditional Merkle collision-reduction theorem for conflicting openings at the same checked sample index, plus an explicit counterexample to treating Lightning payment as proof of storage.

## Kernel-checked theorems

### Bond accounting and authorizations

`accepted_samples_authenticated` states what the abstract acceptance predicate grants for every sampled index. `increased_revenue_requires_bound_fresh_epoch` strengthens the payment rule: a revenue-changing step carries an accepted proof whose deal ID and Merkle root match the agreed contract, with a nonempty sampled-index set and an epoch ID absent from the paid ledger. The proof also includes a nonce field, whose randomness and binding to sampled indices remain verifier obligations.

`step_retains_paid_epochs`, `reachable_retains_paid_epochs` and `paid_epoch_cannot_be_replayed_after_history` prevent a paid epoch ID from becoming eligible for payment again after any length of authorized state history. `step_keeps_deal_and_root` and `reachable_keeps_deal_and_root` prove the committed deal identity and replica root remain unchanged through payment, challenge, response, refund and forfeiture. The actual Lightning payer must persist paid-epoch state and authenticate invoice identifiers for this abstract rule to describe its behavior.

`step_preserves_bond`, `reachable_preserves_bond` and `any_reachable_bond_is_conserved` prove that **locked + provider released + client forfeited + miner fees** remains equal to initial bond value across all authorized histories. This required a substantive revision: terminal settlement subtracts the fee from the recipient payout; a challenge or successful response can also pay fees out of the live locked amount. A successful sentinel response *advances the round* and reopens the bond, rather than paying out the provider.

`terminal_is_absorbing` ensures that a refunded or forfeited bond cannot continue through a protocol Step constructor.

### Bitcoin UTXO refinement boundary

`admitted_refines_abstract` proves a one-transaction forward simulation from a checked UTXO bond spend to the appropriate abstract Step, covering script-path authorization, value equation, payout recipient, fee and successor.

`old_prevout_cannot_be_reused` uses an actual consumed-outpoint list in the formal ledger. `terminal_spend_prevents_further_bond_spends` and `response_advances_round` prove that spent collateral cannot be reused and that a response creates the next live bond round.

`bitcoin_run_refines_abstract` and `arbitrary_run_conserves_bond_including_fees` extend the simulation to **arbitrarily long chains of transactions**, conditional on `ConsensusCoverage`. That premise is:

```
For every state and transaction:
  RealBitcoinConsensusAccepts(state, tx)
    implies admitted(state, tx)
```

In the actual code this is parametrized as `ConsensusCoverage bitcoinAccepts`. It is an **unproved implementation-security obligation**, and is exactly where script-path exhaustiveness, real BIP341/342 witness/script checks, sighash commitment coverage, UTXO ownership and output binding must be established. The internal theorem `formal_ledger_initial_value_conserved` instantiates acceptance with the formal `admitted` predicate, so it cannot certify real Bitcoin consensus.

`unenumerated_path_counterexample` proves that admitting an unspecified path breaks the implication from generic spend acceptance to the formal authorization rule. `independent_journal_refund_bypass` formally witnesses an old provider refund that passes its local CLTV/UTXO checks despite an unanswered external stronger-fork challenge. These are explicit logical counterexamples, complementing the unfunded Bitcoin Core counterexample of ADR-006.

### Storage-commitment binding

`parallel_path_collision_or_equal` handles two Merkle paths with the same left/right orientation bits, even with different sibling hashes. `two_verified_openings_imply_collision` proves that distinct chunks opening the same committed root at a fixed indexed path force a collision at either the domain-separated leaf hash, internal-node compression hash, or count-bound root hash.

`checked_same_index_openings_imply_collision` additionally checks both openings against the same index's direction bits and a common path depth. Hence different payloads accepted at that same position imply a concrete collision witness. `unique_chunk_if_collision_free` is the conditional uniqueness corollary when no such collisions occur.

These theorems treat the hash functions as **arbitrary functions**. They do not assume global injectivity of 256-bit SHA-256, which is mathematically impossible on unbounded messages. The remaining computational assumption is that an adversary cannot feasibly find one of the exhibited SHA-256 collisions. Formal treatment of SHA-256 collision-resistant security and the exact TypeScript buffer encoding is separate.

`lightning_alone_does_not_certify_storage` exhibits a settled invoice with no accepted sample proof. The verification-before-payment rule must be enforced by the **client application**, rather than being inferred from the Lightning protocol.

## Remaining architecture proof obligations

1. **Exact Merkle verifier correspondence.** Show that `model/storage_bonds.ts` computes the same indexed leaf, inner-node and root bytes, including the 4 KiB chunk padding, chunk-count commitment, odd-sibling duplication, path length and index validity. The Lean Merkle model currently takes an explicit tree depth and assumes every path was produced according to the committed tree geometry.
2. **Sentinel response soundness.** Link salted sentinel hashes to the correct ciphertext windows and prove that every exposed Taproot response path checks the required preimages and preserves the agreed replica root/next round. Hash collision resistance, challenge-secret unpredictability and setup cut-and-choose honesty are cryptographic/economic assumptions.
3. **Bitcoin consensus coverage.** Audit all Taproot key paths and script leaves, exact BIP341/342 signatures/sighash, sequence-based BIP68/112 CSV finality, BIP65 CLTV, confirmation rules, and every possible collateral exit. Current `UTXORefinement` enumerates challenge, response, forfeit and term-end refund. It intentionally excludes cooperative close/keypath cases until their recipient splits and actual signature conditions are formalized. No existing theorem states that Bitcoin Core satisfies `ConsensusCoverage`.
4. **Confirmation/liveness and adversarial timing.** The Lean Step semantics encode eligibility of a confirmed transition. They do not establish eventual miner inclusion or an absolute response upper deadline. Competing valid Bitcoin transactions still race for the same UTXO.
5. **Lightning settlement correctness.** Verify the real client's fresh-nonce generation and its deterministic binding to sample indices, authenticated deal/epoch identifiers, durable exactly-once receipt persistence, unique invoices and actual Lightning settlement. Lean prevents repeated epoch authorization in its model; the application/Lightning bridge is unproved. A valid Merkle proof is necessary for the modeled authorization; a real payer can still voluntarily send Lightning value outside this application policy.
6. **Economic security.** Formally state independent uniform sample assumptions for the `f^q` deletion-detection model, multi-window sentinel survival, dishonest setup cut-and-choose and incentive conditions. The TypeScript estimators are not Lean proofs.
7. **Independent fork-admission game.** The Binohash/BitVM fork-certificate journal in ADR-001 to ADR-010 remains a separate contract design, with an old CLTV refund bypass in ADR-006. Its soundness does not follow from this sentinel-bond accounting proof.

## Reproduce

CI: `.github/workflows/blossom-formal.yml` uses pinned Lean 4.15.0 and rejects `sorry` or `admit` before compiling.

```sh
lean -o formal/Blossom.olean formal/Blossom.lean
LEAN_PATH=formal lean formal/UTXORefinement.lean
LEAN_PATH=formal lean formal/MerkleBinding.lean
```

The existing Node and Bitcoin Core Script regressions are independent test suites. Their success establishes only the properties they explicitly execute. Lean theorems establish mathematical consequences of the stated formal predicates.

## Handoff milestone

The next most useful formal PR is a **Taproot spending-path refinement matrix**, beginning with the on-chain sentinel contract's actual `regtest/src/bin/bond.rs` transaction templates and every Taproot key path/leaf. One proven unauthorized escape should halt a full-architecture security claim even if all the abstract preservation theorems continue to pass.
