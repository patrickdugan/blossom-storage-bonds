# ADR-012: Signer-controlled economic disposition and contextual settlement finality

**Status:** Lean 4 kernel-checked on `research/binohash-admission`, with executable height-only model cross-checked against real serialized Rust templates. This is a formal and regression-tested refinement of the storage-bond economic model. It does **not** establish complete Bitcoin consensus coverage, full-chain settlement, or dynamic Binohash/BitVM fork-cert admission.

## 1. Correcting the unilateral payout rule

ADR-011's Bitcoin Core 26 Taproot witness matrix proves that the existing refund and forfeit leaves authorize the **provider** and **client** respectively through Schnorr signatures and timelocks. A fresh signature by the relevant signer can choose a different Bitcoin output script. The counterexample is a valid *exercise of the authorized claimant's disposal right*. A stale signature over the old output is invalid.

`formal/UTXORefinement.lean` now treats `recipientExpected` as a fixed-output predicate for **pre-signed challenge/response successor transactions**, while for `.refund` or `.forfeit` it accepts a signer-selected destination. The `.cooperative` path remains an abstract jointly authorized split; its two signatures and settlement amounts still require the real MuSig2/refinement bridge.

The `Account.provider` and `Account.client` counters track **economic entitlement/disposition**, not guaranteed physical receipt at any named address. If the protocol needs direct on-chain payment to a fixed destination, its current unilateral Script leaves cannot enforce that. It would need a complete pre-signed output template, a covenant, or a different enforceable adjudication construction.

`formal/RecipientAuthority.lean` preserves the former rule as `strictRecipientExpected` and `strictAdmitted`. It proves:

- `signer_discretion_refutes_fixed_recipient_coverage`: the old strict Bitcoin-to-protocol claim fails.
- `terminal_signer_disposition_refines_admission`: a terminal transaction with verified unilateral Script authorization, valid outpoint/value/lock and a single payout amount satisfies the **revised** UTXO admission predicate.
- `forfeit_redirect_meets_revised_admission` and `refund_redirect_meets_revised_admission`: positive counterexamples become permitted signer-controlled settlements.
- The economic ledger credits the signer whose disposal right was exercised. The actual output may pay another person.

These theorems have **external premises** for validated Schnorr signatures, Taproot UTXO membership, and output binding. The [39-case offline Bitcoin Core matrix](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39877272463) independently confirms the concrete authorized-redirection examples; its other 31 adversarial rejects and six honest accepts remain.

## 2. Contextual CSV and CLTV obligations

Bitcoin Core's per-input Script library checks OP_CSV/OP_CLTV but cannot determine the birth height of a synthetic outpoint, a candidate block's effective height, or whether a complete transaction is final there.

`formal/ContextualFinality.lean` and `model/contextual_finality.mjs` therefore state separate height-only obligations:

- **Forfeit (BIP112 + BIP68):** version at least 2, sequence disable bit clear, block-based sequence type, sequence magnitude at least the 144-block Script minimum, *and* candidate inclusion height at least the spent challenged output's confirmation height plus the actual signed sequence delay. The BIP68 delay uses the sequence value, even if it exceeds the script's minimum.
- **Refund (BIP65 + nLockTime finality):** the signed height-based `nLockTime` is at least the Script's term-end height and the input sequence is nonfinal; the candidate confirming block must have height strictly greater than that `nLockTime`.

The actual Rust terminal templates use `Sequence::from_height(144)` and `LockTime::from_height(t_end)` respectively. The independent transaction parser checks these fields. Executable model regressions confirm the 500→644 BIP68 boundary and `960000→960001` CLTV boundary, and reject unsupported time-based/MTP cases instead of silently assuming height finality.

**Main proof results:** `contextual_csv_waits_at_least_contract_delay`, `refund_confirmation_follows_contract_height`, `csv_opcode_without_maturity_counterexample`, `cltv_opcode_without_transaction_finality`, `contextual_forfeit_requires_bip68`, `contextual_refund_requires_absolute_height`, and `contextual_admission_refines_protocol`.

Lean now also proves `contextual_history_refines_abstract` and `contextual_history_conserves_economic_bond`: under that authenticated contextual coverage premise, arbitrary-length chains of timed bond spends refine the authorized storage-bond transition relation and conserve the economic collateral plus miner fees. The assertion still depends on trustworthy Bitcoin proof of each transaction's UTXO and timing context.

`ContextualConsensusCoverage` remains an explicit **unproved** premise that the actual Bitcoin block/UTXO validator authenticates these conditions. This module does not formalize MTP, BIP68 time-based sequences, block-header work, coinbase maturity, active-chain membership, UTXO creation height provenance, relay, package policy or miner liveness.

## 3. Timing and payout threats that still matter

- A provider refund and client challenge may both remain eligible after term end until one confirms. The existing `mature_live_bond_has_competing_challenge_and_refund` theorem witnesses their shared source state.
- A valid provider response may still race with a forfeit after the forfeit becomes spendable. Neither CSV nor CLTV gives a spend an exclusive *upper* deadline.
- Old provider-only refunds ignore independent Binohash fork-admission journals (ADR-006); recursive permissionless challenge admission and exact-work proof verification remain blocked.
- Pre-signed zero-fee sentinel parents preserve bond value while external CPFP wallets pay package fees. The accounting distinction is formalized in `PresignedParents.lean`.
- Invoice authenticity, persistence, random epoch challenge soundness, and actual storage possession remain their own payment-security obligations.

## 4. Reproduce

```sh
lean -o formal/Blossom.olean formal/Blossom.lean
LEAN_PATH=formal lean -o formal/UTXORefinement.olean formal/UTXORefinement.lean
LEAN_PATH=formal lean formal/RecipientAuthority.lean
LEAN_PATH=formal lean formal/ContextualFinality.lean
node --test model/contextual_finality.test.mjs
node --test model/*.test.mjs
cargo run --locked --release --manifest-path regtest/Cargo.toml --bin bsb-formal-evidence > /tmp/bsb-taproot-evidence.json
node --experimental-strip-types model/verify_formal_evidence.mjs /tmp/bsb-taproot-evidence.json
cargo run --release --manifest-path research/consensus-check/Cargo.toml --bin taproot-evidence < /tmp/bsb-taproot-evidence.json
```

**Funding, mining, live Bitcoin broadcasts, proof jobs, and pilot deployment remain deferred.**