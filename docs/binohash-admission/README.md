# Binohash and permissionless Bitcoin storage-bond challenges

**Status: RESEARCH / BLOCKED AT BITCOIN-ENFORCED DYNAMIC CERTIFICATE ADMISSION.** This branch contains real Bitcoin transaction serialization, legacy Script ECDSA tests, a tiny unfunded Bitcoin Core consensus check, and several explicitly idealized protocol specifications. None is a deployable storage-bond contract.

**272 deterministic Node tests and 39 offline Bitcoin Core 26 input Script cases passed in GitHub CI** ([witness-binding run](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39817682863)). The Core harness checks three scripts separately on one unfunded transaction. It does not establish real UTXO spendability, Bitcoin block validity, or a deployable bond.

```bash
node --test model/*.test.mjs
node model/binohash_consensus_vectors.mjs > /tmp/binohash-vectors.json
cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/binohash-vectors.json
```

No bitcoind, block mining, GPU proofs, or funded pilot runs are invoked by these commands. The GitHub workflow runs these checks on the research branch and PR.

## Two protocol directions

**[ADR-001: Mutable journal cursor](cursor-architecture.md).** Each challenge replaces one UTXO containing the journal state. Settlement co-spends that live cursor and the bond, invalidating settlements on older outpoints. The blocker is authorization of a unique, permissionlessly generated valid successor without allowing a malicious challenger to burn or redirect the cursor. The Binohash toy demonstrates why a fresh signature can also authorize an unwanted transaction when the actual successor policy is absent.

**[ADR-002: Stateless stronger-fork refutation](stateless-refutation-alternative.md).** Freeze the provider's exact work assertion at cutoff and allow any stranger to refute it with **one** verified, Bitcoin-anchored, strictly stronger fork. A weaker submitted candidate cannot consume collateral, so later stronger candidates remain actionable. This can avoid maintaining a maximal-work journal, but it changes the provider-claim and rebuttal semantics. The challenger must supply a dynamically verifiable exact-work proof, whose validity, inclusion, binding and fixed payout the current model assumes as external predicates.

**[ADR-003: One-hop protected composite cursor](one-hop-composite.md).** A previously authorized SIGHASH_SINGLE|ANYONECANPAY signature pins the next cursor amount and script for a single known parent outpoint, while a toy Binohash input cryptographically binds the candidate's transaction data. Core Script accepts fresh certificate commitments while rejecting Binohash regrinds that burn the protected successor. The parent txid changes with each new certificate; a second transition needs a newly authorized signature. This protects exactly one dynamic transition and does not solve recursion.

**[ADR-004: BIP141-anchored challenge witnesses](witness-anchored-certificates.md).** A SegWit certificate witness can leave its txid unchanged while changing its wtxid and eventual coinbase witness commitment. The composite signs SHA256(certificate) in OP_RETURN. Synthetic BIP141 proofs authenticate which witness bytes a hypothetical block included; a separate BitVM verification predicate must compare those bytes to the signed output commitment. All three script inputs pass the offline Core consensus check, including a mutated witness that fails the off-chain certificate-equality predicate.

## What is reproducible

- `model/binohash_finddelete_poc.mjs` and `secp256k1_legacy_demo.mjs`: insecure low-security ECDSA/FindAndDelete proof of concept, signed toy transactions
- `model/binohash_consensus_vectors.mjs`, `model/binohash_linked_cursor_vectors.mjs`, `model/single_acp_successor_vectors.mjs`, `model/composite_cursor_consensus_vectors.mjs` and `research/consensus-check/`: unfunded raw transaction checks using vendored Bitcoin Core's consensus Script engine, including a three-input composite
- `model/stateless_refutation*.mjs`: 22 stronger-work existential counterexample tests with explicit external-oracle assumptions
- `model/stateless_public_input*.mjs`: 13 canonical 32-byte RISC Zero journal schema tests, including exact uint256 work, payout script and collateral binding
- `model/journal_cursor*.mjs`, `model/cutoff_race.test.mjs` and `model/utxo_admission_graph*.mjs`: cursor races and refund bypass
- `model/contest_spec*.mjs`: idealized maximal-work journal and rebuttal state
- `model/recursive_sighash_boundary.test.mjs`: each non-bug legacy sighash binds its current prevout, while the historical SINGLE bug discards its output constraint; this narrows the recursive pre-signature route
- `model/witness_anchor*.mjs` and `model/composite_witness_binding.test.mjs`: 28 deterministic synthetic BIP141 commitment and certificate-equivalence tests. They verify Merkle arithmetic but do not authenticate a real header chain.
- `model/txid_admission*.mjs`, `model/legacy_sighash*.mjs`, `model/cursor_sighash.test.mjs`: transaction serialization, verified sighash vectors, and input binding
- [Transaction-level acceptance checklist](next-step.md), [initial adversarial review](../binohash-admission-review.md)

## Missing integration

The local Phase 7 regression `4494714` and its six-transaction/151-header fixture remain unavailable in this GitHub remote. The research branch starts from pushed `phase-6-bitvm2-spike`. The real spending graph has not been integrated or proven safe; old provider-only refund paths remain a known bypass.

The PR is intentionally draft. Any deployed solution must protect every collateral exit, validate arbitrary challengers' exact work and anchoring, and enforce the admission cutoff and payout with current Bitcoin consensus rules. The miner/relay question for full Binohash remains deferred.
