# ADR-002: Stateless stronger-fork refutation

**Status:** Research alternative, model-only. **Exact cumulative work and permissionless admission are retained as required predicates.** This proposal has **not** constructed a Bitcoin consensus-valid verifier or collateral payout. The existing journal-cursor ADR-001 remains active.

## The observation

If the provider's frozen claim is exactly:

> At cutoff height T, the provider selected fork F with cumulative work W, and there exists no eligible publicly committed fork with greater cumulative work.

then a single eligible fork with **verified** work W' > W falsifies the statement. A challenger does not need to identify the strongest fork among all available forks to establish this counterexample. This is an *existential refutation*:

```text
Provider asserts at cutoff T: selected-work = W
     |
     +-- provider may refund only after dispute deadline D
     |
     +-- anyone may prove:
           certificate C committed in Bitcoin by T
           C is tied to the same claim
           C contains valid linked Bitcoin headers
           exact_chain_work(C) > W
           spend is tied cryptographically to C
           payout is restricted to predetermined recipients/amounts
           challenge transaction confirms by D
            |
            v
         forfeit bond
```

A weak challenger who only possesses 100 work against a claim of 120 has an invalid refutation branch and leaves the collateral spendable for a later challenger presenting 151 work. If a challenger successfully proves 151 and takes the collateral, later challengers offering 160 need no further admission *for the binary truth of this claim*, because 151 already disproved it. This is a **different payout and dispute policy** from a provider-rebuttal protocol that must handle every valid stronger timely challenge.

No mutable journal-cursor UTXO is needed to encode an ever-growing maximum. There remains a fixed provider claim, a proof-of-inclusion requirement for any selected certificate, and a single global collateral input, whose valid spend can win only once.

## Public-input bridge into the existing Phase 6 prover wrapper

`model/stateless_public_input.mjs` defines a canonical byte serialization and one 32-byte SHA-256 journal digest for future RISC Zero guest output. The existing `zk/risc0/host/src/wrap.rs` requires a 32-byte RISC Zero journal and the existing `zk/bitvm-check/src/main.rs` verifies a Groth16 proof against one public field element, so this interface fits the *size* of the current pipeline. It does **not** mean that the existing guest proves the new refutation statement.

Encoded fields, all domain separated and versioned:

- Bitcoin network genesis hash, provider frozen-claim commitment and challenger certificate digest
- Challenger fork tip and provider/challenger work as unsigned 256-bit big-endian integers
- Bitcoin anchor block hash, its confirmation height, admission cutoff and dispute deadline
- Collateral outpoint (Bitcoin txid serialized little-endian, vout little-endian)
- SHA-256 of the exact payout scriptPubKey

`model/stateless_public_input.test.mjs` contains 13 independent binding/encoding tests. An actual guest must recompute the digest *from cryptographically verified data* and commit that exact digest as its output. This JS adapter currently hashes arbitrary caller-supplied values, so its output remains untrusted. The final construction must bind that digest to the actual Bitcoin transaction and prohibit arbitrary payout scripts. Encoding the payout-script hash alone is insufficient enforcement.

## Model implementation

- `model/stateless_refutation.mjs`: frozen claim, counterexample digest, exact unsigned 256-bit work comparison and reference contest.
- `model/stateless_refutation.test.mjs`: 22 adversarial examples `R01-R22`.
- Four enforcement predicates are explicitly **external oracles**: `verifiedAnchor`, `verifiedExactWork`, `transactionBound`, `fixesPayouts`.

The test harness supplies those predicates as booleans. Passing those tests proves only that the specification is internally consistent *given correct cryptographic/consensus verification*.

## Important change in security statement

A counterexample with more work does **not** establish it is Bitcoin's actual canonical chain. Bitcoin nodes may have different views of valid competing chains, a private heavier fork may be unknown, and a chain reorganization can invalidate the on-chain commitment used as an anchor.

This alternate contract enforces only a precise public assertion about the existence of an eligible higher-work fork under specified anchor, cutoff, and validity rules. It does not automatically reproduce the original storage-proof semantics.

A real fork certificate must commit to a specific sequence of headers and an objective starting point, establish full validation conditions relevant to those headers (including target adjustments, timestamps, consensus rules, linkage, and starting-state assumptions), and compute 256-bit exact cumulative work. A Boolean like `verifiedExactWork=true` is not cryptographic evidence.

**Cutoff interpretation:** `inclusionHeight` should mean the block height at which a commitment to the *specific certificate digest* was confirmed on the canonical reference Bitcoin chain. A challenger may reveal its preimage/proof later, within D. This is distinct from requiring a privately mined fork to be a part of Bitcoin's canonical chain. Proving anchor inclusion requires an independently valid chain of Bitcoin header commitments, transaction Merkle inclusion, and explicit reorg handling.

## Threats this removes

- No current cursor that anyone can burn into an arbitrary output.
- No journal-completeness oracle: the challenger only proves the existence of **one** correctly anchored stronger fork.
- No first-weak-challenger connector that consumes collateral before proving stronger work.
- No global sort/max over multiple submitted certificates when the only remedy is forfeiture.

## Remaining hard obligations

1. **Generic proof at runtime.** The challenger must supply an arbitrary strong fork certificate and convince a Bitcoin-enforced verifier of its validity. Standard BitVM2's operator-prover commitments and permissionless fraud-challenger roles do not automatically supply a stranger's fresh proof of a dynamic statement. Replacing `verifiedExactWork` with an on-chain spend condition is a substantial independent protocol design. This alternative may require challengers to participate as provers or a modified interactive rebuttal construction.
2. **Binding to actual transaction.** A consensus-valid Binohash or other legitimate carrier must make the actual spend, the fixed claim, the chosen proof commitment and payout destinations consistent. The local toy Binohash Script is an **insecure, unconstrained two-selection demo**, and cannot serve as this verifier. In the offline Bitcoin Core experiment, a fresh Binohash signature for a burning output is accepted. Therefore the permitted payout requires independent authorization beyond the bare transaction-binding puzzle.
3. **Confirmed anchor versus cutoff.** The claim needs a Bitcoin consensus-enforceable rule that the certificate commitment was included by T. `nLockTime` alone cannot establish this historical upper bound or check block inclusion.
4. **Challenge/refund races.** The provider refund must be provably unavailable through every other Taproot or legacy script leaf before D. After D, valid challenge transactions must become ineligible under actual spending rules, not a local boolean.
5. **Data availability and resource costs.** A stranger must be able to prepare and publish the large header certificate and any BitVM witness before expiry. Fee pressure, miner censorship and nonstandard legacy script relay are real deployment constraints.
6. **Equal-work policy.** A strict greater-than predicate intentionally does not slash for equal-work conflicting forks. That rule must agree with the application's actual definition of what makes a storage proof valid.
7. **Reorganizations.** An SPV anchor at height T may disappear or move after a reorg. Define confirmation depth, alternate-branch treatment, and a dispute clock that continues safely across reorganizations.

## Recommendation for next executable milestone

Keep both research alternatives in draft. Test the stateless model against a genuine fixed Bitcoin collateral script under two candidate classes:

- A **single-step challenger-supplied SNARK verifier** with a complete chain-work and anchor proof accepted by a fully on-chain executable spending condition.
- A **BitVM2-style challenge graph** in which anyone can invoke an already-precommitted verifier that evaluates a dynamic certificate without a mutable winner cursor, and where only successful proofs can invalidate collateral settlement.

Produce one consensus-valid spend accepting a fresh certificate while rejecting weaker, forged, unanchored or differently paid certificates. Accept an explicit, small counterexample if existing Bitcoin Script cannot enforce the required path. Do not mistake a passing model or a toy Binohash puzzle for a solved protocol.

## Current status

This proposal is a change in the provider's claim and dispute semantics. Review it against the existing requirement that the provider must answer the *actual submitted certificate*. The original provider-rebuttal route remains an option if that interaction is required.

No new ZK proofs, mining, funded transactions or pilot deployments have been initiated.
