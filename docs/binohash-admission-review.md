# Binohash and long-chain admission: adversarial handoff

Date: 2026-10-22. Status: **BLOCKED / MODEL-ONLY**.

## Provenance and scope

- GitHub repository: https://github.com/patrickdugan/blossom-storage-bonds
- GitHub remote branch baseline: `a8c9bb11ebf90ef22019dd3d2ac567580e2eaab9` (`phase-6-bitvm2-spike`). The default branch `main` remains at `9d01c4ea8e4300abba0b3d49a288aa9e71131f9f`.
- Local commitments `83f39be` and `4494714` were reported by the project owner but are absent from the accessible remote Git history.
- The local JSON report at `C:/Users/patri/Documents/Codex/2026-10-21/blossom-storage-bonds-phase7-handoff/outputs/bitvm-storage-admission-carriers.json` is not accessible in this runtime. Therefore this research adds **no claims** about its nine particular carrier attempts.
- Constraints: research-only GitHub branch created with owner approval; no proof jobs, new proof generation, Bitcoin Core tests, mining, pilot transactions, or network submissions.
- Repo-compatible models use the native Node `node:test` runner; no new dependencies.

## Critical Binohash constraints

Robin Linus, *Binohash: Transaction Introspection Without Softforks*, §2.7 and §§5–8:
https://robinlinus.com/binohash.pdf

1. Original Binohash depends on the **legacy** pre-SegWit signature-hashing behavior: `FindAndDelete`, `OP_CHECKMULTISIG`, and the old `SIGHASH_SINGLE` bug. It is **not a Taproot tapscript leaf**.
2. The published long script exceeds the P2SH redeem-script limit, so it uses a **legacy bare output**. The scheme is consensus-valid under assumed consensus rules but **nonstandard for regular relay**. Direct mining or modified miner policy is needed, a serious liveness assumption.
3. It is a computational transaction-field commitment and not a direct Bitcoin global-state introspection opcode. Its stated ~84-bit collision work depends on a particular parameter set, expensive grinding, and an identified cryptanalytic threat model. Do not mistake this for SHA-256 collision security.
4. The proposed binding does not establish the **completeness of the permissionless challenge journal**. Nor do signatures covering transaction fields automatically cover arbitrary scriptSig/witness disclosures. Any such data must be separately authenticated under a correct Bitcoin Script spend path.
5. Integrating the legacy transaction into a Taproot presigned refund graph must address the changed spending transaction identifiers and descendant signatures. A late-changing scriptSig of a legacy input participates in its txid, unlike a SegWit witness.

## Minimal counterexamples confirmed by the model

- **Stale journal root:** A provider commits to `[fork-100]` in a perfectly bound refund and omits a valid timely `[fork-151]`. A validator checking only that refund's internal claim accepts; a specification oracle with complete timely candidates rejects. Files A01/A03/A11/A15.
- **Correct root, unanswered strong challenge:** Even with the right complete root, refund can be inappropriate until the strongest admitted challenge has been answered and its deadline resolved. A04/A05.
- **First challenger consumes shared gate:** A fixed one-time challenge connector can permanently obstruct later stronger candidates. A16.
- **Alternative refund branch:** Adding Binohash enforcement on one path leaves a separate provider-signed refund path available when the old leaf remains. A17.
- **Witness substitution:** Cryptographic binding to one set of signed fields leaves extraneous witness/scriptSig content out of those fields. A09 (idealized projection).

## The acceptance criterion is a Bitcoin-enforced monotone admission state

A valid construction must implement *all* of the following using actual valid Bitcoin spends:

1. The permissionless challenge transaction admitted at height `h <= T_admit` must constrain collateral settlement, independently of the provider's consent.
2. Any stronger authenticated conflicting-chain certificate presented at `h' <= T_admit` must be able to update or supersede the challenge state even if weaker evidence already appeared.
3. Provider assertion and rebuttal must refer to the **actually admitted certificate**, including exact cumulative work and header linkage.
4. Every path that releases the provider's collateral must be unavailable while a timely unresolved challenge remains actionable.
5. After the challenge and response windows, the honest provider must be able to exit without relying on a favorable miner or censorship assumptions beyond Bitcoin's ordinary inclusion/liveness assumptions.
6. The entire spending graph must accommodate pre-signed transaction identifiers, fee bumping, witness/scriptSig mutation, standard relay policy, and Bitcoin script stack/opcode limits.

Candidate path to analyze: a monotonic `best-known-certificate` challenge UTXO, advanced permissionlessly by evidence of strictly greater cumulative work; provider rebuttal operates on its final state after admission closes, then a dispute timeout controls refund or forfeiture. **This is a specification, not a construction.** Dynamic state transition authorization, script enforcement of greater work, timelock-safe replacement, and on-chain inclusion of the final state remain unresolved.

Binohash could be considered as a binding layer for the candidate refund/rebuttal transaction after the state machine is fully enforceable. Under the published nonstandard relay requirements, the deployment would have additional miner-dependence that must be eliminated or explicitly accepted. Nothing here establishes a practical permissionless implementation.

## Integration protocol for the local owner tree

1. Retain `4494714` unchanged as the base and keep the existing 16 rejection checks and six-mined-transaction fixture as the source of truth.
2. Copy the two files in this handoff's `model/` directory to the repository's `model/` directory. Execute `node --test model/binohash_admission.test.mjs`.
3. Convert A01/A04/A05/A16/A17 into full Bitcoin Core regression tests against the six-transaction journal graph. They must be enforced by consensus-valid spends rather than a complete-journal oracle injected by the test runner.
4. Before investing in Binohash signature grinding, build one **small**, specifically designed legacy test-case using reduced parameters to determine script consensus validity and relay standardness. Only do so when the existing no-proof/no-pilot restriction is lifted; it does not require a full proving job.
5. Prefer experiments proving that the stale-provider-refund transaction **cannot spend** to experiments making it attach and verify another digest.

## How to run the research model

```bash
node --test model/binohash_admission.test.mjs
```

Passing tests mean that the attack examples and specification distinctions behave as coded. **They do not mean the Bitcoin protocol is working.**