# ADR-001: Binohash journal cursor for permissionless fork admission

**Date:** 2026-10-22  
**Status:** RESEARCH / NOT A VALID BITCOIN CONTRACT  
**Branch:** `research/binohash-admission`  
**Target:** exact cumulative Bitcoin chain work, permissionless challengers, and enforceable provider collateral.

## Why this record exists

The local Phase 7 regression at `4494714` (reported by the project owner, not available on the GitHub remote) mined six storage transactions and reproduced a 151-header stronger challenge that fails to constrain provider refund. The public Phase 6 repository also contains a provider-only `refund_leaf` constructed from `CLTV DROP <provider> CHECKSIG` in `regtest/src/common.rs`. Attaching a new authenticated proof to another branch cannot change the spending conditions of this existing refund leaf.

This branch tests a candidate architecture inspired by **Appendix C** of [Binohash: Transaction Introspection Without Softforks](https://robinlinus.com/binohash.pdf), in which a chain of spendable “read outputs” commits to published state and the operator must consume the relevant read output in an introspected transaction.

## Candidate: independently advancing journal cursor, co-spent at settlement

```text
Collateral UTXO B --------------------------------------+
                                                       |
Journal cursor J0 -- challenge W100 --> J1             |
                -- challenge W151 --> J2 (live)         |
                                        |              |
                                freeze after cutoff     |
                                        |              |
                                        v              v
                                joint settlement(B, live J2)
                                          |
                             Binohash commits to *both* prevouts
                                          |
                              BitVM exact-work rebuttal
                                          |
                             provider or slash destination
```

A confirmed stronger challenge consumes J1 and creates J2. A provider settlement that tries to spend J1 after J2 has confirmed is invalid because J1 is already spent. It is an ordinary **UTXO double-spend conflict**; the Script does not need to enumerate unrelated messages to reject that exact stale outpoint.

We model this using Bitcoin-serialized transaction identifiers in `model/journal_cursor.mjs` and `model/utxo_admission_graph.mjs`. `model/cursor_sighash.test.mjs` compares actual legacy signature hashes for settlement transactions with different cursor inputs.

**Important:** the model permits a challenger to update the cursor only when an external `authorized=true` oracle approves it. None of the tests has yet replaced that oracle with Bitcoin Script.

### Why Binohash is relevant

The Binohash legacy bare-script carrier commits to a transaction that spends selected inputs, allowing an authenticated Lamport commitment to its digest inside a BitVM computation. The proposed settlement spends BOTH the collateral UTXO and the live cursor. An older cursor does not remain live after a confirmed successor update.

Our signature-hash regression tests establish that `SIGHASH_ALL` on the collateral input changes when the cursor input changes. `SIGHASH_ALL|ANYONECANPAY` on that same collateral input does NOT cover the other cursor input. The full published Binohash pinning mechanism spans the relevant signature-hash modes; accepting one arbitrary signature with a weak mode would leave an input-substitution attack.

This is *transaction binding*, with no demonstrated mechanism yet to guarantee admissible cursor updates.

## What the executable research proves

Run `node --test model/*.test.mjs` (Node 22+, no dependencies, no proof jobs, no bitcoind). There are **132 deterministic research tests** grouped as follows:

| Group | Tests | Evidence |
| --- | ---: | --- |
| A: initial admission and refund bypass | 17 | Binohash-like ideal transaction binding does not establish journal completeness |
| T: Bitcoin txid / wtxid and presigned descendants | 12 | Legacy scriptSig and outputs change txid; witness-only mutation preserves txid |
| L: legacy sighash and FindAndDelete | 8 | Three Bitcoin Core `sighash.json` vectors match; Script not executed |
| S: ideal contest specification | 18 | Timely stronger and equal-work contenders, rebuttal and deadlines with an omniscient oracle |
| G: UTXO graph topology | 24 | Independent publication cannot block refund; consuming collateral can, but forces a successor transition |
| C: serialized journal cursor | 20 | Live-cursor co-spend rejects stale ancestors, under ideal authorization; malicious burn and cutoff remain |
| B: published Binohash parameter arithmetic | 9 | Section 6 opcode and size budget calculations |
| E: sponsored fees and tied maxima | 7 | Additional challenger fee input can preserve cursor value, optional equal-work contender tracking |
| H: four legacy signature-hash modes | 10 | Input and output commitment differences for a two-input settlement |
| F: cutoff/freeze races | 7 | Bitcoin locktime lower bounds do not impose latest admission height by themselves |
| **Total** | **132** | Research test results; no consensus-valid storage-bond solution implied |

## Unresolved consensus obligations

1. **Valid successor covenant.** Any unrelated challenger must be able to spend the active cursor and create precisely one valid successor UTXO, preserving the agreed script and carrying a certificate whose *exact* cumulative work has actually been verified. A malicious challenger must be unable to burn the cursor in an arbitrary output. `C09` demonstrates this irreversible liveness failure when the authorization oracle accepts arbitrary outputs.

2. **All-path bond binding.** Every provider-only spending path for the collateral, including all Taproot leaves, keypaths, and presigned transactions, must require the correct dispute outcome or a transaction consuming an authenticated live cursor. The Phase 6 `refund_leaf` must be replaced in any proposed Phase 7 integration. Requiring Binohash on a separate branch while retaining that leaf leaves the bypass intact (`A17`, `G17`, `C07`).

3. **Chain-work and input integrity.** A challenger must not choose an arbitrary larger `work` value. A real BitVM proof, verified Bitcoin header linkage, and authentic mapping from certificate to successor output are required. The current tests pass `validatedWork=true` as an assumption. Exact-work comparison requires 256-bit integers, not floating-point work approximations.

4. **Cutoff and freeze liveness.** The protocol should define admission by **Bitcoin-confirmed** inclusion no later than cutoff block `T`; mempool announcement is outside consensus. A freeze with `nLockTime=T` can first confirm after `T`, while an open challenge path can also spend the cursor after `T`. Without a consensus-enforced upper-bound rule or a safe freeze mechanism, they race. `F01-F07` reproduce this in the transaction-topology model. A challenge confirmed in block `T` invalidates a freeze presigned for the old cursor. Rebuilding or preauthorizing a new freeze must be supported without denying this last-block challenge.

5. **Response windows.** A challenge confirmed in the last allowed block must receive the entire response interval, after the freeze has captured the valid final state. A unilateral provider refund at `T + delta` bypasses an unresolved challenge unless the bond contract explicitly gates it.

6. **Tied maximal-work certificates.** Distinct conflicting forks can have the same exact cumulative work. A strict-increase-only cursor ignores one of them. The optional `allowTies=true` ideal reference can append both certificate IDs, and supersedes that set on a strictly stronger certificate. The true on-chain representation needs replay prevention, duplicate control, and bounded anti-griefing costs.

7. **Fee funding.** Unlimited permissionless updates cannot be funded solely by decrementing a finite-value cursor. `journal_cursor_extensions.test.mjs` demonstrates a second, challenger-owned transaction input that pays the update fee while the cursor output keeps its value. A real successor covenant must permit this extra input without enabling arbitrary output redirection.

8. **Legacy Script limits.** From Binohash §6, the canonical two-round design uses approximately `13 + 2*(11*8+4) + 2 = 199` non-push opcodes against the 201-opcode legacy limit and approximately 8,028 bytes against the 10,000-byte script limit. The published Appendix D polyglot formula for two rounds and ten selections gives `13 + 2*(9*10+4) + 2 = 203` opcodes. That arithmetic appears two opcodes above the base limit. A compiled implementation may rearrange these counts; this is a **parameter-review finding**, not a claim that the Appendix D optimization is impossible. Do not assume that full fork verification and successor validation fit inside the Binohash script.

9. **Miners.** The published Binohash carrier is nonstandard and needs a direct miner path. This operational question is intentionally deferred. The paper documents only low-security 4-byte proof-of-concept transactions on real chains; do not treat them as a deployment of the full proposed security parameters.

## Suggested next implementation sprint

**Goal: remove the `authorized=true` oracle for one journal-update transition.**

Build one actual, consensus-checkable legacy Script output which a permissionless challenger can spend from J0 to an authenticated J1. The challenger may supply an arbitrary certificate commitment and additional fee input, but must be unable to burn J0, redirect value, or replace the required J1 script. A fallback recovery mechanism may be needed if the challenge is invalid.

Required experiments, in order:

1. Extract byte-level, output-script and amount commitments that a Binohash-authenticated transition would need. Enumerate sighash flag coverage and all fee-input mutation vectors.
2. Specify and compile the least expensive enforceable successor rule under Bitcoin consensus. If Script cannot implement the rule, produce its smallest counterexample and state precisely what constraint fails.
3. Only once this rule is sound, attach a BitVM verifier for an exact-work certificate and demonstrate J0→J1→J2 with unrelated challengers; then implement freeze after an admissible last-block J2 update.
4. Finally integrate with the local `4494714` six-transaction storage fixture and prove every old refund escape is invalid.

**Stop conditions:** a challenger can burn the only live cursor; a provider can exit via the old refund leaf; a pre-signed descendant assumes a fixed changing scriptSig/output txid; or the freeze lets a weak earlier challenger suppress a timely stronger one.

No new proof jobs, Bitcoin Core mining, or pilot transactions were initiated for this research branch.

## Primary sources

- [Binohash paper](https://robinlinus.com/binohash.pdf), §§2.7, 3–6, Appendix C and Appendix D
- [BitVM2 permissionless verification overview](https://bitvm.org/bitvm2)
- [BIP143: legacy FindAndDelete is absent for SegWit v0](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
- [Bitcoin Core historical sighash vectors](https://github.com/bitcoin/bitcoin/blob/master/src/test/data/sighash.json)
- Public baseline: [Phase 6 bond refund definition](https://github.com/patrickdugan/blossom-storage-bonds/blob/phase-6-bitvm2-spike/regtest/src/common.rs)
