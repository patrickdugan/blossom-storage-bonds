> **2026-10-22 update:** The research suite now has 132 passing Node tests. See [ADR-001: journal cursor and joint settlement](cursor-architecture.md) for the concrete dual-input settlement topology, live-cursor outpoint tests, external challenger fee sponsorship, legacy sighash checks, script-budget arithmetic and cutoff/freeze races. This remains model-only: no Bitcoin-enforced cursor successor exists yet.

# Binohash admission: transaction-graph integration gate

Research branch: `research/binohash-admission`; starts from pushed `phase-6-bitvm2-spike` (`a8c9bb11`). Local Phase 7 commit `4494714`, and its nine failed commitment-carrier experiments, remain outside accessible GitHub history. The local journal regression remains the authoritative starting fixture when available.

## Results that genuinely run

Run `node --test model/*.test.mjs` (Node 22+). 55 deterministic tests, zero external dependencies:

| Tests | Scope | What passing means |
| --- | --- | --- |
| A01–A17 | Stale roots, omitted stronger forks, alternate refund path, first-gate griefing | Attacks succeed against illustrative unsafe designs; ideal binding alone cannot prove completeness |
| T01–T12 | Bitcoin transaction byte serialization, `txid`, `wtxid`, pre-signed child prevouts | Legacy scriptSig and output mutations change txid; SegWit witness-only mutations preserve txid |
| L01–L08 | Legacy SIGHASH, `FindAndDelete`, separator handling, SIGHASH_SINGLE bug | Three raw-transaction test vectors reproduce Bitcoin Core `sighash.json` expected digests; no signature grinding or Script execution |
| S01–S18 | Reference admission-and-rebuttal state machine | The desired rules work **if** a complete, authenticated journal, confirmation heights and exact-work verifier exist as an oracle |

## Contract sketch requiring a consensus construction

```
funded bond UTXO
       |
       v
claim/contest UTXO (no independent provider refund branch)
       |
       +-- anyone can publish a valid fork certificate and transition to
       |   successor contest UTXO that carries an authenticated monotone state
       |   (later higher-work certificates remain admissible until the cutoff)
       |
       +-- after cutoff, freeze to a rebuttal UTXO committed to all relevant
           strongest certificates, including distinct exact-work ties
                 |
                 +-- valid, certificate-bound rebuttals -> provider exit
                 |
                 +-- invalid/missing rebuttal after deadline -> forfeiture
```

This is a **specification**, not a deployable covenant. A node cannot see a global challenge journal from ordinary Script. Bitcoin must enforce the transition from each spent contest UTXO to its authorized successor, forbid every bypassing refund, and verify that the successor's claimed work and certificate came from the actual challenge. Binohash is a candidate binding mechanism for a transaction carrying such a transition; it does not supply journal completeness by itself.

## Minimal transaction-level proof obligations

1. **Live permissionless update:** An arbitrary unregistered challenger can spend the current contest UTXO into a valid higher-work state without the provider signing or revealing a secret. Demonstrate this twice in a row, with unrelated challengers.
2. **Work authentication:** The update's 256-bit cumulative work is cryptographically checked against a real verified header-chain certificate. The challenger cannot write an arbitrary larger `work` value. No trust in Nostr, indexers or an off-chain monitor.
3. **Strict monotonicity and ties:** A weaker state cannot replace a stronger state. Equal-work conflicting certificates must have an explicit fair rule; the reference model requires rebuttal to each distinct maximal tie.
4. **Cutoff and response clocks:** A challenge confirmed in the last admissible block can still affect the settlement. The freeze transition begins only after admission ends and leaves a complete rebuttal period.
5. **All-path collateral lock:** Enumerate every Taproot keypath, script leaf, legacy bare-script carrier and pre-signed transaction. Show the provider cannot exit through any branch while a timely higher-work challenge remains unresolved.
6. **Real transaction binding:** Verify that the digest consumed by the rebuttal refers to the actual challenge transition and that the transaction which pays collateral enforces the verdict. Binohash-to-BitVM authentication must bind the same certificate bytes and amount/outpoint.
7. **Descendant safety:** Account for txid changes when scriptSig, output scripts or input sets change. A legacy carrier can be moved into a terminal step only if no dependent pre-signed child needs its original txid; this move alone does not solve update authorization.

## Where a clean design will fail first

- If an old `CLTV <provider> CHECKSIG` leaf remains independently spendable, it bypasses every new Binohash path.
- If the first challenger consumes a one-shot connector without creating a reusable permissionless successor, later stronger challengers have no spending path.
- If the provider chooses a journal root at refund time, a true Binohash attestation of that root still allows omitted certificates.
- If all challenger entries are only off-chain messages or unconnected OP_RETURN outputs, the bond contract lacks the information needed to reject a stale refund.
- If a legacy Binohash scriptSig is mutated inside a parent of pre-signed descendants, their fixed outpoint references can break.

## Staging when the Phase 7 graph becomes available

- Port **A01/A04/A05/A16/A17**, **T02/T04/T06**, **S01/S04/S05/S09/S16** into the existing six-transaction Bitcoin Core fixture.
- Require a valid higher-work 151-header submission to make the *old provider refund consensus-invalid*, not merely uneconomic or unlikely to confirm.
- Include a late competing certificate and show it is admissible after an earlier weaker one, without provider cooperation.
- Treat `model/contest_spec.mjs` as a failing specification target until the spending graph itself implements each acceptance case.

## Deferred operational risks

Binohash as published needs a legacy bare-script carrier and nonstandard miner inclusion. Relay, fee pinning, miner censorship and computational grinding remain unsolved. They can be deferred for protocol research, but a production claim of permissionless liveness must eventually confront them.

No proof jobs, regtest mining, pilot funds or remote execution were used for these model-level research tests.
