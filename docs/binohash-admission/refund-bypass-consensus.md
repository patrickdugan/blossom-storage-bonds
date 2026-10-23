# ADR-006: Provider refund bypass is a consensus-positive negative control

**Status:** Unfunded representative Bitcoin Core Script experiment. The original local Phase 7 six-transaction, 151-header fixture at commit 4494714 is not in this branch; this is a reproducible successor test rather than a claim to have imported that fixture.

## Question

Does a stronger fork challenge, committed in an independent UTXO/journal path, make the old provider refund consensus-invalid?

The existing journal model says no. This ADR tests the provider refund Script alongside the journal model using the same fully serialized refund transaction. The independent fork journal changes no byte of the refund transaction and spends no input the refund requires.

## Construction

The refund input spends a fabricated 149,000-satoshi bond locked by the representative Script:

    <150> OP_CHECKLOCKTIMEVERIFY OP_DROP <provider-public-key> OP_CHECKSIG

The provider signs input 0 under legacy SIGHASH_ALL|ANYONECANPAY. The refund pays 148,000 satoshis to a public test-key P2PK output. Input 1 represents a separately funded 5,000-satoshi fee carrier whose native-v0 P2WSH witness holds a variable certificate **tag** and executes OP_DROP OP_TRUE. The remaining 6,000 satoshis pay transaction fees. All relevant test private keys/outpoints are public or fabricated.

Bitcoin Core 26's vendored libbitcoinconsensus checks **both inputs** for 11 cases:

| Case | Expected Core Script result |
| --- | --- |
| Weak certificate tag in fee witness | Accept |
| Stronger, independently labeled 151-header certificate tag in fee witness | Accept |
| Same bytes after journal records weak then stronger challenge | Accept |
| Alternate maximum-size 520-byte witness element | Accept |
| Replacement fee sponsor outpoint (ANYONECANPAY) | Accept |
| Redirected provider payout or shaved amount | Reject refund input |
| Re-signed refund with transaction locktime below 150 | Reject refund input |
| Re-signed refund with final sequence | Reject refund input |
| Missing provider signature or stale signed bond outpoint | Reject refund input |

The two fee-witness tag variants have the same txid and provider signature; their wtxids differ. Core's positive Script result after the stronger tag is expected, since the old refund has no journal-cursor input or verification rule. The Core harness verifies scripts only. It does not check whether those fabricated UTXOs exist, whether a certificate is valid, or what chain height includes the transaction. The CLTV script is satisfied at nLockTime 150; the modeled earliest confirming block is height 151.

## Joint graph regression

A separate Node topology test uses three explicitly seeded UTXOs:

1. A mock CLTV-locked bond and independent fee input, matching the exact raw Core refund vector.
2. An independent journal funded by a third outpoint.
3. Two journal updates with asserted work 100 then 151, accepted only under a **boolean external verification oracle**.

After both updates, the height-151 provider refund can spend the old bond while the strong journal cursor remains live. The specification oracle, supplied the same claimed higher-work history, would forfeit that unanswered challenge after the response deadline. Thus the modeled refund and desired protocol disagree.

The positive Script case and the topology case answer complementary questions; the test is not a mined, funded, complete Bitcoin validation.

## Architectural consequence

A witness-stable parent txid helps preserve a pre-signed descendant. Witness inclusion can authenticate **which witness** a Bitcoin block committed to if a verifier also proves canonical inclusion and exact chain work. Neither property by itself makes a bond's *independent* refund spend conditional on stronger challenges elsewhere in the UTXO set.

A candidate repair must give every provider-reachable collateral exit a consensus-enforced dependency on the effective contest state. This includes legacy refund Script branches, Taproot key paths and leaves, and any unguarded pre-signed settlements. Permissionless challenges must also advance an allowed successor until the full admission cutoff. A finite pre-signed path permits slot exhaustion unless its deadline and challenge fairness are proved safe. The actual confirmed witness must be bound to the proof's public input and payout transaction, with a verifier that authenticates work and each required rebuttal.

The simplest test of a proposed fix is to run this same case after replacing the old bond lock. The refund must become invalid **when a timely stronger certificate is left unanswered**, while the provider remains able to collect after a valid response to that very certificate. That statement remains a research target and currently requires an external specification oracle.

## Reproduction

    node --test model/*.test.mjs
    node model/refund_bypass_consensus_vectors.mjs > /tmp/bsb-refund-bypass.json
    cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-refund-bypass.json

This suite performs no mining, proof generation, remote Bitcoin RPC or funded transaction broadcast. The stronger certificate is a labeled digest, not an actual 151-header certificate. The Phase 7 graph and its real Bitcoin Core chain fixture must be imported separately when available.