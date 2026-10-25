# TRUC/P2A child occupancy and replacement: real Core regtest

**Status:** experimental Bitcoin Core 30.3 policy probes. Neither
fully generalized anti-pinning proof nor real network relay guarantee.

Base: [draft PR #10](https://github.com/patrickdugan/blossom-storage-bonds/pull/10).
It already established that third-party fee sponsors can replace a spent
candidate fee input after the FROST signer disappears by creating a
new v3 CPFP child without changing the signed zero-fee Taproot parent.
This follow-up studies the harder situation in which a *different child*
is already in the local mempool spending the parent's public P2A anchor.

## Threat and actual Bitcoin policy

The frozen parent is a one-input, version-3 Bitcoin transaction signed
under BIP341 by 2-of-3 FROST. The last output is zero-value P2A
script `51024e73`; anyone may construct a child spending this output
and supplement it with an independently owned funding UTXO.
Core TRUC policy constrains the unconfirmed parent/child cluster to
one parent and one child and permits limited replace-by-fee or
sibling eviction where the replacement has appropriate fees.

The attack here is an adversary *paying* for a child that attaches
to the parent's anchor before the holder's designated fee payer arrives.
The adversary's child cannot change the signed parent payout scripts,
principal or FROST transaction hash, but may occupy the package child
position and create a replacement fee requirement.

## Three separate real Bitcoin histories

| Trial | Owner order / attack stage | Fees | Acceptance boundary |
| --- | --- | --- | --- |
| `alice-first-low` | Alice-first parent, hostile child enters mempool first | 1,200 sats incumbent, 5,000 sats challenger | Honest higher-fee child should replace hostile child via Core RBF; both owner payouts later confirm |
| `bob-second-low` | Bob-first parent confirms; Alice-second parent gets hostile child | 1,200 vs 5,000 sats | Second-owner recovery must not become stranded; same original FROST parent bytes |
| `alice-first-high` | Alice-first parent, high-fee rival child enters first | 12,000 sats incumbent, 5,000 sats attempted challenger | Cheaper replacement should be refused, but the already-fee-paying hostile child itself can confirm the parent and release Alice's funds |

The existing frozen manifest is SHA256 verified *before* reading
any of the signed transaction bytes. Payouts are checked at six
confirmations. The preparatory FROST process must have exited,
and the original sponsor, Alice, Bob wallets are unloaded before
the Node-only probe creates new fee wallets. The funds are all
disposable regtest coins; there is no public network expenditure.

Funding UTXOs for **both** rival and competing child are confirmed
*before* admitting either child to the mempool. This is essential:
mining a new fee UTXO while the attacker child is already in the
mempool could mine the parent and mask the actual pinning question.

The probe records incumbent mempool ancestry, feerate, child
replacement result, spent fee UTXOs, parent and child txids/wtxids,
and confirmed outputs. All passes/failures must be observed in
Bitcoin Core; no mock signing state machine is accepted as evidence.

## What it does and does not test

This is one-node, one-parent/one-child local mempool policy under
the tested Core version, fee levels and confirmation conditions.
It does **not** test propagation across diverse peers, hostile
orphan storms, network topology, feerate floors under congestion,
reorgs, long ancestor packages, mutated witnesses, or malicious
signers creating entirely different P2TR keypath spends.

A high-fee incumbent requiring an even higher replacement is not
automatically a liveness failure: if its Bitcoin package confirms,
the holder is paid. It does demonstrate that a fee-budget-limited
relayer cannot unconditionally displace every P2A child.

An absence of a willing fee payer, a missing latest-generation
frozen package, or an unrestricted malicious two-share quorum
remains an independently unresolved failure. The older preparatory
carrier refreshes still require FROST and sponsor inputs before
signer disappearance; future unattended refresh is unproven.

## Reproduce

```bash
BITCOIND_EXEC=/absolute/path/to/bitcoind \
BITCOIN_CLI_EXEC=/absolute/path/to/bitcoin-cli \
BSB_PINNING_RECEIPT_DIR=/private/new-pinning-receipts \
bash experiments/storage-bond-ab/b-layertree/p2a-fee-child/pinning/run_regtest.sh
```

CI entry: `.github/workflows/frost-p2a-mempool-pinning.yml`.
Archive only sanitized public transaction IDs, measurements and
negative classifications. Private FROST material and original
signed recovery packages remain in the disposable test directory.

References:
- Bitcoin Core package policy: https://github.com/bitcoin/bitcoin/blob/master/doc/policy/packages.md
- Bitcoin Core TRUC policy: https://github.com/bitcoin/bitcoin/blob/master/src/policy/truc_policy.h
- BIP431 TRUC: https://bitcoin.org/bip/431/
- Original A-side package regtest: ../../../../../regtest/src/main.rs
