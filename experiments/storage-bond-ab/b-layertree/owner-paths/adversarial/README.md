# Pre-signed FROST exits: real fee-sponsor sabotage and package availability

Research-only negative testing on `patrickdugan/blossom-storage-bonds`.
Base: passing Alice-first/Bob-first Bitcoin Core signer-outage recovery
[PR #7](https://github.com/patrickdugan/blossom-storage-bonds/pull/7).
Do not promote this adversarial experiment into a security proof.

## The concrete vulnerability

Every pre-signed BIP341 keyspend from the frozen owner-first DAG commits
the **exact** sponsor input's outpoint, amount and script. It needs
the independent 10,000-sat fee coin to remain unspent until broadcast.
At preparation time, a two-of-three FROST quorum signs the desired
transaction, and the sponsor wallet also signs its input. After
FROST and the oracle vanish, the sponsor still controls that UTXO and
can double spend the specific fee input to a third-party address.
Bitcoin then rejects the original full transaction even though the
100,000-sat bond has not been touched. The owner has no replacement
signature for a different sponsor input.

## Three reproducible real Bitcoin experiments

| Trial | Sponsor adversary | Required Bitcoin Core outcome |
| --- | --- | --- |
| `alice-first` | Spends Alice-first's precommitted 10k fee UTXO after signer death | Alice-first invalid, untouched Bob-first still valid; Bob-first 40k then Alice-second 60k both confirm without signing |
| `both-first` | Spends both first-branch fee UTXOs, without spending the carrier | Neither first-branch exit can enter mempool; 100k remains locked and no signer-free owner-first recovery is possible from this frozen DAG |
| `bob-second` | Spends the fee UTXO needed by Bob's follow-on exit after Alice-first | Alice-first 60k confirms, but Bob-second 40k remains in a P2TR successor that Bob cannot spend through his pre-signed package |

Each trial uses a separate **fresh** Bitcoin Core 30.3 regtest chain,
fresh disposable FROST shares, 14 separate sponsor UTXOs, and a
SHA256-pinned frozen export. The real FROST signer preparation
process exits **before** the adversarial sponsor spends its coin.
The sponsor's regtest wallet signs and confirms only its own
selected inputs. Then the sponsor, Alice and Bob wallets unload.
A second Node-only worker inspects the real Bitcoin UTXO set,
wtxids, exact outputs, active-chain transaction ancestry, and
mempool acceptance without accessing FROST signing code.

A one-fee-input failure must not be misreported as complete recovery
failure if the *other owner-first* signed path and all its descendant
fee UTXOs remain available. Conversely, a partial Alice-first
payout must not be misreported as success for Bob when the 40k
successor is stranded. The consumer distinguishes those cases.

## Missing-package negative control

The harness also makes a local copy of the frozen recovery archive
and removes Bob's current-generation second-exit signed bytes. It
keeps the **original external hash pin**. The recovery worker must
reject the altered package without broadcasting. This demonstrates
tamper/omission detection, **not durable package availability**:
there is currently no authenticated per-owner delivery ACK,
anti-rollback copy, independent witness warehouse, or guarantee
that a holder received the current generation's full subtree.

## Reproduce

Requires disposable `bitcoind`, `bitcoin-cli`, Node 22, pinned Rust
Cargo dependencies. No mainnet, Signet, testnet4 or live funding.

```bash
BITCOIND_EXEC=/absolute/bitcoind \
BITCOIN_CLI_EXEC=/absolute/bitcoin-cli \
BSB_SPONSOR_ATTACK_RECEIPT_DIR=/private/clean-regtest-results \
bash experiments/storage-bond-ab/b-layertree/owner-paths/adversarial/run_sabotage_regtest.sh
```

The separate experimental workflow is
`.github/workflows/frost-sponsor-sabotage.yml`.
Only public regtest outcome receipts are uploaded, never FROST
shares, private Bitcoin wallet files or the complete signed branch DAG.

## Possible repairs (not implemented or claimed as proven)

One backup fee UTXO per exit needs a *different full presigned
Bitcoin transaction*, and a different first-exit txid creates a
different successor outpoint. Every descendant would need
signatures for each funded ancestor alternative; this quickly
multiplies branch count and witness storage. Backup sponsorship
must cover the **second owner exit**, not only the first.

A stronger candidate is a zero-fee presigned v3/TRUC parent with
a P2A-style fee anchor and an independently constructed CPFP child
that can choose funding inputs *at relay time*. The existing
sentinel-bond A harness already explores v3/P2A package policy.
That removes the fixed sponsor-outpoint dependency from the
parent's BIP341 sighash, but introduces package relay and pinning
assumptions. It requires a fresh isolated real Bitcoin Core test
of relay policy, exact payout conservation, honest and hostile
fee sponsors, and missing package availability. Do **not**
declare such a repair from the present test alone.

Regardless of fee policy, an active colluding two-share FROST
quorum may still sign an unauthorized P2TR keypath spend.
Neither presigned branches nor fee replacement enforce LayerTree
MID rules under Bitcoin consensus. Filecoin fault verification
and long-lived refresh are also outside this experiment.
