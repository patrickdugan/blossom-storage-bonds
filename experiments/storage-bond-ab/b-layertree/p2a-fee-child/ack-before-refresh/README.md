# Holder ACK before FROST carrier refresh: honest-coordinator experiment

Child of [draft PR #13](https://github.com/patrickdugan/blossom-storage-bonds/pull/13).
Tracks [issue #14](https://github.com/patrickdugan/blossom-storage-bonds/issues/14).
**Research mode; disposable regtest only.**

## Actual ordering change

The existing `--freeze-p2a` mode remains unchanged when gate options are absent.
With `--gate-script`, `--gate-store` and `--gate-scenario`, the trusted
FROST signer produces the prospective complete next-generation **real BIP341
keypath signed** one-input v3/P2A recovery parents, including Alice-first,
Bob-first and the two successor exits. It signs the fee-sponsored refresh
but holds it **unbroadcast** while the prospective holder delivery occurs.

Each next-generation holder-specific Ed25519 delivery envelope contains the
identical signed Bitcoin recovery set and is tied to the known future
refresh txid/outpoint, current prospective manifest digest, owner payout
script and previous delivery chain. Two distinct Node holder processes
each own a generated Ed25519 ACK key in separate private directories.
They authenticate the sender envelope, append and fsync the package and
rollback checkpoint, reread retained state, and sign ACK receipts.
The coordinator verifies both receipts against the same generation,
prospective carrier and manifest SHA256. The Rust signer checks an
independently created source-bound gate receipt before it permits the
`sendrawtransaction` of that refresh.

This happens independently at generation **0→1** and **1→2**. Signatures
for each future generation are cached, so the signed bytes approved by
holders are reused as the actual FROST recovery witnesses, without
generating fresh or different signatures later. After the second refresh
is confirmed, signer shares disappear and the original
`relay_dynamic.mjs` publishes the frozen generation-2 recovery with
fresh third-party P2A child fee inputs. The 60k/40k owner outputs must
confirm at six-block depth.

On denied ACKs, the signer exits **before any Bitcoin broadcast of the
prospective carrier spend**. The runner queries the real Core mempool
and original spendable carrier UTXO. The separately signed prior
generation remains available.

## Tests

```bash
node --test experiments/storage-bond-ab/b-layertree/p2a-fee-child/ack-before-refresh/holder_gate.test.mjs
```

The eight offline scenarios cover success, missing Alice, missing Bob,
tampered envelope, forged holder ACK, partial/crashed package write,
stale generation-1 ACK during generation-2 refresh, and rollback of
Alice's package after signing generation-2 ACK.

On a local machine with preinstalled Bitcoin Core 30.3, Rust dependencies
and Node 22:

```bash
BITCOIND_EXEC=/absolute/path/bitcoind \
BITCOIN_CLI_EXEC=/absolute/path/bitcoin-cli \
BSB_GATE_RECEIPT_DIR=/private/new-gate-evidence \
bash experiments/storage-bond-ab/b-layertree/p2a-fee-child/ack-before-refresh/run_regtest.sh
```

The CI workflow pins Bitcoin Core's downloaded tarball by SHA256.
Only sanitized JSON outcomes go into the CI artifact; FROST shares,
actual signed transaction data, public testnet transactions, ACK private
keys and the private delivery manifests stay off GitHub artifacts.

## Boundaries and remaining blockers

- This is an **honest-coordinator application policy**. A fully signed
  refresh could still be broadcast by someone holding its bytes. An
  active malicious 2-of-3 FROST quorum can sign an arbitrary competing
  P2TR keypath spend. The simulated ACK gate is **not enforced by
  Bitcoin consensus**.
- Holder processes run separately, while their keys and checkpoint
  stores exist on **one CI host**. The bootstrap pins and sender identity
  originate from the same temporary coordinator/test environment.
  There is no physically separate independent-device custody,
  independently attested enrollment or remote asynchronous delivery.
- The rollback checkpoints must be protected under an independent
  trust boundary. Rolling back both the package and its local checkpoint
  passes unnoticed without a separately trusted monotonic root.
- An approval requires both holders on every refresh, so the
  coordinator deliberately halts if either holder is offline. This
  does not provide an **unattended** LayerTree refresh that can keep
  proceeding through arbitrarily long holder outages.
- The two initial preparatory refreshes still depend on fixed sponsor
  inputs and a live FROST signer. Fee-unrestricted, indefinite refresh
  and general package relay availability are separate.
- A genuine Bitcoin covenant/alternative control mechanism, verified
  Filecoin adjudication, holder-owned rollback-resistant storage and
  real network-independent FROST signing all remain unresolved.

Research PR should remain draft and separate from Binohash and main.
