# Physical two-node 1P1C FROST/P2A relay at different fee floors

## Verified head result — 25 October 2026

[**Passing two-node Bitcoin Core CI #40150689489**](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40150689489) 
ran one low-floor and one high-floor sender/receiver pair, with
[sanitized node-separated receipts](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40150689489/artifacts/12581673541).

| Actual receiver minimum relay feerate | Bitcoin Core outcome |
| --- | --- |
| 2 sat/vB | Both successive owner recovery packages propagated automatically over real connected P2P before **any** receiving-node `submitpackage` call; no RPC fallback needed |
| 25 sat/vB | 5,000-sat child packages failed the receiver fee floor; a **different 15,000-sat child** was selected at origin for each frozen parent and both higher-fee packages propagated over P2P without receiving-node package submission |

Four actual parent/child pairs were submitted, propagated and mined
across the two independent histories; both Bitcoin nodes agreed on
witness txids, active-chain blocks, payout scripts and the full
60k/40k satoshi entitlements. No FROST private share was needed
after the original signer process exited. The evidence flags
`opportunisticP2PPropagationAllSteps=true` and
`receiverLocalRpcFallbackNeeded=false` for **both** scenarios.

An initial CI run failed only because the shell receipt verifier used
strict floating-point equality for a BTC/kB-to-sats/vB conversion:
2 sats/vB can evaluate to `2.0000000000000004`. The verifier now
uses a narrow numerical tolerance, while the source experiment
continues to assert its own fee-floor consistency. The successful
end-to-end test is linked above; the unsuccessful run was not
counted as an acceptance result.


**Disposable real Bitcoin Core 30.3 regtest, not a global propagation or anti-pinning proof.**

This child of [draft PR #11](https://github.com/patrickdugan/blossom-storage-bonds/pull/11)
extends the real local TRUC/P2A sibling replacement test.
Bitcoin Core 28 introduced opportunistic one-parent-one-child relay using
the ordinary transaction relay protocol; Core 30 improves behavior where
some parents are already in the mempool. A successful `submitpackage` RPC
on one node **does not guarantee P2P propagation** to others. This is
what the new experiment actually measures, using two separate processes
and dissimilar receiver mempool policy settings.

## Topology

```text
FROST signer process (terminated before P2P experiment)
     |  SHA256-frozen BIP341 P2TR signed v3 parents
     v
Origin Bitcoin Core node A      --real TCP P2P---> Receiver Core node B
  regtest, own datadir/mempool                      regtest, own datadir/mempool
  trusted miner wallet                             NO wallets loaded
  fresh third-party fee wallets                    minrelaytxfee 2 or 25 sat/vB
  local submitpackage RPC
     |
     +-- package 1: owner-first 0-fee FROST v3 parent + CPFP P2A child
     +-- package 2: other-owner 0-fee FROST v3 parent + CPFP P2A child
```

Node B connects to A using `addnode` across `127.0.0.1` with distinct
P2P and RPC ports. Its wallets remain unloaded throughout. The prep
signer creates the full three-generation Alice/Bob source DAG on node A,
broadcasts two preparatory carrier refreshes and then terminates.
Alice/Bob and original sponsor wallets are unloaded from A.

The relay probe first funds and mines candidate child fee UTXOs
**before** putting the owner recovery package into A's mempool.
This prevents a preexisting package from being accidentally mined
while the fee wallet is funded. B's chain tip is checked against A's.

## Trial structure

| Case | Owner order | Receiver `minrelaytxfee` | Attempt |
| --- | --- | --- | --- |
| `peer-low` | Alice first, Bob second | 2 sat/vB | A submits 5,000-sat 1P1C, probe B's mempool *before any B package RPC* |
| `peer-high` | Bob first, Alice second | 25 sat/vB | A submits 5,000-sat 1P1C; B must refuse the underpriced package. Then A replaces the child with 15,000-sat independently funded P2A child and probes B's mempool |

Each parent is a previously signed one-input BIP341 FROST v3
transaction with exact remaining-carrier and owner payout outputs,
plus an intact zero-value P2A output. No fresh FROST signature is made
during P2P observation or fee-child replacement.

**Evidence labels matter:**

- `initialP2PObservation.propagated`: node B independently had both
  actual txids in its mempool BEFORE any B `submitpackage` call.
- `explicitReceiverSubmitpackageFallback`: opportunistic P2P had not
  delivered the complete pair within the bounded observation interval;
  the probe explicitly inserted the known signed package into B.
  This is *not* evidence of automatic P2P delivery.
- `lowFeeBelowReceiverFloor`: high-floor B did not admit the
  original underpriced package even when submitted explicitly.
- `secondFeeChildReplacement`: A accepted a fresh, higher-fee child
  without changing the FROST parent, and B was probed again.
- Both nodes confirm actual signed parent and child witness bytes
  in the same active blocks. Alice's and Bob's payouts are checked
  against their immutable scripts and **six confirmations**.

## Run

```bash
BITCOIND_EXEC=/absolute/path/to/bitcoind \
BITCOIN_CLI_EXEC=/absolute/path/to/bitcoin-cli \
BSB_P2P_RECEIPT_DIR=/private/new-p2p-proof \
bash experiments/storage-bond-ab/b-layertree/p2a-fee-child/p2p/run_two_nodes.sh
```

Use only private/disposable regtest datadirs. The Bitcoin Core binary
is checksum verified by CI. No real public-network broadcasting occurs.
The script uses two separate isolated chain histories, and each
history contains TWO physically connected nodes. All wallet keys,
FROST shares and frozen signed witnesses remain in temporary
directories; only sanitized observations are uploaded.

## Interpretation boundaries

This is local TCP P2P among two controlled Bitcoin Core nodes, not a
representative test of real-world network fee policies, peer topology,
or mempool congestion. The 1P1C gossip implementation is opportunistic
and may omit a package even when both nodes accept it explicitly.

The receiver's higher static `minrelaytxfee` is not the same as a
temporarily elevated dynamic `mempoolminfee` due to full-mempool
eviction. That separate congestion test remains necessary.

All principal conservation claims are Bitcoin output/value checks
under current FROST keypath signatures. Two actively colluding
signers can still authorize another parent with different payouts;
no MID or Filecoin consensus predicate is enforced by Bitcoin.

Signed recovery package authentication, delivery acknowledgement,
rollback-resistant retention and future unattended refresh are
separate unproven requirements. Missing fee payers and P2P policy
rejections can independently cause liveness failures.

References:
- https://bitcoincore.org/en/releases/28.0/
- https://bitcoincore.org/en/releases/30.0/
- https://bitcoincore.org/en/doc/30.0.0/rpc/rawtransactions/submitpackage/
- https://github.com/bitcoin/bitcoin/blob/master/doc/policy/packages.md
