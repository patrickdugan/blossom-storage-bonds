# Phase 7C: minimal pilot deployment and recovery

This is the smallest deployment that uses only active Bitcoin consensus, real storage proofs, and one
of the two payment backends. BitVM adjudication is not part of it.

## Parties and processes

| Party | Processes | Persistent state (keep it on durable disk, back it up) |
| --- | --- | --- |
| Provider | `bitcoind` (signet, txindex); `node layer1/provider.ts --pay ln\|onchain\|channel [--zk]`; for `--pay ln`, its own `lnd`; for `--zk`, `bsb-zk` and the Blake2s holdings executable (Linux-native since phase 7C) | `--dir`: blobs and metadata, deal files, presignatures, bond resume and refund records, `channel-payments.ledger` / `onchain-invoices.ledger`, zk `deals.json`; lnd's own data directory |
| Client | `bitcoind`; `lnd` or a Core wallet; `node layer1/full-stack.ts` (or `market.ts` for the channel backend) | `--dir`: deal files, sentinel secrets, `client-onchain.ledger` / `client-payments.ledger` |
| Watchtower | `node layer1/watchtower.ts` (with its own node, or `--headers`) | `--dir` |
| Relays | two or more Nostr relays (`layer1/relay.ts`, or public relays checked with `layer1/relay-probe.ts`) | none required |

The signet runbook (`docs/signet-pilot.md` §8) has the full commands. The phase 7C changes for a
pilot are:
- set `BSB_ZK_BIN` and `BSB_ZK_EXE` on a Linux provider;
- keep `--dir` on a disk that survives reboots: the payment ledgers are fsync'd there;
- run providers with `--uploaders <client key>` and `--max-term` (unsealed-deal griefing, runbook §11).

## Recommended pilot parameters (from `model/pilot_economics.ts`)

| Parameter | Value | Why |
| --- | --- | --- |
| q (challenged chunks per epoch) | 64 | The Blake2s per-proof maximum. A 5% deleter escapes 3 epochs with p ≈ 5×10⁻⁵; the demo's q = 16 lets a 10% deleter escape 2 epochs 3.4% of the time, as the phase 7b rehearsal saw |
| Epoch | 144 blocks (about daily) | 30 epochs a month; a 1% deleter escapes a month at q = 64 with p < 10⁻⁸ |
| Sentinels per bond k | 4 or more, spent only on watchtower-attested missing or invalid proofs | Each answered challenge uses one. The phase 7C market spent all four on a withholder that still had the data |
| Bond per deal | ≥ 100,000 sats | Deterrence is tiny for small deals; the floor is enforceability: about 84k sats so the client can challenge, CPFP and forfeit at a 100 sat/vB spike and still outbid a late responder. The demo's 1 BTC is unnecessary |
| Payment | Lightning per epoch; or on chain batched over ≥ 30 epochs | A single 512-sat on-chain epoch payment loses over 75% to fees at 5 sat/vB; batched over 30 epochs, under 3% |
| Forfeit fee policy | Broadcast the forfeit at the first eligible block, at a competitive fee, and fee-bump it while it is unconfirmed | Harness S1: a late answer at 25 sat/vB replaced a 1,000-sat forfeit (package RBF) |
| Retrieval | Client runs with the retrieval probe (`retrievalProbe`) and keeps replicas at ≥ 2 providers | The bond enforces possession only. A withholder keeps its bond, but the probe stops paying it |

## Recovery procedures

| Failure | What happens | Operator action |
| --- | --- | --- |
| Provider process crash (SIGKILL tested) | Restarted with the same `--dir` and port, it resumes its bonds (`bond-resumed`) and replays its channel ledger: latest client state, issued invoices, and exact retries answered once | Restart the process. `market.ts --crash-honest` is the test |
| Provider crash, on-chain payments | `onchain-invoices.ledger` restores issued invoices, so payments made before the crash stay sweepable | Restart, then `POST /admin/sweep` |
| Client crash during a channel payment | `client-payments.ledger` counts the signed state as paid. `ChannelPayer.resume()` re-sends it, and the provider answers an exact retry with the same preimage | Restart and call `resume()`. The client never signs a lower total or pays an invoice twice |
| Client crash during an on-chain payment | `client-onchain.ledger` has the signed transaction. On restart those invoices count as paid and `rebroadcast()` sends the same bytes | Restart and rebroadcast. Never re-pay |
| Client orchestrator crash mid-run (`full-stack.ts`) | **Not restartable mid-run** (runbook §11). Payments and deal files survive, but the epoch loop and enforcement scheduling are in memory | Pilot condition: a restartable client loop, or an operator who re-runs enforcement by hand from the deal files before Δ expires |
| Missing confirmations | Signet mode waits for `--confs` (use 6, because signet reorgs daily); receipts are checked at depth | Keep `BSB_CONFS=6` |
| Torn ledger write | The last partial line is ignored, because it was never acted on. Damage anywhere else stops the restart | Restore the ledger from a backup; never delete lines by hand |
| lnd crash | lnd's own database holds channel and invoice state | Restart lnd before the provider |
