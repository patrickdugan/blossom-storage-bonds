# Signet rehearsal on a private signet (phase 7b)

Before the public signet pilot (`docs/signet-pilot.md`), the stack ran in its signet mode against a signet
of its own on one Windows laptop. No public chain, faucet or relay was involved. The rehearsal covers the
code paths regtest cannot reach:

- waiting for blocks instead of mining them;
- depth before relying on an output, with `--confs 3`;
- fees from `estimatesmartfee`, which on a fresh chain falls back to 2 sat/vB;
- signet prefixes, the cookie login and fresh keys per party;
- funding requests and the client's fee-coin split;
- a first boundary fixed after setup;
- providers that refund their own bonds and publish `settled`;
- enforcement of all flagged providers at once;
- the watchtower's header chain with signet's parameters;
- the relay pool over two separate relay processes.

## The setup

- **`layer1/private-signet.ts`** runs Bitcoin Core 31.1 on a signet with challenge `51` (`OP_TRUE`).
  - It writes `connect=0` and `dnsseed=0`, and either `listen=0`, or with `--local-p2p` P2P on
    127.0.0.1 only.
  - It mines a block every `--block-secs` with `generatetoaddress`, standing in for signet's block
    signers.
  - With `--fund-from`, it pays each "send at least N sats (signet) to …" line of a `full-stack.ts` log
    once, from its own wallet, as a faucet would.
  - It refuses the public signet's challenge.

  The protocol code never mines off regtest; this process is the only miner.
- **`node layer1/relay.ts 7801`** and **`7802`**: the bundled relay as two separate processes, so the
  parties use the relay pool over two URLs.
- **The client:**
  ```bash
  BSB_NETWORK=signet BSB_RPC=http://127.0.0.1:38332 BSB_RPC_COOKIE=<datadir>/signet/.cookie BSB_SIGNET_CHALLENGE=51 \
    node layer1/full-stack.ts --network signet --relays ws://127.0.0.1:7801,ws://127.0.0.1:7802 --dir <run dir> \
    --pay onchain --epochs 3 --from-epoch 2 --q 16 --epoch-blocks 50 --deadline 40 --term 470
  ```
  It spawns three providers (honest, deletes 10%, outsources) and a watchtower, all in signet mode
  with fresh keys.

Proof of work at signet's minimum difficulty costs Core about 4 s of one core per block on this laptop.
A block every 8 s therefore keeps that core about half busy.

## Findings

1. **lnd v0.21 cannot use a bitcoind backend on a custom signet.** With `--bitcoin.signetchallenge`, lnd
   computes the private chain's network magic. It then maps bitcoind's `getblockchaininfo` chain name
   ("signet") to the public signet's magic, and stops with `expected network Unknown BitcoinNet
   (3178222164), got SigNet`. This does not affect the public pilot, where the two agree.
   - For a private signet, lnd can use its neutrino backend: `BSB_LND_NEUTRINO=127.0.0.1:38334`, with
     `private-signet.ts --local-p2p` serving compact block filters on loopback.
   - A neutrino lnd synced to the private chain in 5.9 s.
2. **The laptop bugchecked during the second rehearsal attempt** (`0x133 DPC_WATCHDOG_VIOLATION`,
   2026-10-23 02:59 UTC). Core's last log line was a `CreateNewBlock` while it mined; the cause is a
   driver, and the link to the mining load is not established. The script now runs `bitcoind` at
   below-normal priority, and the rehearsal uses 8 s blocks instead of back-to-back mining.
3. **A provider could not sweep a one-epoch payment at signet's fallback fee rate** (a stack bug, now
   fixed).
   - With the estimate falling back to 2 sat/vB, `sendall` of a lone 512-sat payment output leaves
     290 sats, below the dust limit. Core then says "Dynamically assigned remainder results in dust
     output".
   - The sweep retried at the 1 sat/vB floor only on Core's other wording, "fee too low", which is what
     regtest's 5 sat/vB had produced. So the run stopped at the cheaters' sweeps.
   - The sweep now retries on either message. A sweep that still fails is recorded as unswept rather
     than ending the run: a provider's loss, not the protocol's.
   - This is phase 5's economics (design §4.5) seen from the provider's side: a single 512-sat epoch
     payment is barely worth spending.
4. **Parallel enforcement raced for the client's fee coins** (found while fixing 3, before the run
   reached it; now fixed).
   - Off regtest the client challenges all flagged bonds at once. Each challenge's CPFP child spends
     one fee coin, and two `bsb-bond` processes started together pick the same largest unspent coin.
   - The client now sends one challenge at a time. The next then sees the first coin spent in the
     mempool, and skips it (`fee_utxo` checks `gettxspendingprevout`).
5. **`generatetoaddress` gives up after 1,000,000 hashes by default** (a rehearsal-tool bug, now fixed).
   - A block at signet's minimum difficulty needs about 4.8 million hashes on average, so roughly four
     calls in five returned no block. Blocks came every 30–45 s instead of every 8 s.
   - The script now passes a `maxtries` large enough to always find one.
6. **The demo's cheaters started one epoch late** (a test-harness timing bug, now fixed off regtest).
   - `full-stack.ts` told the cheaters to misbehave just before waiting for their first bad epoch's
     boundary.
   - Off regtest that boundary had already passed: the client was still waiting for the previous
     payment to reach 3 confirmations, while the providers proved the new boundary as soon as it was
     deep. They proved from data still intact, 2 s before the deletion.
   - Off regtest the harness now injects misbehaviour as soon as the previous epoch's proofs are in.
   - Nothing in the protocol changes: an honest-then-cheating provider is caught one epoch later.
7. **A provider's second sweep on the same node failed** (a stack bug that would hit the pilot, now
   fixed).
   - The sweep imports its payment keys into a Core wallet named after the provider (`bsb-honest-paid`).
   - On a node that keeps its wallets across runs and restarts, `createwallet` answers "already
     exists". The code accepted that without loading the wallet, and `importdescriptors` then failed
     with "Requested wallet does not exist or is not loaded".
   - Regtest never saw it, because every regtest run starts on a fresh datadir.
   - The sweep now loads an existing wallet. Off regtest the wallet is named after the provider's pay
     key, so two runs never share one.

## Result: paid on chain (`--pay onchain`), 2026-10-23

Settings: `--confs 3`, epochs of 50 blocks, deadline 40, term 400, 100,000-sat bonds and 8 s blocks.
The run covered signet heights 303 to 727 in 56 minutes, from 04:13 to 05:09 UTC. Results are in
`results/full-stack-onchain-signet.json`.

| Provider | Proofs | Paid on chain | Watchtower (stored / paid) | Bond |
| --- | --- | --- | --- | --- |
| honest | 3/3 | 1,536 sats | valid / paid, all three epochs | refunded at `t_end` by the provider's own agent, via the CLTV refund leaf |
| deletes 10% | 2/3 | 1,024 sats | missing at block 450 | forfeited to the client after 144 blocks, via the CSV leaf |
| outsources | 2/3 | 1,024 sats | missing at block 450 | forfeited to the client after 144 blocks, via the CSV leaf |

- **Funding.** The client printed what each wallet needed and waited. The faucet paid each request, and
  the client saw each payment confirmed within 30 s of the next block. It then split its fee wallet
  into 6 coins and waited for 3 confirmations.
- **Deals.** All three deals went over the two relay processes: propose, accept, seal, then live, the
  last with the provider's presignatures, checked by `bond-check`. The client sealed each bond only at
  3 confirmations. Setup took 3.5 minutes, and the first boundary was then fixed at block 350.
- **Proofs and payment.**
  - Every proof waited until its boundary was 3 blocks deep and took 18–68 s; three proofs at once
    queue for the one prover.
  - The client paid each verified epoch on chain at the 2 sat/vB fallback rate. The batches were 240,
    240 and 154 vB (482, 482 and 310 sats), the sizes the model gives (design §4.5).
- **The watchtower** ran without a node. It validated 726 headers from the genesis block under signet's
  parameters (`SIGNET` in `layer1/headerchain.ts`, exercised for real here). It attested 16 times
  (stored valid, paid, stored missing). A third party's final re-check verified 3 of 3 receipts in 30–90
  ms each.
- **Enforcement.**
  - The client challenged both flagged bonds at once, one fee coin each.
  - Each provider's agent read the revealed secret from the chain and tried to answer; Core's script
    check rejected both answers.
  - After 144 blocks the client forfeited both bonds; each forfeit counted at 3 confirmations.
- **Refund.** At `t_end` the honest provider refunded its own bond, with no orchestrator asking. It
  counted the refund at 3 confirmations and published `settled`; the client read the txid from that
  event.
- **Not as in phase 5, and why.**
  - The cheaters started one epoch late (finding 6).
  - The honest provider's payments were not swept (finding 7).
  - Both bugs are fixed, and the Lightning run below has the fixes.
- **Earlier attempts.**
  1. Over Lightning, it stopped at startup (finding 1).
  2. On chain, the machine bugchecked during funding (finding 2).
  3. On chain again, it stopped at the cheaters' sweep (finding 3) after 67 minutes. Its blocks had been
     slow (finding 5), and its epoch table matched phase 5 exactly until then: both cheaters valid at
     block 150, then missing at 200 and 250.

## Result: over Lightning (`--pay ln`), 2026-10-23

Settings: the same, with a 50,000-sat private channel from the client's lnd to each provider's lnd.
Every lnd ran on neutrino against the private node's loopback P2P port (finding 1). The run covered
signet heights 728 to 1153 in 57 minutes, from 05:10 to 06:07 UTC, with the fixes for findings 3–7 in
place. Results are in `results/full-stack-signet.json`.

| Provider | Proofs | Paid over Lightning | Watchtower | Bond |
| --- | --- | --- | --- | --- |
| honest | 3/3 | 1,536 sats | valid throughout | refunded at `t_end` by its own agent (CLTV leaf); `settled` published at 3 confirmations |
| deletes 10% | 1/3 | 512 sats | missing at block 850 | forfeited to the client after 144 blocks (CSV leaf) |
| outsources | 1/3 | 512 sats | missing at block 850 | forfeited to the client after 144 blocks (CSV leaf) |

This is phase 4's regtest table epoch for epoch, now in signet mode.

- **Channels.** Each opened at 2 sat/vB, counted at 3 confirmations, and was then accepted by the
  provider's node.
- **Payments.** Each verified epoch was paid by a BOLT 11 invoice with the `lntbs` prefix and route
  hints for the private channel.
- **Closes.** Each channel was closed cooperatively from the provider's node at 3 confirmations, paying
  the provider exactly what it was paid (1,536 or 512 sats).
- **The cheaters** started on time (the fix for finding 6). Their bonds were challenged at once, one fee
  coin each (the fix for finding 4). The provider files show what a restarted provider would resume
  from: `party.seed`, the deal, presignature and refund files, and `settled`.

## Regtest after the fixes

Every fix keeps regtest's behaviour except on the paths regtest never took (a dust sweep error, a sweep
wallet that already exists). After them, on fresh regtest datadirs:

- **Tests.** `node --test model/*.test.ts layer1/*.test.ts`: 96 of 96 pass.
- **Whole stack, on chain.** Every bond transaction, revealed secret and the final height (1,614) are
  byte-identical to phase 5's committed run.
- **Whole stack, over Lightning.** The honest provider's and the outsourcer's bond transactions are
  byte-identical to phase 4's, and so is the deleter's funding. The deleter itself was never caught:
  it proved all three epochs and kept its bond.
  - That was chance, and checked as such. The hashes of blocks 180 and 190 drew 16 challenges each,
    and none landed on any of the deleter's 46 zeroed chunks.
  - A provider holding 90% of its chunks passes a q = 16 epoch with probability 0.9^16 ≈ 18.5%, and two
    epochs running about 3.4% of the time (design §4.4, `p_detect_10pct_per_epoch` = 0.815).
  - The on-chain run's deleter escaped block 180 the same way and was caught at 190.
  - The earlier phase 7 runs all caught it at the first epoch. Regtest block hashes, and so the seeds,
    differ between runs.

## What this shows, and what it does not

**Shown:** the stack runs end to end in signet mode, both ways of paying, on a chain with real block
times (8 s here) where nothing in the protocol code mines.

- Fresh keys per party, the cookie login, `tb`/`tbs` prefixes and the fee fallback all held.
- So did depth before relying on outputs, the deal handshake over two relays, and public proofs
  waiting for depth.
- So did the watchtower's signet header chain, parallel enforcement, and refunds providers made on
  their own.

**Not shown:**

- **The public signet's reorgs.** A private chain with one miner never reorgs.
- **A real fee market or estimates.** Every rate was the 2 sat/vB fallback.
- **Separate machines, real relays, public Blossom URLs, multi-hop Lightning.** Everything ran on one
  laptop.
- **lnd's bitcoind backend on signet.** Only neutrino ran here, because of finding 1.
- **Restarts mid-run.** None was exercised.

The public pilot (`docs/signet-pilot.md`) is still the test for those. The findings here, 3, 4 and 7
above all, are bugs that pilot would otherwise have hit on its first run.
