# Signet pilot runbook (phase 7)

The phase 4–5 stack (sentinel bonds, public Stwo epoch proofs, a watchtower, pay per proof over
Lightning or on chain) is ready to run on Bitcoin's default signet, with every party on its own machine
and talking over public Nostr relays. All code work was done and tested on regtest (§10). **Nothing has
run on signet yet.**

Every step below that starts a signet node, downloads the chain, asks a faucet for coins, rents or
starts a machine, or publishes to a public relay needs Patrick's go-ahead first. The pilot never touches
mainnet or real funds. Every entry point and `bsb-bond` refuse any network but `regtest` and `signet`.

Sources for the external numbers below were read on 2026-10-21. Section 11 lists them.

## 1. What the pilot tests that regtest cannot

| Area | What regtest showed | What only the pilot can show |
| --- | --- | --- |
| Separate machines | Separate processes, keys and wallets, but one host, one node and localhost URLs | Public Blossom URLs behind TLS, lnd peers across the internet, clocks that disagree, each party on its own node that briefly sees a different tip, and process restarts mid-run (a provider resumes its bonds from `--dir`) |
| Real relays | The bundled minimal relay, plus the relay pool against several local relays, one dropped and restarted (`layer1/signet.test.ts`) | Rate limits, event-size limits (strfry's default `maxEventSize` is 65,536 bytes), write policies that drop unknown kinds, NIP-42 or paid writes, connections that drop for hours, and how long a deal handshake takes across relays |
| Block times | A block every 150 ms | Δ = 144 blocks at real block times (§5); epochs, deadlines and proof latency against real blocks; the term and refund at a real `t_end` |
| Reorgs | None | Default signet has deliberately reorged about once a day since 2026-06-02 (§11). This tests the code's answers: proofs wait for `--confs` before proving a seed, a provider re-sends an answer a reorg dropped until it is deep, and the client re-sends a dropped challenge or forfeit |
| Fees during Δ | Fixed fees | Fees are estimated when each CPFP child, funding, forfeit and refund goes out, so a rise during Δ is paid by whoever broadcasts then. **Signet has no real fee market**, though: blocks are near empty, and Core 31's `estimatesmartfee` is broken on signet (issue #35507). The pilot can test the mechanics, by pinning different `BSB_FEE_RATE`s per party and changing one mid-Δ, but not competition for block space |
| Multi-hop Lightning | One direct private channel per pair | Client → hub → provider routes with a routing-fee budget (`--ln-fee-budget-msat`), and route hints for private channels (providers put them in invoices off regtest). The public signet LN graph looks stale (last indexed snapshot 2025-12), so the pilot should run its own hub (§3) |

## 2. The node

Use Bitcoin Core 31.1, the version every regtest phase used, on default signet with `txindex=1`.
`bsb-bond` looks transactions up by txid and refuses to start off regtest without txindex, so a pruned
node will not do.

```ini
# bitcoin.conf on each machine that runs bitcoind
signet=1
server=1
txindex=1
[signet]
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
```

Every party authenticates with the node's cookie: set `BSB_RPC_COOKIE=<datadir>/signet/.cookie`.
`BSB_RPC_USER` and `BSB_RPC_PASS` also work. Off regtest there is no default login, and the regtest
password is refused. The default RPC URL is `http://127.0.0.1:38332`, or set `BSB_RPC`.

Disk per full node:

| Part | Size | Basis |
| --- | --- | --- |
| Blocks | about 24–25 GB | Core 31.x and master `chainparams` assumed sizes; signet tip about 327,300 |
| Chainstate | about 4–5 GB | the same |
| txindex | about 1.5–2 GB | an estimate, not measured: scaled from mainnet's txindex by transaction count (about 32M on signet) |
| **Total** | **about 32 GB; plan for 40 GB** | |

Initial sync time on signet is not published. Measure it on the first machine before scheduling the
others.

**Measured, phase 7C pilot step 1 (2026-10-23):**
- **Setup:** Core 31.1 on default signet, `txindex=1`, `dbcache=2000`, below-normal priority, on one
  Windows laptop over a home connection.
- **Sync:** from empty to tip 327,643 in **2 h 27 min** (13:04 to 15:31 UTC), with txindex synced at
  the same height.
- **On disk:** blocks 24 GB, chainstate 4.2 GB, txindex 1.6 GB, **30 GB in total**. This is inside the
  estimate above; the 40 GB plan leaves room for growth.

The watchtower can run with no node at all. Its `--headers` mode follows an untrusted header mirror and
checks every header from genesis with signet's parameters (`layer1/headerchain.ts` `SIGNET`). On signet
that shows the mechanism and nothing more, for two reasons:

- a header chain cannot check signet's block signature, which lives in the coinbase;
- signet proof of work is cheap.

For the pilot, give the watchtower its own node and use RPC mode.

## 3. Machines

The minimum is three machines: a client, one provider and one watchtower. That shows the protocol but
not a cheater. **The recommended pilot is five or six machines**, as in the regtest run:

| Machine | Runs | Needs |
| --- | --- | --- |
| client | `bitcoind`; `lnd` (or a Core wallet with `--pay onchain`); `node layer1/full-stack.ts --providers ... --watchtower ...`; the `bsb-zk` verifier (Linux or WSL) | 40 GB disk, 4 GB RAM. Must stay up for the whole run: the client's run state is in memory, and its deal files are in `--dir` |
| provider × 3 (honest, deletes 10%, outsources) | `bitcoind`; `lnd`; `node layer1/provider.ts --zk ...`; `bsb-zk` and the Cairo executables (`/root/build/bsb-zk/exe3b`) | 40 GB disk plus blobs and proofs (about 11 MB per epoch), 8 GB RAM (a q = 16 Blake2s proof has a floor of about 2 GB). Public HTTPS for its Blossom server (`--public-url`, behind a reverse proxy) and a public TCP port for lnd (`--ln-listen 0.0.0.0:9735 --ln-external <host>:9735`) |
| watchtower | `bitcoind` (recommended) or none (`--headers`); `node layer1/watchtower.ts`; the `bsb-zk` verifier | 40 GB disk with a node, 2 GB RAM |
| Lightning hub (optional, can share the client machine) | `bitcoind`, `lnd` with public channels to each provider | For the multi-hop test: the client pays through it with `--ln-open none` |

Every party pays its own fees, so every machine except the watchtower needs signet coins (§4).

Two machines can share one `bitcoind`. Each party still keeps its own keys, because `bsb-bond` uses no
node wallet. Doing so loses the "each party on its own node" test, though.

## 4. Coins

Each party's wallet must be funded before setup goes on. `full-stack.ts` prints each address and the
amount it needs, then waits. The amounts follow from the code (`full-stack.ts`, "coins"), with fees at
`f` sat/vB:

| Wallet | Needs | At bond 100,000, capacity 50,000, f = 2 | At bond 20,000, capacity 25,000, f = 2 |
| --- | --- | --- | --- |
| each provider's fee wallet | `bond_sats + 4·800·f + 20,000` | 126,400 | 46,400 |
| client fee wallet (CPFP for challenges) | `providers·4·400·f + 20,000` | 29,600 | 29,600 |
| client lnd (channels) | `providers·(capacity + 2,000)` | 156,000 | 81,000 |
| or client payment wallet (`--pay onchain`) | `providers·epochs·512 + 20,000` | 24,608 | 24,608 |
| **Total, 3 providers, Lightning** | | **about 565,000 sats (0.0057 sBTC)** | **about 250,000 sats** |

lnd's smallest channel is 20,000 sats. `--bond-sats` must be at least 10,000.

Where the coins come from:

| Faucet | Gives | Limits |
| --- | --- | --- |
| bitcoinsignetfaucet.com | 1,000–10,000 sats a request | 5 requests per IP and address per 24 h |
| faucet.coinbin.org | 10,000–90,000 sats | none stated |
| signet.dcorral.com | 10,000 sats | none stated |
| alt.signetfaucet.com | random amounts | none stated; asks users to return coins |

signetfaucet.com was down on 2026-10-21 (HTTP 522). signet.bc-2.jp now redirects to an unrelated
domain, so treat it as dead.

The web faucets give at most about 50,000 sats per IP per day, which makes 250,000–565,000 sats a matter
of 5 to 12 IP-days. That leaves three options:

- **Ask a signet block signer** (AJ Towns or Kalle Alm) for about 0.01 sBTC. No formal process is
  documented.
- **Shrink the run**: `--bond-sats 20000 --capacity 25000`, or `--pay onchain`, which needs no channels.
- **Run the pilot on a signet of its own** (§9).

`bsb-bond fee-split <n> <sats>` splits a fee wallet's largest coin. Off regtest a spend waits a block
before its change can be spent again, and the client challenges every flagged provider at once, so the
client should split its fee wallet into at least `providers × 2` coins.

## 5. Time at signet block times

Recent signet blocks came about every 12 minutes, against a 10-minute target. The table gives both.

| Interval | Blocks | At 10 min | At 12 min |
| --- | --- | --- | --- |
| Confirmation depth, `--confs 3` (the default off regtest) | 3 | 30 min | 36 min |
| Depth recommended for default signet, given its daily reorgs (`--confs 6`) | 6 | 1 h | 1.2 h |
| Setup per provider (bond, then channel, both to depth; providers one after another) | 2 × confs | 1–2 h | 1.2–2.4 h |
| Epoch (`--epoch-blocks`) | 36 / 144 | 6 h / 24 h | 7.2 h / 28.8 h |
| Deadline (`--deadline`); must exceed `confs` plus proving time (a q = 16 proof takes about 1–3 min) | 12 | 2 h | 2.4 h |
| Δ, a challenged provider's time to answer | 144 | 24 h | 28.8 h |
| Enforcement of a provider that answers no sentinel | 1 + 144 | about 1 day | about 1.2 days |
| Enforcement, worst case (answers 3 of the 4 sentinels) | 4 × 145 | about 4 days | about 4.8 days |

Flagged providers are enforced in parallel off regtest.

The term must cover setup, the epochs, the deadline and enforcement. A provider must also accept it:
`--min-term` defaults to 300 blocks. A pilot of three 36-block epochs with confs 6 then needs about:

- setup: 3 providers × 2 × 6 = 36 blocks;
- epochs: 3 × 36 + 12 = 120 blocks;
- enforcement, worst case: 580 blocks.

That comes to a `--term 800`: about 5.5–6.7 days from start to the honest provider's refund. A shorter
smoke test needs `--epochs 2 --epoch-blocks 12 --deadline 9 --term 450`, roughly 3–4 days. Most of that
is the enforcement window: Δ is fixed at 144 blocks by the bond's script.

## 6. Keys and safety

- **Fresh keys per party and per run.** Off regtest each party makes 32 random bytes on first start
  and keeps them in `<dir>/party.seed` (`layer1/net.ts` `partySeed`). Its bond, fee wallet, Nostr and
  on-chain pay keys all derive from that seed. Use a new `--dir` for each run. A restarted process with
  the same `--dir` keeps its keys, which it needs to answer challenges and to refund its bond.
- **Fixed values are refused off regtest.**
  - `bsb-bond` and every TypeScript entry point refuse a seed that is not 64 hex digits. Every fixed
    test label in this repository fails that check (`bsb/provider/honest`, `bsb/client/...`,
    `bsb/watchtower`, `bsb/fee-wallet`), and so do constant byte strings such as the MuSig2 nonce
    seeds.
  - The fixed RPC password is refused.
  - The client's deterministic demo nonces are switched off.
  - The MuSig2 cooperative close with fixed nonce seeds lives only in the regtest harness
    (`bsb-regtest`), which refuses any chain but regtest.
  - The Winternitz test secrets in `zk/bitvm-check` run only inside BitVM's script interpreter and touch
    no network.
- **lnd wallets** are made fresh per node with `--noseedbackup`. That is fine for test coins, but a
  lost machine loses its channel balance.
- **`model/schnorr.ts`** signs Nostr events and on-chain invoices with bigint arithmetic that is not
  constant time. That is acceptable for signet test coins, not for real funds.
- **The run directory** is kept at the end of every signet run, because it holds the keys.

## 7. Relays and Blossom

- **Relays.** Give every party the same `--relays wss://a,wss://b,...`. The relay pool publishes to all
  of them and counts an event as published if any relay accepts it. It reads from all of them, drops
  duplicates, and reopens a dropped relay with backoff, re-sending its subscriptions.
  - Before choosing relays, run `node layer1/relay-probe.ts --relays wss://a,wss://b`. It publishes one
    event of each kind the stack uses, tagged `network: probe`, plus events of 4 to 100 kB, and reports
    what each relay kept. **It posts to the named relays, so it needs a go-ahead.**
  - The candidates run strfry (relay.damus.io, nos.lol, relay.primal.net). nostr.wine charges for
    writes.
  - **Probed, phase 7C pilot step 2 (2026-10-23; `results/relay-probe-signet-pilot.json`).** Each relay
    got one event of each of the six kinds, then padded events of 4–100 kB, from a fresh key:

    | Relay | Kinds kept | Largest kept | First round trip | Verdict |
    | --- | --- | --- | --- | --- |
    | relay.primal.net | 6/6 | 100 kB | 554 ms | **use** |
    | relay.snort.social | 6/6 | 100 kB | 636 ms | **use** |
    | nostr.mom | 6/6 | 64 kB (100 kB "event too large") | 484 ms | **use** |
    | nos.lol | 6/6 | 64 kB | 1,277 ms | fallback |
    | relay.damus.io | 6/6 | none | 470 ms | avoid: after six events, a fresh key is rate-limited ("you are noting too much"), then banned for a while |
    | offchain.pub | 6/6 | 4 kB | 516 ms | avoid: larger events refused unless the key is in its web of trust |

    **Pilot relays:** `--relays wss://relay.primal.net,wss://relay.snort.social,wss://nostr.mom`, with
    nos.lol as the fallback. Every event the stack publishes is under 64 kB: a deal acceptance is about
    6 kB, and NIP-44 answers over 60 kB already go by encrypted URL.

    A client publishing many events at setup should still pace them: damus shows a relay can rate-limit
    a burst from a new key.
  - The stack's events are small: the deal acceptance is about 6 kB, a payment receipt a few kB, and a
    proof announcement under 1 kB. The proof itself is a Blossom blob.
  - The kinds are unregistered placeholders: 4245 (proof), 4246 (attestation), 4247 (payment receipt),
    4248 (deal), 8242 (epoch receipt) and 34248 (offer, addressable). None of them is in the NIPs kinds
    table as of 2026-10-21.
- **Blossom.** Each provider serves its own Blossom server: uploads, PDP and sentinel answers, and its
  epoch proofs, which are about 11 MB of JSON each. Public Blossom servers are no substitute. nostr.build
  takes only media on its free tier, and the others publish no limits for opaque blobs. Put each
  provider's server behind HTTPS and pass that URL as `--public-url`. It goes into the offer, into blob
  descriptors and into proof URLs.

## 8. Running it

Each step is gated: none runs without Patrick's yes.

0. **Preflight on regtest** (done, §10): `node --test model/*.test.ts layer1/*.test.ts`, and
   `node layer1/full-stack.ts` on a fresh regtest datadir.
1. **Machines and nodes.** Provision the machines (§3). Install Core 31.1 (checking its signatures),
   Node 24, lnd v0.21.4, and the WSL or Linux `bsb-zk` build. Sync signet with txindex.
2. **Relays.** Run the probe and pick three relays.
3. **Start the parties.** On the client machine,
   `node layer1/full-stack.ts --network signet --dir ~/bsb-run1/client --print-key` makes the client's
   keys for this run and prints its Nostr key (for the providers' `--uploaders`) and fee address. Then
   start the watchtower and the providers; each prints its Nostr key and fee address.
   ```bash
   # every machine
   export BSB_NETWORK=signet BSB_CONFS=6 BSB_RPC_COOKIE=$HOME/.bitcoin/signet/.cookie
   export RELAYS=wss://relay-a,wss://relay-b,wss://relay-c

   # each provider (its own --dir, a new one per run)
   node layer1/provider.ts --name honest --dir ~/bsb-run1/honest --relays $RELAYS --admin-token $(openssl rand -hex 16) \
     --public-url https://p1.example --host 127.0.0.1 --port 8080 --pay ln --ln-listen 0.0.0.0:9735 --ln-external p1.example:9735 \
     --zk --epoch-blocks 36 --zk-q 16 --zk-from <first boundary> --bond-max-sats 100000 --max-term 1000 \
     --uploaders <client nostr key> --failure-domain "<host, region>"

   # the watchtower, on its own node
   node layer1/watchtower.ts --relays $RELAYS --providers <p1>,<p2>,<p3> --epoch-blocks 36 --from <first boundary> \
     --deadline 12 --min-q 16 --dir ~/bsb-run1/watchtower
   ```
4. **Fund** each provider's fee address (§4).
5. **Start the client.** It finds the providers by their offers, waits for its own wallets to be
   funded, makes the deals, and runs to the end:
   ```bash
   node layer1/full-stack.ts --providers <p1>,<p2>,<p3> --watchtower <tower key> --relays $RELAYS --dir ~/bsb-run1/client \
     --epochs 3 --epoch-blocks 36 --deadline 12 --first <first boundary> --term 800 --bond-sats 100000 --q 16
   ```
   For the multi-hop test, open channels client → hub → each provider beforehand and add
   `--ln-open none`.
6. **Misbehave.** From the second epoch, the cheating providers' operators act on their own machines,
   through the admin port on 127.0.0.1:
   ```bash
   curl -H "x-admin-token: $T" -d '{"kind":"delete","sha":"<own replica sha>","indices":[...]}' http://127.0.0.1:<admin>/admin/misbehave
   curl -H "x-admin-token: $T" -d '{"kind":"outsource","sha":"<own replica sha>","from":{"url":"https://p1.example","sha256":"<honest replica sha>"}}' http://127.0.0.1:<admin>/admin/misbehave
   ```
   Replica hashes are public: they are the `x` tags of each provider's deal events. The simplest
   cheater just stops its process, and the watchtower then attests it missing.
7. **Watch and collect.**
   - The client writes `results/full-stack-signet.json` (or `full-stack-onchain-signet.json`) when the
     run ends, with every txid read back from its node, the offer and the four deal events per provider,
     and the attestations.
   - Providers log one JSON line per event. Off regtest they refund their own bonds at `t_end` and
     publish a `settled` deal event.
   - With `--pay onchain`, each provider's operator sweeps its payments with `POST /admin/sweep`.

`node layer1/market.ts --network signet` also works. It runs the four providers on one machine, though,
and is slower to enforce. The pilot uses `full-stack.ts`.

## 9. A signet of the pilot's own

Stock Core runs a custom signet: `signetchallenge=<script>` on every node, with blocks produced by
`contrib/signet/miner` at any interval the pilot chooses.

What it gives:

- unlimited coins, so the 1 BTC bonds of the regtest runs are possible;
- short blocks: at 30 s, Δ is 72 minutes;
- no third-party reorgs.

What it loses:

- the public chain and its reorgs;
- any outside Lightning node;
- the realism of a shared block producer.

Separate machines and real relays work the same way. The code takes it as `signet`. The watchtower's
`--headers` mode would need the custom genesis only if its challenge changed it (§2 of
`layer1/headerchain.ts`).

Mutinynet (30 s blocks, an active LN graph, a Lightning faucet) needs benthecarman's fork of Core, now
based on Bitcoin Inquisition. Stock Core 31.1 cannot follow it, so it is out of scope unless the pilot
adopts that fork.

## 10. What was done for the pilot, and checked on regtest

- **Network flag** (`layer1/net.ts`, `regtest/src/common.rs` `NetCfg`). `--network` / `BSB_NETWORK`
  sets RPC ports and logins, address and BOLT 11 prefixes (bcrt/tb, bcrt/tbs), and the confirmation
  depth (`--confs`, default 3 off regtest). Blocks are mined on regtest and waited for elsewhere; no
  `generatetoaddress` or `generateblock` runs off regtest. Fees are estimated off regtest (capped at
  `BSB_MAX_FEE_RATE`, default 10 sat/vB because of Core #35507; `BSB_FEE_RATE` pins one). It covers
  `bsb-bond`, `provider.ts`, `full-stack.ts`, `market.ts`, `watchtower.ts`, lnd (`--bitcoin.signet`)
  and the header chain (signet parameters).
- **Keys** (§6). Fresh per party and per run, kept for restarts; fixed values refused.
- **Deals as Nostr events** (`layer1/deals.ts`, design §6).
  - The provider's offer is an addressable event.
  - A deal is four events: propose (client), accept (provider: the deal, Bond_0's outpoint, script and
    merkle root, its presignatures), seal (client: its presignatures, after the bond is deep), and live
    (provider).
  - A proposal is honoured only from the key that uploaded the blob, and only for the commitments its
    cut and choose ran on.
  - Relays and Blossom URLs are configurable (`--relays`, `--public-url`).
- **Per-deal bond size** (`bond_sats` in the deal; 1 BTC by default as before), funded from several
  faucet-sized coins when no single coin covers it, and a channel close fee in the channel file.
- **The presignature order** (design finding 13). The provider's Challenge_i signatures now come
  last, in `live`, after it holds the client's Respond_i signatures. Up to phase 6 they came first,
  which let a client that never sealed challenge a bond the provider could not answer. A bond whose
  client never seals is refunded at `t_end`. Offers cap the term with `--max-term` (default 4,320
  blocks off regtest), and `--uploaders` limits who may store and so propose at all.
- **Restarts and reorgs.**
  - A provider resumes from `--dir`: its bonds (sealed or not), its cut-and-choose records, its deal
    list, and the last epoch it proved and billed, so it bills no epoch twice.
  - A provider proves a boundary only once it is `--confs` deep, and re-sends an answer until it is
    deep.
  - A provider counts its refund only at depth, and keeps answering challenges until then.
  - The client re-sends a dropped challenge or forfeit, and stops if its input is gone for good.
  - The client pays each provider at most once per epoch.
  - Waits for blocks retry through RPC errors.
  - Each `bsb-bond` call, each RPC call and the provider's call to its own server have timeouts.
  - The provider's agent reaches its server on loopback, never through its public URL.
- **Relays.** A subscription a relay closes is sent again; a relay that times out on a publish, or
  fails the once-a-minute probe, is reopened. The watchtower drops receipts that claim blocks far ahead,
  checks receipts in a queue of their own, and does not let an invalid receipt block a later valid one.
- **Remote parties.** `full-stack.ts --providers` and `--watchtower` use parties running elsewhere.
  Off regtest the first boundary is fixed when setup ends, and the local watchtower starts then.
- **Regression on fresh regtest datadirs** (2026-10-21):
  - **Tests.** `node --test model/*.test.ts layer1/*.test.ts`: 92 tests, all pass, none skipped, the
    11 in `signet.test.ts` included. `cargo test`: 4 new tests.
  - **The harness.** `bsb-regtest`: 21 checks, 0 failed, and `results/regtest.json` byte-identical to
    phase 1's.
  - **The whole stack over Lightning.** `node layer1/full-stack.ts` ended as in phase 4.
    - The honest provider was paid 1,536 sats over Lightning and refunded at `t_end`.
    - "deletes 10%" and "outsources" were attested missing at block 180 and forfeited after 144
      blocks.
    - Every bond transaction is byte-identical to phase 4's, and so is the final height of 1,614: the
      fundings (`6cbf47b6…`, `e92aaadd…`, `50227bf5…`), both challenges with their revealed secrets,
      both forfeits and the refund. Regtest transactions are unchanged by default, even with the deal
      now made over Nostr in its new order.
    - Results: `results/full-stack.json`.
  - **Paid on chain.** `--pay onchain` ended as in phase 5, with the same bond transactions, payment
    transactions of 240 / 154 / 154 vB as modelled, and a third party verifying 3 of 3 receipts from
    mirrored headers. Results: `results/full-stack-onchain.json`.
  - **The market.** `node layer1/market.ts`, on one-way channels, paid the honest provider 5,120 sats
    and refunded it. Deletes 10%, deletes 50% and outsources all forfeited. Its sentinels, bond and
    channel fundings and forfeits are byte-identical to a baseline run of the phase 4 code with the
    phase 6 `bsb-bond`. Results: `results/market.json`; the file it replaces dates from phase 2a.
  - **Funding from several coins, and the new order**, on its own regtest node:
    - A 120 BTC bond was funded from three 50 BTC coins, at 269 vB.
    - The client presigned before seeing the provider's signatures.
    - `bond-challenge` was refused until those signatures arrived.
    - `bond-check` caught a swapped signature.

    Running market and full-stack one after another, the old `bsb-bond` (one connection per RPC) left
    about 18,000 sockets in TIME_WAIT. The phase 6 baseline failed once on Windows port exhaustion (error
    10048). The new `bsb-bond` reuses one connection per call.

## 11. Open before or during the pilot

- **Confirmation depth.** The default stays 3, as specified, but default signet now reorgs daily; use
  `--confs 6` there.
- **Fees.** Core #35507 makes `estimatesmartfee` useless on signet. The cap keeps that from draining
  wallets, but pinning `BSB_FEE_RATE=1` or `2` is simpler. lnd uses bitcoind's estimator for its own
  sweeps (`bitcoind.estimatemode` defaults to CONSERVATIVE); channel opens and closes here pass explicit
  rates.
- **Setup runs one provider after another.** That costs about 2 × confs blocks per provider.
- **The client is not restartable mid-run.** Providers and the watchtower are, though the watchtower
  re-publishes attestations after a restart.
- **Griefing by unsealed deals.** A client can make a provider fund a bond and never seal. That locks
  the provider's capital until `t_end`, which `--max-term` bounds. Nothing limits how many such deals one
  client makes beyond `--uploaders`. For the pilot, run providers with `--uploaders <client key>`.
- **These fixes came from a code review of the signet-only paths and are unit-tested or regtest-tested
  where regtest reaches them.** Reorgs, relays that close subscriptions, and restarts mid-deal have not
  happened for real.
- **No pruned nodes.** txindex is required, so plan for about 32 GB per node.
- **The watchtower's header mode is a stand-in on signet** (§2).
- **The kinds are unregistered** (§7).
- **Nothing here has met a public relay, a public Blossom server, or another machine yet.**

Sources (read 2026-10-21):

- Signet tip, block interval and mempool: mempool.space/signet.
- Disk sizes: Bitcoin Core `src/kernel/chainparams.cpp` (31.x branch and master).
- Daily reorgs: delvingbitcoin.org/t/regular-signet-reorgs/2549.
- Fee estimation on signet: Bitcoin Core issue #35507.
- Relay defaults: Core 30.0 release notes (0.1 sat/vB `minrelaytxfee`).
- Faucets: each faucet's page.
- The signet Lightning graph: mempool.space's signet Lightning pages.
- strfry defaults: the strfry configuration reference.
- Mutinynet: its faucet and the benthecarman/bitcoin fork.
- Nostr kinds: the NIPs README and registry-of-kinds.
