# blossom-storage-bonds

Filecoin's job, verifiable paid storage, rebuilt from Nostr, Blossom, Lightning and plain Bitcoin
tapscript. It needs no token, no chain of its own, no committee and no oracle.

- **Layer 1, pay per proof (off-chain).** Each epoch the client sends a random nonce over Nostr. The
  Blossom provider answers with Merkle paths for the chunks it selects, and the client checks them and
  pays over Lightning. The client is the verifier, so its own randomness is the challenge.
- **Layer 2, the sentinel bond (on-chain).** The provider's collateral sits in a chain of presigned
  taproot states. To challenge, the client reveals a 16-byte secret r. The provider then has Δ blocks to
  publish r plus each of the m 64-byte windows r names, one 80-byte item per window, each checked by
  `OP_SHA256`, or it forfeits the bond. This works on mainnet today.

The whole market runs on regtest (`node layer1/market.ts`), with every party in its own process and
holding only its own keys and wallet. Four Blossom providers each post a 1 BTC bond. Each is paid per
proof in real bitcoin, against epoch challenges sent as NIP-44 encrypted Nostr events: by default
through a one-way Bitcoin payment channel, and with `--pay ln` over real Lightning, with BOLT 11
invoices from each provider's own LND node paid over a channel from the client's node. When challenged on chain, each provider's own process reads the revealed secret from the
chain and answers from the bytes it actually stores. The honest provider is paid and gets its bond back.
The ones that deleted 10% or 50% of their data, or answered from another provider's copy, have their
answers rejected by Bitcoin Core's script check and lose their bonds to the client.

The full design, findings and plan are in [docs/design.md](docs/design.md).

## Layout

| Path | What |
| --- | --- |
| `docs/design.md` | Design note: trust table, findings, both layers, griefing, cut and choose, BitVM as phase 3 |
| `model/` | Executable TypeScript model: replica encryption, chunk tree, epoch proofs, sentinels, tapscript leaves with an interpreter, sizes, economics |
| `layer1/` | A Blossom server with PDP, sentinel and cut-and-choose endpoints; the provider process; the client; a Nostr relay; NIP-44 v2; epoch challenges over NIP-44; three payment backends behind one interface (Bitcoin payment channels, LND over REST with a BOLT 11 decoder, and an in-memory stub); the layer-1 demo and the market |
| `model/fixture.ts` | Writes `fixtures/sentinels.json`, the seam between the model and the regtest harness |
| `regtest/` | Rust (rust-bitcoin 0.32.7, musig2 0.4.1): `bsb-regtest`, the phase-1 harness, and `bsb-bond`, one party's on-chain agent for bonds and payment channels (it signs only as `BSB_SEED`) |
| `scripts/regtest-node.sh` | Starts a throwaway regtest node on RPC port 18543 |
| `results/regtest.json` | Last harness run: measured vsizes and every accept/reject with Core's reason |
| `results/layer1.json` | Last layer-1 demo run: every epoch's outcome per provider, receipts, balances |
| `results/market.json` | Last market run: per provider, its process, epochs, payments read back from the chain, every challenge, and its own agent's log |
| `results/market-ln.json` | The same, for the last run paid over Lightning (`--pay ln`) |

## Run

Model and layer 1 (Node 22.18+ or 24, which run the `.ts` files directly; tested on 24.19; no npm
packages):

```bash
node --test model/*.test.ts layer1/*.test.ts
```

Layer 1 demo: one relay, four providers and one client, all on 127.0.0.1 with real HTTP and WebSocket
sockets. The client uploads a 1 MiB blob encrypted per provider and runs 10 epochs at q = 8. From
epoch 4, one provider zeroes 10% of its chunks, one zeroes 50%, and one deletes its replica and answers
from the honest provider's copy. All three keep their leaf hashes, so they can still send valid paths.

```bash
node layer1/demo.ts
```

```
epoch  honest       deletes 10%  deletes 50%  outsources
    1  pass         pass         pass         pass
    2  pass         pass         pass         pass
    3  pass         pass         pass         pass
    4  pass         FAIL         FAIL         FAIL          ← misbehaviour starts
    5  pass         FAIL         FAIL         FAIL
    6  pass         FAIL         FAIL         FAIL
    7  pass         pass         FAIL         FAIL
    8  pass         FAIL         FAIL         FAIL
    9  pass         pass         FAIL         FAIL
   10  pass         FAIL         FAIL         FAIL

provider      passed before  passed after  P(pass) after = kept^q  earned msat
honest                  3/3           7/7                    1.00         2560
deletes 10%             3/3           2/7                   0.430         1280
deletes 50%             3/3           0/7                 0.00391          768
outsources              3/3           0/7                    0.00          768
```

The nonces come from a fixed seed, so this table repeats on every run. Pass `--random` for fresh
nonces, and `--epochs`, `--q` and `--from` to change the run. The script then reads the 40 receipts
back from the relay and checks each one's signature, and each paid receipt's preimage against its
invoice hash. It downloads and decrypts the honest replica, and shows that the 50% deleter's blob no
longer hashes to its id. `node layer1/blossom.ts [port] [dir]` runs one server on its own for other
Blossom clients; its invoices cannot be paid from outside that process.

What layer 1 is and is not:

- **Blossom:** BUD-01 `GET`/`HEAD /<sha256>[.ext]` with ranges, and BUD-02 `PUT /upload` with BUD-11
  kind-24242 auth: base64url token, expiration, `t`, the `x` tag against `X-SHA-256`, and the optional
  `server` scope. It also sends CORS headers and `X-Reason`. It has no mirror, list, delete or
  `HEAD /upload`. The upload descriptor adds a `bsb` field with the chunk root that the provider
  recomputed, and the client refuses the deal unless it equals its own.
- **PDP sidecar:** `GET /pdp/<sha256>?nonce=<32-byte hex>&q=<1..256>&epoch=<e>` returns the selected
  4 KiB chunks, their paths and an invoice for the epoch. The client checks the answer with the model's
  `verifyEpoch` against its own root, n, nonce and q, and pays only if it checks.
- **Nostr:** NIP-01 events signed with the model's BIP340 code. A minimal relay (EVENT, REQ, CLOSE;
  hand-written RFC 6455 framing, memory only, no NIP-42 auth or rate limits) carries one receipt per
  epoch, kind 8242. That kind is a placeholder and is not registered. The nonce goes to the sidecar over
  HTTP, not as a NIP-17/NIP-44 DM as the design says, because that encryption is not built yet. Offers
  and deals (design §6) are passed in code rather than as events.
- **Lightning: stubbed in this demo.** No Lightning node runs here. Payment sits behind a
  `Payee`/`Payer` interface (`layer1/lightning.ts`), and this demo uses an in-memory ledger with real
  hash locks: the provider issues an invoice for SHA-256(preimage), and the client learns the preimage
  only by paying. Its invoices are `lnstub1…` strings, not BOLT 11. The market implements the same
  interface twice for real: with Bitcoin payment channels (`layer1/channel.ts`, the default) and with
  LND (`layer1/lnd.ts`, `--pay ln`, below).

Regtest (Bitcoin Core 28+ for TRUC and P2A; tested on 31.1). Start the node in one shell:

```bash
scripts/regtest-node.sh /tmp/bsb-regtest /path/to/bitcoind
```

Then, in another:

```bash
node model/fixture.ts 3 && cd regtest && cargo run --release --bin bsb-regtest
```

On Windows, build with the MSVC toolchain (`RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc`), since
`secp256k1-sys` needs a C compiler. Keep `CARGO_TARGET_DIR` outside synced folders.

### The market: both layers, every party in its own process

With the regtest node running and `cargo build --release` done in `regtest/`:

```bash
node layer1/market.ts
```

This process is the client. It starts four provider processes (`layer1/provider.ts`), each with its own
keys and fee wallet, and mines their coins. It then runs storage, cut and choose, 1 BTC bonds and
50,000-sat payment channels, ten NIP-44 epochs, enforcement, and settlement (design §2.5). The end of a
run:

```
enforcement: the client reveals sentinels; each provider's own process must answer within 144 blocks
    [honest pid 4468] saw challenge 0 on chain, r = 810384cf…: responded
  honest       challenge 0: answered on chain after 2 block(s)
    [deletes10 pid 16880] saw challenge 0 on chain, r = 6fc94129…: responded
  deletes 10%  challenge 0: answered on chain after 2 block(s)
    [deletes10 pid 16880] saw challenge 1 on chain, r = a595f107…: rejected (... Script failed an OP_EQUALVERIFY operation)
  deletes 10%  challenge 1: no valid answer in 144 blocks → forfeit d9d2753d53b4aa48…
    [deletes50 pid 32956] saw challenge 0 on chain, r = 58d2de13…: rejected (... Script failed an OP_EQUALVERIFY operation)
  deletes 50%  challenge 0: no valid answer in 144 blocks → forfeit 32706c1d2f54f734…
    [outsources pid 16028] saw challenge 0 on chain, r = 101ec656…: rejected (... Script failed an OP_EQUALVERIFY operation)
  outsources   challenge 0: no valid answer in 144 blocks → forfeit c712d179a9d810f1…

provider      failed  paid on chain (sats)  bond (1 BTC)                        P(forfeit | k)
honest             0                  5120  provider (refund at term end)                0.000
deletes 10%        2                  4096  client (forfeit leaf)                       0.9988
deletes 50%        7                  1536  client (forfeit leaf)                        1.000
outsources         7                  1536  client (forfeit leaf)                        1.000

relay holds 40 signed receipts; 24 carry a preimage that opens their invoice
```

The "paid on chain" column is read back from each channel's closing transaction, and the run fails if
any close pays other than what the client signed. `bsb-bond` is found under `$BSB_BOND`,
`$CARGO_TARGET_DIR/release` or `regtest/target/release`. `--windows 1` reproduces the one-window
sentinel, which let the 10% deleter keep its bond (design finding 9).

### The market paid over Lightning

```bash
BSB_LND=/path/to/lnd node layer1/market.ts --pay ln
```

The same market, with the one-way channels replaced by Lightning. The client process and each of the
four provider processes start their own `lnd` on the same regtest bitcoind, each with its own wallet,
TLS certificate and admin macaroon in its own directory, so no process can spend or invoice as another.
lnd polls bitcoind over RPC (`bitcoind.rpcpolling`), so `scripts/regtest-node.sh` needs no ZMQ. The
client's node is funded with its own coinbases and opens a private 50,000-sat channel to each provider's
node, and each provider's node checks the channel from its side. Each epoch's answer carries a BOLT 11
invoice signed by the provider's node. The client decodes it itself (`layer1/bolt11.ts`, which passes
every example in the BOLT 11 spec), checks the network, amount and that the recovered payee is that
provider's node, and pays through its node with `/v2/router/send`. It then checks the returned
preimage against the payment hash. Right after the last epoch, each provider closes its channel
cooperatively from its own node, and every lnd stops before the bond phase. lnd opens a new RPC
connection per call and fetches every block, so five nodes following a block every 150 ms exhaust
Windows' ephemeral ports. The run fails unless each close spends that channel's funding output and
pays the provider exactly the sum of the invoices the client paid. The client, as funder, pays the
close fee. Then every receipt on the relay is checked again from its invoice alone. The output goes to
`results/market-ln.json`.

Tested with lnd v0.21.4-beta (`lnd-windows-amd64-v0.21.4-beta.zip`, its manifest's PGP signatures
checked against the maintainer keys in lnd's `scripts/keys`, and the zip's SHA-256 against the
manifest). Without `BSB_LND` or `--lnd`, the script looks for `%LOCALAPPDATA%\Programs\lnd\lnd-*\lnd.exe`,
then `lnd` on the PATH.

A run takes under three minutes. Its epoch table, enforcement and bonds are the same as the channel
run above, since the nonces are seeded. What differs:

```
Lightning settlement: each provider closes its channel cooperatively from its own node
  honest       close 7a0f83ab88f25513…  (5120 sats paid over Lightning)
  deletes 10%  close 072b52f9355acd90…  (4096 sats paid over Lightning)
  deletes 50%  close 048986c0a371eb3b…  (1536 sats paid over Lightning)
  outsources   close 419087c97fc8d5bc…  (1536 sats paid over Lightning)
...
relay holds 40 signed receipts; 24 carry a preimage that opens their invoice's BOLT 11 payment hash
```

Start each market run, in either mode, on a fresh regtest datadir. Regtest's block subsidy halves every
150 blocks and a run mines about 1,600, so a second run on the same chain cannot fund 1 BTC bonds. A
failed run keeps its temp directory, with every lnd's `lnd.out`, and prints its path.

For the full set of official NIP-44 vectors, run `scripts/fetch-nip44-vectors.sh` once. It downloads the
file and checks it against a pinned SHA-256; the file is not committed because its repository declares
no license. Without it the NIP-44 test checks only the embedded vectors.

## Status

- Phase 0 (model): done, 16 tests.
- Phase 1 (regtest): done, 21 checks against Core 31.1. All four paths (challenge then respond,
  forfeit, refund, cooperative close) were broadcast and mined, and every predicted size matched to the
  byte. It found that Core will not relay the first design's 520-byte answer (see finding 4a).
- Phase 1b (layer 1 on localhost): done, 12 tests, with Lightning stubbed (above). A provider that
  deletes chunks fails exactly the epochs whose nonce selects a deleted chunk, and is not paid for them.
  A provider that answers from another provider's replica fails every epoch.
- Phase 2a (the market): done. Every party runs in its own process, epoch challenges go over NIP-44
  (the full official vector set passes), payments settle on chain through Bitcoin payment channels,
  and each provider's own agent answers its on-chain challenges. Every cheating provider forfeits; the
  honest one is paid and refunded. 43 TypeScript tests.
- Phase 2b (Lightning): done. `--pay ln` runs the same market over real LND nodes, one per party, with
  BOLT 11 invoices and private channels from the client's node; preimages, payees and closes are all
  checked (above). The one-way Bitcoin channel stays the default. 51 TypeScript tests.
- Next: a zk setup proof replacing cut and choose (2), and a pooled BitVM bond (3, research).

The keys and MuSig2 nonce seeds in `regtest/` are fixed test values. Never use this code with real
funds.
