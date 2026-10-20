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

Both layers run together on regtest (`node layer1/bonded.ts`). Four Blossom providers each post a
1 BTC bond and are paid per proof. When challenged on chain, each answers from the bytes it actually
stores. The honest provider gets its bond back. The ones that deleted 10% or 50% of their data, or
answered from another provider's copy, have their answers rejected by Bitcoin Core's script check and
lose their bonds to the client.

The full design, findings and plan are in [docs/design.md](docs/design.md).

## Layout

| Path | What |
| --- | --- |
| `docs/design.md` | Design note: trust table, findings, both layers, griefing, cut and choose, BitVM as phase 3 |
| `model/` | Executable TypeScript model: replica encryption, chunk tree, epoch proofs, sentinels, tapscript leaves with an interpreter, sizes, economics |
| `layer1/` | Layer 1 on localhost: a Blossom server with PDP, sentinel and cut-and-choose endpoints, a client, a Nostr relay, a Lightning interface with an in-memory stub, and the two demos |
| `model/fixture.ts` | Writes `fixtures/sentinels.json`, the seam between the model and the regtest harness |
| `regtest/` | Rust (rust-bitcoin 0.32.7, musig2 0.4.1): `bsb-regtest`, the phase-1 harness, and `bsb-bond`, which funds and enforces the bond for one real deal |
| `scripts/regtest-node.sh` | Starts a throwaway regtest node on RPC port 18543 |
| `results/regtest.json` | Last harness run: measured vsizes and every accept/reject with Core's reason |
| `results/layer1.json` | Last layer-1 demo run: every epoch's outcome per provider, receipts, balances |
| `results/bonded.json` | Last end-to-end run: epochs, cut and choose, every on-chain challenge with Core's verdict, bond outcomes |

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
- **Lightning: stubbed.** No Lightning node runs. Payment sits behind a `Payee`/`Payer` interface
  (`layer1/lightning.ts`), and the stub is an in-memory ledger with real hash locks. The provider issues
  an invoice for SHA-256(preimage), and the client learns the preimage only by paying. Invoices are
  `lnstub1…` strings, not BOLT11. A regtest LND/CLN pair, or NWC, has to implement those two interfaces.

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

### Both layers end to end

With the regtest node running and `cargo build --release` done in `regtest/`:

```bash
node layer1/bonded.ts
```

It finds `bsb-bond` under `$BSB_BOND`, `$CARGO_TARGET_DIR/release` or `regtest/target/release`. The
client commits to 64 sentinels of 16 windows per replica. Each provider opens 60 of them over HTTP and
checks them against its stored bytes, and a 1 BTC bond is funded on the other 4. Ten paid epochs follow,
with the same misbehaviour as the layer-1 demo, and then the on-chain enforcement:

```
enforcement on regtest (Core decides every answer)
  honest       challenge 0: accepted by Core (challenge 187 vB, answer 639 vB)
  deletes 10%  challenge 0: accepted by Core (challenge 187 vB, answer 639 vB)
  deletes 10%  challenge 1: rejected by Core: ... (Script failed an OP_EQUALVERIFY operation)  → forfeit 123317cafb37d2b2…
  deletes 50%  challenge 0: rejected by Core: ... (Script failed an OP_EQUALVERIFY operation)  → forfeit 3b9c411a7f7c15e8…
  outsources   challenge 0: rejected by Core: ... (Script failed an OP_EQUALVERIFY operation)  → forfeit ff209800d702d5ca…

provider      failed epochs  earned msat  challenged  answered  P(forfeit | k challenges)  bond (1 BTC)
honest                    0         2560           1         1                     0.000  closed → provider
deletes 10%               3         1792           4         1                    0.9988  forfeited → client
deletes 50%               7          768           4         0                     1.000  forfeited → client
outsources                7          768           4         0                     1.000  forfeited → client
```

The provider's agent sends whatever its server returns for `GET /sentinel/<sha>?r=&m=16`, and the tool
never checks it against h first, so Bitcoin Core is the only verifier. `--windows 1` reproduces the
one-window sentinel. In that run the 10% deleter answered all four challenges and kept its bond, which
is why sentinels have 16 windows now (design finding 9).

## Status

- Phase 0 (model): done, 16 tests.
- Phase 1 (regtest): done, 21 checks against Core 31.1. All four paths (challenge then respond,
  forfeit, refund, cooperative close) were broadcast and mined, and every predicted size matched to the
  byte. It found that Core will not relay the first design's 520-byte answer (see finding 4a).
- Phase 1b (layer 1 on localhost): done, 12 tests, with Lightning stubbed (above). A provider that
  deletes chunks fails exactly the epochs whose nonce selects a deleted chunk, and is not paid for them.
  A provider that answers from another provider's replica fails every epoch.
- Phase 2a (both layers end to end): done. 7 more tests for cut and choose and sentinel answers, plus
  the regtest run above, in which every cheating provider forfeits and the honest one closes. 35
  TypeScript tests in all.
- Next: real Lightning (a regtest node pair or NWC) and NIP-44 DMs for layer 1, then a zk setup proof
  replacing cut and choose (2), and a pooled BitVM bond (3, research).

The keys and MuSig2 nonce seeds in `regtest/` are fixed test values. Never use this code with real
funds.
