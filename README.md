# blossom-storage-bonds

Filecoin's job, verifiable paid storage, rebuilt from Nostr, Blossom, Lightning and plain Bitcoin
tapscript. It needs no token, no chain of its own, no committee and no oracle.

- **Layer 1, pay per proof (off-chain).** Each epoch the client sends a random nonce over Nostr. The
  Blossom provider answers with Merkle paths for the chunks it selects, and the client checks them and
  pays over Lightning. The client is the verifier, so its own randomness is the challenge.
- **Layer 2, the sentinel bond (on-chain).** The provider's collateral sits in a chain of presigned
  taproot states. To challenge, the client reveals a 16-byte secret. The provider then has Δ blocks to
  publish that secret plus the 64-byte window it names, one 80-byte item checked by `OP_SHA256`, or it
  forfeits the bond. This works on mainnet today.

The full design, findings and plan are in [docs/design.md](docs/design.md).

## Layout

| Path | What |
| --- | --- |
| `docs/design.md` | Design note: trust table, findings, both layers, griefing, cut and choose, BitVM as phase 3 |
| `model/` | Executable TypeScript model: replica encryption, chunk tree, epoch proofs, sentinels, tapscript leaves with an interpreter, sizes, economics |
| `layer1/` | Phase 1b, layer 1 on localhost: a Blossom server with a PDP sidecar, a client, a Nostr relay, a Lightning interface with an in-memory stub, and the demo |
| `model/fixture.ts` | Writes `fixtures/sentinels.json`, the seam between the model and the regtest harness |
| `regtest/` | Rust harness (rust-bitcoin 0.32.7, musig2 0.4.1) that runs the bond chain as real transactions against Bitcoin Core |
| `scripts/regtest-node.sh` | Starts a throwaway regtest node on RPC port 18543 |
| `results/regtest.json` | Last harness run: measured vsizes and every accept/reject with Core's reason |
| `results/layer1.json` | Last demo run: every epoch's outcome per provider, receipts, balances |

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
node model/fixture.ts 3 && cd regtest && cargo run --release
```

On Windows, build with the MSVC toolchain (`RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc`), since
`secp256k1-sys` needs a C compiler. Keep `CARGO_TARGET_DIR` outside synced folders.

## Status

- Phase 0 (model): done, 15 tests.
- Phase 1 (regtest): done, 21 checks against Core 31.1. All four paths (challenge then respond,
  forfeit, refund, cooperative close) were broadcast and mined, and every predicted size matched to the
  byte. It found that Core will not relay the first design's 520-byte answer (see finding 4a).
- Phase 1b (layer 1 on localhost): done, 12 tests, with Lightning stubbed (above). A provider that
  deletes chunks fails exactly the epochs whose nonce selects a deleted chunk, and is not paid for them.
  A provider that answers from another provider's replica fails every epoch.
- Next: real Lightning (a regtest node pair or NWC) and NIP-44 DMs for layer 1, then a zk setup proof
  replacing cut and choose (2), and a pooled BitVM bond (3, research).

The keys and MuSig2 nonce seeds in `regtest/` are fixed test values. Never use this code with real
funds.
