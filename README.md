# blossom-storage-bonds

Research on verifiable paid storage using Nostr, Blossom, Lightning and Bitcoin
Taproot. The original sentinel proposal avoids a committee; the separate
LayerTree/FROST overlay instead uses threshold signing and exposes different
trust and custody assumptions.

**Research only. Do not use with real funds.** Passing Bitcoin Core regtest
checks show bounded script and transaction behavior under their exact fixtures.
Permissionless fault enforcement, malicious-quorum theft prevention, durable
independent-holder custody and unattended refresh remain open.
See [research security status](docs/RESEARCH_SECURITY_STATUS.md).

- **Layer 1, pay per proof (off-chain).** Each epoch the client sends a random nonce over Nostr. The
  Blossom provider answers with Merkle paths for the chunks it selects, and the client checks them and
  pays over Lightning. The client is the verifier, so its own randomness is the challenge.
- **Layer 2, the sentinel bond (on-chain).** The provider's collateral sits in a chain of presigned
  taproot states. To challenge, the client reveals a 16-byte secret. The provider then has Δ blocks to
  publish that secret plus the 64-byte window it names, one 80-byte item checked by `OP_SHA256`, or it
  forfeits the bond. The underlying Taproot script operations are available in Bitcoin, while the complete storage-bond protocol remains experimental.

The full design, findings and plan are in [docs/design.md](docs/design.md).

## Layout

| Path | What |
| --- | --- |
| `docs/design.md` | Design note: trust table, findings, both layers, griefing, cut and choose, BitVM as phase 3 |
| `model/` | Executable TypeScript model: replica encryption, chunk tree, epoch proofs, sentinels, tapscript leaves with an interpreter, sizes, economics |
| `model/fixture.ts` | Writes `fixtures/sentinels.json`, the seam between the model and the regtest harness |
| `regtest/` | Rust harness (rust-bitcoin 0.32.7, musig2 0.4.1) that runs the bond chain as real transactions against Bitcoin Core |
| `experiments/storage-bond-ab/` | Parallel sentinel and pooled LayerTree/FROST research, including signer-dead P2A recovery and holder ACK-before-refresh checks |
| `docs/RESEARCH_SECURITY_STATUS.md` | What has merged, independently tested properties, and remaining consensus/security blockers |
| `scripts/regtest-node.sh` | Starts a throwaway regtest node on RPC port 18543 |
| `results/regtest.json` | Last harness run: measured vsizes and every accept/reject with Core's reason |

## Run

Model (Node 22+; it runs the `.ts` files directly):

```bash
node --test model/*.test.ts
```

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
- Next: a Blossom sidecar and a client that pays per proof (1b), a zk setup proof replacing cut and
  choose (2), and a pooled BitVM bond (3, research).

The keys and MuSig2 nonce seeds in `regtest/` are fixed test values. Never use this code with real
funds.
