# Storage term binding for the BitVM spike

`src/storage_binding.rs` adds a storage-specific disprove leaf to the phase-6 work. It checks that
the asserted Groth16 public input is the one belonging to the graph's storage term:

```text
preimage = "bsb/r0-term|v1" || hold_id || header_chain_id || u32be(q, deal_count) || D
           || u32be(first, step, epochs, depth, tip_height) || tip_hash_internal || u256be(work)
journal  = SHA256(preimage)                         # 202 bytes before hashing
public   = BLAKE3(constants_digest || journal)[0..31] # big-endian integer, without field reduction
```

The 134-byte term prefix and the wrapper's constants digest are fixed when compiling the leaf.
The tip height, hash and work are messages under three additional Winternitz keys. The public-input
key must be **the same key as `PublicKeys.0[0]` in the Groth16 chunker's assertion**. The graph must
also include those chain-value keys in its assertion transactions. A separate, unrelated signature
key would not bind this leaf to the asserted proof.

The pinned chunker (`BitVM` 7d1ca36, `chunk/elements.rs::serialize_to_byte_array`) signs a scalar as
32 big-endian bytes with the high and low nibbles of each byte swapped. The leaf uses that exact
message format. It does not interpret the signature message as ordinary big-endian or little-endian.

Every signature must verify. The leaf returns true only when the recomputed public input differs
from the signed one. Thus an honest assertion cannot be spent through this leaf, while a genuine
proof for another term cannot substitute for this term merely because its Groth16 verification passes.

`model/bitvm_term.ts` supplies the shared off-chain encoder used by `zk/risc0/check-groth16.ts`.
Its tests reconstruct the existing phase-6 proof's journal, circuit constants and public input and
check mutations of every term field. It rejects empty schedules, shallow tips, integer overflow and
non-canonical public-input encodings. These off-chain checks do not replace the script.

## Local verification

With the pinned dependencies already fetched, these commands do not need network access:

```bash
cargo test --offline --locked --manifest-path zk/bitvm-check/Cargo.toml --lib -- --nocapture
cargo build --offline --locked --manifest-path zk/bitvm-check/Cargo.toml --bins
bsb-bitvm-check results/bitvm2-spike-groth16 --wrong-public 1 --verify-only
```

The seven interpreter tests enforce Bitcoin's 1,000-item stack limit. The lower-stack SHA-256 path
and the BLAKE3 word-order conversion are checked against the recorded term, with intermediate
journal and scalar-order assertions. The leaf uses at most 760 stack items.

`binding-regtest.ts` then tests actual Taproot spends against a fresh Core node, using fresh one-time
test keys for each case. The existing Groth16 proof is reused; this does not regenerate a ZK proof.

```bash
node zk/bitvm-check/binding-regtest.ts \
  --bitcoind <installed-bitcoind> --checker <built-bsb-storage-binding> \
  --dir <new-test-directory> --out <new-result-file>
```

For Windows Node with the checker built in the existing WSL distribution, replace `--checker` with
`--wsl-checker /root/build/bsb-bitvm-target/debug/bsb-storage-binding`. Paths passed to `--dir` and
`--out` are Windows paths. `--distro` defaults to `Ubuntu-24.04`.

The harness disables peers, binds RPC to loopback, mines only regtest coins, refuses an existing
datadir, and stops its own node in `finally`. It sets `acceptnonstdtxn=1` and
`limitclustersize=2000` kB: the roughly 1.224 MB script is too large for default relay policy, and
Core 31.1's default 101 kB cluster limit rejects the transaction before script evaluation.

`results/bitvm-storage-binding-regtest.json` records the fresh Core 31.1 run: the honest disprove
is rejected at script evaluation, and signed wrong-public-input, wrong-tip, wrong-work and wrong-term cases
are accepted and mined. The disprove transaction is about 307,000 vB, at an explicit 2 sat/vB test fee.
Generated signatures, test wallet data and raw transaction vectors remain in the test datadir;
the result file contains only verdicts, sizes and transaction identifiers. No secret keys are exported.

## Storage graph integration

The leaf is now connected to a presigned storage graph with the same fresh Winternitz keys as all
364 real Groth16 verifier leaves. Core 31.1 regtest passed seven refund, slash and timeout scenarios,
including a real Groth16 disprove of a corrupted intermediate and rejection of redirected slashing.
See [the graph documentation](../../docs/bitvm-storage-graph.md) and
[the fresh result](../../results/bitvm-storage-graph-regtest.json).

This graph run reuses the phase-6 proof. A separate v1 lifecycle now verifies a fresh proof for its
own funded chain before signing. The heavier-chain challenge and per-epoch deal updates remain. The phase-6 proving key retains
the setup assumptions in design §4.6. No signet or public-network test has run.

The provider's one-time keys can now be registered before funding, with committee setup and
term-end assertion signing in separate processes. See [the lifecycle protocol](../../docs/bitvm-storage-lifecycle.md)
for the fresh v1 proof, Core regressions and one-shot signer guards. Optional setup v2 adds a
382nd commitment for the provider's term-journal digest; `--journal` selects it in the lifecycle
and graph harnesses. Both the phase-6 regression and a fresh proof from the v2 funded chain pass.
The latter executes full BitVM on the VPS and audits the sealed result locally before signing; see
`results/bitvm-storage-journal-lifecycle-fresh.json`. A funded fork contest remains unimplemented.
