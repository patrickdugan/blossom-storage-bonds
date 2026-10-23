# ADR-013: Confirmed regtest UTXO provenance and witness inclusion

**Status:** Bitcoin Core 31.1 full-node regtest and independent Bitcoin commitment arithmetic tested on `research/binohash-admission`. Mainnet/testnet mining, production funds, and ZK proof generation were not performed. This ADR does not establish an independent proof of active best-chain work, complete Taproot spending-path coverage, or a working permissionless fork-admission payout protocol.

## Security question

Can the existing Blossom sentinel bond's *actually confirmed* UTXO spends supply source-grounded evidence for the Lean settlement model? Can the proof authenticate both the non-witness **txid** and the actual BIP141 **wtxid**, rather than treating mutable witness bytes as if the ordinary block Merkle root commits to them?

## Executed construction

`scripts/audit-regtest-context.mjs` runs against a separately started, consensus-validating Bitcoin Core node in [.github/workflows/blossom-regtest-context.yml](../../.github/workflows/blossom-regtest-context.yml). The job downloads the official x86-64 Bitcoin Core 31.1 tarball by HTTPS and verifies the pinned archive SHA-256:

```text
b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e
```

The node uses an isolated, throwaway regtest directory, no P2P connections and known **test-only** RPC credentials. The existing `bsb-regtest` Rust harness generates and confirms real regtest transactions: fund → challenge → response → challenge → forfeit, an independent term-end refund, a MuSig2 cooperative key-path close, and relay/consensus-adversarial witness tests. This job runs only sandboxed regtest block generation; it does not send a real-world transaction.

The audit independently reparses raw transactions, looks up their source transactions and UTXO values, checks their presence in Bitcoin Core's active-chain blocks, obtains canonical block heights via `getblockhash(height)`, and confirms the spent bond outputs are no longer unspent at the audited tip.

### Contextually verified results

[Successful full-node run](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39883245984) reports **21/21 Bitcoin Core scenarios**, nine audited confirmed transactions and no failed contextual checks. The relative forfeiture input with sequence 144 was confirmed at height **368**, matching challenged output height **224** plus 144. The refund with signed `nLockTime = 380` confirmed at height **381**. Real block-index results replace caller-chosen sample heights in the contextual model. [Lean's abstract BIP68/BIP65 inequalities](../../formal/ContextualFinality.lean) remain separately proved.

## Dual Merkle inclusion proof

The auditor obtains Bitcoin Core's `gettxoutproof` for each transaction and independently decodes the serialized BIP37 `CMerkleBlock` via [bitcoin_merkleblock.mjs](../../model/bitcoin_merkleblock.mjs). It reconstructs the ordered SHA256d transaction Merkle tree, validates the matched txid and index against the 80-byte block header, and cross-checks Core `verifytxoutproof`. Noncanonical and corrupted Merkle proofs fail.

A **txid-only** proof does not authenticate a SegWit witness. The auditor takes a real confirmed challenge, substitutes one of its witness bytes (without broadcasting it), and demonstrates that its txid and BIP37 inclusion proof remain unchanged. This is not an authorized spend, and it is explicitly marked unconfirmed.

To authenticate witness data, the auditor additionally:

- Recomputes the challenged transaction's **wtxid** from the confirmed raw witness-bearing bytes, comparing with Bitcoin Core's block record.
- Reconstructs the BIP141 witness Merkle branch at the transaction index, using a zero coinbase leaf and the other transactions' wtxids.
- Checks `SHA256d(witnessMerkleRoot || coinbaseReserved32)` against the highest matching coinbase output beginning `6a24aa21a9ed`.
- Independently parses the real serialized coinbase to bind the commitment output to its **coinbase txid** and verifies that txid's normal Merkle path to the same block header.
- Verifies that substituting a different wtxid fails the saved witness commitment even though its txid inclusion proof still matches.

Each confirmed spend yields reusable JSON evidence: block header, normal transaction partial Merkle proof, coinbase transaction bytes, coinbase transaction Merkle branch, witness reserved value and BIP141 witness branch. This evidence verifies cryptographic inclusion *conditional on an authenticated header*. The active-chain identity and full block validity currently come from the trusted local Bitcoin Core node.

## Lean results

[BitcoinInclusion.lean](../../formal/BitcoinInclusion.lean) specializes the storage Merkle binding reduction to Bitcoin transaction IDs. Distinct txids accepted at one indexed position/root imply an internal SHA256d Merkle node collision. It includes the orphan-header counterexample and a concrete witness-substitution counterexample.

[BitcoinWitnessBinding.lean](../../formal/BitcoinWitnessBinding.lean) proves that two distinct wtxids claiming the same indexed witness slot, coinbase reserved value, and witness commitment would require **either** a witness Merkle internal-node collision **or** a collision in the final SHA256d(root || reserved) commitment. The proof neither assumes globally injective SHA-256 nor proves its computational collision resistance. The implementation's correct odd-tree geometry and byte-level BIP141 layout are separately tested on real blocks and fixtures.

## Limits of the claim

1. A Bitcoin Core RPC response to `getblockhash(height)` is authenticated only by the full node's local consensus state; it is not an independent proof that the header has maximal mainnet chainwork. Regtest work does not establish mainnet confirmation guarantees.
2. Bitcoin's transaction Merkle proof and BIP141 commitment authenticate inclusion, **not** the validity of arbitrary Binohash fork-certificate computations, exact 256-bit work claims, or the collateral release rule.
3. A wtxid is bound to the actual Bitcoin transaction and its witness by SHA256d, subject to collision resistance. The experiment does not prove that a malicious proof system accepts only verified fork certificates.
4. The audit observes a finite set of actually confirmed regtest paths, not all potential cooperative key paths, script leaves, alternative signatures or future signed outputs. The `ConsensusCoverage`/`ContextualConsensusCoverage` hypothesis remains open.
5. CSV/CLTV settlement races, provider-only refunds that bypass independent journals, and the fixed setup certificate problem remain protocol design blockers. Miner inclusion and liveness are not guaranteed.

## Reproduce

Run the CI job `blossom-regtest-context.yml`. Locally, using the pinned Bitcoin Core binary:

```sh
bash scripts/regtest-node.sh /tmp/bsb-regtest-context /path/to/bitcoind
# another shell:
node --experimental-strip-types model/fixture.ts 3
cargo run --locked --release --manifest-path regtest/Cargo.toml --bin bsb-regtest
node --experimental-strip-types scripts/audit-regtest-context.mjs results/regtest.json
node --test model/bitcoin_merkleblock.test.mjs model/bitcoin_witness_commitment.test.mjs
lean -o formal/Blossom.olean formal/Blossom.lean
LEAN_PATH=formal lean -o formal/MerkleBinding.olean formal/MerkleBinding.lean
LEAN_PATH=formal lean -o formal/BitcoinInclusion.olean formal/BitcoinInclusion.lean
LEAN_PATH=formal lean formal/BitcoinWitnessBinding.lean
```

**Next proof obligation:** establish authenticated header-chain provenance and exact cumulative work against a trusted checkpoint/genesis, then connect the witness-bound challenge certificate and a sound BitVM verdict into the *same enforceable collateral payout*. Until then PR #1 remains draft.