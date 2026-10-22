# Claude agent handoff: Binohash admission and collateral binding

Date: 2026-10-23. Status: protocol design blocker, not an execution resource blocker.

## Entry point

Repository: https://github.com/patrickdugan/blossom-storage-bonds
Working branch: `research/binohash-admission`
Baseline before this handoff: `692d449d4bd7d88d356438b6b2f7385f5235130d`
Draft PR: https://github.com/patrickdugan/blossom-storage-bonds/pull/1
Tracked blocker: https://github.com/patrickdugan/blossom-storage-bonds/issues/2

Latest confirmed run on baseline: https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39861714302
363/363 deterministic Node tests and 133/133 offline vendored Bitcoin Core 26 *per-input Script* cases passed. All are UNFUNDED. No mining, live UTXO enforcement, actual proof job, relay test or pilot.

## New formal verification track (2026-10-23)

Blossom now has three kernel-checked Lean 4 modules:

- `formal/Blossom.lean`: epoch payments require a nonempty accepted proof bound to the correct deal and Merkle root and a fresh epoch ID; the paid-epoch ledger prevents replay through any authorized history. Deal/root commitments remain immutable. A sentinel response advances to the **next live round** and miner fees are included in bond conservation.
- `formal/UTXORefinement.lean`: spent outpoint tracking, payout restrictions and `bitcoin_run_refines_abstract` across arbitrary histories **conditional on** `ConsensusCoverage`. Counterexamples exhibit a missing spend path and an old independent CLTV refund bypass.
- `formal/MerkleBinding.lean`: same-index chunk-opening collisions reduce to a concrete leaf, node or root commitment hash collision, without an assumption of SHA256 global injectivity. A paid Lightning invoice alone is not proof of storage.

Detailed caveats and reproduction: `docs/binohash-admission/LEAN-STORAGE-PROTOCOL.md`.

For the sentinel/payment formal track, the next task is an auditable refinement from every real Taproot spend path and Bitcoin signature in `regtest/src/bin/bond.rs` to `UTXORefinement.admitted`. Include cooperative key paths, payout splits, and fee accounting. `ConsensusCoverage` is an explicit premise and MUST NOT be represented as established for real Bitcoin. The TypeScript Merkle verifier's byte layout, odd-leaf duplication and 4 KiB padding remain implementation-refinement obligations.

Latest confirmed CI: [Lean #39872532815](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39872532815) and [Node/TS/Core #39872532810](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39872532810). Four Lean modules compile; 372 Node research tests, 33 executable TypeScript tests and 133 unfunded offline Core cases pass. Earlier 363/133 figures below are historical handoff baseline.
## Current executable/formal refinement progress

The ongoing formalization now has four Lean 4 modules, all kernel-checked in CI:

- `formal/Blossom.lean` includes a finite `maxRounds` sentinel chain, slot exhaustion and joint cooperative closure with a signed provider/client split.
- `formal/UTXORefinement.lean` has a configuration flag for a MuSig2 cooperative keypath versus the operational NUMS agent's unavailable keypath, with explicit rejection theorems for NUMS mode. Real consensus coverage remains unproved.
- `formal/MerkleBinding.lean` reduces two conflicting same-index openings to an explicit collision event.
- `formal/PaymentChannel.lean` models positive, deal/root-bound signed channel increments, monotonic cumulative amounts, no replay in the formal receipt ledger, provider close, client timeout refund and their post-deadline race.

Code-level progress: `model/taproot_spend_inventory.mjs` adds Rust source-drift checks for the actual bond-state variants, including the final refund-only state, BIP341 sighash and fee shape. `model/storage_bonds.ts` now rejects zero-sample epochs and invalid proof array shapes; `model/merkle_refinement.test.ts` cross-checks the actual TypeScript implementation against independent SHA256 Merkle roots. `layer1/channel.ts` rejects malformed/nonpositive/expired invoices, overflow, client-side replay and concurrent signing. It now also serializes provider `chan-verify` updates per client channel to prevent delayed lower cumulative signatures overwriting higher ones, tested against concurrent HTTP requests in `layer1/channel-server-race.test.ts`. These protections are in-memory only and do not establish restart safety.

The latest confirmed model CI prior to this document revision is [run #39871845755](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39871845755), and the formal Lean run is [#39871845739](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39871845739). The model suite includes 372 Node regressions, 32 TypeScript storage/channel tests and 133 unfunded Core Script cases. Counts and CI state must be rechecked after further commits.

The payment-channel invoice is unsigned `bsbch1` JSON; provider identity/origin authentication still depends on application transport. Payment tracking is in memory and cannot yet satisfy durable restart-safe exactly-once semantics. The standalone bond tool uses NUMS, while the older regtest harness tests a MuSig2 keypath close. The formal source inventory is not a compiler or consensus proof. Next work must connect verified BIP341/342 and channel signatures, exact state output amounts, Merkle tree geometry, and persistent receipts to `ConsensusCoverage` and `ChannelStep`.
## Research goal

Create a Bitcoin-enforced storage-bond construction allowing arbitrary permissionless stronger-fork certificates with exact 256-bit verified chain work and appropriate inclusion/cutoff proofs to control collateral settlement, while protecting timely stronger challenges and requiring the provider to answer the *actual submitted certificate* if that original protocol policy is retained.

## What exists

Read these ADRs in order:
- `docs/binohash-admission/cursor-architecture.md` (ADR-001): journal cursor; external authorization gaps.
- `docs/binohash-admission/stateless-refutation-alternative.md` (ADR-002): existential stronger-fork counterexample to a frozen provider assertion. Promising escape from maximum-journal recursion, but changes economics and rebuttal semantics.
- `docs/binohash-admission/one-hop-composite.md` (ADR-003): legacy P2PK SINGLE|ANYONECANPAY protection + toy Binohash.
- `docs/binohash-admission/witness-anchored-certificates.md` (ADR-004): synthetic BIP141 inclusion arithmetic, not canonical confirmation or work.
- `docs/binohash-admission/two-generation-witness.md` (ADR-005): parent txid stable with changed witness, but substituted witness can mismatch fixed OP_RETURN.
- `docs/binohash-admission/refund-bypass-consensus.md` (ADR-006): old independent CLTV refund stays spendable after unrelated journal updates.
- `docs/binohash-admission/fixed-certificate-gate.md` (ADR-007): fixed certificate SHA256 witness check, output-protected guardian.
- `docs/binohash-admission/fixed-payout-gate.md` (ADR-008): conditional P2WSH payouts. WARNING: external guardian input is optional. This design has a fatal bond-only payout bypass.
- `docs/binohash-admission/self-guarded-payout.md` (ADR-009): actual consensus-positive bypass vectors, plus BIP143 ALL signature verified INSIDE bond's P2WSH script. Two-input example still depends on drainable OP_TRUE sponsor.
- `docs/binohash-admission/one-input-self-guarded.md` (ADR-010): one-input bond-only pre-signed provider/forfeit settlements avoid sponsor. Fixed cert and mock response. Separate positive attacks show retained test signing key can redirect/burn payout; later provider response remains Script-valid after CLTV.

The last one-input construction proves only signed-template confinement for a setup-selected certificate, assuming signing key erased and no other collateral exit. It does not provide arbitrary future cert admission, BitVM verdict, exact-work proof, absolute upper response deadline, or useful dynamic fee policy.

Core sources:
- `model/contest_spec.mjs` is the ideal *external oracle* spec for all strongest timely certificates, ties, answer and forfeiture.
- `model/stateless_refutation.mjs`, `model/stateless_public_input.mjs` are ideal stateless model and 32-byte journal public input adapter. They do not prove data true.
- `model/witness_anchor.mjs` supports synthetic BIP141 hash paths; synthetic block is not a confirmed Bitcoin block.
- `model/bond_only_bypass_vectors.mjs`, `model/self_guarded_payout_vectors.mjs`, `model/one_input_self_guarded_vectors.mjs` contain the concrete negative controls and fixes.
- `research/consensus-check/src/main.rs` verifies each provided Script against vendored libbitcoinconsensus 26; it is not a full node/UTXO consensus check.

## The essential unresolved question

Can a fixed funded Bitcoin spending graph enforce a sound verifier for a previously unknown challenger certificate, with exact work and authenticated Bitcoin witness inclusion, and bind its result to a permitted payout *without* introducing a provider-controlled signature, exploitable refund leaf, witness substitution, unauthorized output, or finite admission slot griefing?

Separately, CLTV only gates the earliest valid forfeit spend. A pre-signed provider-answer transaction remains Script-valid after the deadline, so the two branches race; merely exposing both exits is insufficient for an unconditional missed-deadline forfeiture.

## Assignment for the next agent

1. Perform a skeptical protocol threat-model audit of ADR-002's *stateless existential counterexample* versus ADR-001's *rebuttal-to-every-strongest-certificate journal*. State explicitly which storage-bond economic commitment each satisfies. Do not quietly change the security game.
2. Choose ONE smallest concrete next proof obligation. Preference: use the stateless 32-byte journal schema and construct a certificate-specific, payout-enforced verification flow; else produce an explicit impossibility / residual-trust statement for available current Bitcoin Script primitives.
3. Add failing-first adversarial regressions for (a) forged higher work, (b) valid stronger certificate with wrong Bitcoin inclusion anchor, (c) same-txid altered witness, (d) payout redirection, (e) late response race, (f) independent provider refund path, and (g) second stronger challenger after first weaker.
4. When adding working transactions, generate actual serialized Bitcoin transactions and verify Bitcoin Script using existing Core checker. Keep honest controls and positive exploitable attack cases. Treat model oracle booleans only as oracle booleans.
5. Make a minimal, reviewable commit on this research branch or a new stacked branch, run CI, record exact test counts/links, update an ADR and draft PR. Keep PR draft while any core security obligation is unmet.

## Explicit limits and constraints

Do not claim an unknown-certificate verifier from a hashlock or pre-signed fixed SHA256. A BIP141 witness Merkle proof does not prove transaction Script validity, canonical chain or total work. A valid toy Binohash signature does not authorize safe successors. A signed optional extra input cannot constrain an unguarded bond spend. A setup public test private key can re-sign anything. A provider-only CLTV exit bypasses independent journal state. A finite pre-signed cursor path can be exhausted by weak entrants.

Original local Phase 7 fixture: six storage transactions / 151-header regression, local commit `4494714`, not present on GitHub. Do not invent or represent it as imported. Obtain it from user-provided source if truly required, but advance bounded research without it.

No funded transaction broadcasts, Bitcoin mining, large proof generation, VPS/GPU costs, or pilots without further explicit authorization.

## Reproduction

```bash
node --test model/*.test.mjs
node model/one_input_self_guarded_vectors.mjs > /tmp/bsb-one-input.json
cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-one-input.json
```

Final deliverable from agent should identify the exact cryptographic consensus enforcement actually gained, one smallest counterexample that still breaks the design, and the next proof obligation. Maintain a hard distinction between consensus-verified Script input, synthetic UTXO topology, model oracle policy, and genuine Bitcoin consensus enforcement.
