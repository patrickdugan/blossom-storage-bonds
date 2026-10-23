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
## New Core/Taproot proof bridge

**Verified result:** [Taproot CI #39877272463](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39877272463) checked 39 real BIP341/B342 P2TR witness cases using the vendored Bitcoin Core 26 `libbitcoinconsensus` code: six legitimate templates accepted, 31 malicious mutated spends rejected, and two payout redirections newly signed by the authorized unilateral party accepted. The latter are expected positive examples. The older legacy/P2WSH research suite remains 133 Core cases and the Node/TypeScript regressions are separate.

Critical API trap: `bitcoinconsensus::verify()` enables `VERIFY_TAPROOT` ONLY when `spent_outputs: Some(&[Utxo])` is provided. Passing `None` selected pre-Taproot flags and initially accepted ALL 24 mutated P2TR fixtures. That failure is preserved in earlier CI history. `research/consensus-check/src/bin/taproot-evidence.rs` now provides the script and amount as a spent-output record, and the raw-byte mutations fail as expected. Rust's real transaction construction is `regtest/src/bin/formal_vectors.rs`, independently parsed in `model/verify_formal_evidence.mjs`.

**Formalization:** `formal/PresignedParents.lean` proves the zero-fee v3 parent, full-bond successor and independent CPFP wallet conservation under template premises. `formal/RecipientAuthority.lean` constructs a counterexample to fixed-recipient `ConsensusCoverage`: native Taproot forfeit/refund leaves authorize the CLIENT/PROVIDER signer respectively, while the signer can create a new signature directing the payout elsewhere. This is confirmed empirically by real Core Script. The universal fixed-output interpretation of `UTXORefinement.recipientExpected` is therefore too strong. A revised specification should model signer-authorized disposition or a genuine output covenant, with explicitly stated consent and keys.

**Remaining high-value development:** formalize the actual BIP341 signature context, verify complete Taproot keypath/leaf enumeration for funded states, verify contextual BIP68 finality/CLTV inclusion against real chain heights, and link the discovered recipient-discretion semantics to the storage-bond economics. Use Core's verified witness result only for per-input Script checks; do not claim the offline library checked synthetic UTXO membership, active chain, block economics, relay, mining or the still-blocked dynamic Binohash fork proof.

Full proof scope and reproduction: `docs/binohash-admission/LEAN-STORAGE-PROTOCOL.md`.
## ADR-012 verified continuation (2026-10-23)

Branch proof baseline now includes [ADR-012](entitlement-contextual-finality.md), `formal/ContextualFinality.lean`, and `model/contextual_finality.mjs`. The old fixed-recipient `ConsensusCoverage` claim was repaired in `UTXORefinement.lean`: the provider or client on a unilateral exit controls payout disposition, and can sign an output to another person's address. `RecipientAuthority.lean` retains the previous strict rule as a falsified counterexample and proves revised terminal admissibility. Treat `Account.provider/client` as economic disposal counters, not physical Bitcoin-address receipt assertions.

The contextual finality proof separates BIP65 CLTV Script conditions from transaction block-height finality and BIP112 CSV Script conditions from BIP68 output-age finality. Height-only model checks actual Rust transaction locktime and sequence bytes, without pretending to have verified active-chain UTXO ancestry. [Lean #39879404477](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39879404477) passed seven kernel modules; [research #39879778019](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39879778019) passed 380 Node regressions, 33 TypeScript tests and the Core witness checks.

Next: supply and verify UTXO heights / block context, Bitcoin consensus path coverage and authentic signer evidence as refinements, plus the unresolved exact-work fork-cert BitVM payout. The original six-storage-transaction 151-header Phase 7 fixture remains unavailable.
## ADR-013 real Bitcoin inclusion and storage-payout proof checkpoint (2026-10-23)

Current validated research-branch baseline:

- [Regtest CI #39883245984](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39883245984): Bitcoin Core 31.1 regtest, 21/21 protocol harness scenarios, nine audited confirmed spends and verified source UTXO heights; BIP68 forfeit source height 224 and confirmed height 368; CLTV refund nLockTime 380 confirmed at 381.
- [Lean CI #39883570653](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39883570653): nine kernel-checked Lean modules, including two new transaction/witness Merkle collision reductions.
- [Node/Core CI #39883245968](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39883245968): 398 Node model tests, 33 TypeScript tests; offline Core legacy/SegWit plus 39 P2TR cases are independent checker suites.

Source [ADR-013](confirmed-regtest-witness-refinement.md). `scripts/audit-regtest-context.mjs` now exports raw Bitcoin Core-validated inclusion bundles: BIP37 ordinary txid Merkle proof, BIP141 witness Merkle path, coinbase reserved value, coinbase commitment output, coinbase raw transaction and its txid Merkle path, with block header, transaction data and confirmation/source heights. Independent verifier modules: `model/bitcoin_merkleblock.mjs`, `model/bitcoin_witness_commitment.mjs`. The negative control substitutes an unconfirmed witness with the SAME txid: BIP37 still matches but BIP141 fails. Never equate a legacy txid proof to a witness/certificate inclusion proof.

Formal [BitcoinInclusion.lean](../../formal/BitcoinInclusion.lean) and [BitcoinWitnessBinding.lean](../../formal/BitcoinWitnessBinding.lean) prove conditional collision reductions at a fixed indexed Merkle position, with explicit no-collision assumptions. They do NOT prove SHA256 computational hardness, Bitcoin chainwork, best-chain selection, transaction-context finality without a trusted full node, or that an arbitrary certificate controls a BitVM payout.

Next priority: authenticate the Bitcoin block-header chain's exact 256-bit work from genesis/checkpoint and ensure BIP141 witness inclusion is bound to the SAME certificate/public input used for final BitVM adjudication. Integrate active-chain/reorg assumptions into Lean only after obtaining concrete validated proof data. The storage-sentinel bond and the Binohash fork-certificate arbitration remain different security games. Keep Draft PR #1 blocked.

**Latest parser hardening (Oct 23, 2026):** `model/bitcoin_coinbase_witness.mjs` extracts the BIP141 reserved value and highest-index commitment from the serialized coinbase itself, verifying its recomputed txid. Regtest [CI #39884628809](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39884628809) passes after this change: 398 Node regressions, 33 TypeScript tests, 21 full-node scenarios and nine confirmed BIP141 bundles. Preserve the distinction between authenticated witness/tx inclusion and unknown best-chain work or Bitcoin-to-BitVM payout enforcement.

## ADR-014: portable serialized receipts (2026-10-23)

The repo now contains [ADR-014](portable-serialized-receipt.md), which formalizes the trust boundary of the portable Bitcoin settlement proof. `model/bitcoin_serialized_receipt.mjs` recomputes txid and wtxid from **raw serialized target bytes**, parses the **actual raw coinbase witness** and highest-index BIP141 OP_RETURN output, and matches both BIP37 and BIP141 proof leaf indices and transaction counts to one Bitcoin block header. This prevents an adversary from inserting arbitrary free-standing commitment fields into an otherwise valid BIP141 arithmetic transcript.

`model/bitcoin_serialized_receipt.test.mjs` includes a deliberately positive counterexample: without raw coinbase binding, a forged witness commitment passes the field-only Merkle arithmetic helper, although the actual coinbase never committed to it. The strict serialized verifier rejects the attack. Tests also cover witness substitution, altered reserved bytes, forged coinbase outputs, mismatched transaction counts and malformed serialized data.

`scripts/verify-regtest-receipt.mjs` replays the exported `scripts/audit-regtest-context.mjs` receipt **offline and without any RPC/network**: complete genesis-anchored regtest headers (PoW, MTP, difficulty, BigInt accumulated work); nine dual txid/wtxid witness inclusion proofs; concrete bond predecessor amounts, pre-signed successor/P2A templates, terminal payout value, and contextual 144-block CSV/CLTV evidence. It can optionally compare a caller-supplied trusted tip and minimum work, but it cannot prove that those external anchors are trustworthy or that no higher-work alternative chain exists. The exporting Core node was still trusted to execute full Bitcoin block, Script and UTXO consensus.

The CI job `blossom-regtest-context.yml` runs both the original full-node regtest audit and the new offline receipt verifier. Current Node suite includes 417 passing research cases and 33 TypeScript tests. The earlier 39-case Core P2TR Script suite remains separate; the unresolved protocol target remains permissionless stronger-fork certificate verification **controlling the actual collateral payout**, not just producing independently auditable settlement receipts.
## ADR-015: Script capability boundary and enforcement review (2026-10-23)

Read [the review](certificate-to-collateral-enforcement-review.md) first. Its verdict is **BLOCKED**, and the missing primitive is OP_CAT (BIP347).

What was added:
- **Vectors:** `regtest/src/bin/admission_vectors.rs` writes 16 real P2TR spends.
- **Independent check:** `model/verify_admission_vectors.mjs` recomputes each design verdict from the bytes.
- **Core check:** `research/consensus-check/src/bin/tapscript-vectors.rs` runs Core 26 with Taproot flags. The result is 0 mismatches and 5 counterexamples.
- **Lean:** `formal/CertificateAdmission.lean` holds the security games. `CertificateAdmissionAxioms.lean` is the CI gate allowing only the standard axioms.

Trap: `tapscript-vectors` needs a Linux build. The vendored C++ library fails to link with MSVC (LNK1120).

ADR-016 ran the §7 experiment on Core 26 with a local BIP347 patch:
- **Pieces:** `research/bip347-check/` (with `prepare.sh` and `bip347.patch`) and `bsb-cat-verifier-vectors`, independently checked by `model/verify_cat_vectors.mjs`.
- **Result:** 13 cases. Honest forks pass and all 10 attacks fail under BIP347; on stock Core all 10 are valid.
- **ADR-017:** dynamic claims via a presigned freeze set (the `F/*` cases of `bsb-cat-verifier-vectors`; see [ADR-017](dynamic-claim-freeze.md)).
- **Next:** an Inquisition cross-check (needs approval), retarget-aware work, and BIP141 timeliness in the leaf.

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
