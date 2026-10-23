# Independent Claude/Codex implementation handoff

Repository: `patrickdugan/blossom-storage-bonds`
Base research branch: `research/layertree-storage-bond-overlay-2026-10-23`
Draft proposal: https://github.com/patrickdugan/blossom-storage-bonds/pull/5

This file coordinates two **parallel signet-ready implementations** from
the same immutable A/B scenario format. Work in separate child branches
based on the research branch. Both candidate implementations may ultimately
be submitted as independent PRs targeting PR #5's branch. Keep the
permissionless Binohash research PR #1 untouched.

## Already implemented, with CI

The common deterministic storage evidence lives in
`experiments/storage-bond-ab/shared/scenario.mjs`. The A adapter imports
the existing `model/storage_bonds.ts` Script interpreter and sentinel
commitments. The B adapter imports the research LayerTree state machine.
`run.mjs` emits JSON/CSV comparisons; `testnet/observe.mjs` is a
read-only signet/testnet4 witness-bound transaction observer.

Run the local baseline before editing:

```bash
node --test model/layertree_bond_overlay.test.mjs \
  experiments/storage-bond-ab/run.test.mjs \
  experiments/storage-bond-ab/testnet/observe.test.mjs
node experiments/storage-bond-ab/run.mjs --out /tmp/storage-bond-ab
```

## Revised checkpoints: funded regtest already available

Do not start by rebuilding the existing source from scratch. The parallel
A folder already executes the original Rust BIP341/Taproot chain on Bitcoin
Core at both 60k and 40k; see [matched A CI](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39972992480).
Those 42 real Core checks include presigned v3 parents, P2A children, real
MuSig2 keypath signatures and Script failure cases.

The B folder already has a funded Bitcoin Core 2-of-3 **P2WSH SURROGATE**.
[B CI](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39971028444) proves
full principal conservation under a separately funded fee sponsor and
that two dishonest quorum signers can redirect the entire pooled collateral
despite a valid independent reference Blossom Merkle proof.

These are not yet genuine signet-ready A/B implementations. Your task is to
improve the fidelity: translate BOTH into the same real scheduled PDP
epochs, key-loss/offline conditions, fee targets, participant values and
output constraints. FROST remains absent: do not relabel 2-of-3 CHECKMULTISIG
as threshold Schnorr. The actual Sapio MID oracle is absent from B.

Use `compare-funded.mjs` and the combined funded regtest workflow as the
acceptance gate. It deliberately sets `matchedFullScenarios=false` and
`feeComparisonPermitted=false` until both agents show identical scenario
semantics. Preserve the genuine attack receipt; do not hide it to improve
B's apparent security score.

### CLAUDE: A sentinel Bitcoin implementation

**Suggested branch:** `claude/storage-ab-sentinel-signet`

Build inside `experiments/storage-bond-ab/a-sentinel/testnet/` and avoid
changing the B adapter. Port the real transaction construction from
`regtest/src/main.rs` and `regtest/src/rpc.rs`, preserving the
well-tested BIP341 sighash, pre-signed Challenge_i/Respond_i states,
MuSig2 keypath, Taproot Script leaves, v3 zero-fee parents, P2A CPFP
children and CSV/CLTV boundary conditions.

Use separate Alice/Bob funding outputs and participant keys. The shared
proof generator fixes the input bytes, roots and challenge nonces; translate
the reference sentinel commitment faithfully, then verify actual
sentinel responses in the appropriate Taproot witness. Exercise honest
response, missing-window forfeiture, full-term refund, and the independent
client exit while the other party or coordinator is unavailable.

Deliver an isolated regtest first, and move to signet only after the
regtest harness succeeds. For signet export a manifest conforming to
`testnet/MANIFEST.md`, the saved signed tx/wtxids, scripts, vbytes, fees,
block heights and a raw witness-mutation negative test.

Explicitly test the actual Bitcoin path rather than accepting the
reference model's stand-in sighash. Confirm transaction input/output
coverage, signer-selected output redirection, timed exits and extra
Taproot spend paths. Secure test keys must be disposable and clearly
labeled; production wallet material is prohibited.

### CODEX: B pooled LayerTree/FROST Bitcoin implementation

**Suggested branch:** `codex/storage-ab-layertree-signet`

Build in `experiments/storage-bond-ab/b-layertree/testnet/`. Use the
pinned LayerTree MID reference in Sapio
`patrickdugan/sapio@616cdba38bc9102d0994eb5fd5aa4db88508d8f4`
and the adversarial replay findings in Sapio PR #1. Preserve one shared
100,000-sat principal with Alice=60,000 and Bob=40,000 through
parent/outpoint-preserving refreshes and eventual separate exits.

Your first milestone is a real Bitcoin Core regtest transaction graph
with frozen independently agreed payout scripts, signed witness copies,
saved Merkle-sum proofs and state-root history. Test the current
experimental MID policy **through the actual oracle/wrapper signatures**.
Record every threshold signer identity, precisely identify who has
signing authority, and never describe the MID predicate as Bitcoin
consensus. If a reviewed FROST-secp256k1 implementation is brought in,
pin its exact version and exercise 2-of-3 signing, key-share isolation,
missing quorum, equivocation and guardian compromise.

Mandatory adversarial tests: unauthorized old voucher replay, stale
successor, parent-child double counting, changed payout scripts, invalid
storage checkpoint, arbitrary fabricated-fault approval by 2 compromised
signers, forbidden keypath/alternate leaves, user exit while all
federation signers are offline, and fee sponsor spending client principal.

Use SaplingOS PR #2's fully signed recovery export and third-party
fee-sponsor work where compatible. Describe any existing dependency on
the federation as an explicit liveness failure. A Filecoin checkpoint
or missing WindowPoSt is **unverified** until a separate real
consensus/finality verifier supplies that evidence.

Regtest must be green before any public signet transaction. Export B's
manifest and externally archived transaction/witness proofs through
`testnet/observe.mjs`, using exactly the same test size and fault schedule
as A. An honestly threshold-signed but malicious payout is an expected
counterexample, not a passing entitlement guarantee.

### Mutual red-team review

After independent implementations, Claude reviews B for covenant
bypasses, FROST collusion, unavailable exits and custody substitution.
Codex reviews A for incomplete presigned transactions, Script/witness
mutation, fee starvation and CLTV/CSV height handling. Neither reviewer
may silently change common test fixtures or declare the other scheme
equally secure merely because a Bitcoin transaction confirms.

## Shared acceptance matrix

| Experiment | A | B | Hard gate |
| --- | --- | --- | --- |
| Correct 60k/40k entitlement | two distinct outputs | pooled carrier with exact allocations | no unaccounted principal |
| Healthy 3-epoch service | end-of-term provider refund | frozen, authorized provider disposition | 3 real proofs bound to each deal |
| Deleted sampled chunk | sentinel witness fails, forfeit after CSV | independently verified fault triggers payout | exact challenge ID/checkpoint |
| False-fault by 2/3 signers | storage proof still valid | attempt unauthorized transition | record B's attack and payout exposure |
| Signers disappear | client exit path exercised | show viability or explicit failure | proof of independent liveness |
| Stale voucher after refresh | prior state cannot spend twice | rejects old lineage | chain and signature replay negative tests |
| Fee sponsor unavailable | P2A/CPFP failure observed | same | preserve full client principal |
| Competing late response/refund | model and chain-context timing | same | no unexamined Script-valid alternate exit |

Metrics to preserve with *every* case: network, verified UTXOs and
wtxids, signed transaction bytes, transaction vsize, fee sats,
height/confirmations, signer-online contacts, stored witness bytes,
median/failure percentiles across repeated independent cases,
challenge-to-finalization latency and any unresolvable stalemates.

Match confirmation policies and fee targets when comparing the two
schemes. Report differences in trust assumptions separately; do not
normalize them into a single performance score.

## Merge and security rules

- PR #5 remains draft until both real regtest backends run. Signet
  experiments need disposable wallets, a trusted Core node and a
  written external-funding cap.
- Keep all wallet seeds, key shares, RPC cookies and real signing
  transcripts containing secrets outside CI artifacts or Git history.
- CI must demonstrate real negative controls, including same-txid
  witness substitution and unauthorized payout attempts.
- A Bitcoin confirmation proves inclusion in the node's active chain.
  A correct storage bond needs an independently justified proof and
  a complete spending-path authorization review.
- Only the shared schema, test fixtures and read-only observer should
  be edited in coordinated integration commits, after both reviews.
