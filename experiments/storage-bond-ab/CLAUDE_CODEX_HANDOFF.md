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

The B folder now has **two distinct Bitcoin regtest variants**:

- The historical funded 2-of-3 P2WSH CHECKMULTISIG surrogate still
  demonstrates that an authorized malicious quorum can redirect collateral
  despite a valid reference Blossom Merkle proof.
- [Real FROST P2TR CI](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40077856631)
  uses actual 2-of-3 `frost-secp256k1-tr=3.0.0`, BIP341 Taproot-tweaked
  key-path signatures, a 100k-sat carrier refresh, an externally sponsored
  **60k/40k** payout, and separate six-confirmation Alice/Bob PSBT spends.
  Pre-settlement unilateral holder-wallet attempts fail, and malicious
  quorum theft remains Bitcoin-valid before the honest spend confirms.

**Important:** FROST cryptography is no longer absent. Its signing
shares are still created by a trusted dealer inside ONE process, and the
actual Sapio MID oracle is not bound to those Bitcoin key-path outputs.
Alice/Bob only gain independent wallet control *after* threshold settlement.

These are not yet signet-ready A/B equivalents. Align actual PDP epoch
transitions, missing-signer scenarios, proof timestamps, fee targets and
beneficiary entitlement assertions before claiming cost or security parity.

Use `compare-funded.mjs` and the combined funded regtest workflow as the
acceptance gate. It deliberately sets `matchedFullScenarios=false` and
`feeComparisonPermitted=false` until both agents show identical scenario
semantics. Preserve the genuine attack receipt; do not hide it to improve
B's apparent security score.

### CLAUDE: A sentinel, physical exit and equal-cost test

**Suggested branch:** `claude/storage-ab-sentinel-signet`

The A-side *funded* Rust Taproot implementation already passes 42/42
Bitcoin Core tests on separate 60,000/40,000-sat bonds. It signs true
BIP341/CSV/CLTV/MuSig2 transactions through its existing presigned
challenge/response chain. [Combined passing CI](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40078126695)
and the shared Merkle witness fixtures are the baseline. **Do not rewrite
or reimplement the original `regtest/src/main.rs` for this job.**

Now isolate real client recovery under service loss: freeze original
signed witness bytes, current outpoint and payout script, kill the
original presigning/coordination processes, then independently broadcast
and confirm Alice/Bob outcomes in a fresh worker. Include a stale
prior-generation exit test and a third-party sponsor-funded fee route.
Preserve secret keys outside repository and artifacts. Explicitly
separate actual missing Blossom bytes from the public counterfactual
preimage still included by the older regression harness.

Match B on initial principal, challenge epochs, confirmation depth,
fee assumptions, and 6-block response window without hiding the old
144-block reference. Publish exact regtest txids/wtxids, vbytes and
fee inputs, then pursue disposable Signet only after the complete
negative-control matrix and mutually reviewed spend paths pass.

### Real B FROST signing and actual MID guest now verified

The older `b-layertree/regtest/surrogate.mjs` P2WSH two-of-three
multisig remains a **historical comparative surrogate**. Genuine
`frost-secp256k1-tr=3.0.0` signs funded BIP341 P2TR key-path
refresh and two-owner payouts; Alice and Bob then spend separately
via real six-confirmation Bitcoin Core PSBTs. The one-process
trusted dealer and missing pre-settlement federation-free exits are
still explicit limitations.

[Joint physical MID-versus-FROST CI](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40081402988)
also runs four compiled MID/online-oracle tests against pinned Sapio
`34363851a11d0f2b3ddb27c050537c1a2e5b7e9b`. It exports signed
guest transactions with Merkle-sum roots 100k -> 40k -> 0 sats, then
confirms that Bitcoin permits two real FROST key shares to sign a
*different application-state commitment* with identical beneficiary
and fee outputs. **This shows precisely why Bitcoin authorization
does not presently imply LayerTree transition validity.**

Do not duplicate the FROST signature demo or the pinned oracle test.
The next job is to bind the restrictions to an enforceable Bitcoin
spend path or build a separate, fully presigned offline-recovery DAG.
Any new FROST custody work must use isolated signer processes and
authenticated, replay-resistant nonce coordination. The previous
NCC audit did not cover the Taproot-specific FROST ciphersuite.

### CODEX: enforceable B carrier and outage recovery

**Suggested branch:** `codex/storage-ab-layertree-signet`

Build under `experiments/storage-bond-ab/b-layertree/`. The exact
pinned Sapio source is
`patrickdugan/sapio@34363851a11d0f2b3ddb27c050537c1a2e5b7e9b`
and the exported MID guest vectors, verifier and paired Bitcoin
authority test are in `b-layertree/mid/`.

The next milestone is **not a signature demonstration**. Produce
one physical Bitcoin UTXO whose spend authority cannot sidestep the
reviewed 60k/40k entitlement terms, or document why current Script
cannot enforce that claim and implement a separately consented,
pre-signed full-split recovery transaction for every refresh
generation. Treat the keypath bypass and online oracle's discretionary
authorization as distinct failures. Do not replace the tested FROST
keypath fixture with a synthetic JS vote.

Specifically reproduce the confirmed attack in which two threshold
signers sign a wrong state commitment while keeping correct payouts.
Then exhaustively audit keypath and all script leaves, successor roots,
owner scripts, revoked historical voucher identities, third-party fee
inputs, nonce reuse and stale parent generations. A robust positive
claim requires Bitcoin Core to **reject** unauthorized actions, even
when the adversarial signer coalition is responsive.

Preserve the real FROST regtest's honest 100k-sat refresh, 60k/40k
payout, 59k/39k beneficiary PSBT spends and one-process DKG
limitations. Run an explicit all-FROST-and-oracle-offline test; any
holder-only post-split spend does not count as recovery from a
locked pre-split carrier. If the constraints cannot be met under
current Bitcoin consensus, write the limitation and stop promoting B
to a covenant or noncustodial Filecoin slash.

Independent Filecoin finality and missing WindowPoSt validation are
separate requirements. Keep PR #5 draft, A source intact, and the
Binohash permissionless research PR untouched.

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
