# ADR-011: Core-checked Taproot witness refinement and signer-authorized terminal payouts

**Status:** Verified on the draft `research/binohash-admission` branch. Bitcoin Core 26 **per-input Script** testing, an explicit Lean counterexample, synthetic UTXOs and public deterministic test keys. This ADR does not establish full Bitcoin consensus settlement or dynamic Binohash fork adjudication.

## Question

Does the existing Blossom sentinel bond's **actual serialized P2TR transaction** follow its intended hash-opening, pre-signature and output rules, and does a successful terminal signature constrain its payout destination?

## Construction and verifier correctness

`regtest/src/bin/formal_vectors.rs` invokes the production-like `regtest/src/common.rs` Bitcoin transaction builder, with two sentinel generations under the operational NUMS internal key. Four v3 pre-signed zero-fee challenge/response parents carry the entire **100,000,000-sat bond** to output 0, plus a zero-value P2A output 1. A separate fee-wallet CPFP child pays the package fee. The Rust fixture also builds one BIP112 CSV forfeiture and one BIP65 CLTV refund with a **1,000-sat bond-funded terminal fee**. The fixture uses synthetic outpoints and public test keys.

`model/verify_formal_evidence.mjs` independently parses the actual Rust transaction bytes and verifies txid/wtxid behavior, amounts, outputs and the linked first-/second-generation prevout identity.

`research/consensus-check/src/bin/taproot-evidence.rs` checks witnesses with vendored Bitcoin Core 26's `bitcoinconsensus`. **Critical implementation requirement:** the `verify()` call must receive `Some(&[Utxo])` containing the spent output's actual P2TR script and satoshi value. The binding's default `verify(..., None, ...)` chooses `VERIFY_ALL_PRE_TAPROOT` and evaluates native v1 output spends without Taproot enforcement. The initial naive matrix **accepted all 24 malformed parent transactions**; the corrected suite switches on BIP341/342 and rejects those same attacks. The failed naive run is evidence of a test-harness pitfall, not a Bitcoin Script consensus failure.

## Verified 39-case Core result

[GitHub Actions #39877272463](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/39877272463):

| Cases | Result |
| --- | --- |
| 4 valid witnessed parent transitions + 2 valid terminal settlements | 6/6 accepted |
| Changed signed successor script, amount, outpoint, or sentinel opening; mismatched control block or leaf Script across 4 parents | 24/24 rejected |
| Stale terminal payout signature, wrong signer, early CSV sequence, early CLTV locktime and final CLTV sequence | 7/7 rejected |
| Terminal destination changed with a **fresh signature by the legitimate unilateral signer** | 2/2 accepted |

The BIP341 sighash signature covers the witness-spending transaction's permitted outputs and prevout. It protects the **pre-signed parent transaction** from redirection. The refund and forfeit leaves permit a unilateral authorized signer to choose the destination for a new, correctly signed transaction.

## Formal architecture implication

`formal/PresignedParents.lean` proves that the template shape implies a zero-fee parent and unchanged bond amount. It also proves conservation over arbitrarily long modeled parent + independent CPFP wallet histories, tracking miner fees separately.

`formal/RecipientAuthority.lean` constructs a logical counterexample to `UTXORefinement.recipientExpected` interpreted as a fixed P2TR output destination. The theorem `signer_discretion_refutes_fixed_recipient_coverage` shows that a signer-authorized forfeiture can satisfy a Script-style acceptance predicate yet fail the fixed-recipient property. The real positive Core cases support this boundary. **The current universal `ConsensusCoverage` premise cannot be discharged as written** if its `Recipient` field refers to the specific physical beneficiary output. Either amend the specification to express the rightful signer's *authorized disposition* of the claim, or add an enforceable output covenant/pre-signed template when a fixed destination is a requirement.

This remains a separate matter from the original Binohash fork-admission settlement problem, where a provider-only refund can bypass an independent journal.

## Limits

- Synthetic spent outputs and valid Bitcoin Script witnesses do not establish those UTXOs exist on the active Bitcoin chain.
- `libbitcoinconsensus` checks the relevant Script CSV/CLTV condition but cannot prove a particular output's **BIP68 age** or the transaction's **block-height finality**, which require a chain context.
- The fixed two-generation evidence neither exhausts every possible Taproot keypath/script path nor proves miners will include time-sensitive challenges. The NUMS keypath exclusion remains a discrete-log assumption.
- The actual storage-proof SHA256 and Merkle verifier, random challenge unpredictability, data availability, signed deal provenance, channel crash recovery and Lightning/payment-covenant economics retain their own obligations.
- No proof is given that an arbitrary future higher-work fork certificate can control Binohash/BitVM collateral payout.

## Reproduce

```sh
cargo run --locked --release --manifest-path regtest/Cargo.toml --bin bsb-formal-evidence > /tmp/bsb-taproot-evidence.json
node --experimental-strip-types model/verify_formal_evidence.mjs /tmp/bsb-taproot-evidence.json
cargo run --release --manifest-path research/consensus-check/Cargo.toml --bin taproot-evidence < /tmp/bsb-taproot-evidence.json
lean -o formal/Blossom.olean formal/Blossom.lean
LEAN_PATH=formal lean -o formal/UTXORefinement.olean formal/UTXORefinement.lean
LEAN_PATH=formal lean formal/PresignedParents.lean
LEAN_PATH=formal lean formal/RecipientAuthority.lean
```

The next step is a type- and provenance-aware refinement between each authenticated Bitcoin Core spend and its authorized economic disposition, with contextual locktime and all spend paths included. Keep PR #1 draft.
