# ADR-009: Bond-only bypass and a self-guarding P2WSH repair candidate

**Next iteration:** The ADR-009 fixture uses an externally spendable OP_TRUE sponsor input that could be consumed by a third party before either pre-signed settlement. [ADR-010](one-input-self-guarded.md) removes that input entirely and tests a bond-only, self-guarded settlement with a fixed 1,000-satoshi fee. Its proof and deadline limitations remain unchanged.


**Status:** Adversarial Bitcoin Core Script research. A mock answer token, fixed certificate and publicly known signing key are used throughout. The repaired construction still depends on trusted pre-signing/key erasure and does not authenticate Bitcoin work, BitVM proofs, or deadline ordering.

## Critical correction to ADR-008

ADR-008 describes a two-input transaction where a separately pre-signed guardian input protects output amounts and scripts. Bitcoin only enforces that signature **if a spender elects to include the guardian input**.

The original bond is locked by a P2WSH Script that checks SHA256(certificate), then either SHA256(mock response) or a CLTV timeout. That bond script does not verify the presence of the optional guardian input.

An attacker knowing the public mock answer can construct an entirely different, one-input transaction:

    spend(BOND) -> attacker payout

Its bond witness passes the original certificate/answer checks. The absence of the guardian input leaves no Script requirement that prevents redirecting the output. The same is true of the timeout branch after height 160. A transaction burning the entire bond value as fee is also Script-valid.

The new model/bond_only_bypass_vectors.mjs explicitly generates these full raw Bitcoin transactions, and Core checks input zero against ADR-008's unmodified P2WSH program. Positive consensus checks on this attack **invalidate any security claim that ADR-008's guardian, by itself, locks down all collateral exits**.

## Repair experiment: sign at the bond's own Script level

Move the guardian signature requirement into the bond P2WSH witness Script, using native SegWit v0 BIP143 SIGHASH_ALL.

    <setup_public_key> OP_CHECKSIGVERIFY
    OP_SHA256 <SHA256(preselected_certificate)> OP_EQUALVERIFY
    OP_IF
        OP_SHA256 <SHA256(mock_response)> OP_EQUAL
    OP_ELSE
        <160> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE
    OP_ENDIF

Each provider or forfeit template now carries its own pre-signed setup-key signature as part of the **bond input's witness**. Bitcoin must execute CHECKSIGVERIFY for every spend of this P2WSH output. A witness whose ECDSA signature was prepared under SIGHASH_ALL commits to all input prevouts, sequences, both output scripts/amounts and nLockTime.

If a spender omits the sponsor, substitutes an input, changes outputs, or appends a fee input, the signature becomes invalid. Under the assumed setup-key destruction, the bond cannot be spent with an alternate output by simply declining to include a separate guardian.

The model implementation includes a restricted BIP143 hashing function, pre-signed ECDSA fixture transactions and Core verification of both the bond script and the test sponsor's OP_TRUE script. This demonstrates precisely the signature-hash and Script check properties; it is not a generalized Bitcoin transaction verifier.

## Adversarial checks

The two new independent Core matrices are intended to establish:

| Property | Old independent guardian | New bond-internal guardian |
| --- | --- | --- |
| Provider witness with fixed certificate and mock answer | Accepted | Accepted |
| Direct bond-only spend to attacker after mock opening | **Accepted** | Rejected with reused pre-signature |
| Timeout bond-only spend with arbitrary payout | **Accepted** | Rejected with reused pre-signature |
| Arbitrary payout mutation on legitimate signed transaction | External guardian can reject | Bond CHECKSIGVERIFY rejects |
| Wrong certificate or mock answer | P2WSH rejects | P2WSH rejects |
| Correct payout with second input omitted | Bond Script accepts | Bond signature fails |
| New payout signature obtained using retained setup key | May authorize attacker | **May authorize attacker** |
| Provider response after the forfeiture deadline | Still Script-valid | **Still Script-valid** |

The repaired bond script improves **transaction-template confinement with a securely discarded setup key**. It does not turn Bitcoin into a general-purpose covenant, and the test signer is intentionally public. If an adversary retains the private key, a re-signed malicious payout passes Bitcoin Core checks in the repaired construction as well. Transaction-template confinement also depends on excluding every other spendable bond key path or script leaf.

The P2WSH certificate hash was chosen at setup. Any later arbitrary challenger certificate differs and fails. The response value is an arbitrary 32-byte preimage, not a cryptographically verified BitVM verdict; possession of it has no relation to a correct proof.

## Timeout remains a separate failure

The forfeit branch requires nLockTime at least 160 on a nonfinal input. Bitcoin Script enforces this **lower** threshold. The signed provider branch can still confirm after 160 if the preimage is available and the UTXO is unspent. The two outcome templates compete at the UTXO layer.

A genuine "respond by D or forfeit" rule needs an interactive dispute protocol and explicit assumptions about confirmation/liveness, or a different consensus-enforceable mechanism. The presence of CLTV alone is insufficient for an unconditional post-deadline outcome.

## Verification boundaries

The Core integration runs isolated libbitcoinconsensus checks for supplied input scripts. It does not establish UTXO membership, funding, mining, full transaction economics, Bitcoin header inclusion, exact 256-bit work, BitVM proof verification or objective canonical-chain choice. Node topology tests add synthetic value conservation, locktime finality and conflicting spends, with an external authorization oracle.

## Reproduce

    node --test model/*.test.mjs
    node model/bond_only_bypass_vectors.mjs > /tmp/bsb-bond-only.json
    node model/self_guarded_payout_vectors.mjs > /tmp/bsb-self-guarded.json
    cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-bond-only.json
    cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-self-guarded.json

## Next test gate

A sound permissionless challenger must be able to supply a previously unknown certificate and have Bitcoin enforce that its exact-work and inclusion proof were accepted, with no provider signing at admission time. Binding that result into the actual collateral spend and making a missed response deadline decisive are still open. ADR-002's stateless existential refutation avoids maximum-journal recursion if the application permits changed provider-rebuttal semantics.