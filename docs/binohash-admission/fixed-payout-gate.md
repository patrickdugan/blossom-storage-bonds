# ADR-008: Certificate-specific escrow, two payout branches, and an unsolved response clock

**Status:** Unfunded Bitcoin Core 26 Script test. **The response preimage is a mock token, not a BitVM verdict.** Permissionless fork admission, exact chainwork and dynamic proof verification remain unimplemented.

## Question

Can current Bitcoin Script keep collateral inside a certificate-specific contest, pay the provider after the correct response gate opens, and pay a fixed challenger recipient through a delayed forfeiture path, with signed payout values and scripts?

What happens if the provider only reveals the response *after* the challenger timeout becomes spendable?

## Construction

This experiment replaces the old independent CLTV provider refund of ADR-006 with **one conditional bond locking script**. Both possible settlement transactions spend the *same fabricated bond UTXO* and a second pre-signed guardian UTXO.

The bond is a native-v0 P2WSH output committed to this Script, shown in readable notation:

    OP_SHA256 <SHA256(fixed_certificate)> OP_EQUALVERIFY
    OP_IF
        OP_SHA256 <SHA256(mock_response)> OP_EQUAL
    OP_ELSE
        <160> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE
    OP_ENDIF

Bitcoin Script sees the following witness layouts (excluding the last witness-script element):

- Provider: [mock_response, OP_TRUE, fixed_certificate].
- Forfeit: [OP_FALSE, fixed_certificate].

The certificate hash equality is a **common gate** for both paths. The provider route requires a correct preimage of the fixed, preselected mock response digest. The challenger route is available after the experiment's fixed absolute CLTV height 160, so a transaction using nLockTime 160 with non-final sequence has its earliest valid confirmation in block 161.

The guardian is a fabricated legacy P2PK UTXO. Two separately pre-signed SIGHASH_ALL ECDSA authorizations commit to the exact two-input transaction graph and either the provider's or the challenger's fixed payout. Both transactions commit to SHA256(fixed_certificate) in output zero and pay 150,000 satoshis in output one, with a model fee of 4,000 satoshis against 149,000 + 5,000 satoshis in virtual inputs.

Unlike ADR-007's ALL|ANYONECANPAY guardian, ALL commits to the full input set, which also blocks added fee inputs and substituted bond/guardian outpoints. This fixture assumes guardian pre-signing was done before funding with the secret then safely erased. The test secret is PUBLIC and deliberately reused with an insecure nonce; retaining that secret allows anyone to re-sign a redirected payout. A separate positive consensus attack vector demonstrates that failure.

## Core Script attack matrix

Both scripts are checked for every serialized transaction using the vendored Core 26 libbitcoinconsensus verifier. The cases include:

| Outcome / mutation | Expected acceptance |
| --- | --- |
| Provider with correct certificate and mock answer | Accept |
| Provider with wrong or empty answer | Reject bond input |
| Provider with a different certificate or witness program | Reject bond input |
| Provider redirect, amount shaving, or altered OP_RETURN | Reject guardian input |
| Original guardian signature with different bond or guardian prevout | Reject guardian input |
| Original guardian signature with an added fee input | Reject guardian input |
| Malicious provider redirect re-signed with the retained public fixture guardian key | **Accept: key disposal is a real trust assumption** |
| Timeout forfeit paying pre-signed challenger output | Accept |
| Re-signed timeout with nLockTime 159 or final bond sequence | Reject bond input |
| Mutated timeout payout | Reject guardian input |
| Extra witness stack element on the timeout branch | Reject bond input (SegWit cleanstack) |
| Provider tries timeout branch before CLTV | Reject bond input |
| Provider response transaction signed with nLockTime 165 | **Accept: upper response deadline is absent** |

For each case the verifier validates input zero's P2WSH Script and input one's guardian P2PK Script. It does not validate whether synthetic prevouts are funded, whether a transaction is confirmed at a particular height, or whether the supposedly valid response has been produced by a cryptographic verifier.

## Topology test and the timeout race

The Node UTXO model seeds matching 149,000-satoshi bond and 5,000-satoshi guardian outpoints. It tests a timeout transaction at heights 160 and 161, shows that provider and forfeit transactions double-spend the same UTXOs, and calculates the model fee.

If the forfeit transaction confirms first, the provider spend conflicts with its consumed inputs. If the provider response confirms first, the forfeit transaction conflicts.

But the **late response branch is Script-valid**. Bitcoin's CLTV checks earliest allowed height on the *timeout* branch. It does not place a consensus-enforced upper height on the response branch. Once the mock response preimage is known, both payout transactions can compete after block 160 until one spends the bond. An ideal application deadline of "forfeit if not answered by D" still requires a binding protocol for deciding which branch wins, rather than relying only on two spendable paths.

## Soundness boundary

The Script checks that a fixed public certificate matches a SHA256 digest and that a witness contains a fixed mock response preimage. It does **not** check whether the certificate describes actual Bitcoin headers, whether exact 256-bit cumulative work exceeds a provider claim, whether the answer is a valid BitVM proof, or whether its opening was timely. This is a proof-of-transaction mechanics, not a proof of adjudication.

The guardian prevents changed outputs only if its original signing secret is unavailable to adversaries after templates are prepared. In this test the secret is intentionally public, and a malicious re-signed provider payout passes the same Bitcoin Script checks.

The candidate certificate digest was hard-coded at setup. That makes the working graph unusable for arbitrary permissionless challengers, even though it verifies the desired output amounts for one known contest.

The old independent refund escape of ADR-006 remains a fatal path if any inherited bond key path, other script leaf or separate pre-signed transaction can still spend the real collateral. This experiment replaces the representative bond script; it does not audit an actual funded Taproot tree.

## Next protocol milestone

Construct an on-chain enforceable route from an **arbitrary authenticated certificate** to a sound BitVM result gate controlling payout. A worthwhile design must prove, at minimum:

1. Actual Bitcoin inclusion binds the chosen certificate witness to a particular live contest, a specified cutoff and an authenticated 256-bit cumulative-work claim.
2. Adjudication verifies this specific certificate and releases the provider branch only for a correct rebuttal to it.
3. The effective timeout or refutation output wins under a genuinely consensus-enforced deadline policy. A late response cannot claim the collateral by winning a fee race.
4. Pre-signed templates cannot be used with a forged guardian signature, through slot exhaustion, or through an independently valid provider refund.
5. Stronger challengers can participate before cutoff without a setup signer, including after weaker attempts.

For a binary existential refutation of a fixed false claim, ADR-002's stateless alternative may avoid the maximum-journal problem. It still requires a real verified certificate, a spend-authorized proof verdict, a payout gate and a race-safe dispute clock.

## Reproduce

    node --test model/*.test.mjs
    node model/fixed_payout_consensus_vectors.mjs > /tmp/bsb-fixed-payout.json
    cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-fixed-payout.json

No Bitcoin Core node, mining, funded inputs, proof worker, or live relay is used.