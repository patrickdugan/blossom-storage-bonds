# ADR-010: One-input self-guarded settlement removes the sacrificial sponsor

**Status:** Unfunded Bitcoin Core Script research with static certificate, public insecure setup signer and mock response preimage. Does not solve real BitVM verification or late-response priority.

## Motivation

ADR-009 closed the ADR-008 bond-only payout bypass by putting a BIP143 SIGHASH_ALL signature check inside the bond's P2WSH script.

Its fixed two-input templates still depended on a synthetic OP_TRUE sponsor UTXO. Anyone could spend that sponsor before either pre-signed settlement confirmed, potentially stranding the bond after the setup signer destroys the key. This liveness risk is unnecessary for the property under investigation.

## Construction

The new candidate spends **only the bond UTXO**. Its P2WSH script is inherited from ADR-009:

    <setup-public-key> OP_CHECKSIGVERIFY
    OP_SHA256 <SHA256(fixed_certificate)> OP_EQUALVERIFY
    OP_IF
        OP_SHA256 <SHA256(mock_response)> OP_EQUAL
    OP_ELSE
        <160> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE
    OP_ENDIF

The setup signer prepares two separate SIGHASH_ALL BIP143 signatures for one-input Bitcoin transactions. Each has output zero committed to the certificate hash, and output one pays 148,000 satoshis to either the provider or the challenger, leaving 1,000 satoshis as the model fee against a fabricated 149,000-satoshi bond input.

A valid provider response includes [mock response, true selector, certificate, setup signature, witness script]. A valid challenger forfeiture includes [false selector, certificate, setup signature, witness script] and a pre-signed nLockTime of 160.

Because the bond itself checks the signature, an unrelated sender cannot create a new transaction with a different output and reuse the old signature. It also cannot append a fee input or change the bond outpoint without invalidating its SIGHASH_ALL authorization.

The fixture's known signing key can of course authorize any new payout. Its adversarial Core vectors explicitly demonstrate the redirected and fee-burn spends that succeed if the key was retained. Securely erasing it after setup is a **necessary protocol assumption**, and preparing finite templates still creates liveness constraints around transaction fees and other possible missing settlement paths.

## Consensus test matrix

A one-input libbitcoinconsensus fixture checks the bond P2WSH Script for:

| Variant | Expected |
| --- | --- |
| Pre-signed provider with fixed certificate and mock answer | Pass |
| Wrong / empty answer, wrong certificate or substituted witness script | Reject |
| Missing setup signature | Reject |
| Redirected payout, reduced payout amount or changed OP_RETURN | Reject |
| Changed prevout or appended sponsor input | Reject |
| Redirected payout re-signed with retained public test key | **Pass, unsafe setup** |
| Pre-signed forfeiture at CLTV 160 | Pass |
| Re-signed early forfeiture or final sequence | Reject CLTV |
| Modified forfeiture destination without new signature | Reject |
| Late provider response with a valid pre-signed signature | **Pass, upper deadline still missing** |
| Bond burn re-signed with retained public key | **Pass, unsafe setup** |

The deterministic Node topology regression seeds only the bond, checks nLockTime finality, computes the 1,000-satoshi fee, and confirms first-spend-wins UTXO exclusivity. It also checks that the BIP143 signature hash is invariant to witness-only certificate substitution, leaving the Script hash check responsible for the fixed certificate.

## What remains unsolved

- **Permissionless certificate admission.** The certificate digest and the set of allowable transactions were selected in advance. Arbitrary later challengers cannot enter without setup signing or a more general verified spending path.
- **Sound adjudication.** The response is a public test preimage. A SHA256 preimage by itself does not attest to correct BitVM execution, valid Bitcoin fork headers, a BIP141 anchor or exact cumulative work.
- **Upper response deadline.** CLTV enables forfeiture only from the specified height onward. A valid provider opening can still race for the unspent bond after that date. A sound interactive timeout protocol and explicit liveness assumptions are required.
- **Fee flexibility and relay.** Fixed SIGHASH_ALL signatures restrict fee replacement and appended inputs. Child-pays-for-parent and other package/relay behavior are outside this unfunded Script test.
- **Key custody and alternate exits.** Public research keys are insecure; any alternative live Taproot leaf/key path invalidates the claim that the bond is confined to these branches. A proof of key destruction is itself nontrivial.

This is a minimal executable demonstration of enforcing presigned output restrictions **within the spent bond** and avoiding an independently drainable sponsor input. It is not a complete storage-bond contract.

## Reproduction

    node --test model/*.test.mjs
    node model/one_input_self_guarded_vectors.mjs > /tmp/bsb-one-input.json
    cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-one-input.json

No mining, network nodes, funded transactions or proof jobs were used.