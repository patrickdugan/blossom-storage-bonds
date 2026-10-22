# ADR-007: Bitcoin-enforced fixed-certificate gate with an all-output guardian

**Status:** Unfunded, one-hop, fixed-certificate proof of Script mechanics. A working permissionless fork-admission protocol remains blocked.

## Hypothesis

ADR-005 admitted an arbitrary replacement witness because the witness-carrier script merely dropped its certificate bytes. The pre-signed legacy cursor guardian protected output 1 through SIGHASH_SINGLE|ANYONECANPAY, while output 0 could be regrinded with toy Binohash. This left a mismatch between the actual SegWit certificate and the digest recorded in output 0.

Try enforcing *both halves* of the equality with current Bitcoin Script, even if the certificate must be selected at setup.

## Transaction construction

Three input-level scripts share one serialized transaction:

- **Input 0: fixed P2WSH certificate gate.** The witness contains certificate A and the program OP_SHA256 PUSH32(SHA256(A)) OP_EQUAL. The UTXO's P2WSH program commits to that exact witness script. A different certificate C fails the equality check. Replacing the script with one for C fails the pre-existing P2WSH program hash.
- **Input 1: legacy P2PK guardian.** An ECDSA signature under SIGHASH_ALL|ANYONECANPAY commits to both output 0, an OP_RETURN containing SHA256(A), and output 1, the exact successor script and 40,000-satoshi amount. It also commits to its own prevout. Additional fee inputs can be changed.
- **Input 2: toy legacy Binohash carrier.** A fresh insecure FindAndDelete puzzle binds the non-witness transaction including the certificate commitment, successor and outpoints. It cannot rescue edits rejected by inputs 0 or 1.

The P2WSH and guardian commitments together prevent a challenger from moving output 0 to a different digest by regrinding Binohash. Attempting to change the certificate witness alone fails P2WSH validation. The parent txid remains unchanged across witness-only substitutions, so the original pre-signed descendant's prevout identity remains stable even when the mutant is consensus Script-invalid.

The static construction permits a new fee sponsor after Binohash is regrinded. Its other effect is to constrain this UTXO to one preselected certificate digest.

## Adversarial vectors

The offline Core 26 suite checks ten complete raw transactions against all three individual Script inputs:

| Attack | Expected per-input validity (P2WSH, guardian, Binohash) |
| --- | --- |
| Original fixed certificate A | pass, pass, pass |
| Substitute C in witness | fail, pass, pass |
| Substitute C and its witness script | fail, pass, pass |
| Change OP_RETURN without regrinding | pass, fail, fail |
| Change OP_RETURN and regrind | pass, fail, pass |
| Burn protected successor and regrind | pass, fail, pass |
| Reduce successor amount and regrind | pass, fail, pass |
| Substitute C and change OP_RETURN with regrind | fail, fail, pass |
| Change fee sponsor without regrinding | pass, pass, fail |
| Change fee sponsor and regrind | pass, pass, pass |

These transactions use test keys, fabricated prevouts, a 32-byte fake certificate and deliberately weak toy Binohash parameters. The checker enforces only each supplied input Script. It does not verify amounts, total value conservation, confirmation, actual Bitcoin fork headers, cumulative chainwork, or spent-output existence.

## Architectural decision

**Fixed certificate authentication is enforceable with current Script in this one-hop experiment.** It comes at the price of picking the one permitted digest before signing and funding, so it cannot admit arbitrary later fork certificates. A fixed P2WSH verification program could in principle accept a class of witnesses subject to a more general predicate, but the prototype here checks equality to one hash.

For permissionless challenges we still need a Bitcoin-enforced, dynamically variable certificate validation predicate that can check exact work and link the actual witness to the signed claim, while preserving a safe successor. A BitVM-style assertion/refutation route may help, but it must pay collateral correctly, leave stronger timely challengers a live path, and close the independently valid CLTV refund shown by ADR-006.

## Reproduction

    node --test model/*.test.mjs
    node model/fixed_certificate_gate_vectors.mjs > /tmp/bsb-fixed-certificate-gate.json
    cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-fixed-certificate-gate.json

No mining, funded transaction creation, proof generation or live Bitcoin RPC is involved.