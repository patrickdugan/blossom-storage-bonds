# ADR-005: Two pre-signed cursor generations with witness-stable transaction IDs

**Status:** Unfunded multi-input Bitcoin Script experiment. Presigned stages are finite, and certificate validity remains a separate unimplemented consensus-enforced condition.

## Mechanism

Moving a challenge certificate into an actual SegWit witness leaves the parent transaction ID unchanged. A second-stage transaction that spends the parent's output can therefore be signed in advance without knowing which witness payload will eventually confirm.

We test the same fixed parent with witness certificates A and C. Bitcoin's legacy transaction ID is identical for both, while their witness transaction IDs differ. The second-stage transaction references the parent transaction ID and output index 1, so the same pre-signed P2PK input is applicable under either witness variant.

The second-stage witness likewise supports certificate B or D with the same second-stage txid. All inputs are independently validated by the offline Bitcoin Core 26 Script library.

The transactions use three scripts per generation: native v0 P2WSH holding the certificate, a known-outpoint P2PK `SIGHASH_SINGLE|ANYONECANPAY` guardian fixing the successor output, and an insecure toy Binohash carrier binding nonwitness fields.

## The serious limitation

The output-zero OP_RETURN commitment to certificate A remains fixed when witness C is substituted. Because both the P2WSH script (`OP_DROP OP_TRUE`) and legacy Binohash signatures accept that alternate witness, **all three scripts can pass while SHA256(witness_C) differs from OP_RETURN**.

A verifier must prove the following statement using the **witness that really confirmed**:

- Its bytes are authenticated by BIP141's witness Merkle commitment, followed by Bitcoin header-chain inclusion.
- Its certificate digest matches the signed public input or another authenticated proof input that controls the bond dispute.
- Its headers are valid under the specified starting state and provide the claimed exact 256-bit cumulative work.
- Its admission height is within the cutoff, and the provider responds to this particular certificate.
- Subsequent settlement pays only the allowed recipient under the effective dispute result.

With fixed OP_RETURN as currently constructed, changing the witness changes the authenticated certificate hash without changing the committed hash. A sound circuit rejects this alternate witness, which in turn means this test **does not yet demonstrate arbitrary permissionless candidate admission**. A redesigned commitment may instead bind a fixed verification statement and authorize witness-supplied certificates as inputs, but its live Bitcoin enforcement needs to be constructed.

## Scope of improvement

This establishes that **variable witness bytes alone need not break pre-signed descendants**. That can avoid txid explosion in a bounded graph while retaining cryptographic evidence of what was confirmed.

Even if the certificate check is subsequently solved, this graph has only two pre-signed stages. A weak challenger could occupy a slot before a stronger challenger and exhaust the available window. A real permissionless system must bound griefing while leaving valid later stronger challenges actionable.

A third stage, or unlimited stages, requires another authorized graph transition. Dynamic proof verification, collateral exit gating and full response clocks remain outstanding.

## Reproduce

- `model/witness_stable_chain_vectors.mjs` creates six unfunded variants of two generations, including wrong-prevout and burned-successor cases.
- `model/witness_stable_chain_vectors.test.mjs` checks parent IDs, witness IDs, signatures, and finite-slot implications.
- Offline `libbitcoinconsensus` checks all three inputs separately on each raw transaction.

```bash
node --test model/*.test.mjs
node model/witness_stable_chain_vectors.mjs > /tmp/bsb-witness-stable.json
cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-witness-stable.json
```

No Bitcoin blocks, live funding, proof jobs, miner interactions or pilots are used.
