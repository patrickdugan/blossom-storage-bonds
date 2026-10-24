# Genuine 2-of-3 FROST Taproot signature laboratory

**Implemented and compiled:** Zcash Foundation
[`frost-secp256k1-tr` 3.0.0](https://docs.rs/frost-secp256k1-tr/3.0.0/frost_secp256k1_tr/)
with a checked-in, locked 72-package Rust dependency graph.

This module supplies real threshold Schnorr cryptography for the proposed
LayerTree carrier's federation. It is **not yet Bitcoin transaction signing**.
See the separate `b-layertree/regtest/surrogate.mjs` for real funded Bitcoin
Core execution using a plain 2-of-3 P2WSH CHECKMULTISIG surrogate. These two
capabilities are not represented as one integrated Bitcoin protocol.

## Reproduce

Generate the common Alice epoch-2 failing Merkle evidence hash:

```bash
export BSB_EVIDENCE_HASH="$(node --input-type=module -e '
  import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
  const e=scenario("storage-fault").events.find(x=>x.kind==="proof"&&x.id==="alice"&&x.epoch===2);
  const p=challenge(e); if(p.verified)throw Error("expected actual missing storage sample");
  console.log(p.evidenceHash);
')"
cargo test --locked --manifest-path experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml
cargo run --release --locked --manifest-path experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml \
  -- "$BSB_EVIDENCE_HASH" /private/frost-proof.json
```

The program generates an ephemeral 3-share key using a trusted dealer
and carries out RFC 9591-style commitment, share, and aggregation rounds
for all three participant pairs (1+2, 1+3, 2+3). Each aggregate signature
is checked by ZF FROST and then **independently** by Rust `secp256k1`'s
BIP340 Schnorr verification against the x-only group public key.
Removing one signature share from a two-participant signing package
fails aggregation. Each signature fails verification under a different
message digest. A fresh two-person malicious quorum **can** sign a
different unauthorized intent with the same group public key, which
demonstrates the economic trust boundary remains.

The exact byte message is a SHA-256 digest of a domain-separated text
enclosing the independently generated Alice PDP evidence hash and
100,000/60,000/40,000 satoshi terms. It is not a BIP341
`SighashCache::taproot_key_spend_signature_hash` result. That is the
next integration step.

## Strict security boundary

- The entire cryptographic interaction occurs in one process, with all
  ephemeral dealer-generated shares in that process. It does not
  demonstrate distributed custody, DKG, authenticated participant
  communication, share-erasure or nonce persistence.
- It does not apply the BIP341 TapTweak, nor create a P2TR output,
  script path, PSBT or Bitcoin Core witness.
- It does not enforce the MID covenant or any Filecoin/Blossom proof
  predicate on Bitcoin. Two malicious signers can authorize theft
  once their threshold share is sufficient.
- The Zcash Foundation's historical NCC audit covered base FROST
  ciphersuites but **not** the Taproot-specific
  `frost-secp256k1-tr` ciphersuite. Do not treat the earlier audit as
  assurance for this entire Bitcoin integration.
- The JSON output contains public keys and aggregate signatures only,
  not secret key shares or signing nonce secrets. The exact transitive
  crate dependency versions are captured in `Cargo.lock`.

## Next executable milestone

Build a native P2TR output from the actual aggregate x-only public key
with a well-defined TapTweak policy. Construct an unsigned v2/v3 Bitcoin
transaction, compute the **correct BIP341 sighash for its precise
prevouts**, obtain distinct participant nonce commitments, aggregate
the real FROST signature with the Taproot tweak accounted for, and
broadcast to a disposable Bitcoin Core regtest. Test malformed shares,
wrong prevouts, changed payout scripts, sponsor fee theft, participant
dropout and a dishonest two-share unauthorized settlement. Do not
merge these into the main A/B score until the transaction confirms.
