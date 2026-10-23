# ADR-004: Authenticate txid-stable challenge witnesses through BIP141

**Status:** Research-grade synthetic inclusion proofs. No actual Bitcoin header validation, block mining, BitVM payout verifier, or storage-bond integration.

## Opportunity

A SegWit challenge transaction can keep its transaction ID fixed while carrying an arbitrary certificate in a witness. The witness transaction ID changes with certificate bytes. Bitcoin's deployed BIP141 commits all wtxids into a witness Merkle tree, and places the witness root commitment in the coinbase transaction. The coinbase's txid is committed into the Bitcoin block's ordinary transaction Merkle root.

This supplies a cryptographic way to authenticate *which* witness bytes a confirmed transaction carried without changing the transaction ID used by pre-signed descendants.

BIP141 reference: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki

## Prototype

The module model/witness_anchor.mjs implements, for a synthetic block only:

1. Serialization of a SegWit v0 P2WSH challenge whose witness program is OP_DROP OP_TRUE. The witness carries one arbitrary certificate, with scriptSig empty and a fixed 0x0020 SHA256 scriptPubKey.
2. A witness tree whose coinbase leaf is 32 zero bytes, per BIP141.
3. A coinbase OP_RETURN commitment with prefix 0x6a24aa21a9ed and hash SHA256d(witness_merkle_root || 32-byte_reserved_value).
4. Ordinary transaction Merkle inclusion of that coinbase txid in a synthetic block transaction root.
5. Proof verification, certificate mutation tests, output/root tampering tests, and BIP141's rule to select the highest matching commitment-output index.

model/witness_anchor.test.mjs contains 18 deterministic tests.

## Combined with one-hop Binohash carrier

The updated model/composite_cursor_consensus_vectors.mjs carries three independent Script inputs:

| Input | Script authorization | Purpose |
| --- | --- | --- |
| 0 | P2WSH, OP_DROP OP_TRUE | Arbitrary witness certificate; keeps txid stable across witness changes |
| 1 | Pre-signed legacy P2PK SINGLE|ANYONECANPAY | Fixes a specific successor output and amount |
| 2 | Toy legacy bare Binohash | Commits actual signed transaction fields, including output 0's certificate hash and the protected successor |

The submitted certificate appears in input 0's witness. Output 0 stores SHA256(certificate_witness_bytes). A Binohash regrind binds that OP_RETURN commitment to the actual transaction; a BIP141 inclusion proof binds the witness data actually confirmed in a synthetic block to that same commitment.

The necessary cross-check is: SHA256(witness bytes) == signed OP_RETURN commitment. Neither the Binohash signature alone nor the permissive P2WSH script performs that check. The eventual BitVM circuit must do so.

The input-level Bitcoin Core 26 verifier now verifies **all three scripts** in the same unfunded transaction. The Core test verifies Script spend conditions, and does not inspect a block's witness Merkle commitment or prove a funded UTXO exists.

## How the real verification circuit would have to work

A genuine BitVM or SNARK verifier would take a supplied certificate, its confirmed SegWit challenge transaction, a witness Merkle branch, the coinbase transaction with its witness reserved value, a coinbase transaction-ID Merkle branch, and an authenticated Bitcoin block header chain. It must:

- Check transaction serializations, txid and wtxid.
- Check the witness tree with the coinbase wtxid defined as zero.
- Check the coinbase's highest matching BIP141 witness commitment output and reserved value.
- Check coinbase txid inclusion against the chosen block header's transaction root.
- Cryptographically anchor the header to the intended Bitcoin reference chain, with explicit reorg and confirmation rules.
- Compare SHA256(actual certificate witness bytes) with the OP_RETURN commitment bound by the challenger/settlement protocol.
- Verify the exact chain-work computation and headers in the submitted certificate, and confirm timely inclusion by the admission cutoff.
- Constrain the collateral payout and require provider responses to **that exact certificate**.

**These are circuit requirements, not completed implementations.**

## Critical limits

1. A synthetic block can commit to an invalid transaction too. Inclusion arithmetic alone does not establish transaction input-script validity, consensus block validity, actual proof-of-work, Bitcoin's canonical best chain, or a certificate's upper-bound inclusion height. The model demonstrates this distinction with an intentionally invalid witness-script example.
2. Arbitrary proof data in a witness may be large; SegWit v0 script/witness limits and transaction weight still apply. Chunking, Blob/Blossom support or commitments to separately published data may be necessary.
3. An unchanged txid can have different potential wtxids, but only the witness that actually confirms in a valid block is authoritative. The settlement path must authenticate it cryptographically.
4. Fixed transaction IDs can aid a pre-signed descendant graph; they do not automatically admit arbitrarily many stronger challengers or prevent finite slots from being exhausted by weak submissions.
5. Provider-only refunds, response-window races, dynamic proof binding and settlement enforcement remain the original blockers.

## Direction

This offers a route to **witness-stable pre-signed transaction graphs with independently authenticated certificate content**, potentially using an SPV-in-BitVM verifier instead of a Binohash transaction-introspection carrier for that narrow subproblem.

The next useful executable construction is a real, consensus-validated block fixture plus a verifier proving BIP141 witness and coinbase inclusion against a genuine Bitcoin header. That verifier must eventually be tied to BitVM's fixed collateral graph and support timely stronger challenges. The current restriction against new mining and proof jobs remains in place, so work is limited to offline test vectors and specifications.
