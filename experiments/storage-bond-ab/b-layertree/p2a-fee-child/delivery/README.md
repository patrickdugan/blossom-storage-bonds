# Experimental signed recovery-package delivery to separate holders

Draft child of [two-node FROST v3/P2A relay PR #12](https://github.com/patrickdugan/blossom-storage-bonds/pull/12).
This folder adds a **transport / custody** experiment after the genuine 2-of-3
FROST signer has terminated. The exact original `p2a-frozen.json` bytes are
bound to independently signed, holder-specific Ed25519 delivery envelopes.
The Bitcoin Core relay test still independently verifies frozen BIP341
witnesses, chain outpoints and P2A packages.

## Protocol tested

Each envelope signs domain-separated bytes covering the target holder,
network, generation, current carrier outpoint, pinned payout script,
SHA256 of the entire frozen manifest, previous signed-delivery digest
and the complete actual manifest bytes (base64). Each holder pins the
separate delivery authority's Ed25519 public key **in advance**.

A holder verifies the signature and checks the signed recovery graph's
structure. It stores one immutable package per generation in its
private directory, fsyncs the file and directory, and creates a distinct
write-once checkpoint in a separately protected rollback-anchor directory.
It rereads that checkpoint before generating its own domain-separated,
holder-key-signed acknowledgment. Competing concurrent deliveries,
repeated generations, missing generation steps, stale signatures,
equivocation, altered witnesses and truncated package files fail closed.

The separate refresh-readiness predicate requires **both** genuine holder
acknowledgments to agree on one exact generation, signed-manifest SHA256,
and current carrier outpoint.

## Reproduction

Offline structure and rollback suite:

```sh
node --test experiments/storage-bond-ab/b-layertree/p2a-fee-child/delivery/holder_vault.test.mjs
```

For the real signed transaction manifest, the amended
`../p2p/run_two_nodes.sh` automatically invokes
`check_signed_manifest.mjs` after the signer process exits and before
the existing two-node package-relay probe. It runs on two disposable
Bitcoin Core 30.3 node pairs (2 and 25 sat/vB receiver fee floors).
The new [holder-delivery CI](../../../../../.github/workflows/frost-p2a-holder-delivery.yml)
runs both tests, preserving the previously established 60k/40k beneficiary
amounts and confirming the original signed witnesses at both Bitcoin nodes.
Only sanitized generation, hash and test-result receipts are uploaded.
Ephemeral private keys and signed recovery witnesses stay within the
runner's deleted temporary files.

## Threat boundary

- The external checkpoint must be protected against the adversary
  who can roll back the package store. A complete rollback of **both**
  directories is indistinguishable without an independent trusted
  monotonic counter, external witness or holder-owned hardware.
- Delivery authority keys and holder ACK keys are generated in the same
  disposable test process. This proves signature plumbing and storage
  behavior, **not** independent device custody or an actually offline
  holder receiving, reviewing and approving the latest package.
- The original signer prepares **and confirms two refresh transactions**
  before this transport test. Thus, generation 2 acknowledgment is
  **after** the earlier refreshes. The ACK predicate is not wired into
  the actual Bitcoin refresh signing or broadcast path. Safe unattended
  future refresh still requires ACK-before-invalidation and an onchain
  failure policy for missing or withdrawn ACKs.
- JavaScript examines commitments and declared output agreements.
  It does not implement a Bitcoin consensus verifier or independently
  prove that the signed witness matches those descriptions. The
  existing full-node runner is the evidence for actual BIP341 witness
  validity of this concrete regtest FROST manifest.
- A malicious active 2-of-3 FROST quorum can authorize a different
  Bitcoin keypath spend. Transport signatures and acknowledgments
  cannot constrain that authority, Filecoin fault adjudication or
  Sapio MID transitions.
- Filesystem assumptions: trusted local directories on a system
  where `O_EXCL`, file `fsync` and directory `fsync` have their
  documented persistence semantics; the anchor must be independently
  protected. There is one protocol writer per holder. A crash that
  leaves an orphan file or lock fails closed and requires operator
  examination. No unattended automated repair or remote distributed
  witness protocol is claimed.
- The source already requires a fresh third-party fee payer to publish
  each v3 P2A parent/child recovery package. An ACK does not fund fees.

Follow-on gate: two **separate holder processes/devices** with
pre-established key trust and independent durable monotonic roots,
ACK **before** any refresh invalidates the previous carrier, followed
by an adversarial check that absent ACK halts refresh even under signer
outage. A Bitcoin covenant or different trust model is needed before
claiming Byzantine quorum safety.
