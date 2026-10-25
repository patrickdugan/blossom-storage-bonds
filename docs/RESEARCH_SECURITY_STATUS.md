# Security status: Blossom research merged to `main`

**Updated 25 October 2026. Research-only and disposable regtest.**

The independent LayerTree/FROST track has joined the original sentinel
prototype in the repository's default branch. It remains an executable
research laboratory with distinct trusted assumptions and separate
protocol evidence. Merging these tested fixtures does not establish
permissionless or production-safe collateral custody.

## Merged experimental chain

| PR | Scope of tested implementation | Bitcoin-level claim limit |
| --- | --- | --- |
| [#5](https://github.com/patrickdugan/blossom-storage-bonds/pull/5) | Parallel A/B models, real funded Taproot sentinel, FROST keypath signing | External storage proof and MID policy not consensus enforced |
| [#6](https://github.com/patrickdugan/blossom-storage-bonds/pull/6) | Three-generation signer-dead presigned joint exit | Sponsor outpoint and malicious quorum still threats |
| [#7](https://github.com/patrickdugan/blossom-storage-bonds/pull/7) | Alice-first or Bob-first owner exit, then other-owner recovery | Anyone holding a frozen witness can relay it |
| [#8](https://github.com/patrickdugan/blossom-storage-bonds/pull/8) | Fixed sponsor-input sabotage counterexamples | Sponsor failure can strand fee-committed exits |
| [#10](https://github.com/patrickdugan/blossom-storage-bonds/pull/10) | Real BIP341 FROST v3/P2A parent plus fresh fee-funded child | Third-party fee availability still needed |
| [#11](https://github.com/patrickdugan/blossom-storage-bonds/pull/11) | Real Core child replacement and fee-limited local pinning | No universal anti-pinning |
| [#12](https://github.com/patrickdugan/blossom-storage-bonds/pull/12) | Two connected Core 30.3 nodes, fee-floor policy 2/25 sat/vB | Local P2P observation only |
| [#13](https://github.com/patrickdugan/blossom-storage-bonds/pull/13) | Signed holder delivery, filesystem checkpoints, own-key ACK receipts | Co-hosted keys and rollback anchor, no independent custody |
| [#15](https://github.com/patrickdugan/blossom-storage-bonds/pull/15) | Pre-invalidation two-ACK gate for two Bitcoin refreshes | Honest-coordinator policy, not Bitcoin consensus covenant |

[Final-head Bitcoin Core regtest #40155363408](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40155363408):
nine offline gate tests, eight actual regtest scenarios, two successive
ACK-gated refreshes, seven withheld/forged/stale/rollback denial scenarios,
then signer-dead final recovery of Alice's 60,000 sats and Bob's 40,000 sats.
It proves those properties **only for that frozen source and controlled
regtest fixture**.

## Open architectural boundaries

The FROST aggregate public key remains a spend-authorizing P2TR keypath.
An active malicious two-of-three quorum can sign an alternative spend,
regardless of an application-level ACK, honest MID root, or Filecoin report.
Independent or covenant-constrained custody requires additional Bitcoin
enforcement or a different spend-authorization design.

Both holder processes in the tested delivery and ACK flows share one CI
host and disposable trusted-dealer provisioning. Their separate local
directories demonstrate recovery storage semantics, while an attacker able
to restore the **package and independent rollback checkpoint together**
could evade local rollback detection. True holder-controlled keys, an
out-of-band monotonic witness and remote delivery/ACK challenge protocol
are not implemented.

Each honest-coordinator refresh requires both holders to ACK; unavailable
holders therefore halt refresh. Long-lived unattended LayerTree refresh
and independent seedless unilateral recovery remain open.

The original permissionless Binohash/BitVM fork-admission branch is
still blocked in [PR #1](https://github.com/patrickdugan/blossom-storage-bonds/pull/1)
by the lack of consensus-enforced arbitrary fork-certificate-to-collateral
adjudication. This issue is separate from the FROST overlay's trusted-quorum
limitations.

[Issue #14](https://github.com/patrickdugan/blossom-storage-bonds/issues/14)
tracks externally authenticated holder ACKs and independent rollback
witnesses. PR #9's older parallel P2A implementation remains available
at its original immutable commit; the independent historical receipt
comparison is preserved in
[`experiments/storage-bond-ab/legacy-p2a-v1/`](../experiments/storage-bond-ab/legacy-p2a-v1/).

No conclusion here authorizes real funds, public Signet or a production
storage-bond deployment.
