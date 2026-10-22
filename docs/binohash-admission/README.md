# Blossom storage bonds: Binohash admission research

The GitHub working branch is **[research/binohash-admission](https://github.com/patrickdugan/blossom-storage-bonds/tree/research/binohash-admission)**, based on pushed `phase-6-bitvm2-spike`. The local Phase 7 commit `4494714` is not present on GitHub. This branch does **not** replace that regression fixture.

The model includes **55 deterministic tests**, no external dependencies, and three signature-hash results matched to Bitcoin Core test vectors. Run with Node 22 or later:

```bash
node --test model/*.test.mjs
```

Read [the transaction-graph integration gate](next-step.md) and [the initial Binohash admission review](../binohash-admission-review.md).

Status: **BLOCKED ON CONSENSUS-ENFORCEABLE CHALLENGE ADMISSION.** The branch contains educational models and independently tested Bitcoin transaction serialization and legacy sighash calculations. It does not implement a sound refund covenant, Binohash grinding, or a permissionless miner/relay route.