# Blossom storage bonds: Binohash admission handoff

Status **BLOCKED**, reference model only. Adds 17 deterministic research tests using Node 22's builtin test runner. No external dependencies, Bitcoin activity or proof generation. Published on GitHub in the research branch with explicit owner approval.

For the current research branch, run:

```bash
node --test model/binohash_admission.test.mjs
```

See [`docs/binohash-admission-review.md`](../binohash-admission-review.md) for limitations and the transaction-level integration requirements.

The tests prove a failure of a **specific unsafe class of designs** even under idealized Binohash-style transaction binding. They do not prove that Binohash cannot participate in a viable construction, and do not implement a production Binohash verifier.
The local phase-7 commit `4494714` is not available in GitHub's remote history. The branch starts from `phase-6-bitvm2-spike`. Port these research tests onto that local checkout before trusting interactions with the six-transaction journal.
