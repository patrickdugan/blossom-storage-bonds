# Historical A/B FROST-P2A comparison fixture (2026-10-24)

These two Node files preserve the **independent receipt parser and negative
comparison checks** from
[original research PR #9](https://github.com/patrickdugan/blossom-storage-bonds/pull/9)
at pinned commit [`600056a`](https://github.com/patrickdugan/blossom-storage-bonds/commit/600056a9391c0fbe4d414eb1f72f1a94826bb917).

The original PR #9 also contained a separate, superseded experimental
Rust FROST P2A signer and relay implementation. That implementation remains
accessible at the pinned source commit, rather than being mixed into the
current `--freeze-p2a` implementation merged through PR #10 and later work.

The comparison accepts a specific **historic** B receipt format:
`bsb-frost-p2a-dynamic-fee-offline-regtest-v1`. Later main-branch
receipts use different schemas. Inputs from the historical GitHub Actions
artifact should be treated as an independent, bounded Bitcoin Core
measurement. No live Bitcoin Core or new FROST signatures are needed here.

Run with Node 22:

```sh
node --test experiments/storage-bond-ab/legacy-p2a-v1/compare-p2a-a.test.mjs
```

This test prevents false claims of fee/epoch equivalence, Byzantine safety,
or real Filecoin data nonavailability based only on the shared PDP hash
and the original 100,000-sat starting capital.

Original passing historical CI:
[workflow #40099699524](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40099699524).

This directory is an **archive of a distinct research method**, not an
alternative active recovery transport to deploy with production funds.
