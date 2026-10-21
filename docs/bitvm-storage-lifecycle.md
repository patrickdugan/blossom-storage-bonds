# Storage graph setup before the term

`bsb-storage-live` separates the committee's presigning from the provider's term-end assertion.
The provider registers fresh public one-time keys before funding. A separate committee process
builds and signs the graph using those public keys and the fixed term, exits, and only then may
the harness broadcast funding. The provider keeps its one-time secrets in RAM until it receives
the term-end proof and checked assertions. It signs one request and exits.

The Core 31.1 lifecycle regression still uses the phase-6 proof. It verifies the ordering and
transaction enforcement, not fresh proofs of the new node's chain. Connecting the fresh-proof
job to this lifecycle on one chain and adding a heavier-chain challenge remain.

## Process protocol

The setup file has format `bsb/storage-setup/v1`, network `regtest`, the 134-byte term prefix,
wrapper constants digest, pinned verifying-key hash, and the graph's heights, windows and values.
The prefix fixes the guest IDs, q, deal count, D and epoch schedule. A claim's chain-tip suffix
and proof are supplied later.

1. Start `bsb-storage-live provider <terms.json>`. Its `BSB_LIFECYCLE` ready event contains a public
   registration: setup terms and all 381 one-time public keys. Save that registration for setup.
   No one-time secrets are exported. Keep this process alive through the storage term.
2. Start `bsb-storage-live setup <terms.json> <registration.json> <vk-directory> <partial-cache> <new-graph.json>`.
   This process reads the verifying key and public cached scripts; it needs no proof or assertions.
   Its ready event supplies the funding address. Give it the fixed funding txid, output index,
   amount and current regtest height as a JSON line on stdin. It requires setup before the first
   epoch. The resulting graph pins all 364 real Groth16 leaves and the binding leaf under the
   provider's registered keys. Wait for this process to exit successfully before funding.
3. At term end, send the waiting provider a JSON line containing the `fixture`, `proof_dir`,
   `assertions` and new `output` paths. It independently verifies the actual Groth16 proof, checks
   its public scalar against the original term and wrapper, and checks the cached public-input
   encoding. It requires assertions previously checked by the unsigned chunk executor. It writes
   public one-time signatures, then exits. A second queued request is ignored; it cannot receive
   a second signing event in the same process.
4. Run `bsb-storage-live attach <presigned-graph.json> <term-witnesses.json> <new-asserted-graph.json>`.
   This process uses no secrets. It rejects substituted registration keys, checks all 381
   Winternitz signatures, reconstructs the committed proof tree, and inserts witnesses into the
   two commitment transactions and binding-disprove vector. Every presigned txid must stay fixed.

The JSON graph contains raw public transaction vectors. The isolated marker has the same provider
refund and binding/Groth16 disprove paths as the graph documented in `bitvm-storage-graph.md`.
Committee and ordinary client/provider transaction keys are still generated together inside one
local setup process; this is not a distributed committee ceremony. A provider restart loses the
one-time secrets, so the timeout paths remain necessary.

## Verified results

`lifecycle-regtest.ts` starts a fresh Core node, drives the separate processes, and reads every
mined transaction back from Core. A separate transaction decoder verifies the terminal txid and
payout address. Both test nodes shut down after their runs.

| Case | Measured behavior |
| --- | --- |
| Honest | Public keys registered and committee exited at height 101; funding mined at 102, before epoch 170; witnesses supplied at 222, after the term deadline 220; all presigned txids retained; six graph transactions mined and the provider received 98,431,000 sats |
| Silent provider | Provider exited without witnesses; client recovered 92,314,000 sats from control and 7,470,000 from unused slots; four graph transactions mined |

The honest run also rejected five premature, missing-input or invalid-script spends on Core and
rejected a substituted-key artifact locally. The silence run rejected two premature spends on
Core. Results are `results/bitvm-storage-lifecycle-honest.json` and
`results/bitvm-storage-lifecycle-silence.json`.

`lifecycle-guards.ts` checks five additional provider cases without a node: changed setup terms,
changed wrapper constants, a curve-valid false Groth16 proof, unchecked assertions, and two queued
requests to the same one-time signer. The four invalid cases produce no witness file. The queued
case produces exactly one signed artifact. See `results/bitvm-storage-lifecycle-guards.json`.

```text
node zk/bitvm-check/lifecycle-regtest.ts --bitcoind <core> --checker <bsb-storage-live> --partials <cache> --assertions <checked-assertions.json> --dir <new-node-directory> --out <new-result.json>
node zk/bitvm-check/lifecycle-regtest.ts --scenario silence --bitcoind <core> --checker <bsb-storage-live> --partials <cache> --assertions <checked-assertions.json> --dir <another-new-node-directory> --out <another-new-result.json>
node zk/bitvm-check/lifecycle-guards.ts --checker <bsb-storage-live> --assertions <checked-assertions.json> --dir <new-test-directory>
```

The regression harness defaults to the checked phase-6 proof and fixture. It accepts `--fixture`
and `--proof-dir` for subsequent proof runs, but using another node's header snapshot is not evidence
of a fresh proof for this graph's chain. The fresh inputs must come from the same lifecycle run.
