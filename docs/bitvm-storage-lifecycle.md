# Storage graph setup before the term

`bsb-storage-live` separates the committee's presigning from the provider's term-end assertion.
The provider registers fresh public one-time keys before funding. A separate committee process
builds and signs the graph using those public keys and the fixed term, exits, and only then may
the harness broadcast funding. The provider keeps its one-time secrets in RAM until it receives
the term-end proof and checked assertions. It signs one request and exits.

The default Core 31.1 regression uses the phase-6 proof. The fresh mode now proves the same
funded graph's own chain: public keys at height 101, funding at 102, a snapshot at 220, then native
Groth16 and unsigned BitVM checks before one signing event at 222. Core mined six graph
transactions and refunded the provider 98,431,000 sats. See
`results/bitvm-storage-lifecycle-fresh.json`. A heavier conflicting-chain challenge remains.

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

## Fresh proof return

The fresh mode captures the funded graph's own node at term end and waits for its proof. Use a
new return-directory path; it must not exist when the committee and provider start:

```text
node zk/bitvm-check/lifecycle-regtest.ts --bitcoind <core> --checker <bsb-storage-live> --proof-checker <bsb-bitvm-check> --partials <cache> --dir <new-node-directory> --out <new-result.json> --fresh-proof-dir <new-return-directory>
```

The coordinator writes `<node-directory>/proof-job.json` and `input-snapshot/` after funding
and term end. Transfer only the public input snapshot to the prover and run the pinned proof job
in `bitvm-fresh-proof-job.md`. Keep the local provider alive: its one-time secrets remain in RAM.
The default proof-return wait is two hours; `--proof-wait-ms` sets a different wait explicitly.

Copy the finished proof output back without a readiness file. Once the copy is complete, run:

```text
node zk/risc0/proof-return.ts <node-directory>/input-snapshot <return-directory> <node-directory>/terms.json
```

This checks the copied metadata and hashes, then creates `RETURN_READY.json`. It does not
verify the proof. The coordinator independently runs the native Groth16 verifier and executes
the unsigned BitVM chunks before requesting the provider's single signing event. It also checks
that the node still has the snapshot's tip hash. A failed return stops the provider and node;
the lost one-time setup cannot be resumed by starting another signer with the same public keys.

`proof-return-guards.ts` checks stale snapshots, changed guest IDs, wrapper constants, manifests,
and files changed after copy completion. Its counterfeit return has consistent fresh-chain
metadata and the old proof; the actual native pairing equation rejects that proof.
`lifecycle-replay.ts` exercises this refusal through a separately funded graph and checks that
no signatures, checked assertions or completed graph are produced, and that its processes exit:

```text
node zk/bitvm-check/lifecycle-replay.ts --bitcoind <core> --checker <bsb-storage-live> --proof-checker <bsb-bitvm-check> --partials <cache> --dir <new-test-directory> --out <new-result.json>
```

The rejection evidence is `results/bitvm-proof-return-guards.json` and
`results/bitvm-proof-return-replay.json`. A metadata check is never evidence of a valid proof.

## Verified results

`lifecycle-regtest.ts` starts a fresh Core node, drives the separate processes, and reads every
mined transaction back from Core. A separate transaction decoder verifies the terminal txid and
payout address. Each test node shuts down after its run.

| Case | Measured behavior |
| --- | --- |
| Honest, phase-6 fixture | Public keys registered and committee exited at height 101; funding mined at 102, before epoch 170; witnesses supplied at 222, after the term deadline 220; all presigned txids retained; six graph transactions mined and the provider received 98,431,000 sats |
| Silent provider | Provider exited without witnesses; client recovered 92,314,000 sats from control and 7,470,000 from unused slots; four graph transactions mined |
| Honest, fresh proof | VPS generated the chain, three holdings, term and Groth16 proofs from this node's height-220 snapshot; all independent checks passed before signing at 222; six graph transactions mined, five Core rejections and one local substituted-key rejection; provider refund 98,431,000 sats |

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
of a fresh proof for this graph's chain. The fresh inputs must come from the same lifecycle run;
`--fresh-proof-dir` is the verified route.
`results/bitvm-storage-fresh-proof.json` and `results/bitvm-storage-fresh-groth16/` hold its reusable
proof fixture. Only the fixture's scope note and provenance fields were adapted after integration;
`producer_fixture_sha256` identifies the raw producer fixture, and all proof data are unchanged.
