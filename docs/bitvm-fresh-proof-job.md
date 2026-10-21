# Fresh storage proof job

`capture-snapshot.ts` creates new synthetic holdings inputs using the actual block hashes of a
fresh, loopback-only Core regtest node. `prove-snapshot.sh` consumes that snapshot on a prover
machine and runs the existing RISC Zero header, holdings and term guests, then the pinned
Groth16 wrapper. No wallet or signing key belongs in the snapshot or the proving job.

The standalone capture does not fund a graph. The same-chain mode in
`bitvm-storage-lifecycle.md` now captures the funded graph's node and verifies the returned proof
before term-end signing. That fresh run passed on Core 31.1; see
`results/bitvm-storage-lifecycle-fresh.json`. Neither mode provides a heavier-chain challenge.

## Capture locally

Use the installed Node runtime with TypeScript stripping and a Core binary. Both directories must
be new. Core listens only on loopback, has no peers, mines 200 blocks, and shuts down before the
snapshot is delivered.

```text
node zk/risc0/capture-snapshot.ts --bitcoind <installed-bitcoind> --dir <new-node-dir> --out <new-snapshot-dir>
python3 zk/risc0/fresh_snapshot.py check <snapshot-dir>
python3 zk/risc0/fresh_snapshot_test.py <snapshot-dir>
```

The schedule matches the measured phase-6 workload: three deals of 256 chunks, q=16, epoch seeds
at heights 170, 180 and 190, depth 6, and a chain tip at 200. The synthetic deal roots are
deterministic; each epoch's seed, witness, journal and the aggregate term journal use the new chain.
`snapshot.json` fingerprints every input and records the exact expected 202-byte term preimage.

The Python checker uses only the standard library. It independently checks genesis, header links,
fixed regtest difficulty, proof of work, version and median time; replays all holdings challenges
and Merkle paths; and recomputes the term journal. It also pins the three guest image IDs and the
phase-6 verifying-key file. Its adversarial tests change file hashes along with mutated bytes, so
the altered-header and altered-chunk cases must fail semantic validation rather than just a checksum.
This checker is input validation, not a substitute for a RISC Zero or Groth16 proof verifier.

## Prove on the prepared Linux machine

The successful phase-6 machine had four CPU cores, 15.7 GiB of RAM and no GPU. Header proving
peaked at 9.2 GiB; the Groth16 container's high-water mark was 8.4 GiB including its file cache.

Required tools and pinned inputs are the same as that run:

- The repository's `bsb-r0` host, built from `zk/risc0/Cargo.lock`, with RISC Zero Rust 1.85.0
  and C++ 2024.1.5 for the guests. The recorded host Rust was 1.97.0.
- `chainwayxyz/risc0-to-bitvm2` at `efc448ef016cef2a908d97e69b9d3d1f2b2cfdb5`, including
  `elfs/regtest-header-chain-guest.bin`.
- Docker with the existing image
  `ozancw/risc0-to-bitvm2-groth16-prover@sha256:840b833190a86c87eb71473cd72bcaa3e3b90cefa9bf4ae785ab2de61bc9d262`.
- Bash, Python 3.9 or later, Git and `/usr/bin/time`.

Guest image IDs include dependency paths embedded in panic messages. The phase-6 guests were
built with `/root/.cargo` paths. `risc0-build` clears `CARGO_HOME` when launching guest Cargo, so
an ordinary build under another account produces different image IDs even with the same sources
and toolchain. Normalize the guest cache path before using a fresh build with an existing graph:

```bash
bash zk/risc0/build-pinned.sh /path/to/installed/cargo /path/to/populated/guest-cache /path/to/new-wrapper-directory
```

This offline recipe uses the existing locked dependency cache, maps guest dependency paths to
`/root/.cargo`, and rejects a build unless all three committed guest IDs match. It changes no guest
logic or expected IDs. Pass the installed Cargo launcher directly, rather than another wrapper.

The fresh same-chain run used an 8-vCPU, 31-GiB private VPS with four prover threads. The chain
proof took 16:09, the three holdings proofs about 4:27 each, the term proof 4:14, and the Groth16
wrap 3:17. Header proving peaked at 9.16 GiB. The wrapper's host-process RSS excludes its Docker
container; the old cgroup-v1 collector did not measure container peak RAM on this machine.

Tool installation is separate from the job. The script checks that the image is already installed
before starting, uses the local prover with development mode disabled, and removes Bonsai endpoint
settings from its environment. It rejects a host whose compiled guest IDs differ from the snapshot.

```bash
bash zk/risc0/prove-snapshot.sh /path/to/snapshot /path/to/new-proof-output /path/to/bsb-r0 /path/to/risc0-to-bitvm2
```

Each real proof command runs under `/usr/bin/time -v`, recording its resource use and JSON result.
The collector checks those results against the input snapshot, including every holdings journal,
the proven chain tip and work, the term preimage, and the wrapper's public output. It writes
`fixture.json` in the schema the storage graph builder reads. Receipts remain in the output directory;
`g16/` contains the proof, public input and pinned verifying key. A failed command leaves diagnostics
and cannot produce a completed fixture. Output directories are never reused.

## Verify the returned proof locally

Run the independent TypeScript public-input recomputation and the pinned BitVM tool's arkworks
verifier. These require no prover or cloud service on the verifying machine.

```text
node zk/risc0/check-groth16.ts <output>/g16/groth16.json <output>/term.json <snapshot>/hold-170/statement.json <snapshot>/chain/hashes.json
bsb-bitvm-check <output>/g16 --wrong-public 1 --verify-only
```

Only then generate the checked BitVM assertions for this new proof. The verifying-key-specific
partial-script cache can be reused because this job pins the same key; the assertion values and
their one-time signatures must come from the new proof.

```text
bsb-bitvm-check <output>/g16 --wrong-public 1 --assertions-out <new-assertions.json> --assertions-only
```

The job's use of the phase-6 test proving key retains the setup assumptions documented in design
section 4.6. The snapshot and job do not start signet or publish anything.
