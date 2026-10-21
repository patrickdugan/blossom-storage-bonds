# Storage bond graph with BitVM disputes

The phase-6 proof can now sit behind a storage-bond transaction graph rather than a bridge payout.
The graph commits the actual verifying key's 364 Groth16 disprove leaves and the storage-term binding
leaf, using the same fresh Winternitz public-input key in both. Core 31.1 regtest mined all seven
test scenarios: 32 graph transactions and 32 rejected early, missing-input or invalid-script spends.
The evidence is `results/bitvm-storage-graph-regtest.json`.

This run reuses the checked phase-6 Groth16 proof. Its storage roots, epoch seeds, term journal and
header-chain claim remain that fixture's. The graph uses fresh funding UTXOs, fresh one-time keys and
fresh two-party MuSig2 keys. That seven-case fixture run does not generate fresh proofs or provide
a heavier-chain challenge. A separate same-chain lifecycle now registers keys before funding,
generates the chain, holdings, term and Groth16 proofs on a private VPS, verifies them before
signing, and mines the honest graph through its refund. Its evidence is
`results/bitvm-storage-lifecycle-fresh.json` and `bitvm-storage-lifecycle.md`.

## States and enforced transitions

```mermaid
flowchart TD
  F[Funding: committee control] -->|term height| K[Kickoff]
  F -->|kickoff deadline| CT[Client timeout]
  K -->|unchallenged, CSV window| PR[Provider refund]
  K --> C[Challenge: main control plus 381 commitment slots]
  C -->|no complete assertion, CSV deadline| AT[Client recovers control and unused slots]
  C --> A0[Commit group 0: 300 slots]
  C --> A1[Commit group 1: 81 slots]
  C --> AF[Assert final: requires both commit outputs]
  A0 --> AF
  A1 --> AF
  AF --> M[Main collateral control plus proof marker]
  M -->|dispute window passed, both inputs| PR
  M -->|Groth16 or term-binding disprove, both inputs| CS[Fixed client slash payout]
  M -->|absolute fallback deadline| FT[Client recovers control if marker was destroyed]
```

`storage_graph.rs` builds and presigns these transitions. Control outputs require a two-party MuSig2
signature in a Taproot leaf with a NUMS internal key. Every input uses fresh nonce randomness and
SIGHASH_DEFAULT/ALL. The signatures commit both inputs, the payout, fee budget, sequence and locktime.
Changing the slash destination or substituting another marker invalidates the committee signature.

The 381 commitment slots are the Groth16 public input, 14 proof-field values, 363 intermediate hashes,
and the claimed tip's height, hash and work. Each slot also has a NUMS internal key. Its commit leaf
requires both the pinned committee transaction signature and the corresponding Winternitz signature;
there is no provider key-path bypass. Its alternate CSV leaf lets the client recover an unspent slot
if the provider stops. The final assertion consumes the main control output and both commit-group
outputs, so it cannot become live without those on-chain commitments.

After the assertion, slashing consumes two outputs: committee-controlled collateral and a proof
marker containing the real verifier/binding leaves. The committee signature fixes the slash payout
to the client. Spending the marker alone cannot redirect the collateral or enable a provider refund.
An absolute client fallback recovers the main control output if someone destroys the marker; an
honest provider must complete its refund before that fallback deadline.

All committee and one-time keys in the harness are generated inside one local setup process. It
receives the funding transaction's fixed txid, presigns the graph, exports only public transaction
vectors, and exits before the harness broadcasts funding. This exercises actual MuSig2 signatures,
but it is not a distributed committee setup or a live provider's proof-generation lifecycle.

## Fresh Core results

| Scenario | Result |
| --- | --- |
| Provider never kicks off | Early timeout rejected; client receives 99,997,000 sats after the deadline |
| Nobody challenges | Early refund rejected; provider receives 99,994,000 sats after the challenge window |
| Challenged provider stays silent | Client receives 92,314,000 sats from control and 7,470,000 from the slots |
| Honest proof and assertion | Skipped commitment and premature finalization rejected; binding disprove rejected; provider receives 98,431,000 sats after the dispute window |
| Genuine proof for a different term | Binding leaf 364 slashes to the client: 96,434,000 sats; redirected slash rejected |
| Corrupted intermediate, correct storage public input | Real Groth16 leaf 181 (`MillerPointOpsStep2`) slashes to the client: 96,434,000 sats; redirected slash rejected |
| Provider destroys the marker of a bad assertion | Refund cannot spend the missing marker; absolute fallback returns 97,431,000 sats of main control to the client |

The harness funds a 100,000,000-sat regtest pot that includes assertion and dispute fees. It uses
short regtest challenge/assert/dispute windows of 6/12/6 blocks. These are separate from the sentinel
bond's CSV 144. The corrupted-intermediate disprove is 869,174 vB and pays a fixed 2,000,000-sat fee;
the example is about graph enforcement, not fee estimation. The node explicitly enables
`acceptnonstdtxn=1` and raises `limitclustersize` to 2000 kB.

Core readback confirms mining. `graph-payouts.ts` separately decodes the exact transaction bytes,
checks their txids against Core's mined txids, and verifies each terminal output pays the intended
client or provider and recovers the main collateral. The test node shuts down after the run.

## Reproduction with existing local dependencies

Build `zk/bitvm-check` with the pinned lockfile. Native Windows MSVC is supported for these tools;
using `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_DEV_DEBUG=0` keeps generated build artifacts smaller.

```text
cargo build --offline --locked --manifest-path zk/bitvm-check/Cargo.toml --bins
bsb-bitvm-check results/bitvm2-spike-groth16 --wrong-public 1 --cache-partials <new-cache> --cache-only
bsb-bitvm-check results/bitvm2-spike-groth16 --wrong-public 1 --assertions-out <new-assertions.json> --assertions-only
node zk/bitvm-check/graph-regtest.ts --bitcoind <installed-bitcoind> --checker <bsb-storage-graph> --partials <cache> --assertions <assertions.json> --dir <new-datadir> --out <new-results.json>
```

The public verifier cache is about 1.1 GB before optional filesystem compression. It fingerprints the
verifying-key file and every script. Graph construction streams each cached script into a leaf hash
instead of retaining the whole tree's script bodies. An explicit `--resume-cache` regenerates and
compares existing bytes before completing an interrupted cache; different contents are rejected.
The assertions-only step executes the actual unsigned verifier chunks before exporting their public
values. The corrupt-proof case signs fresh assertions, constructs a real disprove witness, and spends
that same keyed leaf on Core.

## Next work

The same-chain fresh proof is now connected to the pre-term setup and term-end signing lifecycle
(`bitvm-storage-lifecycle.md`). Add the heavier-chain challenge so
a valid proof of a private fork cannot stand in for the intended chain. Per-epoch deal updates,
distributed committee setup, fee changes and the production Groth16 ceremony remain separate work.
No signet or public-service pilot has run.

## Cumulative-work fork defense: measured requirements

The selected direction is an exact cumulative-work comparison, not the paper's superblock contest.
The current graph has no leaf implementing that comparison. The experiments below constrain its
design; they do not change the funded graph or establish a completed fork defense.

### Comparison must allow an extension of the original claim

`zk/bitvm-check/fork-work-regtest.ts` starts two isolated Core 31.1 nodes and transfers full blocks
through RPC, without connecting peers. They share blocks through height 169, then disagree at the
first storage seed, height 170. The provider's original branch reaches height 220, work 442, and
extends to height 232, work 466. The other node produces three conflicting candidates:

| Candidate | Work | Core's existing honest tip | Independent header verifier |
| --- | --- | --- | --- |
| Height 221 | 444 | Retained | Retained |
| Height 232 | 466 | Retained | Retained |
| Height 233 | 468 | Replaced | Replaced |

`results/bitvm-cumulative-work-forks.json` contains the raw headers and the observed results. Both
branches are validated from genesis; their computed work matches Core, and both nodes stop cleanly.
Regtest work is free, so this tests the comparison mechanism, not Bitcoin's economic security.

The first case refutes `valid(candidate) && conflicting(candidate, oldClaim) &&
candidate.work > oldClaim.work` as a sufficient slash condition. An honest old claim can have a newer,
stronger extension. Equal work also does not establish that an already selected branch must be
replaced; the experiment records this node's incumbent preference, not a universal tie ordering.

A future comparison certificate needs the exact graph/term identity, original claim and a responding
branch extending that claim. Its positive relation should establish all of the following:

1. Both compared branches have valid header-chain proofs under a pinned image and network genesis.
   Each receipt's journal must also name that image. Derive work from validated targets with checked
   arithmetic; do not accept a separate work number from a caller.
2. An authenticated opening proves that the responding branch contains the original tip at its exact
   height. Bind the original height/hash/work to the same term preimage and one-time commitments
   already consumed by the graph. A response cannot silently switch to an unrelated stronger chain.
3. The candidate has strictly more work than that responding branch. Ties cannot authorize slashing
   solely through this relation. Height is not a substitute for work when difficulty changes.
4. Authenticate a divergent block at a common height at or before at least one scheduled seed.
   When both branches reach that seed, its exact-position openings can establish the difference.
   A shorter but higher-work branch also needs a route: prove divergence at a lower common height,
   rather than require an opening above its tip. A fork occurring only after all seed blocks does
   not invalidate those seed bindings. A broader stale-tip forfeiture policy must be explicit.
5. Public input commits every comparison value, proof image, network and graph identity. The Bitcoin
   path must authenticate those same values, not merely accept an off-chain certificate file.

This is a relation between supplied branches. It cannot certify that no unseen stronger branch
exists. The transaction protocol must define when candidates and responses become fixed, how an
honest observer can submit its stronger chain, what happens if either party is silent, and which
confirmation/censorship assumptions its deadlines require. A provider response alone is not a proof
that its branch is globally strongest. Repeated fresh challenges cannot extend the bond indefinitely;
one-shot commitment keys cannot be reused for successive comparisons. None of these rules is yet
enforced by the present graph's 6/12/6-block regression windows.

### Direct header replay does not fit the tested implementation

`zk/bitvm-check/examples/chain-hash-cost.rs` measures the pinned BitVM revision `7d1ca36` and executes
all four SHA table configurations against the native regtest genesis double hash. Each matches.
The measurements exclude linking, difficulty, timestamps, work arithmetic, authentication, fork
openings and transaction overhead:

| Add table | Full XOR table | Bytes per double hash | Bytes for 33 headers | Maximum stack items |
| --- | --- | ---: | ---: | ---: |
| No | No | 839,589 | 27,706,437 | 516 |
| Yes | No | 722,907 | 23,855,931 | 676 |
| No | Yes | 749,253 | 24,725,349 | 636 |
| Yes | Yes | 632,571 | 20,874,843 | 796 |

`results/bitvm-chain-hash-cost.json` records the executable measurements. Even the smallest tested
33-header hashing program exceeds a Bitcoin block. This rules out that direct single-transaction
implementation, not every possible SHA optimization or a future protocol spanning transactions.

### Remaining enforcement problem

The experimental RISC Zero fork guest now proves the exact relative-work comparison using three
genuine header receipts and authenticated original-tip and divergence openings (see below).
Its certificate still needs a Bitcoin-enforced route to the collateral. The current BitVM graph
optimistically verifies the provider's fixed-key assertion and lets anyone expose a false chunk.
That is different from accepting a new challenger's positive certificate and making it binding.

Before adding a slash leaf, specify and test how the candidate, responding branch, public input and
execution trace become authenticated across the presigned transactions. An off-chain Groth16 check
does not supply this binding. A second optimistic assertion with newly chosen challenger keys needs
its own graph and a sound way to bind those keys to the collateral. Requiring the original client to
hold all challenger commitment secrets would add a designated online role; revealing those secrets
would allow forged intermediate assertions. Neither is an implementation of permissionless defense.

The next protocol experiment should demonstrate that binding with a small exact comparison program
before paying to generate another full Groth16 verifier tree. Its Core tests must reject substituted
candidate/response data, unrelated response branches, invented work, equal-work slashes, stale
comparison replay and redirected payouts, while preserving an honest provider's extension response
and permitting an observer who did not participate in setup to challenge.

For context, the [BitVM2 paper](https://bitvm.org/bitvm_bridge.pdf) uses a timed superblock contest;
the pinned `bridge/src/connectors/connector_b.rs` leaf compares an individual candidate header hash
with the operator's committed superblock hash. That path is not an exact cumulative-work verifier.
[BitVM2's description](https://bitvm.org/bitvm2) distinguishes permissionless fraud challenges from
the earlier fixed-verifier design. These are relevant design constraints, not missing code that can
be enabled by renaming a connector. Core's [v31.1 mining RPC source](https://github.com/bitcoin/bitcoin/blob/v31.1/src/rpc/mining.cpp)
also explains why `submitblock` may return `inconclusive` for a stored side branch; the harness checks
header readback and eventual actual tip adoption rather than treating that status as an invalid block.

Reproduce with the already installed dependencies:

```text
cargo run --offline --locked --manifest-path zk/bitvm-check/Cargo.toml --example chain-hash-cost
node zk/bitvm-check/fork-work-regtest.ts --bitcoind <installed-bitcoind> --dir <new-data-dir> --out <new-report.json>
```

### Input-binding experiments on Core

`zk/bitvm-check/input-binding-regtest.ts` and the Rust `input-binding` example test three small
designs on isolated Core 31.1. These deliberately use a scalar inequality and arbitrary 32-byte
tags; they do not verify headers or ZK proofs. The ephemeral presigner exits before funding is
broadcast, and the harness chooses its arbitrary tags only afterwards.

* Ordinary witness data: a parent announces `(444, tag A)`, but its child can supply `(468, tag B)`
  and satisfy the local `work > 466` check. Core mines both transactions. Both parent witness
  variants have the same txid and different wtxids; signing the descendant's parent outpoint does
  not authenticate the parent's ordinary witness. This reproduces a missing binding in the toy
  design, not a vulnerability in the existing WOTS-bound storage graph.
* Fixed commitment control: both scripts require the setup's `(468, fixed tag)`. Core mines the
  matching parent and response; changed tags, changed work and a redirected payout are rejected.
  This control binds input correctly, but fixes the input before the challenger observes a fork.
* Output commitment: changing a presigned parent's data output changes its txid and invalidates
  its signature. An independently presigned alternative parent can be mined, but its old descendant
  has missing inputs; rewiring that descendant to the alternative parent invalidates its signature.

`results/bitvm-input-binding.json` records five mined transactions, nine rejected spends and the
actual public transaction bytes. The node stops cleanly. These results rule out these unbound
shortcuts; they do not prove that every permissionless input-binding construction is impossible.
The relevant [Taproot signature rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
commit transaction data and spending context; they do not make a child's outpoint identify a unique
parent witness. [BitVMX's message linking](https://bitvmx.org/knowledge/bitvmx-a-cpu-for-universal-computation-on-bitcoin)
instead uses one-time keys fixed during setup. Its two-party construction is useful context, but
does not by itself supply an after-setup challenger's positive certificate path for this graph.

```text
cargo build --offline --locked --manifest-path zk/bitvm-check/Cargo.toml --example input-binding
node zk/bitvm-check/input-binding-regtest.ts --bitcoind <installed-bitcoind> --checker <input-binding-example> --dir <new-data-dir> --out <new-report.json>
```

### Relative-work certificate and Groth16 wrap

The experimental `methods/fork` guest now proves the relative comparison using three authenticated
header-chain receipts: the original claim, its responding extension, and the competing candidate.
It pins the regtest header image and genesis, checks each MMR's shape and tip, checks the original
tip's exact-position membership in the response, and authenticates a divergent block at or before
a selected storage seed. Its work comparison is a strict comparison of the receipts' big-endian
256-bit cumulative work. The 202-byte term preimage must name that original tip, hash and work.

The certificate commits a 354-byte statement: domain, graph identifier, term-journal digest, the
three height/hash/work triples, epoch index, divergence height, and the two divergent block hashes.
The guest's 32-byte journal is SHA256 of those bytes. `fork_relation.rs` defines the layout;
`check_fork_research.py` independently reconstructs it from the full header files and validates
regtest linking, difficulty, PoW, version and median-time rules. Receipt verification is a separate,
explicit operation of that checker. `check-fork-public.ts` independently recomputes the wrapper's
SHA256/BLAKE3 public input, including the new guest image rather than the holdings or term image.

The VPS job proved the captured experiment's work values `442 < 466 < 468`, and wrapped the
certificate using the existing pinned Groth16 image and verifying key:

* Fork image: `8cf297b91e31b0ee52b57c876888f120416950ab3e7169d26c7315751da39457`.
* Certificate journal: `d78d19d832272aafd9def1236f0c636af020de106ad7ef2e9e2cc75eac40209c`.
* Groth16 public input: `331922694518165887603772562130688070796909051370644513024791622746851652422`.

The certificate evidence is `results/bitvm-cumulative-work-certificate.json`; its Groth16 proof,
public input and verifying key are in `results/bitvm-cumulative-work-groth16/`.

The existing holdings, term and header-chain image IDs remain unchanged. Seven native relation
tests and nine compiled-guest/prover rejection cases cover malformed bindings and invented work.
Independent readback has sixteen checks, including actual receipt verification and rejection of
changed receipt bytes. The native pairing checker accepts the new Groth16 proof and rejects a
replayed storage proof, a changed guest image and a changed graph identity.

This dataset uses the two-node fork experiment and a synthetic graph identifier. It generates no
holdings proof for those experimental branches and attaches no comparison to a funded bond. The
certificate proves a relationship between supplied branches; the challenge/response timing and
collateral-spending protocol described above remain implementation work. The original same-chain
funded storage proof remains the separate lifecycle milestone.

Reproduce with the existing pinned tools. Run the heavy proving commands on a suitable machine;
the recipe starts no Bitcoin node, signer or downloader:

```text
node zk/risc0/prepare-fork-inputs.mjs . <new-input-dir>
bash zk/risc0/build-pinned.sh <installed-cargo> <populated-guest-cargo-home> <new-wrapper-dir>
bash zk/risc0/prove-fork-research.sh <input-dir> <new-proof-dir> <bsb-r0> <pinned-regtest-header-elf>
python3 zk/risc0/check_fork_research.py <input-dir> <proof-dir> --receipt-verifier <bsb-r0>
python3 zk/risc0/check_fork_research_test.py --inputs <input-dir> --output <proof-dir> --receipt-verifier <bsb-r0>
bsb-r0 groth16-fork <proof-dir>/fork.bin <new-g16-dir>
```

`groth16-fork` requires the fork image and an already installed pinned Docker image, and refuses
an existing output directory. The original `groth16` command continues to require the term image.
Copy the pinned `results/bitvm2-spike-groth16/vk.json` into the new Groth16 directory, save the
independent readback result, then check the public input and pairings:

```text
node zk/risc0/check-fork-public.ts --g16 <g16-dir> --readback <readback.json> --out <new-public-report.json>
node zk/risc0/fork-public-guards.ts --g16 <g16-dir> --statement <proof-dir>/fork.bin.statement.bin --checker <bsb-bitvm-check> --dir <new-guard-dir> --out <new-guard-report.json>
bsb-bitvm-check <g16-dir> --wrong-public 1 --out <new-full-check.json> --assertions-out <new-assertions.json>
```

The final command executes the full BitVM verifier and its disprove checks. Its public one-time
test keys are suitable for interpreter experiments. A transaction graph needs its own authenticated
commitments and signatures before any of these checks can control collateral.
