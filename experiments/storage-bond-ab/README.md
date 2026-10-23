# Storage-bond A/B: parallel implementations

**Status: executable research prototype.** Funded Bitcoin, real FROST signatures,
Filecoin consensus proofs and live testnet claims are outside this model. The
separate Bitcoin Core receipt observer is implemented for future signet/testnet4
runs, and it cannot prove that a storage verdict was economically legitimate.

This work stays on the research branch and [draft PR #5](https://github.com/patrickdugan/blossom-storage-bonds/pull/5).
The original Phase 1 sentinel regtest source under `regtest/` and the
permissionless Binohash research PR #1 remain untouched.

## Implementation folders

| Path | Purpose | What is actually executed |
| --- | --- | --- |
| `shared/scenario.mjs` | One fixture, deal terms, consistent data bytes, epochs and Merkle challenges | Original `model/storage_bonds.ts` SHA256 tree, encrypted replicas, sampling and sentinel preimages |
| `a-sentinel/adapter.mjs` | Independently collateralized client/provider bonds | Original `challengeLeaf`, `respondLeaf`, `forfeitLeaf`, `refundLeaf` plus reference Script interpreter and BIP340 test signatures |
| `b-layertree/adapter.mjs` | One pooled 100,000-sat carrier, FROST-like refresh and adjudication | Existing `model/layertree_bond_overlay.mjs` state machine and mock quorum labels |
| `run.mjs` | Identical events to both, JSON trace and CSV table | Deterministic orchestration, no external services |
| `testnet/observe.mjs` | Read-only on-chain evidence collector | Bitcoin Core full-node RPC active-chain check, raw tx wtxid, input/output set, fees, vsize |
| `testnet/observe.test.mjs` | Adversarial receipt regressions | Fake RPC data, deliberately malformed and replayed receipts |
| `CLAUDE_CODEX_HANDOFF.md` | Independent implementation jobs and merge gates | Instructions only |

The modules import each other only through `shared/` and the existing reference
model. Their own state/settlement engines remain separate. This makes it possible
to replace adapter A with real Taproot transactions and adapter B with actual
pinned Sapio/SaplingOS LayerTree/FROST transaction construction without changing
the test stimuli or comparison output format.

## Run the four baseline cases

Requires Node 22.18+ (native TypeScript type stripping for the existing reference
modules). No npm installation is necessary.

```bash
node --test model/layertree_bond_overlay.test.mjs \
  experiments/storage-bond-ab/run.test.mjs \
  experiments/storage-bond-ab/testnet/observe.test.mjs

node experiments/storage-bond-ab/run.mjs --out /tmp/storage-bond-ab
node experiments/storage-bond-ab/run.mjs --scenario false-fault
```

The output directory must be new: the runner creates every file exclusively and
refuses to overwrite an earlier transcript. Outputs are `storage-fault.json`,
`healthy.json`, `false-fault.json`, `quorum-outage.json` and
`comparison.csv`.

All scenarios begin with Alice's 60,000 and Bob's 40,000 satoshis. The common
Blossom storage evidence is generated from eight encrypted 4-KiB chunks per
participant with four sampled Merkle openings per proof epoch. When data is
deleted, the deterministic nonce is chosen so the sample *actually includes*
the missing sentinel chunk. The two backends see the same Merkle evidence,
source root, nonce and fault outcome.

| Case | A sentinel expected | B federation expected |
| --- | --- | --- |
| Storage-fault | Alice forfeits after six modeled blocks; Bob refunds after full service | Quorum accepts real fault, pays Alice and refunds Bob |
| Healthy | Both providers refund after the completed proof term | Both settle by modeled quorum approval |
| False-fault | A valid Blossom proof defeats fabricated fault; no Alice forfeiture | Two fake quorum labels authorize a dishonest Alice fault and payout |
| Quorum-outage | Independent Script paths remain usable in the model | All refresh, observation and settlement requests fail with insufficient mock votes |

### Boundaries of this comparison

A's Script interpreter checks its precise reference branches, but signatures
use a **stand-in** transaction sighash. It does not prove Bitcoin Core accepted
the transaction, key-path exclusions, presigning key erasure or actual
beneficiary scripts. The unilateral claimant authorizes the economic
disposition and can choose another output.

B's signatures are **string labels** `f1`, `f2`, `f3`. A model-approved
transition provides no cryptographic guarantee that Bitcoin enforces a
Filecoin/Blossom verdict, output amount or refresh rule. A quorum can
authenticate a fabricated claim or censor claims altogether.

The CSV keeps A's illustrative historical regtest vbyte estimates separate
from B's **unknown** Bitcoin transaction sizes. Both candidates have
`actual_testnet_confirmations` unpopulated. There is no aggregate safety
score or statistically meaningful speed winner from these model runs.

## Testnet evidence route

`testnet/observe.mjs` is deliberately read-only and permits only
`signet` and `testnet4`. Supply a JSON manifest with independently saved
signed txids **and wtxids**, exact previous outputs and all output amounts and
scripts. It checks the full raw witness transaction hash, an active-chain
block at the configured depth, every spent input, every signed output,
Bitcoin Core-reported vsize, and realized fees through parent transaction
outputs. It can never sign, broadcast or transfer funds.

```bash
node experiments/storage-bond-ab/testnet/observe.mjs \
  --manifest /private/A-sentinel-signet.json \
  --bitcoin-cli /absolute/path/to/bitcoin-cli \
  --datadir /private/bitcoin \
  --out /private/observed-A.json
```

Bitcoin Core must be a trusted, fully synchronized signet or testnet4 node
with `txindex=1`. The receipts disclose which network and endpoint were
checked and explicitly set the storage-verdict, FROST and independent
Bitcoin-consensus reimplementation claims to `false`. The observer refuses
mainnet and regtest (which should use their own isolated test runners).

See [testnet/MANIFEST.md](testnet/MANIFEST.md) for a reviewable manifest,
and [CLAUDE_CODEX_HANDOFF.md](CLAUDE_CODEX_HANDOFF.md) for the staged signet
test plan and agent division.

## Architecture invariants

Economic principal is conserved through refreshes and terminal settlements;
historical `(provider, nonce)` identities cannot be recycled. The
federated candidate's current carrier outpoint must be spent exactly once,
and the independent payout terms must remain fixed. A fresh Sapio MID
integration should consume those terms from a separately pinned file,
validate *actual* BIP341 transaction witnesses, and reproduce both the
quorum-abuse and unilateral-exit failure cases.

The trust-model difference itself is the A/B research outcome worth measuring.
Treat acceptance of a false-fault with a dishonest quorum as a **failure** of
the federated security claim, even if its final satoshi accounting balances.
