# ADR-015: the Script capability boundary for certificate admission

Date: 2026-10-23. Status: accepted as a research finding. The protocol target stays **BLOCKED**.

## Question

Can a funded Taproot output, using only what Bitcoin Core 26 consensus enforces today, do both of these?

1. Admit a stronger-fork certificate unknown at setup. The certificate is a header chain from a checkpoint, with exact cumulative work.
2. Bind the verdict to who receives the collateral.

## Evidence

The generator is `regtest/src/bin/admission_vectors.rs` (`bsb-admission-vectors`). It writes 16 real P2TR script-path spends of fabricated outpoints, built with rust-bitcoin 0.32.7.

Two independent checks follow:
- `model/verify_admission_vectors.mjs` parses the serialized bytes and recomputes each design verdict.
- `research/consensus-check/src/bin/tapscript-vectors.rs` runs Bitcoin Core 26 `libbitcoinconsensus`. It passes every spent output, which turns on `VERIFY_TAPROOT`.

The headers are the real Bitcoin genesis and block 1 headers.

| Case | Core 26 | Design verdict | What it shows |
| --- | --- | --- | --- |
| L1/honest_block1 | valid | ok | control |
| **L1/forged_prev_field** | **valid** | **forbidden** | Without OP_CAT a header is an opaque item: the leaf can hash it but can't read its prev-hash field, so an unlinked header passes as linked |
| **L1/arbitrary_80_bytes** | **valid** | **forbidden** | the same flaw, with garbage in place of a header |
| L2/control_hash_only | valid | ok | HASH256 of a header and its 32-byte size check work |
| L2/honest_genesis_pow | invalid | ok | `OP_LESSTHAN` on a 32-byte hash is a script-number error: no 256-bit target check, even for the real genesis header |
| L3/honest_cat_link | valid | ok | valid only because 0x7e is OP_SUCCESS126 |
| **L3/empty_witness_redirect** | **valid** | **forbidden** | any leaf containing OP_CAT is anyone-can-spend today (BIP342) |
| L4/challenger_claims | valid | ok | a sound check of a certificate fixed at setup |
| **L4/witness_copied_redirect** | **valid** | **forbidden** | the verdict binds no output, so a copied witness takes the bond |
| L4/invalid_certificate | invalid | forbidden | control |
| L5/presigned_payout | valid | ok | a setup key's SINGLE\|ANYONECANPAY signature fixes output 0 (BitVM2 disprove shape) |
| L5/redirect_output0 | invalid | forbidden | the binding holds |
| L5/sponsor_adds_fee_input | valid | ok | a challenger may add fee inputs and outputs |
| L5/new_certificate_after_setup | invalid | **should be admitted** | admission is limited to certificates enumerated at setup |
| **L6/hidden_leaf_drains** | **valid** | **forbidden** | one unaudited leaf beside L5 drains the output |
| L6/audited_leaf_still_bound | invalid | forbidden | control |

Summary: 16 cases, 0 mismatches with Core, 5 consensus-valid counterexamples (in bold). A sixth case, L5/new_certificate_after_setup, is a completeness failure rather than a counterexample.

## Decision

1. Treat **OP_CAT (BIP347)** as the smallest missing primitive for a single-transaction certificate verifier. With native `OP_SHA256` it can:
   - rebuild each header from its witness parts, which links the headers;
   - re-bind a split hash, so its limbs can be compared with a target.

   L1 and L2 are the minimal counterexamples without it. L3 shows that deploying a CAT leaf today would be catastrophic, not just inert.
2. Bind payouts with a setup-presigned SINGLE|ANYONECANPAY signature (L5). That brings in key erasure (A5 in `formal/CertificateAdmission.lean`) and a committee for the setup key. The alternative is a CAT-based covenant once CAT exists.
3. Select **stateless existential refutation** (ADR-002) over the mutable journal (ADR-001). The journal additionally needs a successor-output covenant that carries dynamic state. A fixed graph cannot provide one (`fixed_graph_misses`), while the stateless design needs no successor state at all.
4. Each audit must enumerate every Taproot leaf and the keypath (L6, `hidden_path_breaks_safety`).

## Consequences

- The Lean refutation game (`client_safety`, `provider_safety`, `provider_liveness`) is conditional on hypothesis A2, "a sound and complete refutation leaf". Bitcoin Core 26 refutes A2 as realisable (L1–L3). Those theorems are **not** a proof that the deployed bond is safe.
- Permissionless admission without a soft fork reduces to two options:
  - one non-standard transaction doing limb-arithmetic SHA256 (size not measured here);
  - a permissioned set of committers fixed at setup (`outsider_exists`), as Clementine does with watchtowers.

## Reproduce

```bash
RUSTUP_TOOLCHAIN=stable cargo run --locked --release --manifest-path regtest/Cargo.toml --bin bsb-admission-vectors > /tmp/adr015.json
node model/verify_admission_vectors.mjs /tmp/adr015.json
cargo run --release --manifest-path research/consensus-check/Cargo.toml --bin tapscript-vectors < /tmp/adr015.json
```

The vector file is deterministic. Its SHA-256 at this commit is `cf3cf423e3304669d62d4209e6270f3fb94096bca81e195cbf364c16ff87983c`.

The Core checker was built on Linux (WSL Ubuntu 24.04, as in CI). On Windows MSVC, the vendored C++ library failed to link (LNK1120).
