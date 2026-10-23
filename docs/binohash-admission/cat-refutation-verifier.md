# ADR-016: a one-transaction OP_CAT refutation verifier, checked against a BIP347 interpreter

Date: 2026-10-23. Status: experiment done. The protocol target stays **BLOCKED**, but only on BIP347 activation for the scoped construction below.

## What was built

`regtest/src/bin/cat_verifier_vectors.rs` (`bsb-cat-verifier-vectors`) is the ADR-015 §7 experiment. It refutes a provider claim frozen at funding: "no fork from the checkpoint has more than N−1 headers' work". The refutation is one tapscript leaf.

**Setup signature.** The leaf opens with `<setup key> CHECKSIGVERIFY`. A SIGHASH_SINGLE|ANYONECANPAY signature, presigned at setup, binds output 0 to the client. Anyone may add fee inputs and outputs.

**For each of exactly N headers, starting from the regtest genesis hash:**
1. Rebuild the header with OP_CAT as `version(4) ‖ prev ‖ merkle+time(36) ‖ 0x207fffff ‖ nonce(4)`. Every field size is checked, and the leaf writes nBits itself.
2. Compute `HASH256`, and re-bind it to the witness split `lo(29) ‖ hi(3)` with OP_CAT.
3. Require `0 ≤ hi < 0x7fffff`. That is strictly under the regtest target.
4. Carry the hash on as the next header's prev.

The headers are really mined on Bitcoin's regtest genesis (`0f9188f1…2206`), and rust-bitcoin's `Header::validate_pow` accepts each honest one.

## The interpreter

`research/bip347-check/bip347.patch` makes three hunks of change to the vendored Bitcoin Core 26 `interpreter.cpp`, following BIP347:
1. OP_CAT is no longer a disabled opcode in tapscript.
2. OP_CAT pops x1 and x2 and pushes x1‖x2, failing above `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes).
3. 0x7e is no longer OP_SUCCESS126.

`prepare.sh` copies the exact registry crate (`bitcoinconsensus 0.106.0+26.0`) and applies the patch. `research/bip347-check` links the shared checker (`research/consensus-check/src/tapscript_check.rs`) against the result.

**This is a local research build, not activated consensus**, and it was not cross-checked against Bitcoin Inquisition.

## Results

There are 13 cases, and three verdict sources agree on every one:
- the generator's label;
- `model/verify_cat_vectors.mjs`, which recomputes the chain with the real 256-bit regtest PoW rule;
- Core 26 with the patch.

| Case | Stock Core 26 | Core 26 + BIP347 | Design verdict |
| --- | --- | --- | --- |
| N8/honest_stronger_fork | valid | **valid** | ok |
| N151/honest_stronger_fork (19,428 WU, vsize 4,857, 756 witness items, 6,713-byte leaf) | valid | **valid** | ok |
| N8/claim_length_only (N−1 headers) | valid | invalid | forbidden |
| N8/one_extra_header (N+1) | valid | invalid | forbidden (the leaf is exact-N) |
| N8/broken_link | valid | invalid | forbidden |
| N8/under_target_header | valid | invalid | forbidden |
| N8/different_nbits | valid | invalid | forbidden |
| N8/forged_hash_limbs | valid | invalid | forbidden |
| N8/shifted_fields | valid | invalid | forbidden |
| N8/wrong_checkpoint | valid | invalid | forbidden |
| N8/redirect_output0 | valid | invalid | forbidden |
| N8/sponsor_adds_fee_input | valid | **valid** | ok |
| N8/empty_witness | valid | invalid | forbidden |

Stock Core shows 10 consensus-valid counterexamples: today every attack is anyone-can-spend. The patched build shows 0, and both honest refutations pass.

At N = 151 the spend is about 5% of the 400,000 WU standard limit. Stack items stay within the 80-byte standard size, though relay policy would still reject OP_SUCCESS/CAT before activation.

The vector file's SHA-256 is `c314475f4b7450dd439506e241ffc1f2575871b50dcb9a6c1f3c881ccdf7fca4` (deterministic).

## What this establishes, and what it doesn't

**Established (BIP347 build):** a fixed tapscript leaf can permissionlessly accept any stronger fork of a fixed-difficulty chain, unknown at setup, from any challenger. It rejects every attack class above, and the verdict is bound to the payout. Lean's `exactN_leaf_sound` connects this acceptance to hypothesis A2 (soundness) of `formal/CertificateAdmission.lean`.

**Not established:**
1. **Activation.** BIP347 is not active on Bitcoin, so the result is a patched-interpreter result. On real Bitcoin today the same output is anyone-can-spend (stock column).
2. **Retargeting.** Mainnet work per header varies. Exact 256-bit cumulative work needs bigint limb arithmetic in Script, or per-period targets fixed at setup. Neither is built.
3. **Dynamic frozen claims.** N is fixed at funding. A claim chosen at cutoff needs either a presigned leaf per claim value or a covenant.
4. **Timeliness.** The leaf doesn't prove the fork existed by the cutoff. That needs BIP141 inclusion of the certificate before the cutoff, or timestamp rules; A1's timeliness is still a premise. Header timestamps and median-time-past are not checked.
5. **Payout key.** The payout binding still relies on A5 (setup key erasure). A CAT-based covenant could remove it, and isn't built.
6. **Fidelity.** The patch has not been compared with Bitcoin Inquisition's implementation.

## Reproduce

```bash
cargo run --locked --release --manifest-path regtest/Cargo.toml --bin bsb-cat-verifier-vectors > /tmp/adr016.json
node model/verify_cat_vectors.mjs /tmp/adr016.json
cargo run --release --manifest-path research/consensus-check/Cargo.toml --bin tapscript-vectors < /tmp/adr016.json
bash research/bip347-check/prepare.sh
cargo run --release --manifest-path research/bip347-check/Cargo.toml < /tmp/adr016.json
```

Build the Core checkers on Linux: MSVC fails to link the vendored C++ library (LNK1120).
