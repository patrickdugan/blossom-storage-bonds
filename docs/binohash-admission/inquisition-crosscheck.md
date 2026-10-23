# ADR-018: Bitcoin Inquisition cross-check of the OP_CAT verifier

Date: 2026-10-23. Status: done. This closes ADR-016's open item 6, the fidelity of the local patch.

## Method

`research/inquisition-check/run.sh` does four things:
1. Clones Bitcoin Inquisition at tag `v29.4-inq` (commit `3db09a1b5821b049af295091055c39e0f80846c7`; the script checks it).
2. Builds only its `bitcoin_consensus`, `bitcoin_util`, `bitcoin_crypto` and `secp256k1` libraries.
3. Links `inq_check.cpp` against them. That program calls Inquisition's own `VerifyScript` with Taproot consensus flags and a `PrecomputedTransactionData` built from every spent output.
4. Runs it in two modes:
   - **`cat`** adds `SCRIPT_VERIFY_OP_CAT`, Inquisition's BIP347 deployment flag. It must reproduce `bip347_valid`, our local patch.
   - **`nocat`** omits the flag, so 0x7e stays OP_SUCCESS126. It must reproduce `core_valid`, stock Bitcoin Core 26.

Inquisition's OP_CAT handler, at `src/script/interpreter.cpp` around line 588, matches `research/bip347-check/bip347.patch` exactly: the same stack check, the same 520-byte `SCRIPT_ERR_PUSH_SIZE`, and the same concatenation. The patch differs only in enabling OP_CAT unconditionally, where Inquisition uses a flag.

## Results (local WSL Ubuntu 24.04 run)

| Vectors | Inquisition mode | Cases | Mismatches | Consensus-valid counterexamples |
| --- | --- | --- | --- | --- |
| ADR-015 | no OP_CAT flag | 16 | 0 | 5 (equals stock Core 26) |
| ADR-016/017 | no OP_CAT flag | 25 | 0 | 11 (equals stock Core 26) |
| ADR-016/017 | `SCRIPT_VERIFY_OP_CAT` | 25 | 0 | 0 (equals the BIP347 patch) |

Inquisition's error strings show that each rejected case fails at the intended check, not by accident:
- `broken_link`, `different_nbits`, `forged_hash_limbs`, `shifted_fields` and `wrong_checkpoint` fail OP_EQUALVERIFY, at limb or size binding.
- `under_target_header` fails OP_VERIFY, at the target range.
- `claim_length_only`, `refute_claim5_with_5` and `empty_witness` fail on stack size, because the leaf needs exactly N headers.
- `one_extra_header` fails the clean-stack rule.
- `redirect_output0`, the freeze attacks and `provider_uses_forfeit_leaf` fail as an invalid Schnorr signature.
- `freeze_without_setup_signature` finishes with a false top element.
- The early forfeit and early refund fail the locktime requirement.

## What this changes

The ADR-016/017 verifier and freeze graph are enforced by Inquisition's own consensus code wherever its BIP347 deployment is active. They are anyone-can-spend wherever it isn't. From Inquisition's source (`src/binana.py`, `src/binana/op_cat.json`):
- **Regtest:** OP_CAT is always active, and consensus then applies `SCRIPT_VERIFY_OP_CAT`, the flag the `cat` mode uses.
- **Signet:** OP_CAT is a heretical deployment (start 2024-01-01, timeout 2034, period 432). Its live status was not observed, since no signet node was run.

On Bitcoin mainnet BIP347 is not active, so the review's verdict stays **BLOCKED**, and the single missing primitive is BIP347 activation.

## Reproduce

```bash
bash research/inquisition-check/run.sh /tmp/adr015.json /tmp/adr016.json /tmp/inq-work
```

Generate the two JSON files first, as in ADR-015 and ADR-016. The script needs cmake, g++, the Boost headers and node. It downloads the Inquisition source at the pinned tag.
