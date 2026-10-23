# ADR-017: dynamic frozen claims through a presigned freeze set

Date: 2026-10-23. Status: experiment done. This closes ADR-016's open item 3 for an enumerated claim range.

## Problem

In ADR-016 the claim N−1 is fixed at funding. A provider should be able to freeze its claim at the cutoff without leaving any exit open to itself.

## Construction

The vectors are the `F/*` cases of `bsb-cat-verifier-vectors`.

**Bond B** has two leaves:
- **Freeze:** `<provider> CHECKSIGVERIFY <setup> CHECKSIG`. For each claim k in the range ({3, 5, 7} here), setup presigns one transaction freeze_k with SIGHASH_DEFAULT, paying the whole bond to F_k. At the cutoff the provider adds its signature to the freeze_k it chooses.
- **Forfeit:** `<T_FREEZE> CLTV DROP <client> CHECKSIG`. A provider that never freezes forfeits.

**Each F_k** has two leaves:
- the ADR-016 OP_CAT refutation leaf for exactly k+1 headers, with the SINGLE|ANYONECANPAY payout to the client;
- the refund `<T_DEADLINE> CLTV DROP <provider> CHECKSIG`.

The provider has no exit from B except a presigned freeze. It has no exit from F_k before the deadline.

## Results

25 cases are in the vector file. These 12 are the new `F/*` ones, and they agree across the generator, `model/verify_cat_vectors.mjs` (template, nLockTime and header-chain rules from the bytes) and Core 26 + BIP347:

| Case | Core 26 + BIP347 | Design |
| --- | --- | --- |
| freeze_claim5_honest | valid | ok |
| freeze_unlisted_claim (claim 4) | invalid | forbidden |
| freeze_redirect_to_provider | invalid | forbidden |
| freeze_without_setup_signature | invalid | forbidden |
| no_freeze_forfeit_at_t_freeze | valid | ok |
| no_freeze_forfeit_early | invalid | forbidden |
| provider_uses_forfeit_leaf | invalid | forbidden |
| refute_claim5_with_6 | valid | ok |
| refute_claim5_with_5 | invalid | forbidden |
| refute_claim5_with_prefix_of_9 | valid | ok (any longer fork refutes through its prefix) |
| refund_claim5_at_deadline | valid | ok |
| refund_claim5_early | invalid | forbidden |

On stock Core 26 the refutation leaves are OP_SUCCESS, so `refute_claim5_with_5` is a consensus-valid counterexample. That makes 11 for the whole file. The non-CAT leaves behave the same on both interpreters.

The vector file's SHA-256 is `2ef161399c505caaadef5e18ff41da4457184f8f7633d9d2015b0ffde5544954` (deterministic).

## Limits

1. **Finite claim set.** The claim set is fixed at setup. Lean's `fixed_graph_misses` says this must be so without a covenant. A claim outside the range can't be frozen, so the provider must pick a range that covers it. An honest provider with a claim above the range cannot freeze at all, and forfeits.
2. **Setup key and pre-deadline races.** Setup key erasure (A5) now also guards the freeze. After the deadline, refute and refund race (A4, `late_refutation_can_lose`): Bitcoin has no "valid before height h" timelock, so no leaf can give the refutation an absolute end.
3. **Timeliness and retargets** remain open (ADR-016 items 2 and 4).
