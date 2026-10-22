# ADR-003: One-hop protected cursor with a composite Binohash input

**Status:** Unfunded Bitcoin Script experiment. Recursive authorization, exact-work proof, cutoff enforcement and collateral settlement remain unsolved.

## Construction

For one **known, signed** cursor outpoint, SIGHASH_SINGLE | ANYONECANPAY (0x83) can fix the amount and locking script of the output at the same index as the signed input. Other inputs and output slots remain available to an unrelated challenger.

The experiment combines that signature with an independently ground toy Binohash signature on another input.

| Input | Role | Output |
| --- | --- | --- |
| 0 | Challenger's arbitrary fee input | 0: OP_RETURN with certificate digest |
| 1 | Cursor P2PK, pre-signed SINGLE|ACP | 1: required successor script and fixed amount |
| 2 | Legacy Binohash carrier, freshly ground | No output 2, retaining the legacy SINGLE dummy-signature bug |

Input 1 constrains the one-step transition destination. Input 2 signs the submitted certificate digest, both prevouts, and both outputs. The carrier uses public toy secrets and tiny parameters that provide no practical collision resistance.

## Expected consensus-level observations

- Honest challenger A: both Script inputs valid.
- Honest challenger B with a different certificate: both inputs valid, with a new Binohash signature and **the same cursor pre-signature**.
- Certificate changed without regrinding Binohash: cursor input valid, carrier input invalid.
- Regrind Binohash for a transaction burning the successor: carrier input valid, cursor input invalid.
- Regrind to reduce the protected successor amount: carrier input valid, cursor input invalid.
- Change an unrelated fee input, then regrind: both inputs valid.
- Change the actual cursor prevout without new signatures: both inputs invalid.
- Pre-sign the second generation against A's parent txid, then substitute B's parent txid: the second-generation cursor signature fails.

These outcomes are checked by model/composite_cursor_consensus_vectors.mjs, model/composite_cursor_consensus_vectors.test.mjs, and a vendored Bitcoin Core 26 libbitcoinconsensus harness. The harness checks supplied Script inputs, not the full Bitcoin UTXO set, relay policy, or mined transactions.

## The recursive-admission blocker

The certificate output is a signed transaction field for the Binohash carrier and changes the resulting txid. Therefore, the next cursor's outpoint depends on which certificate was submitted. A pre-signature made for the next cursor created by certificate A cannot authorize the next cursor created by certificate B.

Publishing the provider's signing secret would let challengers redirect output 1. Requiring an online provider to sign each update would let the defendant suppress stronger challengers by refusing to cooperate.

The present construction gives a *real one-hop output guard*, but does not establish a permissionless self-replicating successor covenant.

## Remaining acceptance tests

1. Challenger A spends known J0 to J1(A), preserving script and value.
2. Unknown challenger B, with no provider signature after setup, spends actual J1(A) to a successor J2(A,B), enforcing exact work and output authorization.
3. Neither challenger may burn the cursor or seize its protected amount.
4. The provider must answer the actual certificate; any provider exit must be blocked by unresolved stronger timely challenges.
5. A certificate included in the final admission block remains actionable across a full response period.

The Phase 7 local commit 4494714 and its 151-header six-transaction fixture are not on the accessible GitHub remote, so the original consensus integration remains outstanding.

## Other limitations

- These scripts accept arbitrary 32-byte certificate commitments: no authentic Bitcoin header chain or cumulative-work comparison is checked.
- They do not validate the certificate's historical Bitcoin inclusion height or resolve the admission/freeze race.
- Legacy SIGHASH does not bind unrelated SegWit witness data.
- Any old provider-only timelocked refund script is an independent escape unless it is replaced throughout the real bond.
- Production Binohash needs costly grinding and access to miners willing to include its nonstandard bare Script. Mining and pilot tests remain deferred.

## Reproduce

Run Node 22+ model regressions with: node --test model/*.test.mjs

Generate composites with: node model/composite_cursor_consensus_vectors.mjs > /tmp/bsb-composite.json

Then verify both inputs with: cargo run --release --manifest-path research/consensus-check/Cargo.toml < /tmp/bsb-composite.json

No Bitcoin node, funded UTXO, mining or proof job is invoked.
