# Phase 7C research extension: BitVM2 pooled storage bonds under a 1-of-n honest setup

Status: evaluated from existing evidence. **This does not block the product track.** The pilot
(`docs/pilot/readiness-report.md`) uses per-deal sentinel bonds, which need nothing beyond current
Bitcoin consensus.

## Question

Can BitVM2's permissionless challenge, under a setup that needs only 1 of n honest signers, publicly
adjudicate one pooled bond that backs many Blossom deals?

## What BitVM2 gives, and what it costs (measured in phase 6, design §4.6)

The construction is an operator assertion with a permissionless disprove. The provider is the
operator. At the end of the term it asserts its term proof: a RISC Zero proof of the holdings
statement over every epoch, bound to the header chain, then wrapped in Groth16. Anyone can spend the
disprove connector by showing that one chunk of the asserted verifier computation is wrong. The
presigned graph needs only 1 of the n setup signers to have deleted its key (A5, 1-of-n).

| Item | Phase 6 measurement |
| --- | --- |
| Disprove scripts for one Groth16 key | 364 tapscripts, 1.11 GB in total |
| Assert transactions | about 370,000 vB; assert-commit-1 is 1.09 MB, over the 400k-weight standard limit |
| One disprove | 239,000–990,000 vB, non-standard |
| Relay | assert-commit-1 and every disprove need a miner willing to take non-standard transactions |
| Trusted setup | the Groth16 phase-2 key. The tested key (Citrea's) records one contribution; a pilot would need its own ceremony |
| Header canonicality | the header-chain proof shows work, not that the chain is the heaviest. A chain-work challenge is not built |
| Status | A disprove of a wrong assertion was mined on regtest through BitVM's own bridge test, after three local fixes to BitVM (`zk/bitvm-check/bridge-regtest.patch`, upstream issues drafted) |

## Verdict

**Feasible as research, not as a pilot dependency.** BitVM2 does adjudicate publicly. Anyone can
disprove, so no single client has to be online, and one bond can be pooled across deals. Against the
sentinel bond it adds four assumptions:
1. a committee for the setup keys (1-of-n);
2. a Groth16 phase-2 ceremony;
3. a miner for megabyte non-standard transactions;
4. a chain-work challenge that does not exist yet.

The sentinel bond already enforces possession with standard transactions and needs only the client
(or its watchtower) to be online.

## The smallest executable certificate-to-collateral construction on active consensus

Measured on `research/binohash-admission` (ADR-015 and ADR-016–019, BLOCKED review):
- **Today, with no soft fork:** the smallest construction is a certificate fixed at setup, checked by
  a hash lock, with the payout bound by a SIGHASH_SINGLE|ANYONECANPAY signature presigned by the setup
  key (ADR-015 L5). It is consensus-valid on Core 26, and redirecting output 0 is invalid. It admits
  only certificates enumerated at setup: `enumerated_leaf_incomplete`.
- **Permissionless admission of an unknown certificate** needs OP_CAT (BIP347). The ADR-016 one-tx
  verifier works under BIP347 on Core 26 + patch and on Bitcoin Inquisition (41 cases, 0 mismatches),
  including real mainnet headers across a retarget (ADR-019). On mainnet today it is anyone-can-spend.
- **BitVM2** reaches the same goal without a soft fork, for an operator-asserted claim, at the costs
  above.

So the pilot's collateral settlement uses the per-deal sentinel bond. Public pooled adjudication
waits for BIP347, or for a BitVM2 deployment that brings its own ceremony and miner arrangement.
