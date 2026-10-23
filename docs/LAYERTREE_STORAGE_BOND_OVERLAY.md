# ADR: LayerTree as a carrier for long-lived BTC storage bonds

Status: Research proposal, 23 October 2026. No mainnet or regtest bond settlement is claimed.

## Premise

Matthew Vuk's 23 October post describes a SaplingOS LayerTree whose L3 survives VTXO refreshes while a FROST federation handles online maintenance. Apply this to Bitcoin-denominated collateral for Filecoin storage obligations, or to the existing Blossom/PDP service. A stable L3 bond and mutable short-lived carrier could let clients remain offline over many refresh periods.

In the pinned Sapio LayerTree MID prototype, a Merkle-sum member record includes balance, owner key, exit key, eviction authority, lease height, nonce and voucher sequence. The profile has owner exits, updates, splits, vouchers and cohort rewrites. Experimental Script predicates run through a trusted emulation oracle; actual Bitcoin verifies an ordinary signature, not the experimental CAT/CSFS/OP_TX transition rule. A malicious threshold can therefore bypass the intended balance and payout rules by issuing a different signature.

## Illustrative capital ledger

- One original carrier P0 holds 100,000 sats.
- Alice has a 60,000-sat client entitlement associated with a specified Filecoin miner/deal/sector and an immutable payout script.
- Bob has a separate 40,000-sat entitlement tied to a different storage commitment.
- Refresh P0 -> P1 preserves both economic terms and principal, even while the clients are offline. The full current state, not just balances, must be committed in the successor.
- If a finalized, independently authenticated fault is accepted for Alice, settlement pays 60,000 to her committed entitlement and reissues the remaining 40,000 under P2.
- After Bob's full term is verified, the provider's refund closes the final carrier. All physical Bitcoin fees need external funding.

For each transition use the capital equation B_next + payouts = B_previous + added_bond_principal. The sum of unsettled members must equal the amount locked in the successor carrier. A carrier generation is bound to a unique spent parent and a fresh successor outpoint.

Freeze the invariant economic record: unique bond ID, provider, beneficiary, deal ID, sector ID, proof-policy kind, replica root, amount, refund lock, fault response window, beneficiary and provider settlement scripts, and permanent provider/nonce lineage identifier. Only witness/proof progress, current carrier, and settlement state can advance. A spent lineage identifier must remain tombstoned across all refreshes to block voucher resurrection, as illustrated by Sapio PR #1.

## Where the storage verdict comes from

Filecoin WindowPoSt verifies ongoing sector storage and its actor machinery penalizes faults in FIL. A BTC side bond needs an authenticated finalized Filecoin event with chain checkpoint, miner, sector, proving deadline, and fault status. Verification of a submitted proof differs from an authenticated claim that no timely proof appeared. Absence requires chain/actor-state evidence or a trusted adjudicator. A Filecoin sector fault is a possible trigger for an independent BTC insurance payment; it does not move or directly slash native FIL collateral.

An alternative is the existing Blossom randomized challenge plus replica commitment. Its narrow fixed sentinel proof can be checked in present Bitcoin Script. Extending to mutable deal-specific verdicts requires a new consensus-admissible proof or the federation's adjudication.

For the proposed FROST version, require the threshold to sign a complete structured event (bond ID, deal/sector, proof checkpoint, epoch, outcome, old state root, new state root, parent outpoint and explicit payouts). This only states an authorization policy. It does not verify Filecoin consensus, create a FROST signature implementation, or make its outcome enforceable by Bitcoin.

## Failure cases that must be tested

1. Two adversarial signers in a 2-of-3 federation can approve a fabricated storage fault or sign a malicious Bitcoin spend: the application verifier cannot constrain their key.
2. A quorum outage halts refresh and likely exits if the user path also requires the same oracle. User-offline refresh liveness and user-controlled recovery are independent properties.
3. A malicious refresh silently changes one client's payout key or amount, omits the current proof, reuses a stale parent, or denies inclusion proofs to an offline beneficiary.
4. Historical owner/nonce reuse revives a voucher after exit and readmission, the Sapio LineageGuard counterexample.
5. An independent provider refund path or Taproot keypath escapes any storage-contest settlement gate, as in Blossom ADR-006/009.
6. A provider's late response and client forfeiture may both be valid after the CLTV height; a state-machine freeze alone cannot impose an upper Bitcoin consensus deadline, as in Blossom ADR-008.
7. A fake Filecoin checkpoint, omitted WindowPoSt, wrong sector, or reorg triggers unauthorized payout unless the chain-context evidence is validated.
8. A shared carrier's entire bond is mistakenly counted for both Alice and Bob. The sum and exact successor outpoint need independent checks.
9. A physical transaction supplies only a threshold signature while the claimed abstract payout predicate was never executed. Bitcoin still accepts the signature.

## Comparison with current Blossom options

- Direct sentinel: narrow script-enforced proof, no routine refresh oracle, no generic dynamic Filecoin verdict.
- Binohash / BitVM research: seeks permissionless certificate-to-verdict-to-collateral enforcement; dynamic admission, exhaustive spend-path coverage, and response deadline remain blocked.
- LayerTree / FROST overlay: natural accounting for pooled long-lived bonds and offline refreshes, in exchange for an economically powerful and censor-capable threshold federation.
- SaplingOS recovery: can test separately funded on-chain recovery and exact beneficiary scripts; does not by itself prove that a stable shared L3 bond survives arbitrary federation compromise or malicious refresh.

## Validation boundary and next jobs

First produce a deterministic adversarial ledger model using Alice=60,000 and Bob=40,000, with quorum-labeled transitions that explicitly identify votes as NONCRYPTOGRAPHIC. Test identity invariants, immutable terms, parent/child outpoints, replay, fault event bindings, capital preservation, and both settlement branches; include false-fault quorum and late-response counterexamples.

Next embed equivalent transitions in the actual pinned LayerTree MID interpreter and SaplingOS regtest recovery. Exhaustively inspect Bitcoin keypaths and Taproot leaves for settlement bypasses, confirm that physical fee inputs cannot consume client collateral, and test the signer outage and stale-record availability. Follow with a genuine Filecoin checkpoint/actor proof verifier. Only a funded Bitcoin spend validated under the intended security rules would justify a stronger enforcement claim.

This design is suitable for exploration as a disclosed federated BTC insurance/settlement product. It is not a permissionless Filecoin-on-Bitcoin slash.

References:
- Sapio pinned LayerTree: https://github.com/patrickdugan/sapio/blob/baseline/layertree-314-2026-10-22/docs/LAYERTREE.md
- Sapio replay hardening PR 1: https://github.com/patrickdugan/sapio/pull/1
- SaplingOS recovery PR 2: https://github.com/patrickdugan/sapio/pull/2
- Blossom Binohash admission PR 1: https://github.com/patrickdugan/blossom-storage-bonds/pull/1
- Filecoin PoSt: https://spec.filecoin.io/algorithms/pos/
- Lotus proving tasks: https://lotus.filecoin.io/storage-providers/get-started/tasks/
