# Formal protocol proof: storage, epochs, and the bond payment machine

File: [`formal/Blossom.lean`](../../formal/Blossom.lean).

Lean 4 is pinned in the repository's `lean-toolchain`. The workflow `blossom-formal.yml` runs the checker. The intended trust boundary is smaller than a claim of complete Bitcoin protocol correctness.

## Scope

The TypeScript implementation `model/storage_bonds.ts` has two economic layers:

1. Epochs: sampled 4 KiB chunk openings are verified against the deal's Merkle root; the client pays only after accepting an epoch proof.
2. Sentinels: a bond moves from live to challenged, then resolves by provider response or client forfeiture, with an uncontested provider refund at the contract term end.

The Lean specification models accepted Merkle openings as a proposition (`accepts`), and the authorized state transitions as an inductive relation (`Step`). Accounting tracks locked bond, provider release, client forfeiture, and off-chain epoch revenue separately.

## Theorems

- `accepted_samples_authenticated`: an accepted storage proof provides an authenticated opening for each sampled index (by the definition of `accepts`).
- `initial_bond_total`, `step_preserves_bond`, `reachable_preserves_bond`, `any_reachable_bond_is_conserved`: bond balance is conserved across any permitted sequence.
- `terminal_is_absorbing`: the abstract protocol cannot perform another authorized transition after a terminal provider or client payout.
- `increased_revenue_requires_proof`: every single authorized state transition that changes off-chain epoch revenue carries an accepted proof.

These are exact deductive claims about the Lean transition system. They do not assume the result that conservation holds; the proof follows the transition constructors and their balance updates.

## Refinement obligations before calling this a formal proof of Blossom

The authenticated chunk predicate must be refined to SHA256 domain-separated Merkle inclusion (with binding of root, index, chunk count and committed ciphertext). Proving soundness requires cryptographic collision-resistance assumptions, and possession cannot be inferred from one successful opening.

Epoch proof acceptance currently states proof membership, rather than a fully executable Merkle verifier with nonce-derived random indices, proof path lengths and timing. Random challenge unpredictability, the probability of detecting deletion, proof replay and client prepayment risks need separate theorems and hypotheses.

The sentinel challenge/response relation has an abstract `validResponse` proposition and an abstract `deadlinePassed` proposition. A future refinement must show that actual Taproot/Bitcoin transactions enforce them, including BIP341/342 signatures, exact preimage matching, BIP68/112 CSV heights, every keypath/script leaf, and the continuing bond covenant. The externally signed storage bond can contain a provider refund path that bypasses independent fork-admission state, as ADR-006 demonstrates.

The model treats an authorized refund after term end as a valid transition from `live`; it assumes challenge admission moves that same live bond to `challenged` before competing refunds. Proofs about mining censorship or a missed inclusion deadline require a liveness/fairness model beyond this file.

Payment conservation is for the locked bond. Lightning value conservation, channel solvency, receipt authentication and invoice settlement require another refinement.

**Current status: a formal contract-level safety specification, not a fully verified storage proof, not cryptographic security, and not an on-chain payment mechanism proof.**

## Next milestone

Model Bitcoin UTXO ownership and terminal spend conflict explicitly in Lean, then prove a forward simulation between `model/storage_bonds.ts` transitions, serialized spending transactions and the formal relation. Add assumptions that bind outputs and show that every alternate provider exit is excluded. Retain the counterexample fixture for the independent CLTV refund as a falsifying case.
