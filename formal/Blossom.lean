import Std

/-!
Blossom storage proofs and payments: abstract state-machine safety.

This module models a verifier who accepts a sampled opening only when that
opening is authenticated against the agreed root. Such authentication is an
abstract predicate supplied by a future Merkle/SHA256/BIP341 refinement.

A provable protocol invariant is distinct from a deployed Bitcoin covenant.
In particular, miner liveness, fair challenge selection and signature
unforgeability are outside this abstract state machine.
-/

namespace BlossomFormal

structure StorageProof where
  sampled : List Nat
  authenticated : List Nat

/-- Every sampled position must have an independently authenticated opening. -/
def accepts (p : StorageProof) : Prop :=
  ∀ i, i ∈ p.sampled → i ∈ p.authenticated

theorem accepted_samples_authenticated (p : StorageProof)
    (h : accepts p) (i : Nat) (hi : i ∈ p.sampled) :
    i ∈ p.authenticated := h i hi

inductive Stage where
  | live
  | challenged
  | providerPaid
  | clientForfeit
  deriving DecidableEq, Repr

structure Account where
  stage : Stage
  round : Nat
  locked : Nat
  provider : Nat
  client : Nat
  epochRevenue : Nat
  minerFees : Nat
  deriving Repr

def bondTotal (s : Account) : Nat := s.locked + s.provider + s.client + s.minerFees

def initial (bond : Nat) : Account :=
  { stage := .live, round := 0, locked := bond, provider := 0, client := 0,
    epochRevenue := 0, minerFees := 0 }

/-- Every authorized accounting transition is specified here. For a real
Bitcoin contract, Script and transaction validity must refine this relation.
Settlement value includes the miner fee debited from the locked bond. -/
inductive Step (price : Nat) : Account → Account → Prop where
  | payEpoch (s : Account) (proof : StorageProof)
      (stageOk : s.stage = .live) (verified : accepts proof) :
      Step price s { s with epochRevenue := s.epochRevenue + price }
  | challenge (s : Account) (fee : Nat) (affordable : fee ≤ s.locked)
      (eligible : s.stage = .live) :
      Step price s { s with stage := .challenged,
        locked := s.locked - fee, minerFees := s.minerFees + fee }
  | answer (s : Account) (fee : Nat) (affordable : fee ≤ s.locked)
      (challenged : s.stage = .challenged)
      (validResponse : Prop) (verified : validResponse) :
      Step price s { s with stage := Stage.live, round := s.round + 1,
        locked := s.locked - fee, minerFees := s.minerFees + fee }
  | forfeit (s : Account) (fee : Nat) (affordable : fee ≤ s.locked)
      (challenged : s.stage = .challenged)
      (deadlinePassed : Prop) (verified : deadlinePassed) :
      Step price s { s with stage := Stage.clientForfeit, locked := 0,
        client := s.client + (s.locked - fee), minerFees := s.minerFees + fee }
  | refund (s : Account) (fee : Nat) (affordable : fee ≤ s.locked)
      (uncontested : s.stage = .live)
      (termEnded : Prop) (verified : termEnded) :
      Step price s { s with stage := Stage.providerPaid, locked := 0,
        provider := s.provider + (s.locked - fee), minerFees := s.minerFees + fee }

theorem initial_bond_total (bond : Nat) :
    bondTotal (initial bond) = bond := by
  simp [bondTotal, initial]

theorem step_preserves_bond (price : Nat) {s t : Account}
    (h : Step price s t) : bondTotal s = bondTotal t := by
  cases h <;> simp [bondTotal] <;> omega

/-- A completed provider payout or forfeiture admits no further authorized step. -/
theorem terminal_is_absorbing (price : Nat) {s t : Account}
    (h : Step price s t)
    (done : s.stage = .providerPaid ∨ s.stage = .clientForfeit) :
    False := by
  cases h <;> simp_all

/-- Reflexive/transitive closure of the authorized settlement graph. -/
inductive Reach (price : Nat) : Account → Account → Prop where
  | refl (s : Account) : Reach price s s
  | more {a b c : Account} (path : Reach price a b)
      (edge : Step price b c) : Reach price a c

theorem reachable_preserves_bond (price : Nat) {a b : Account}
    (h : Reach price a b) : bondTotal a = bondTotal b := by
  induction h with
  | refl => rfl
  | more path edge ih =>
    exact ih.trans (step_preserves_bond price edge)

theorem any_reachable_bond_is_conserved (bond price : Nat)
    {s : Account} (h : Reach price (initial bond) s) :
    bondTotal s = bond := by
  exact (reachable_preserves_bond price h).symm.trans (initial_bond_total bond)

/-- A direct epoch payment must carry an accepted storage-proof instance.
This theorem checks authorization at the transition boundary; it does not
establish SHA256 collision resistance or possession of all stored chunks. -/
theorem increased_revenue_requires_proof (price : Nat) {s t : Account}
    (h : Step price s t) (changed : s.epochRevenue ≠ t.epochRevenue) :
    ∃ p : StorageProof, accepts p := by
  cases h with
  | payEpoch p _ verified => exact ⟨p, verified⟩
  | challenge _ _ _ => exact False.elim (changed rfl)
  | answer _ _ _ _ _ => exact False.elim (changed rfl)
  | forfeit _ _ _ _ _ => exact False.elim (changed rfl)
  | refund _ _ _ _ _ => exact False.elim (changed rfl)

end BlossomFormal
