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
  dealId : Nat
  epochId : Nat
  nonce : Nat
  rootCommitment : Nat
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
  dealId : Nat
  rootCommitment : Nat
  paidEpochs : List Nat
  locked : Nat
  provider : Nat
  client : Nat
  epochRevenue : Nat
  minerFees : Nat
  deriving Repr

def bondTotal (s : Account) : Nat := s.locked + s.provider + s.client + s.minerFees

def initial (bond : Nat) : Account :=
  { stage := .live, round := 0, dealId := 0, rootCommitment := 0,
    paidEpochs := [], locked := bond, provider := 0, client := 0,
    epochRevenue := 0, minerFees := 0 }

/-- Agreement parameters are fixed at deal creation and retained across
all authorized state transitions. -/
def initialDeal (bond deal root : Nat) : Account :=
  { initial bond with dealId := deal, rootCommitment := root }

/-- Every authorized accounting transition is specified here. For a real
Bitcoin contract, Script and transaction validity must refine this relation.
Settlement value includes the miner fee debited from the locked bond. -/
inductive Step (price : Nat) : Account → Account → Prop where
  | payEpoch (s : Account) (proof : StorageProof)
      (stageOk : s.stage = .live) (verified : accepts proof)
      (dealMatches : proof.dealId = s.dealId)
      (rootMatches : proof.rootCommitment = s.rootCommitment)
      (fresh : proof.epochId ∉ s.paidEpochs)
      (nonempty : proof.sampled ≠ []) :
      Step price s { s with epochRevenue := s.epochRevenue + price, paidEpochs := proof.epochId :: s.paidEpochs }
  | challenge (s : Account) (fee : Nat) (affordable : fee ≤ s.locked)
      (eligible : s.stage = .live) :
      Step price s { s with stage := Stage.challenged, locked := s.locked - fee, minerFees := s.minerFees + fee }
  | answer (s : Account) (fee : Nat) (affordable : fee ≤ s.locked)
      (challenged : s.stage = .challenged)
      (validResponse : Prop) (verified : validResponse) :
      Step price s { s with stage := Stage.live, round := s.round + 1, locked := s.locked - fee, minerFees := s.minerFees + fee }
  | forfeit (s : Account) (fee : Nat) (affordable : fee ≤ s.locked)
      (challenged : s.stage = .challenged)
      (deadlinePassed : Prop) (verified : deadlinePassed) :
      Step price s { s with stage := Stage.clientForfeit, locked := 0, client := s.client + (s.locked - fee), minerFees := s.minerFees + fee }
  | refund (s : Account) (fee : Nat) (affordable : fee ≤ s.locked)
      (uncontested : s.stage = .live)
      (termEnded : Prop) (verified : termEnded) :
      Step price s { s with stage := Stage.providerPaid, locked := 0, provider := s.provider + (s.locked - fee), minerFees := s.minerFees + fee }

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
  | payEpoch p _ verified _ _ _ _ => exact ⟨p, verified⟩
  | challenge _ _ _ => exact False.elim (changed rfl)
  | answer _ _ _ _ _ => exact False.elim (changed rfl)
  | forfeit _ _ _ _ _ => exact False.elim (changed rfl)
  | refund _ _ _ _ _ => exact False.elim (changed rfl)

/-- Every payment record must be bound to this deal and the agreed Merkle
root, must have at least one sampled opening and must use a fresh epoch ID.
This strengthens the earlier existential proof prerequisite. -/
theorem increased_revenue_requires_bound_fresh_epoch
    (price : Nat) {s t : Account}
    (h : Step price s t) (changed : s.epochRevenue ≠ t.epochRevenue) :
    ∃ p : StorageProof,
      accepts p ∧ p.dealId = s.dealId ∧
      p.rootCommitment = s.rootCommitment ∧
      p.epochId ∉ s.paidEpochs ∧ p.sampled ≠ [] := by
  cases h with
  | payEpoch p _ valid dealOk rootOk fresh nonempty =>
      exact ⟨p, valid, dealOk, rootOk, fresh, nonempty⟩
  | challenge _ _ _ => exact False.elim (changed rfl)
  | answer _ _ _ _ _ => exact False.elim (changed rfl)
  | forfeit _ _ _ _ _ => exact False.elim (changed rfl)
  | refund _ _ _ _ _ => exact False.elim (changed rfl)

/-- Neither a sentinel spend nor a verified Lightning epoch changes the
original deal identity or the committed replica Merkle root. -/
theorem step_keeps_deal_and_root (price : Nat) {s t : Account}
    (h : Step price s t) :
    s.dealId = t.dealId ∧ s.rootCommitment = t.rootCommitment := by
  cases h <;> simp

theorem reachable_keeps_deal_and_root (price : Nat) {s t : Account}
    (history : Reach price s t) :
    s.dealId = t.dealId ∧ s.rootCommitment = t.rootCommitment := by
  induction history with
  | refl =>
      exact ⟨rfl, rfl⟩
  | more path edge ih =>
      have later := step_keeps_deal_and_root price edge
      exact ⟨ih.1.trans later.1, ih.2.trans later.2⟩

/-- An already paid epoch cannot disappear from authorized state history. -/
theorem step_retains_paid_epochs (price : Nat) {s t : Account}
    (h : Step price s t) (epoch : Nat)
    (already : epoch ∈ s.paidEpochs) : epoch ∈ t.paidEpochs := by
  cases h <;> simp_all

theorem reachable_retains_paid_epochs (price : Nat) {s t : Account}
    (history : Reach price s t) (epoch : Nat)
    (already : epoch ∈ s.paidEpochs) : epoch ∈ t.paidEpochs := by
  induction history with
  | refl => exact already
  | more path edge ih =>
      exact step_retains_paid_epochs price edge epoch ih

/-- If an epoch has already been paid, the payEpoch constructor's freshness
requirement is unavailable in every later reachable account state. -/
theorem paid_epoch_cannot_be_replayed_after_history
    (price : Nat) {start finish : Account}
    (history : Reach price start finish) (p : StorageProof)
    (already : p.epochId ∈ start.paidEpochs) :
    ¬ (p.epochId ∉ finish.paidEpochs) := by
  intro duplicate
  exact duplicate (reachable_retains_paid_epochs price history p.epochId already)

end BlossomFormal
