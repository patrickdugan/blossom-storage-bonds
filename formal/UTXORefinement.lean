import Blossom

/-!
A small Bitcoin-UTXO *refinement boundary* for the Blossom sentinel bond.

The model exposes the checks required before one spent bond outpoint may be
interpreted as one of the abstract transitions in Blossom.lean. It includes
amounts and transaction fees, an explicit consumed outpoint set, signed
output destinations and a list of allowable Script spend paths.

The input-validity, signature-verification, SHA256-preimage and output-binding
fields are independent abstract predicates. This module proves a conditional
simulation; it does not claim to implement the Bitcoin consensus interpreter.

An independently spendable Taproot key path or refund leaf is NOT part of the
listed spend cases. The missing-exhaustiveness counterexample at the end of
this file makes that limitation explicit.
-/

namespace BlossomFormal

inductive SpendPath where
  | challenge
  | response
  | forfeit
  | refund
  | cooperative
  | outsidePath
  deriving DecidableEq, Repr

inductive Recipient where
  | successorBond
  | provider
  | challenger
  | jointSplit
  | arbitrary
  deriving DecidableEq, Repr

structure BondTx where
  prevout : Nat
  successor : Nat
  path : SpendPath
  recipient : Recipient
  payout : Nat
  clientPayout : Nat := 0
  fee : Nat
  providerSignature : Bool
  clientSignature : Bool
  hashOpening : Bool
  timelockSatisfied : Bool
  signedOutputs : Bool
  deriving Repr

structure UTXOState where
  account : Account
  liveBond : Option Nat
  spent : List Nat
  deriving Repr

def utxoInitial (bond ref : Nat) : UTXOState :=
  { account := initial bond, liveBond := some ref, spent := [] }

/-- A leaf-specific Script condition. The booleans represent authenticated
results of an external consensus verifier, not arbitrary caller assertions. -/
def witnessValid (tx : BondTx) : Prop :=
  match tx.path with
  | .challenge => tx.providerSignature = true ∧ tx.clientSignature = true ∧ tx.hashOpening = true
  | .response => tx.providerSignature = true ∧ tx.clientSignature = true ∧ tx.hashOpening = true
  | .forfeit => tx.clientSignature = true ∧ tx.timelockSatisfied = true
  | .refund => tx.providerSignature = true ∧ tx.timelockSatisfied = true
  | .cooperative => tx.providerSignature = true ∧ tx.clientSignature = true
  | .outsidePath => False

def stageEligible (s : Account) (tx : BondTx) : Prop :=
  match tx.path with
  | .challenge => s.stage = Stage.live
  | .response => s.stage = Stage.challenged
  | .forfeit => s.stage = Stage.challenged
  | .refund => s.stage = Stage.live
  | .cooperative => s.stage = Stage.live ∨ s.stage = Stage.challenged
  | .outsidePath => False

def recipientExpected (tx : BondTx) : Prop :=
  match tx.path with
  | .challenge => tx.recipient = Recipient.successorBond
  | .response => tx.recipient = Recipient.successorBond
  | .forfeit => tx.recipient = Recipient.challenger
  | .refund => tx.recipient = Recipient.provider
  | .cooperative => tx.recipient = Recipient.jointSplit
  | .outsidePath => False

/-- Value accounting uses the bond's actual UTXO amount. Fees must appear in
the equation. signedOutputs represents BIP341 authorization for the entire
output template (or an equally strong covenant). -/
def payoutValid (s : Account) (tx : BondTx) : Prop :=
  tx.payout + tx.clientPayout + tx.fee = s.locked ∧
  (tx.path = SpendPath.cooperative ∨ tx.clientPayout = 0) ∧
  tx.signedOutputs = true ∧ recipientExpected tx

/-- UTXO membership, spend-once, Script evidence, exact payout accounting,
and a fresh successor outpoint are distinct premises. -/
def admitted (s : UTXOState) (tx : BondTx) : Prop :=
  s.liveBond = some tx.prevout ∧
  tx.prevout ∉ s.spent ∧
  stageEligible s.account tx ∧
  witnessValid tx ∧
  payoutValid s.account tx ∧
  tx.successor ≠ tx.prevout ∧ tx.successor ∉ s.spent

def accountAfter (a : Account) (tx : BondTx) : Account :=
  match tx.path with
  | .challenge => { a with stage := Stage.challenged, locked := a.locked - tx.fee, minerFees := a.minerFees + tx.fee }
  | .response => { a with stage := Stage.live, round := a.round + 1, locked := a.locked - tx.fee, minerFees := a.minerFees + tx.fee }
  | .forfeit => { a with stage := Stage.clientForfeit, locked := 0, client := a.client + (a.locked - tx.fee), minerFees := a.minerFees + tx.fee }
  | .refund => { a with stage := Stage.providerPaid, locked := 0, provider := a.provider + (a.locked - tx.fee), minerFees := a.minerFees + tx.fee }
  | .cooperative => { a with stage := Stage.cooperativeClosed, locked := 0, provider := a.provider + tx.payout, client := a.client + tx.clientPayout, minerFees := a.minerFees + tx.fee }
  | .outsidePath => a

def nextLive (tx : BondTx) : Option Nat :=
  match tx.path with
  | .challenge | .response => some tx.successor
  | .forfeit | .refund | .cooperative | .outsidePath => none

def applyBondTx (s : UTXOState) (tx : BondTx) : UTXOState :=
  { account := accountAfter s.account tx,
    liveBond := nextLive tx,
    spent := tx.prevout :: s.spent }

/-- This is the forward simulation theorem. It requires each of the
underlying Bitcoin/script checks in admitted, rather than assuming that a
generic Bitcoin-valid spend automatically meets the abstract protocol. -/
theorem admitted_refines_abstract (s : UTXOState) (tx : BondTx)
    (h : admitted s tx) :
    Step 0 s.account (accountAfter s.account tx) := by
  rcases h with ⟨_, _, st, wit, out, _, _⟩
  have hv : tx.fee ≤ s.account.locked := by
    rcases out with ⟨balance, _, _, _⟩
    omega
  have ordinaryClientZero : tx.path ≠ SpendPath.cooperative → tx.clientPayout = 0 := by
    intro notCoop
    rcases out with ⟨_, splitOrZero, _, _⟩
    exact splitOrZero.resolve_left notCoop
  cases hp : tx.path with
  | challenge =>
      simp [stageEligible, hp] at st
      have zero := ordinaryClientZero (by simp [hp])
      simpa [accountAfter, hp] using
        (Step.challenge (price := 0) s.account tx.fee hv st)
  | response =>
      simp [stageEligible, hp] at st
      simp [witnessValid, hp] at wit
      simpa [accountAfter, hp] using
        (Step.answer (price := 0) s.account tx.fee hv st
          (tx.hashOpening = true) wit.2.2)
  | forfeit =>
      simp [stageEligible, hp] at st
      simp [witnessValid, hp] at wit
      simpa [accountAfter, hp] using
        (Step.forfeit (price := 0) s.account tx.fee hv st
          (tx.timelockSatisfied = true) wit.2)
  | refund =>
      simp [stageEligible, hp] at st
      simp [witnessValid, hp] at wit
      simpa [accountAfter, hp] using
        (Step.refund (price := 0) s.account tx.fee hv st
          (tx.timelockSatisfied = true) wit.2)
  | cooperative =>
      simp [stageEligible, hp] at st
      simp [witnessValid, hp] at wit
      rcases out with ⟨balance, _, _, _⟩
      simpa [accountAfter, hp] using
        (Step.cooperativeClose (price := 0) s.account
          tx.payout tx.clientPayout tx.fee st balance
          (tx.providerSignature = true ∧ tx.clientSignature = true) wit)
  | outsidePath =>
      simp [stageEligible, hp] at st

theorem admitted_spend_conserves_bond (s : UTXOState) (tx : BondTx)
    (h : admitted s tx) :
    bondTotal s.account = bondTotal (applyBondTx s tx).account := by
  change bondTotal s.account = bondTotal (accountAfter s.account tx)
  exact step_preserves_bond 0 (admitted_refines_abstract s tx h)

/-- The permitted cooperative key-path spend requires both authorizations.
A Bitcoin MuSig2 aggregate signature is modeled by these TWO premises: the
real cryptographic connection still requires an implementation refinement. -/
theorem admitted_cooperative_requires_both
    (s : UTXOState) (tx : BondTx)
    (h : admitted s tx) (coop : tx.path = SpendPath.cooperative) :
    tx.providerSignature = true ∧ tx.clientSignature = true := by
  rcases h with ⟨_, _, _, witness, _, _, _⟩
  simpa [witnessValid, coop] using witness

theorem admitted_cooperative_split_conserves_input
    (s : UTXOState) (tx : BondTx)
    (h : admitted s tx) (coop : tx.path = SpendPath.cooperative) :
    tx.payout + tx.clientPayout + tx.fee = s.account.locked := by
  exact h.2.2.2.2.1

theorem spent_prevout_recorded (s : UTXOState) (tx : BondTx) :
    tx.prevout ∈ (applyBondTx s tx).spent := by
  simp [applyBondTx]

theorem old_prevout_cannot_be_reused (s : UTXOState) (tx next : BondTx)
    (same : next.prevout = tx.prevout) :
    ¬ admitted (applyBondTx s tx) next := by
  intro hn
  have unused := hn.2.1
  have consumed : next.prevout ∈ (applyBondTx s tx).spent := by
    rw [same]
    exact spent_prevout_recorded s tx
  exact unused consumed

theorem terminal_spend_has_no_live_bond (s : UTXOState) (tx : BondTx)
    (done : tx.path = SpendPath.forfeit ∨ tx.path = SpendPath.refund) :
    (applyBondTx s tx).liveBond = none := by
  cases done with
  | inl h => simp [applyBondTx, nextLive, h]
  | inr h => simp [applyBondTx, nextLive, h]

theorem terminal_spend_prevents_further_bond_spends
    (s : UTXOState) (tx next : BondTx)
    (done : tx.path = SpendPath.forfeit ∨ tx.path = SpendPath.refund) :
    ¬ admitted (applyBondTx s tx) next := by
  intro nextOk
  have noneLive := terminal_spend_has_no_live_bond s tx done
  have hasLive := nextOk.1
  rw [noneLive] at hasLive
  cases hasLive

/-- A confirmed response advances the sentinel round while preserving the
remaining escrow balance, adjusted for its fee. -/
theorem response_advances_round (s : UTXOState) (tx : BondTx)
    (hp : tx.path = SpendPath.response) :
    (applyBondTx s tx).account.round = s.account.round + 1 := by
  simp [applyBondTx, accountAfter, hp]

/-- A low-level history parameterized by any alleged Bitcoin acceptance
predicate. This permits the refinement obligation to be stated for real
consensus acceptance rather than only the hand-written formal checks. -/
inductive RawBitcoinRun
    (bitcoinAccepts : UTXOState → BondTx → Prop) :
    UTXOState → UTXOState → Prop where
  | refl (s : UTXOState) : RawBitcoinRun bitcoinAccepts s s
  | extend {start middle : UTXOState}
      (prefixRun : RawBitcoinRun bitcoinAccepts start middle)
      (tx : BondTx) (accepted : bitcoinAccepts middle tx) :
      RawBitcoinRun bitcoinAccepts start (applyBondTx middle tx)

/-- Exact statement of the *unproved* Bitcoin-to-Script refinement premise:
every accepted real consensus spend must satisfy the UTXO, path, witness,
payout, timelock and successor checks in admitted. -/
def ConsensusCoverage (bitcoinAccepts : UTXOState → BondTx → Prop) : Prop :=
  ∀ s tx, bitcoinAccepts s tx → admitted s tx

/-- Conditional multi-transaction forward simulation. It lifts the one-step
proof to an arbitrarily long Bitcoin run, assuming consensus coverage. -/
theorem bitcoin_run_refines_abstract
    (bitcoinAccepts : UTXOState → BondTx → Prop)
    (coverage : ConsensusCoverage bitcoinAccepts)
    {start finish : UTXOState}
    (history : RawBitcoinRun bitcoinAccepts start finish) :
    Reach 0 start.account finish.account := by
  induction history with
  | refl =>
      exact Reach.refl _
  | extend prefixRun tx accepted ih =>
      exact Reach.more ih
        (admitted_refines_abstract _ tx (coverage _ tx accepted))

theorem arbitrary_run_conserves_bond_including_fees
    (bitcoinAccepts : UTXOState → BondTx → Prop)
    (coverage : ConsensusCoverage bitcoinAccepts)
    {start finish : UTXOState}
    (history : RawBitcoinRun bitcoinAccepts start finish) :
    bondTotal start.account = bondTotal finish.account := by
  exact reachable_preserves_bond 0
    (bitcoin_run_refines_abstract bitcoinAccepts coverage history)

/-- Instantiating coverage with the formal verifier yields a completed
abstract safety theorem. Replacing this instantiation with Bitcoin Core
remains the outstanding implementation-conformance proof. -/
theorem formal_ledger_initial_value_conserved
    (bond ref : Nat) {finish : UTXOState}
    (history : RawBitcoinRun admitted (utxoInitial bond ref) finish) :
    bondTotal finish.account = bond := by
  have coverage : ConsensusCoverage admitted := by
    intro s tx h
    exact h
  have preserved := arbitrary_run_conserves_bond_including_fees
    admitted coverage history
  calc
    bondTotal finish.account = bondTotal (utxoInitial bond ref).account := preserved.symm
    _ = bond := initial_bond_total bond

/-- This hypothetical policy allows an unenumerated key path. It creates a
counterexample to deriving the refinement theorem from mere UTXO inclusion.
A full Bitcoin theorem needs to prove complete coverage of ALL spend paths. -/
def weakExternalAdmission (tx : BondTx) : Prop :=
  tx.path = SpendPath.outsidePath ∨ witnessValid tx

def outsidePathExample : BondTx :=
  { prevout := 1, successor := 2, path := .outsidePath,
    recipient := .arbitrary, payout := 99, fee := 1,
    providerSignature := false, clientSignature := false,
    hashOpening := false, timelockSatisfied := false,
    signedOutputs := false }

theorem unenumerated_path_counterexample :
    weakExternalAdmission outsidePathExample ∧ ¬ witnessValid outsidePathExample := by
  simp [weakExternalAdmission, witnessValid, outsidePathExample]

/-- ADR-006 counterexample: an old provider refund depends only on its own
CLTV and bonded UTXO, while the desired fork-contest rule also needs to check
an unanswered stronger challenge in a separate journal. -/
structure ExternalJournalView where
  bondLive : Bool
  termEnded : Bool
  strongerChallengeUnanswered : Bool
  deriving Repr

def legacyRefundPermitted (view : ExternalJournalView) : Prop :=
  view.bondLive = true ∧ view.termEnded = true

def contestRefundPermitted (view : ExternalJournalView) : Prop :=
  legacyRefundPermitted view ∧ view.strongerChallengeUnanswered = false

def bypassView : ExternalJournalView :=
  { bondLive := true, termEnded := true, strongerChallengeUnanswered := true }

theorem independent_journal_refund_bypass :
    legacyRefundPermitted bypassView ∧ ¬ contestRefundPermitted bypassView := by
  simp [legacyRefundPermitted, contestRefundPermitted, bypassView]

end BlossomFormal
