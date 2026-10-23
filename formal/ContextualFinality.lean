import UTXORefinement

/-!
Contextual Bitcoin locktime requirements for Blossom's terminal bond spends.

Bitcoin Core's libbitcoinconsensus checks per-input tapscript including
OP_CSV / OP_CLTV. Without a block/UTXO view, this does not establish the
transaction's nLockTime finality or BIP68 age of the spent UTXO. This module
states height-only counterparts of the BIP65/BIP68/BIP112 obligations.

Every variable here is abstract. Real block inclusion, MTP, time/height
type flags, UTXO creation height, and chainwork are not machine-verified.

The operational regtest bond uses integer heights (under threshold
500,000,000), version 2 for direct terminal spends, Sequence::from_height(144)
for forfeiture, and LockTime::from_height(t_end) for refund.
-/
namespace BlossomFormal

structure CsvHeightCase where
  version : Nat
  sequenceBlocks : Nat
  disableSequenceLock : Bool
  sequenceUsesTime : Bool
  outputConfirmedHeight : Nat
  candidateBlockHeight : Nat
  contractDelayBlocks : Nat
  deriving DecidableEq, Repr

/-- Modeled BIP112 opcode conditions in the block-height domain. -/
def csvScriptOk (c : CsvHeightCase) : Prop :=
  c.version ≥ 2 ∧ c.disableSequenceLock = false ∧
  c.sequenceUsesTime = false ∧
  c.sequenceBlocks ≥ c.contractDelayBlocks

/-- Contextual BIP68 earliest-confirmation height of a transaction spending
the output. The relative delay is encoded in the signed input's sequence.
This must use *sequenceBlocks*, not merely contractDelayBlocks. -/
def bip68HeightFinal (c : CsvHeightCase) : Prop :=
  c.outputConfirmedHeight + c.sequenceBlocks ≤ c.candidateBlockHeight

def csvContextOk (c : CsvHeightCase) : Prop :=
  csvScriptOk c ∧ bip68HeightFinal c

theorem contextual_csv_waits_at_least_contract_delay
    (c : CsvHeightCase) (h : csvContextOk c) :
    c.outputConfirmedHeight + c.contractDelayBlocks ≤ c.candidateBlockHeight := by
  rcases h with ⟨⟨_, _, _, minSequence⟩, matured⟩
  omega

/-- The exact operational sequence (144 blocks) can satisfy the CSV opcode
while still lacking the BIP68 age needed for confirmed inclusion. -/
def immatureCsvFixture : CsvHeightCase :=
  { version := 2, sequenceBlocks := 144, disableSequenceLock := false,
    sequenceUsesTime := false, outputConfirmedHeight := 500,
    candidateBlockHeight := 643, contractDelayBlocks := 144 }

def matureCsvFixture : CsvHeightCase :=
  { immatureCsvFixture with candidateBlockHeight := 644 }

theorem csv_opcode_without_maturity_counterexample :
    csvScriptOk immatureCsvFixture ∧ ¬ bip68HeightFinal immatureCsvFixture := by
  decide

theorem first_mature_csv_boundary :
    csvContextOk matureCsvFixture ∧ ¬ csvContextOk immatureCsvFixture := by
  decide

/-- A larger signed sequence creates a longer contextual wait; a party
cannot shorten actual BIP68 finality to the minimum script delay. -/
def slowerCsvFixture : CsvHeightCase :=
  { immatureCsvFixture with sequenceBlocks := 200, candidateBlockHeight := 644 }

theorem larger_sequence_requires_its_own_bip68_wait :
    csvScriptOk slowerCsvFixture ∧ ¬ bip68HeightFinal slowerCsvFixture := by
  decide

structure CltvHeightCase where
  contractEndHeight : Nat
  txLockHeight : Nat
  candidateBlockHeight : Nat
  inputNonFinal : Bool
  lockIsBlockHeight : Bool
  deriving DecidableEq, Repr

/-- Modeled OP_CHECKLOCKTIMEVERIFY (BIP65) consensus Script preconditions
for the height-only contract (timestamp-based locks are a separate case). -/
def cltvScriptOk (c : CltvHeightCase) : Prop :=
  c.lockIsBlockHeight = true ∧ c.contractEndHeight < 500000000 ∧
  c.txLockHeight < 500000000 ∧ c.txLockHeight ≥ c.contractEndHeight ∧
  c.inputNonFinal = true

/-- Height-locked nLockTime L becomes transaction-final for block H when
L < H if the input is nonfinal. -/
def absoluteHeightFinal (c : CltvHeightCase) : Prop :=
  c.txLockHeight < c.candidateBlockHeight

def cltvContextOk (c : CltvHeightCase) : Prop :=
  cltvScriptOk c ∧ absoluteHeightFinal c

theorem refund_confirmation_follows_contract_height
    (c : CltvHeightCase) (h : cltvContextOk c) :
    c.contractEndHeight < c.candidateBlockHeight := by
  rcases h with ⟨⟨_, _, _, enoughLock, _⟩, finalHeight⟩
  omega

def earlyRefundFixture : CltvHeightCase :=
  { contractEndHeight := 960000, txLockHeight := 960000,
    candidateBlockHeight := 960000, inputNonFinal := true,
    lockIsBlockHeight := true }

def matureRefundFixture : CltvHeightCase :=
  { earlyRefundFixture with candidateBlockHeight := 960001 }

theorem cltv_opcode_without_transaction_finality :
    cltvScriptOk earlyRefundFixture ∧ ¬ absoluteHeightFinal earlyRefundFixture := by
  decide

theorem first_mature_cltv_boundary :
    cltvContextOk matureRefundFixture ∧ ¬ cltvContextOk earlyRefundFixture := by
  decide

/-- Link the contextual timing predicates to the existing abstract BondTx
path. A signed forfeit/refund must carry a corresponding real-chain witness
of maturity before it is entitled to the UTXO transition. -/
structure TimingEvidence where
  csv : CsvHeightCase
  cltv : CltvHeightCase

def contextAttests (tx : BondTx) (e : TimingEvidence) : Prop :=
  match tx.path with
  | .forfeit => csvContextOk e.csv
  | .refund => cltvContextOk e.cltv
  | .challenge | .response | .cooperative => True
  | .outsidePath => False

def contextuallyAdmitted (s : UTXOState) (tx : BondTx)
    (e : TimingEvidence) : Prop :=
  admitted s tx ∧ contextAttests tx e

theorem contextual_forfeit_requires_bip68
    (s : UTXOState) (tx : BondTx) (e : TimingEvidence)
    (h : contextuallyAdmitted s tx e)
    (path : tx.path = SpendPath.forfeit) :
    e.csv.outputConfirmedHeight + e.csv.contractDelayBlocks ≤
       e.csv.candidateBlockHeight := by
  have context := h.2
  simp [contextAttests, path] at context
  exact contextual_csv_waits_at_least_contract_delay e.csv context

theorem contextual_refund_requires_absolute_height
    (s : UTXOState) (tx : BondTx) (e : TimingEvidence)
    (h : contextuallyAdmitted s tx e)
    (path : tx.path = SpendPath.refund) :
    e.cltv.contractEndHeight < e.cltv.candidateBlockHeight := by
  have context := h.2
  simp [contextAttests, path] at context
  exact refund_confirmation_follows_contract_height e.cltv context

theorem contextual_admission_refines_protocol
    (s : UTXOState) (tx : BondTx) (e : TimingEvidence)
    (h : contextuallyAdmitted s tx e) :
    Step 0 s.account (accountAfter s.account tx) := by
  exact admitted_refines_abstract s tx h.1

/-- Stronger than ConsensusCoverage: any real bitcoin acceptance must satisfy
both the script / UTXO premises AND height-contextual maturity. This is an
UNPROVED bridge condition, not an axiom about the actual Core interpreter. -/
def ContextualConsensusCoverage
    (bitcoinAccepts : UTXOState → BondTx → TimingEvidence → Prop) : Prop :=
  ∀ s tx e, bitcoinAccepts s tx e → contextuallyAdmitted s tx e

theorem contextual_coverage_implies_base
    (bitcoinAccepts : UTXOState → BondTx → TimingEvidence → Prop)
    (coverage : ContextualConsensusCoverage bitcoinAccepts)
    (s : UTXOState) (tx : BondTx) (e : TimingEvidence)
    (accepted : bitcoinAccepts s tx e) : admitted s tx := by
  exact (coverage s tx e accepted).1

end BlossomFormal
