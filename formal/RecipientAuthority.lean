import UTXORefinement

/-!
A constructive counterexample to universal Bitcoin-to-Lean coverage when
the Lean payout predicate demands a FIXED address on unilateral terminal
exits. The operational Taproot refund/forfeit leaves constrain the signer
and the locktime. A correct signer can authorize a different output.

The corresponding real BIP341 signed transactions are independently checked
against Bitcoin Core 26 with spent-output data in the Taproot evidence CI.
This module proves only the logical mismatch under an explicit Script-style
acceptance predicate; it does not embed Core or Schnorr cryptography in Lean.
-/

namespace BlossomFormal

/-- A declared policy that checks Script authorization, value conservation,
UTXO ownership and signature commitment to the actual chosen output, while
granting the unilateral signer discretion over the destination. -/
def signerControlledAdmission (s : UTXOState) (tx : BondTx) : Prop :=
  s.liveBond = some tx.prevout ∧
  tx.prevout ∉ s.spent ∧
  stageEligible s.account tx ∧
  witnessValid tx ∧
  tx.payout + tx.clientPayout + tx.fee = s.account.locked ∧
  tx.signedOutputs = true ∧
  tx.successor ≠ tx.prevout ∧ tx.successor ∉ s.spent ∧
  keypathPermitted s tx

def challengedFixture : UTXOState :=
  { utxoInitial 100000000 1 with
    account := {initial 100000000 with stage := Stage.challenged}}

def liveFixture : UTXOState :=
  utxoInitial 100000000 1

/-- This re-signed forfeiture uses the CLIENT'S key and satisfies the CSV
authorization predicate, but pays an address classified as provider-owned.
The client voluntarily exercises disposition authority. -/
def clientSignedRedirect : BondTx :=
  { prevout := 1, successor := 2, path := SpendPath.forfeit,
    recipient := Recipient.provider, payout := 99999000, fee := 1000,
    providerSignature := false, clientSignature := true,
    hashOpening := false, timelockSatisfied := true, signedOutputs := true }

/-- This re-signed refund uses the PROVIDER'S key and satisfies CLTV,
but voluntarily redirects the economic payout to the client. -/
def providerSignedRedirect : BondTx :=
  { prevout := 1, successor := 2, path := SpendPath.refund,
    recipient := Recipient.challenger, payout := 99999000, fee := 1000,
    providerSignature := true, clientSignature := false,
    hashOpening := false, timelockSatisfied := true, signedOutputs := true }

theorem forfeit_redirect_meets_script_style_predicate :
    signerControlledAdmission challengedFixture clientSignedRedirect := by
  simp [signerControlledAdmission, challengedFixture, clientSignedRedirect,
    utxoInitial, initial, stageEligible, witnessValid, keypathPermitted]

theorem refund_redirect_meets_script_style_predicate :
    signerControlledAdmission liveFixture providerSignedRedirect := by
  simp [signerControlledAdmission, liveFixture, providerSignedRedirect,
    utxoInitial, initial, stageEligible, witnessValid, keypathPermitted]

/-- The OLD stricter policy demanded that a unilateral exit pay a hardcoded
party's address. This is a counterfactual application rule, not what the
current Taproot leaf enforces. Keep it for regression against a false claim. -/
def strictRecipientExpected (tx : BondTx) : Prop :=
  match tx.path with
  | .forfeit => tx.recipient = Recipient.challenger
  | .refund => tx.recipient = Recipient.provider
  | _ => recipientExpected tx

def strictAdmitted (s : UTXOState) (tx : BondTx) : Prop :=
  admitted s tx ∧ strictRecipientExpected tx

def StrictConsensusCoverage (accepts : UTXOState → BondTx → Prop) : Prop :=
  ∀ s tx, accepts s tx → strictAdmitted s tx

theorem forfeit_redirect_fails_fixed_recipient :
    ¬ strictAdmitted challengedFixture clientSignedRedirect := by
  intro strict
  have wrong := strict.2
  simp [strictRecipientExpected, clientSignedRedirect] at wrong

theorem refund_redirect_fails_fixed_recipient :
    ¬ strictAdmitted liveFixture providerSignedRedirect := by
  intro strict
  have wrong := strict.2
  simp [strictRecipientExpected, providerSignedRedirect] at wrong

/-- The original fixed-address coverage claim fails in the presence of
signer-authorized payout redirection, as verified by the Core fixture. -/
theorem signer_discretion_refutes_fixed_recipient_coverage :
    ¬ StrictConsensusCoverage signerControlledAdmission := by
  intro coverage
  exact forfeit_redirect_fails_fixed_recipient
    (coverage challengedFixture clientSignedRedirect
      forfeit_redirect_meets_script_style_predicate)

/-- A terminal spend meeting the full signer-controlled predicate and the
single-beneficiary amount shape refines the revised authorization rule.
The input's Script evidence is still an abstract external premise. -/
theorem terminal_signer_disposition_refines_admission
    (s : UTXOState) (tx : BondTx)
    (h : signerControlledAdmission s tx)
    (terminal : tx.path = SpendPath.forfeit ∨ tx.path = SpendPath.refund)
    (singleAmount : tx.clientPayout = 0) :
    admitted s tx := by
  rcases h with ⟨active, fresh, eligible, valid, balance, signed, different, newRef, keypath⟩
  have recipientAllowed : recipientExpected tx := by
    rcases terminal with forfeit | refund
    · simp [recipientExpected, forfeit]
    · simp [recipientExpected, refund]
  exact ⟨active, fresh, eligible, valid,
    ⟨balance, Or.inr singleAmount, signed, recipientAllowed⟩,
    different, newRef, keypath⟩

theorem forfeit_redirect_meets_revised_admission :
    admitted challengedFixture clientSignedRedirect := by
  exact terminal_signer_disposition_refines_admission
    challengedFixture clientSignedRedirect
    forfeit_redirect_meets_script_style_predicate (Or.inl rfl) rfl

theorem refund_redirect_meets_revised_admission :
    admitted liveFixture providerSignedRedirect := by
  exact terminal_signer_disposition_refines_admission
    liveFixture providerSignedRedirect
    refund_redirect_meets_script_style_predicate (Or.inr rfl) rfl

/-- The settlement state credits the CLIENT whose signing authorization
disposed of the forfeiture, despite the concrete output being provider-owned.
This is an economic entitlement measure, not physical coin receipt. -/
theorem client_forfeit_disposal_even_if_output_redirected :
    (accountAfter challengedFixture.account clientSignedRedirect).client =
      challengedFixture.account.client + 99999000 := by
  rfl

theorem provider_refund_disposal_even_if_output_redirected :
    (accountAfter liveFixture.account providerSignedRedirect).provider =
      liveFixture.account.provider + 99999000 := by
  rfl

/-- The economic-beneficiary rule now distinguishes the signer's disposition
authority from the on-chain output destination. The connection to actual
Schnorr and UTXO consensus validation remains an external proof obligation. -/
def terminalAuthority (tx : BondTx) : Prop :=
  match tx.path with
  | .forfeit => tx.clientSignature = true
  | .refund => tx.providerSignature = true
  | _ => False

theorem forfeit_redirect_has_client_disposal_authority :
    terminalAuthority clientSignedRedirect := by
  simp [terminalAuthority, clientSignedRedirect]

theorem refund_redirect_has_provider_disposal_authority :
    terminalAuthority providerSignedRedirect := by
  simp [terminalAuthority, providerSignedRedirect]

end BlossomFormal
