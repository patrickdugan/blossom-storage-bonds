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
authorization predicate, but pays an address classified as provider-owned. -/
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

theorem forfeit_redirect_fails_fixed_recipient :
    ¬ admitted challengedFixture clientSignedRedirect := by
  simp [admitted, payoutValid, recipientExpected, clientSignedRedirect]

theorem refund_redirect_fails_fixed_recipient :
    ¬ admitted liveFixture providerSignedRedirect := by
  simp [admitted, payoutValid, recipientExpected, providerSignedRedirect]

/-- The prior universal ConsensusCoverage proposition is false if Bitcoin
acceptance allows signers to select their own terminal recipient. -/
theorem signer_discretion_refutes_fixed_recipient_coverage :
    ¬ ConsensusCoverage signerControlledAdmission := by
  intro coverage
  have accepted := forfeit_redirect_meets_script_style_predicate
  exact forfeit_redirect_fails_fixed_recipient
    (coverage challengedFixture clientSignedRedirect accepted)

/-- A useful revised beneficiary rule is based on the signer's authority
to DISPOSE of the payout, rather than the script's destination bytes. This
remains a specification proposal until linked to actual signer policy. -/
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
