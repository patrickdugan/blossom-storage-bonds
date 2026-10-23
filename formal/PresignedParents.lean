import Blossom

/-!
The concrete template shape of the operational rust-bitcoin sentinel chain.

The companion Rust evidence producer in regtest/src/bin/formal_vectors.rs
constructs actual BIP341-signed transaction templates from common.rs.
Its outputs are checked using independent Bitcoin byte decoding in
model/verify_formal_evidence.mjs.

Lean's theorem is about the *template accounting relation* under explicit
premises. It does not ingest Rust JSON, prove BIP341 unforgeability, or
establish Bitcoin Core's acceptance of any transaction.
-/

namespace BlossomFormal

structure PresignedParent where
  inputRef : Nat
  successorRef : Nat
  inputSats : Nat
  successorSats : Nat
  anchorSats : Nat
  version : Nat
  sighashAllOutputs : Bool
  deriving Repr

/-- Matches the zero-fee version-3 parent and zero-valued P2A output in
regtest/src/common.rs::presigned. -/
def validParentShape (p : PresignedParent) : Prop :=
  p.inputSats = p.successorSats + p.anchorSats ∧
  p.anchorSats = 0 ∧
  p.version = 3 ∧
  p.sighashAllOutputs = true ∧
  p.successorRef ≠ p.inputRef

def parentFee (p : PresignedParent) : Nat :=
  p.inputSats - (p.successorSats + p.anchorSats)

theorem valid_parent_has_zero_fee (p : PresignedParent)
    (h : validParentShape p) : parentFee p = 0 := by
  rcases h with ⟨balance, _, _, _, _⟩
  simp [parentFee, balance]

theorem valid_parent_preserves_bond (p : PresignedParent)
    (h : validParentShape p) : p.successorSats = p.inputSats := by
  rcases h with ⟨balance, anchorZero, _, _, _⟩
  omega

/-- Bond collateral and independent miner-fee wallet are different UTXOs.
The source's CPFP transaction spends its own wallet UTXO and the zero-value
P2A anchor; its miner fee is charged to the wallet. -/
structure PackageLedger where
  bondRef : Nat
  bondSats : Nat
  feeWalletSats : Nat
  minerFees : Nat
  deriving Repr

def packageValue (s : PackageLedger) : Nat :=
  s.bondSats + s.feeWalletSats + s.minerFees

def initialPackage (bondRef bondSats feeWalletSats : Nat) : PackageLedger :=
  { bondRef, bondSats, feeWalletSats, minerFees := 0 }

/-- This relation accounts for bond-preserving parent transitions and
independent CPFP fee-wallet children. Signatures and actual UTXO validation
remain implementation/cryptographic assumptions external to this relation. -/
inductive PackageStep : PackageLedger → PackageLedger → Prop where
  | parent (s : PackageLedger) (tx : PresignedParent)
      (valid : validParentShape tx)
      (spendsCurrent : tx.inputRef = s.bondRef)
      (inputAmount : tx.inputSats = s.bondSats) :
      PackageStep s { s with bondRef := tx.successorRef, bondSats := tx.successorSats }
  | child (s : PackageLedger) (fee : Nat)
      (affordable : fee ≤ s.feeWalletSats) :
      PackageStep s { s with feeWalletSats := s.feeWalletSats - fee,
        minerFees := s.minerFees + fee }

theorem package_step_conserves_all_funds {s t : PackageLedger}
    (h : PackageStep s t) : packageValue s = packageValue t := by
  cases h with
  | parent s tx valid _ inputAmount =>
      have amount := valid_parent_preserves_bond tx valid
      simp [packageValue]
      omega
  | child s fee affordable =>
      simp [packageValue]
      omega

theorem parent_leaves_fee_wallet_unchanged
    (s : PackageLedger) (tx : PresignedParent)
    (valid : validParentShape tx)
    (spendsCurrent : tx.inputRef = s.bondRef)
    (inputAmount : tx.inputSats = s.bondSats) :
    ({ s with bondRef := tx.successorRef, bondSats := tx.successorSats }).feeWalletSats =
      s.feeWalletSats := by
  rfl

theorem child_leaves_bond_unchanged
    (s : PackageLedger) (fee : Nat)
    (affordable : fee ≤ s.feeWalletSats) :
    ({ s with feeWalletSats := s.feeWalletSats - fee,
      minerFees := s.minerFees + fee }).bondSats = s.bondSats := by
  rfl

/-- Arbitrary finite histories of parent/CPFP spends preserve the sum of
locked collateral, fee-wallet balance, and miner fees. -/
inductive PackageReach : PackageLedger → PackageLedger → Prop where
  | refl (s : PackageLedger) : PackageReach s s
  | extend {a b c : PackageLedger}
      (past : PackageReach a b)
      (step : PackageStep b c) : PackageReach a c

theorem package_history_conserves_all_funds {a b : PackageLedger}
    (h : PackageReach a b) : packageValue a = packageValue b := by
  induction h with
  | refl => rfl
  | extend past step ih =>
      exact ih.trans (package_step_conserves_all_funds step)

theorem initial_package_value (ref bond wallet : Nat) :
    packageValue (initialPackage ref bond wallet) = bond + wallet := by
  simp [packageValue, initialPackage]

theorem any_parent_cpfp_history_conserves_initial
    (ref bond wallet : Nat)
    {finish : PackageLedger}
    (h : PackageReach (initialPackage ref bond wallet) finish) :
    packageValue finish = bond + wallet := by
  calc
    packageValue finish =
        packageValue (initialPackage ref bond wallet) :=
      (package_history_conserves_all_funds h).symm
    _ = bond + wallet := initial_package_value ref bond wallet

/-- Witnesses can vary without changing the stripped transaction.
The eventual Bitcoin txid is a hash of stripped bytes, while wtxid hashes
the witness-bearing serialization. This formal observation cannot itself
authenticate the witness against a fork certificate. -/
structure WitnessVersion where
  strippedBytes : Nat
  witnessBytes : Nat
  deriving Repr

def modeledTxid (digest : Nat → Nat) (tx : WitnessVersion) : Nat :=
  digest tx.strippedBytes

theorem same_stripped_bytes_same_txid
    (digest : Nat → Nat) (a b : WitnessVersion)
    (same : a.strippedBytes = b.strippedBytes) :
    modeledTxid digest a = modeledTxid digest b := by
  simp [modeledTxid, same]

end BlossomFormal
