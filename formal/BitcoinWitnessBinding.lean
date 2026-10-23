import BitcoinInclusion

/-!
Cryptographic binding reduction for BIP141 witness transaction inclusion.

Given a FIXED coinbase witness reserved value and a fixed commitment digest,
two conflicting wtxids at one indexed witness-tree slot require either:
  (a) a collision in the ordered SHA256d Merkle internal-node hash, or
  (b) a collision in SHA256d(witnessRoot || coinbaseReserved).
No global injectivity of SHA256 is postulated.

Concrete SHA256d bytes, BIP141 coinbase output authentication, full odd-leaf
geometry, block-chainwork/canonicality and real UTXO membership are outside
the Lean predicates. The real Bitcoin Core regtest implementation proves
the byte-level examples with model/bitcoin_witness_commitment.mjs.
-/

namespace BlossomFormal

def witnessLeaf (wtxid : Nat) : Nat := wtxid

/-- The final BIP141 tagged-by-context digest covers the Merkle root plus
the fixed 32-byte coinbase reserved value (not the witness txid's index). -/
def witnessCommitTag (commitHash : Nat → Nat → Nat)
    (reserved : Nat) (_txCount : Nat) (root : Nat) : Nat :=
  commitHash root reserved

def WitnessCommitCollision (commitHash : Nat → Nat → Nat)
    (reserved : Nat) : Prop :=
  ∃ a b : Nat, a ≠ b ∧ commitHash a reserved = commitHash b reserved

theorem witness_leaf_has_no_collision :
    ¬ LeafCollision witnessLeaf := by
  intro h
  rcases h with ⟨a,b,neq,eq⟩
  exact neq (by simpa [witnessLeaf] using eq)

/-- Two different SegWit witness transaction IDs that both verify as the
same indexed leaf, transaction count and BIP141 coinbase commitment imply
an explicit collision witness in one of the two hash layers. -/
theorem conflicting_wtxids_imply_witness_or_commit_collision
    (nodeHash commitHash : Nat → Nat → Nat)
    (reserved txCount depth commitment index x y : Nat)
    (pathX pathY : List Sibling)
    (verifiedX : checkedIndexedOpening witnessLeaf nodeHash
      (witnessCommitTag commitHash reserved)
      txCount depth commitment index x pathX)
    (verifiedY : checkedIndexedOpening witnessLeaf nodeHash
      (witnessCommitTag commitHash reserved)
      txCount depth commitment index y pathY)
    (different : x ≠ y) :
    NodeCollision nodeHash ∨ WitnessCommitCollision commitHash reserved := by
  rcases checked_same_index_openings_imply_collision
    witnessLeaf nodeHash (witnessCommitTag commitHash reserved)
    txCount depth commitment index x y pathX pathY
    verifiedX verifiedY different with leaf | inner | final
  · exact False.elim (witness_leaf_has_no_collision leaf)
  · exact Or.inl inner
  · rcases final with ⟨a,b,neq,eq⟩
    exact Or.inr ⟨a,b,neq,by simpa [witnessCommitTag] using eq⟩

theorem authenticated_slot_binds_wtxid_if_no_collision
    (nodeHash commitHash : Nat → Nat → Nat)
    (reserved txCount depth commitment index x y : Nat)
    (pathX pathY : List Sibling)
    (verifiedX : checkedIndexedOpening witnessLeaf nodeHash
      (witnessCommitTag commitHash reserved)
      txCount depth commitment index x pathX)
    (verifiedY : checkedIndexedOpening witnessLeaf nodeHash
      (witnessCommitTag commitHash reserved)
      txCount depth commitment index y pathY)
    (noNode : ¬ NodeCollision nodeHash)
    (noCommit : ¬ WitnessCommitCollision commitHash reserved) :
    x = y := by
  by_cases same : x = y
  · exact same
  · rcases conflicting_wtxids_imply_witness_or_commit_collision
      nodeHash commitHash reserved txCount depth commitment index x y
      pathX pathY verifiedX verifiedY same with collision | collision
    · exact False.elim (noNode collision)
    · exact False.elim (noCommit collision)

/-- Even a correctly bound wtxid and coinbase commitment say nothing about
whether the containing Bitcoin header is the most-work active-chain header.
That is an additional, external chain-authentication obligation. -/
def WitnessAnchoredToActiveChain (witnessValid chainValid : Bool) : Prop :=
  witnessValid = true ∧ chainValid = true

theorem witness_commitment_alone_is_not_active_chain_evidence :
    ¬ WitnessAnchoredToActiveChain true false := by
  simp [WitnessAnchoredToActiveChain]

end BlossomFormal
