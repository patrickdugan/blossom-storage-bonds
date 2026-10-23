import MerkleBinding

/-!
Transaction inclusion binding for Bitcoin's untagged double-SHA256 Merkle
tree. A BIP37 partial merkleblock reconstructs this exact tree from one or
more matched transaction IDs.

This module specializes MerkleBinding's generic same-index opening theorem.
Leaf/root encodings are identity functions; the only cryptographic event is
a collision in the internal double-SHA256 node hash on ordered 64-byte pairs.

The theorem is about a fixed root/index/depth with checked sibling direction
bits. It does NOT prove Bitcoin header PoW, chainwork, best-chain selection,
transaction Script validity, UTXO membership, BIP37 parser equivalence or
the lack of alternative Bitcoin transaction encodings.

The runtime companion is model/bitcoin_merkleblock.mjs, independently tested
with partial-merkle fixtures and Bitcoin Core 31.1 gettxoutproof results.
-/
namespace BlossomFormal

def bitcoinTxLeaf (txid : Nat) : Nat := txid
def bitcoinHeaderRoot (_n : Nat) (merkle : Nat) : Nat := merkle

theorem bitcoin_tx_leaf_has_no_collision :
    ¬ LeafCollision bitcoinTxLeaf := by
  intro bad
  rcases bad with ⟨x,y,distinct,equal⟩
  exact distinct (by simpa [bitcoinTxLeaf] using equal)

theorem bitcoin_header_root_tag_has_no_collision (n : Nat) :
    ¬ RootCollision bitcoinHeaderRoot n := by
  intro bad
  rcases bad with ⟨x,y,distinct,equal⟩
  exact distinct (by simpa [bitcoinHeaderRoot] using equal)

/-- If two BIP37-style checked indexed openings claim different txids
in the SAME Merkle slot/root, there must be a collision in the Bitcoin
internal node compressor (double-SHA256 over ordered child hashes). -/
theorem two_distinct_txids_same_block_index_imply_node_collision
    (node : Nat → Nat → Nat)
    (n depth root index x y : Nat)
    (pathX pathY : List Sibling)
    (hx : checkedIndexedOpening bitcoinTxLeaf node bitcoinHeaderRoot
      n depth root index x pathX)
    (hy : checkedIndexedOpening bitcoinTxLeaf node bitcoinHeaderRoot
      n depth root index y pathY)
    (different : x ≠ y) :
    NodeCollision node := by
  rcases checked_same_index_openings_imply_collision
      bitcoinTxLeaf node bitcoinHeaderRoot n depth root index x y
      pathX pathY hx hy different with leaf | inner | rootCollision
  · exact False.elim (bitcoin_tx_leaf_has_no_collision leaf)
  · exact inner
  · exact False.elim
      (bitcoin_header_root_tag_has_no_collision n rootCollision)

/-- Under the explicit NO-collision premise on the internal compressor,
the same root, transaction index and checked path-direction sequence
uniquely bind the transaction ID. -/
theorem same_index_header_commitment_binds_txid
    (node : Nat → Nat → Nat)
    (noNodeCollision : ¬ NodeCollision node)
    (n depth root index x y : Nat)
    (pathX pathY : List Sibling)
    (hx : checkedIndexedOpening bitcoinTxLeaf node bitcoinHeaderRoot
      n depth root index x pathX)
    (hy : checkedIndexedOpening bitcoinTxLeaf node bitcoinHeaderRoot
      n depth root index y pathY) :
    x = y := by
  by_cases same : x = y
  · exact same
  · exact False.elim (noNodeCollision
      (two_distinct_txids_same_block_index_imply_node_collision
        node n depth root index x y pathX pathY hx hy same))

/-- Inclusion alone does not imply the header belongs to the authenticated
active chain. A foreign header may contain a completely valid Merkle proof
yet fail the current-chain authentication predicate. -/
structure BitcoinHeaderClaim where
  headerHash : Nat
  txid : Nat
  included : Bool
  isAuthenticatedActive : Bool
  deriving DecidableEq, Repr

def isLocalInclusion (c : BitcoinHeaderClaim) : Prop :=
  c.included = true

def isAuthenticatedInclusion (c : BitcoinHeaderClaim) : Prop :=
  isLocalInclusion c ∧ c.isAuthenticatedActive = true

def orphanProof : BitcoinHeaderClaim :=
  { headerHash := 5, txid := 7,
    included := true, isAuthenticatedActive := false }

theorem orphan_header_inclusion_is_not_chain_proof :
    isLocalInclusion orphanProof ∧ ¬ isAuthenticatedInclusion orphanProof := by
  simp [isLocalInclusion,isAuthenticatedInclusion,orphanProof]

/-- A Bitcoin block's ordinary transaction Merkle tree binds the
non-witness txid, not the wtxid. This simplified record isolates the
evidence gap without assuming a particular hash preimage representation. -/
structure WitnessedTransaction where
  strippedId : Nat
  witnessVersion : Nat
  deriving DecidableEq, Repr

def bitcoinMerkleLeafId (tx : WitnessedTransaction) : Nat :=
  tx.strippedId

def confirmedWitnessExample : WitnessedTransaction :=
  { strippedId := 42, witnessVersion := 10 }

def substitutedWitnessExample : WitnessedTransaction :=
  { strippedId := 42, witnessVersion := 11 }

/-- Constructive logical counterexample to treating a txid inclusion proof
as authentication of a particular SegWit witness. Both transactions have
the same Merkle leaf identity but different witness records. -/
theorem bitcoin_txid_proof_cannot_bind_witness :
    bitcoinMerkleLeafId confirmedWitnessExample =
      bitcoinMerkleLeafId substitutedWitnessExample ∧
    confirmedWitnessExample.witnessVersion ≠
      substitutedWitnessExample.witnessVersion := by
  decide

end BlossomFormal
