import Blossom

/-!
A cryptographic binding reduction for Blossom's Merkle storage proofs.

This module deliberately treats hash functions as arbitrary functions. It does
NOT assume that SHA256 is injective, which is impossible over an unbounded
input domain. Instead it proves: distinct chunk openings at the same indexed
position that verify against the same commitment imply an explicit collision
at the leaf, internal node, or count-bound root hash layer.

The real storage_bonds.ts tree has a nonempty leaf set, domain-separated
SHA256 leaf/internal/root hashes and an odd-node duplication rule. The
position witness herein is a path of sibling hashes and orientations.
Its equivalence to the TypeScript verifier's index/depth/odd-node rules is
a separate implementation-refinement obligation.
-/

namespace BlossomFormal

structure Sibling where
  siblingHash : Nat
  siblingOnLeft : Bool
  deriving DecidableEq, Repr

def hashStep (node : Nat → Nat → Nat) (s : Sibling) (h : Nat) : Nat :=
  if s.siblingOnLeft then node s.siblingHash h else node h s.siblingHash

def pathRoot (node : Nat → Nat → Nat) : List Sibling → Nat → Nat
  | [], h => h
  | s :: tail, h => pathRoot node tail (hashStep node s h)

/-- The paths correspond to the same position and depth, so each level has
the same orientation. Their sibling *hash values* may differ. -/
inductive SameDirections : List Sibling → List Sibling → Prop where
  | nil : SameDirections [] []
  | cons (a b : Sibling) {xs ys : List Sibling}
      (same : a.siblingOnLeft = b.siblingOnLeft)
      (tail : SameDirections xs ys) :
      SameDirections (a :: xs) (b :: ys)

def LeafCollision (leaf : Nat → Nat) : Prop :=
  ∃ a b : Nat, a ≠ b ∧ leaf a = leaf b

def NodeCollision (node : Nat → Nat → Nat) : Prop :=
  ∃ a b c d : Nat, (a, b) ≠ (c, d) ∧ node a b = node c d

def RootCollision (rootTag : Nat → Nat → Nat) (n : Nat) : Prop :=
  ∃ a b : Nat, a ≠ b ∧ rootTag n a = rootTag n b

/-- If two sibling paths have equal direction bits, equal computed Merkle
subtree hashes either identify the same starting hash or exhibit an internal
compression collision. This is an unconditional arithmetic proof. -/
theorem parallel_path_collision_or_equal
    (node : Nat → Nat → Nat)
    {a b : List Sibling} (orientation : SameDirections a b)
    (x y : Nat) (equalRoots : pathRoot node a x = pathRoot node b y) :
    x = y ∨ NodeCollision node := by
  induction orientation generalizing x y with
  | nil =>
      exact Or.inl (by simpa [pathRoot] using equalRoots)
  | @cons left right xs ys same rest ih =>
      have eqNext :
          pathRoot node xs (hashStep node left x) =
            pathRoot node ys (hashStep node right y) := by
        simpa [pathRoot] using equalRoots
      rcases ih (hashStep node left x) (hashStep node right y) eqNext with eq | collision
      · by_cases hxy : x = y
        · exact Or.inl hxy
        · right
          cases hl : left.siblingOnLeft with
          | false =>
              have hr : right.siblingOnLeft = false := same.symm.trans hl
              refine ⟨x, left.siblingHash, y, right.siblingHash, ?_, ?_⟩
              · intro h
                exact hxy (congrArg Prod.fst h)
              · simpa [hashStep, hl, hr] using eq
          | true =>
              have hr : right.siblingOnLeft = true := same.symm.trans hl
              refine ⟨left.siblingHash, x, right.siblingHash, y, ?_, ?_⟩
              · intro h
                exact hxy (congrArg Prod.snd h)
              · simpa [hashStep, hl, hr] using eq
      · exact Or.inr collision

def verifiesRoot (leaf : Nat → Nat) (node : Nat → Nat → Nat)
    (rootTag : Nat → Nat → Nat) (chunkCount root chunk : Nat)
    (siblings : List Sibling) : Prop :=
  rootTag chunkCount (pathRoot node siblings (leaf chunk)) = root

/-- Main binding reduction: for the same chunk index (same orientation),
two successfully verified openings of DIFFERENT payloads require a
SHA256-family collision. It never assumes hash injectivity as an axiom. -/
theorem two_verified_openings_imply_collision
    (leaf : Nat → Nat) (node : Nat → Nat → Nat)
    (rootTag : Nat → Nat → Nat) (n root x y : Nat)
    (a b : List Sibling) (hOrient : SameDirections a b)
    (h1 : verifiesRoot leaf node rootTag n root x a)
    (h2 : verifiesRoot leaf node rootTag n root y b)
    (distinct : x ≠ y) :
    LeafCollision leaf ∨ NodeCollision node ∨ RootCollision rootTag n := by
  unfold verifiesRoot at h1 h2
  by_cases sameTop : pathRoot node a (leaf x) = pathRoot node b (leaf y)
  · rcases parallel_path_collision_or_equal node hOrient (leaf x) (leaf y) sameTop with eqLeaf | coll
    · exact Or.inl ⟨x, y, distinct, eqLeaf⟩
    · exact Or.inr (Or.inl coll)
  · exact Or.inr (Or.inr ⟨_, _, sameTop, h1.trans h2.symm⟩)

/-- Conditional corollary under the exact collision-free event for this
commitment. No probabilistic SHA256 claim is being made inside Lean. -/
theorem unique_chunk_if_collision_free
    (leaf : Nat → Nat) (node : Nat → Nat → Nat)
    (rootTag : Nat → Nat → Nat) (n root x y : Nat)
    (a b : List Sibling) (hOrient : SameDirections a b)
    (h1 : verifiesRoot leaf node rootTag n root x a)
    (h2 : verifiesRoot leaf node rootTag n root y b)
    (noLeaf : ¬ LeafCollision leaf)
    (noNode : ¬ NodeCollision node)
    (noRoot : ¬ RootCollision rootTag n) :
    x = y := by
  by_cases h : x = y
  · exact h
  · rcases two_verified_openings_imply_collision leaf node rootTag n root x y a b
      hOrient h1 h2 h with badLeaf | badNode | badRoot
    · exact False.elim (noLeaf badLeaf)
    · exact False.elim (noNode badNode)
    · exact False.elim (noRoot badRoot)

/-- A receipt policy for epoch payment: accepting evidence is a separate
condition from merely observing Lightning value movement. -/
structure OffchainReceipt where
  invoiceSettled : Bool
  sampledOpeningVerified : Bool
  deriving Repr

def clientPolicyPays (r : OffchainReceipt) : Prop :=
  r.invoiceSettled = true ∧ r.sampledOpeningVerified = true

def externalLightningPaymentObserved (r : OffchainReceipt) : Prop :=
  r.invoiceSettled = true

def prematureReceipt : OffchainReceipt :=
  { invoiceSettled := true, sampledOpeningVerified := false }

/-- An ordinary paid invoice, without a client-side check, is not evidence
of storage correctness. This prevents importing a false on-chain guarantee. -/
theorem lightning_alone_does_not_certify_storage :
    externalLightningPaymentObserved prematureReceipt ∧
    ¬ clientPolicyPays prematureReceipt := by
  simp [externalLightningPaymentObserved, clientPolicyPays, prematureReceipt]

end BlossomFormal
