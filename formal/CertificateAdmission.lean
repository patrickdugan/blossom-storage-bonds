/-
ADR-015: certificate admission and collateral binding as security games.

Core Lean 4 only: no Mathlib, no `sorry`, no `admit`, no `axiom`. `#print axioms` on the main theorems
shows at most Lean's standard `propext`, `Quot.sound` and `Classical.choice`. Every protocol or
cryptographic fact is a *hypothesis* (a structure field or a theorem argument), never a postulate:

  A1 `Env.valid` stands for the full certificate check: PoW on every header, linkage to the
     checkpoint, exact cumulative work, and BIP141 inclusion of the certificate. It is external.
  A2 `Graph.leaf` sound and complete for "timely, valid and stronger than the frozen claim". Bitcoin
     Core 26 tapscript cannot realise this leaf (ADR-015 vectors L1-L3).
  A3 Exclusive exits: the bond has no spend path beyond the refutation and refund leaves (L6 shows a
     hidden leaf breaks this; it must be audited over every leaf and the keypath).
  A4 Mining liveness: a refutation broadcast in time confirms before the deadline. Without it a late
     refutation races the refund (`late_refutation_can_lose`).
  A5 Key erasure: only the presigned signatures exist for setup keys (`Presigned.erased`).
  A6 SHA256 and BIP340 security are folded into A2 and A5; nothing here proves hardness.

Safety, liveness and incentives are separate theorems below. These are statements about a model.
`ADR-015 vectors` are the real Bitcoin Core evidence for which hypotheses current Script can meet.
-/
namespace BSB.Admission

/-! ## Objects -/

/-- A stronger-fork certificate as the protocol sees it: an identity, its claimed exact cumulative
work, and the height at which its evidence was confirmed. -/
structure Cert where
  id : Nat
  work : Nat
  time : Nat

/-- External environment (A1): what counts as a valid certificate, the admission cutoff, and the
deadline after which the provider's refund leaf (CLTV) becomes valid. -/
structure Env where
  valid : Cert → Prop
  cutoff : Nat
  deadline : Nat

/-- The refutation predicate for a provider claim frozen at work `w`. -/
def TimelyStronger (E : Env) (w : Nat) (c : Cert) : Prop :=
  E.valid c ∧ w < c.work ∧ c.time ≤ E.cutoff

/-! ## Game 1: stateless existential refutation of a frozen claim (ADR-002) -/

/-- Confirmed spends of the bond outpoint, with the block height each would confirm at. -/
inductive Spend where
  | refute (c : Cert) (height : Nat)
  | refund (height : Nat)
  | hidden (height : Nat)

def Spend.height : Spend → Nat
  | .refute _ h => h
  | .refund h => h
  | .hidden h => h

/-- The spending graph. `leaf` is the refutation leaf's acceptance relation; `hiddenPath` says whether
an unaudited spend path exists. -/
structure Graph where
  leaf : Cert → Prop
  hiddenPath : Prop

/-- Which spends Bitcoin would accept: the refutation leaf has no timelock, the refund leaf has a CLTV
at the deadline, and a hidden path is valid whenever it exists. -/
def Admissible (E : Env) (G : Graph) : Spend → Prop
  | .refute c _ => G.leaf c
  | .refund h => E.deadline ≤ h
  | .hidden _ => G.hiddenPath

/-- A2 as hypotheses. -/
structure LeafSpec (E : Env) (G : Graph) (w : Nat) : Prop where
  sound : ∀ c, G.leaf c → TimelyStronger E w c
  complete : ∀ c, TimelyStronger E w c → G.leaf c

/-- One outpoint is spent once: the settlement is the first admissible spend in confirmation order. -/
inductive First (P : Spend → Prop) : List Spend → Spend → Prop where
  | here {s : Spend} {l : List Spend} : P s → First P (s :: l) s
  | skip {s t : Spend} {l : List Spend} : ¬ P s → First P l t → First P (s :: l) t

/-- Confirmation order: heights never decrease. -/
def Ordered : List Spend → Prop
  | [] => True
  | [_] => True
  | a :: b :: l => a.height ≤ b.height ∧ Ordered (b :: l)

theorem ordered_tail {a : Spend} {l : List Spend} (h : Ordered (a :: l)) : Ordered l := by
  cases l with
  | nil => trivial
  | cons b l => exact h.2

theorem ordered_head_le {a x : Spend} {l : List Spend} (h : Ordered (a :: l)) (hx : x ∈ l) :
    a.height ≤ x.height := by
  induction l generalizing a with
  | nil => cases hx
  | cons b l ih =>
    have hab : a.height ≤ b.height := h.1
    cases List.mem_cons.mp hx with
    | inl e => subst e; exact hab
    | inr hm => exact Nat.le_trans hab (ih h.2 hm)

theorem first_admissible {P : Spend → Prop} {l : List Spend} {s : Spend} (h : First P l s) : P s := by
  induction h with
  | here hp => exact hp
  | skip _ _ ih => exact ih

theorem first_mem {P : Spend → Prop} {l : List Spend} {s : Spend} (h : First P l s) : s ∈ l := by
  induction h with
  | here _ => exact List.Mem.head _
  | skip _ _ ih => exact List.Mem.tail _ ih

/-- **Client safety.** With exclusive exits (A3), a sound refutation leaf, and a refutation that
confirms before the deadline (A4), the bond settles by refutation (some refutation, possibly an
earlier one), never by refund. -/
theorem client_safety (E : Env) (G : Graph) (l : List Spend) (s : Spend) (c : Cert) (h : Nat)
    (excl : ¬ G.hiddenPath) (hleaf : G.leaf c) (hdl : h < E.deadline)
    (hin : Spend.refute c h ∈ l) (hord : Ordered l) (hfirst : First (Admissible E G) l s) :
    ∃ c' h', s = Spend.refute c' h' := by
  induction hfirst with
  | @here s l hp =>
    cases s with
    | refute c' h' => exact ⟨c', h', rfl⟩
    | refund h0 =>
      exfalso
      have hd : E.deadline ≤ h0 := hp
      cases List.mem_cons.mp hin with
      | inl e => cases e
      | inr hm =>
        have : h0 ≤ h := ordered_head_le hord hm
        exact Nat.lt_irrefl _ (Nat.lt_of_le_of_lt (Nat.le_trans hd this) hdl)
    | hidden _ => exact absurd hp excl
  | @skip s t l hnp _ ih =>
    cases List.mem_cons.mp hin with
    | inl e => subst e; exact absurd hleaf hnp
    | inr hm => exact ih hm (ordered_tail hord)

/-- **Provider safety.** A refutation settlement implies a timely, valid, stronger certificate (A2
soundness). An honest provider whose frozen claim is at least every timely valid work is never
forfeited, whatever the order of spends. -/
theorem provider_safety (E : Env) (G : Graph) (w : Nat) (spec : LeafSpec E G w)
    (honest : ∀ c, ¬ TimelyStronger E w c) (l : List Spend) (c : Cert) (h : Nat) :
    ¬ First (Admissible E G) l (Spend.refute c h) := by
  intro hf
  exact honest c (spec.sound c (first_admissible hf))

/-- If some element of a list is admissible, a first admissible element exists (classical). -/
theorem first_exists {P : Spend → Prop} {l : List Spend} {x : Spend} (hx : x ∈ l) (hp : P x) :
    ∃ s, First P l s := by
  induction l with
  | nil => cases hx
  | cons a l ih =>
    by_cases ha : P a
    · exact ⟨a, First.here ha⟩
    · cases List.mem_cons.mp hx with
      | inl e => subst e; exact absurd hp ha
      | inr hm =>
        obtain ⟨s, hs⟩ := ih hm
        exact ⟨s, First.skip ha hs⟩

/-- **Provider liveness.** With exclusive exits, a sound leaf and an honest claim, a refund confirmed
at or after the deadline makes the settlement a refund. -/
theorem provider_liveness (E : Env) (G : Graph) (w : Nat) (spec : LeafSpec E G w)
    (excl : ¬ G.hiddenPath) (honest : ∀ c, ¬ TimelyStronger E w c)
    (l : List Spend) (d : Nat) (hd : E.deadline ≤ d) (hin : Spend.refund d ∈ l) :
    ∃ s, First (Admissible E G) l s ∧ ∃ h', s = Spend.refund h' := by
  obtain ⟨s, hs⟩ := first_exists hin (show Admissible E G (Spend.refund d) from hd)
  refine ⟨s, hs, ?_⟩
  have hp := first_admissible hs
  cases s with
  | refute c h => exact absurd (spec.sound c hp) (honest c)
  | refund h' => exact ⟨h', rfl⟩
  | hidden _ => exact absurd hp excl

/-- **A4 is necessary.** A refutation that confirms at the deadline races the refund, and miners pick
the order: here a timely, valid, stronger certificate exists and the provider still refunds. -/
def lateEnv : Env := { valid := fun _ => True, cutoff := 5, deadline := 10 }
def lateGraph : Graph := { leaf := fun c => 3 < c.work ∧ c.time ≤ 5, hiddenPath := False }
def lateCert : Cert := { id := 1, work := 9, time := 4 }

theorem late_refutation_can_lose :
    TimelyStronger lateEnv 3 lateCert ∧
    First (Admissible lateEnv lateGraph) [Spend.refund 10, Spend.refute lateCert 10] (Spend.refund 10) := by
  refine ⟨⟨trivial, by decide, by decide⟩, First.here ?_⟩
  show 10 ≤ 10
  exact Nat.le_refl _

/-- **A3 is necessary** (the L6 vector in the abstract). One unaudited leaf drains the bond before a
valid, timely refutation, even though the refutation leaf is sound and complete. -/
def hiddenGraph : Graph := { leaf := fun c => 3 < c.work ∧ c.time ≤ 5, hiddenPath := True }

theorem hidden_path_breaks_safety :
    First (Admissible lateEnv hiddenGraph) [Spend.hidden 1, Spend.refute lateCert 2] (Spend.hidden 1) :=
  First.here trivial

/-! ## Game 2: the mutable strongest-certificate journal (ADR-001), as a specification -/

/-- Decidable validity for the journal fold. -/
structure JEnv where
  valid : Cert → Bool
  cutoff : Nat

def admitStep (E : JEnv) (best : Nat) (c : Cert) : Nat :=
  if E.valid c = true ∧ best < c.work ∧ c.time ≤ E.cutoff then c.work else best

def journal (E : JEnv) (best : Nat) (cs : List Cert) : Nat := cs.foldl (admitStep E) best

theorem step_ge (E : JEnv) (b : Nat) (c : Cert) : b ≤ admitStep E b c := by
  unfold admitStep
  split
  · next h => exact Nat.le_of_lt h.2.1
  · exact Nat.le_refl _

/-- A weaker or equal certificate never replaces the stored state. -/
theorem weaker_never_replaces (E : JEnv) (b : Nat) (c : Cert) (h : c.work ≤ b) : admitStep E b c = b := by
  unfold admitStep
  split
  · next hc => exact absurd hc.2.1 (Nat.not_lt.mpr h)
  · rfl

theorem step_ge_cert (E : JEnv) (b : Nat) (c : Cert) (hv : E.valid c = true) (ht : c.time ≤ E.cutoff) :
    c.work ≤ admitStep E b c := by
  by_cases hlt : b < c.work
  · unfold admitStep
    rw [if_pos ⟨hv, hlt, ht⟩]
    exact Nat.le_refl _
  · exact Nat.le_trans (Nat.not_lt.mp hlt) (step_ge E b c)

theorem journal_ge_init (E : JEnv) (b : Nat) (cs : List Cert) : b ≤ journal E b cs := by
  induction cs generalizing b with
  | nil => exact Nat.le_refl _
  | cons c cs ih => exact Nat.le_trans (step_ge E b c) (ih (admitStep E b c))

/-- The journal's final work is at least that of every valid timely certificate it saw, in any
order. This is the property ADR-001 needs Bitcoin to enforce; Game 3 shows a fixed graph cannot. -/
theorem journal_ge (E : JEnv) (b : Nat) (cs : List Cert) (c : Cert) (hin : c ∈ cs)
    (hv : E.valid c = true) (ht : c.time ≤ E.cutoff) : c.work ≤ journal E b cs := by
  induction cs generalizing b with
  | nil => cases hin
  | cons d cs ih =>
    cases List.mem_cons.mp hin with
    | inl e =>
      subst e
      exact Nat.le_trans (step_ge_cert E b c hv ht) (journal_ge_init E _ cs)
    | inr hm => exact ih (admitStep E b d) hm

/-! ## Game 3: what a fixed spending graph can enforce -/

def maxList : List Nat → Nat
  | [] => 0
  | x :: l => if x ≤ maxList l then maxList l else x

theorem maxList_head (x : Nat) (l : List Nat) : x ≤ maxList (x :: l) := by
  simp only [maxList]; split <;> omega

theorem maxList_tail (x : Nat) (l : List Nat) : maxList l ≤ maxList (x :: l) := by
  simp only [maxList]; split <;> omega

theorem le_maxList {x : Nat} {l : List Nat} (h : x ∈ l) : x ≤ maxList l := by
  induction l with
  | nil => cases h
  | cons y l ih =>
    cases List.mem_cons.mp h with
    | inl e => subst e; exact maxList_head _ _
    | inr hm => exact Nat.le_trans (ih hm) (maxList_tail _ _)

/-- Without an output-introspection covenant, the successor of a journal UTXO is either one of the
templates presigned at setup (each fixing the journal state it carries), or whatever the spender
writes. `templates` lists the journal works the presigned successors can carry. -/
structure FixedGraph where
  templates : List Nat

/-- **Journal incompleteness.** If timely valid certificates of arbitrarily high work can exist, then
for every fixed graph some such certificate has no presigned successor. The graph must either refuse it
(admission is incomplete) or admit it through a spender-chosen output, which the spender can also pay
to itself (collateral not bound, as in vector L4). In Bitcoin, works are bounded but outnumber any
presigned list; the same argument applies to any certificate set larger than `templates`. -/
theorem fixed_graph_misses (E : Env) (G : FixedGraph)
    (unbounded : ∀ n, ∃ c, E.valid c ∧ n ≤ c.work ∧ c.time ≤ E.cutoff) :
    ∃ c, E.valid c ∧ c.time ≤ E.cutoff ∧ c.work ∉ G.templates := by
  obtain ⟨c, hv, hw, ht⟩ := unbounded (maxList G.templates + 1)
  refine ⟨c, hv, ht, fun hm => ?_⟩
  have := le_maxList hm
  exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le (Nat.lt_of_lt_of_le (Nat.lt_succ_self _) hw) this)

/-- The same bound for a leaf that recognises only setup-enumerated certificates (vector
L5/new_certificate_after_setup): a stronger certificate outside the list exists. -/
theorem enumerated_leaf_incomplete (E : Env) (S : List Cert)
    (unbounded : ∀ n, ∃ c, E.valid c ∧ n ≤ c.work ∧ c.time ≤ E.cutoff) :
    ∃ c, E.valid c ∧ c.time ≤ E.cutoff ∧ c ∉ S := by
  obtain ⟨c, hv, ht, hnot⟩ := fixed_graph_misses E ⟨S.map Cert.work⟩ unbounded
  refine ⟨c, hv, ht, fun hm => hnot ?_⟩
  exact List.mem_map.mpr ⟨c, hm, rfl⟩

/-! ## Game 4: binding the verdict to the payout -/

/-- A spend of the bond, reduced to what matters here: the witness and output 0. -/
structure Tx where
  witness : Nat
  out0 : Nat

/-- A leaf whose acceptance doesn't depend on the outputs (no signature, no covenant). -/
def OutputBlind (acc : Tx → Prop) : Prop := ∀ t t' : Tx, t.witness = t'.witness → (acc t ↔ acc t')

/-- **Front-running** (vector L4): any accepted spend of an output-blind leaf stays accepted with
output 0 redirected, so whoever sees the certificate first can take the bond. -/
theorem copy_redirect {acc : Tx → Prop} (blind : OutputBlind acc) {t : Tx} (ht : acc t) (a : Nat) :
    acc { t with out0 := a } :=
  (blind t { t with out0 := a } rfl).mp ht

/-- A setup key's SIGHASH_SINGLE|ANYONECANPAY signature, with A5 as a field: every signature that
verifies commits to the same output 0. -/
structure Presigned where
  fixedOut : Nat
  sigOk : Tx → Prop
  erased : ∀ t, sigOk t → t.out0 = fixedOut

/-- **Payout binding** (vector L5): with a presigned signature in the leaf, an accepted spend pays the
fixed output 0. The binding holds only for verdicts enumerated at setup (Game 3). -/
theorem presigned_binds (P : Presigned) (leafOk : Nat → Prop) (t : Tx)
    (h : leafOk t.witness ∧ P.sigOk t) : t.out0 = P.fixedOut :=
  P.erased t h.2

/-! ## Game 5: chunked verification is permissioned -/

/-- A verifier too large for one transaction is split across transactions, and each chunk's inputs
must be bound to the previous chunk's outputs. Without OP_CAT or a covenant, that binding is a
one-time signature (Winternitz/Lamport) whose public key is in a leaf fixed at setup. -/
structure Chunked where
  keys : List Nat

def CanCommit (C : Chunked) (k : Nat) : Prop := k ∈ C.keys

/-- **Outsiders exist.** A challenger whose commitment key wasn't placed at setup can't drive a
chunked dispute over its own certificate. Admission is limited to the setup set, as with Clementine's
watchtowers. -/
theorem outsider_exists (C : Chunked) : ∃ k, ¬ CanCommit C k :=
  ⟨maxList C.keys + 1, fun h => Nat.lt_irrefl _ (Nat.lt_of_lt_of_le (Nat.lt_succ_self _) (le_maxList h))⟩

/-! ## Fixed-difficulty refinement (ADR-016)

On a fixed-target chain (regtest: nBits 0x207fffff, no retarget) every valid header carries the same
work `w > 0`, so a chain of `n` headers has work `n * w`. The ADR-016 OP_CAT leaf accepts exactly `N`
linked, target-meeting headers from the checkpoint. This was observed in Core 26 with the BIP347 patch
and is a premise here, not proved about Script. That leaf is sound for the frozen claim "at most
`N - 1` headers" in this sense: -/

def chainWork (w n : Nat) : Nat := n * w

/-- `N` headers are strictly stronger than a claim of `N - 1`. -/
theorem exactN_stronger (w N : Nat) (hw : 0 < w) (hN : 0 < N) :
    chainWork w (N - 1) < chainWork w N := by
  unfold chainWork
  cases N with
  | zero => exact absurd hN (Nat.lt_irrefl 0)
  | succ k =>
    show k * w < (k + 1) * w
    rw [Nat.succ_mul]
    exact Nat.lt_add_of_pos_right hw

/-- The bridge from the leaf's acceptance to A2's soundness. If the leaf accepts only certificates
whose work is `N * w`, then every accepted certificate refutes the frozen claim `(N - 1) * w`. Validity
and timeliness (`E.valid`, `c.time ≤ E.cutoff`) remain separate premises: the ADR-016 leaf checks PoW
and linkage, but not BIP141 inclusion or a cutoff. -/
theorem exactN_leaf_sound (E : Env) (G : Graph) (w N : Nat) (hw : 0 < w) (hN : 0 < N)
    (work_of_leaf : ∀ c, G.leaf c → c.work = chainWork w N)
    (valid_timely : ∀ c, G.leaf c → E.valid c ∧ c.time ≤ E.cutoff) :
    ∀ c, G.leaf c → TimelyStronger E (chainWork w (N - 1)) c := by
  intro c hc
  obtain ⟨hv, ht⟩ := valid_timely c hc
  exact ⟨hv, by rw [work_of_leaf c hc]; exact exactN_stronger w N hw hN, ht⟩

/-! ## Incentives (economic layer, distinct from safety and liveness) -/

/-- Provider payoff from the settlement: the bond `B` on refund, nothing otherwise. -/
def providerPayoff (B : Nat) : Spend → Nat
  | .refund _ => B
  | _ => 0

/-- **Incentive compatibility.** Under Game 1's hypotheses, a truthful claim (at least every timely
valid work) keeps the bond once a refund confirms, and a claim beaten by a timely refutation that
confirms before the deadline loses it. Claiming the true maximum is therefore weakly dominant for the
provider. This rests on A4: a challenger with cost below its reward is assumed to broadcast in time. -/
theorem truthful_keeps_bond (E : Env) (G : Graph) (w B : Nat) (spec : LeafSpec E G w)
    (excl : ¬ G.hiddenPath) (honest : ∀ c, ¬ TimelyStronger E w c)
    (l : List Spend) (d : Nat) (hd : E.deadline ≤ d) (hin : Spend.refund d ∈ l) :
    ∃ s, First (Admissible E G) l s ∧ providerPayoff B s = B := by
  obtain ⟨s, hs, h', e⟩ := provider_liveness E G w spec excl honest l d hd hin
  exact ⟨s, hs, by subst e; rfl⟩

theorem underclaim_forfeits (E : Env) (G : Graph) (w B : Nat) (spec : LeafSpec E G w)
    (excl : ¬ G.hiddenPath) (c : Cert) (hc : TimelyStronger E w c) (h : Nat) (hdl : h < E.deadline)
    (l : List Spend) (hin : Spend.refute c h ∈ l) (hord : Ordered l) (s : Spend)
    (hf : First (Admissible E G) l s) : providerPayoff B s = 0 := by
  obtain ⟨c', h', e⟩ := client_safety E G l s c h excl (spec.complete c hc) hdl hin hord hf
  subst e
  rfl

end BSB.Admission
