import Blossom

/-!
A channel-side refinement of Blossom pay-per-proof economics.

This models the independent one-way regtest channel in layer1/channel.ts
and regtest/src/bin/bond.rs. The channel is NOT a Lightning channel.

A client authorizes a monotonically increasing cumulative provider payment
after checking nonempty, deal/root-bound Merkle sampling. The provider may
close with the latest valid co-signed state. After a CLTV maturity condition,
the client can alternatively spend the unclosed channel by its refund leaf.

All Schnorr signatures, Bitcoin transactions, invoice preimages, channel
funding, finality, persistence and miner inclusion are EXTERNAL obligations.
In particular, CLTV makes refund available; it does not remove a still-valid
cooperative close from the UTXO set. The model preserves that race.
-/

namespace BlossomFormal

inductive ChannelPhase where
  | open
  | providerClosed
  | clientRefunded
  deriving DecidableEq, Repr

structure Channel where
  phase : ChannelPhase
  dealId : Nat
  rootCommitment : Nat
  locked : Nat
  providerReceived : Nat
  clientReceived : Nat
  minerFees : Nat
  closeFee : Nat
  promisedProvider : Nat
  authorizedEpochs : List Nat
  deriving Repr

def channelTotal (s : Channel) : Nat :=
  s.locked + s.providerReceived + s.clientReceived + s.minerFees

def channelFund (capacity fee deal root : Nat) : Channel :=
  { phase := .open, dealId := deal, rootCommitment := root,
    locked := capacity, providerReceived := 0, clientReceived := 0,
    minerFees := 0, closeFee := fee, promisedProvider := 0,
    authorizedEpochs := [] }

/-- A channel signature itself only authorizes a value promise. Signing a
new cumulative state does not move Bitcoin UTXOs until the close confirms.
The proof-to-channel link is currently an abstract acceptance predicate. -/
inductive ChannelStep : Channel → Channel → Prop where
  | authorize (s : Channel) (p : StorageProof) (increment : Nat)
      (isOpen : s.phase = .open)
      (valid : accepts p) (nonempty : p.sampled ≠ [])
      (deal : p.dealId = s.dealId)
      (root : p.rootCommitment = s.rootCommitment)
      (fresh : p.epochId ∉ s.authorizedEpochs)
      (positive : increment > 0)
      (capacity : s.promisedProvider + increment + s.closeFee ≤ s.locked)
      (clientSigned : Prop) (verified : clientSigned) :
      ChannelStep s { s with promisedProvider := s.promisedProvider + increment, authorizedEpochs := p.epochId :: s.authorizedEpochs }
  | close (s : Channel)
      (isOpen : s.phase = .open)
      (capacity : s.promisedProvider + s.closeFee ≤ s.locked)
      (providerSignature clientSignature : Prop)
      (both : providerSignature ∧ clientSignature) :
      ChannelStep s { s with phase := ChannelPhase.providerClosed, locked := 0, providerReceived := s.providerReceived + s.promisedProvider, clientReceived := s.clientReceived + (s.locked - s.promisedProvider - s.closeFee), minerFees := s.minerFees + s.closeFee }
  | timeoutRefund (s : Channel)
      (isOpen : s.phase = .open)
      (feeAffordable : s.closeFee ≤ s.locked)
      (matured clientSignature : Prop)
      (both : matured ∧ clientSignature) :
      ChannelStep s { s with phase := ChannelPhase.clientRefunded, locked := 0, clientReceived := s.clientReceived + (s.locked - s.closeFee), minerFees := s.minerFees + s.closeFee }

theorem funded_channel_value (capacity fee deal root : Nat) :
    channelTotal (channelFund capacity fee deal root) = capacity := by
  simp [channelTotal, channelFund]

theorem step_preserves_channel_capacity {s t : Channel}
    (h : ChannelStep s t) : channelTotal s = channelTotal t := by
  cases h <;> simp [channelTotal] <;> omega

theorem signed_cumulative_value_is_monotone {s t : Channel}
    (h : ChannelStep s t) : s.promisedProvider ≤ t.promisedProvider := by
  cases h <;> simp

theorem no_channel_step_after_terminal {s t : Channel}
    (h : ChannelStep s t)
    (terminal : s.phase = .providerClosed ∨ s.phase = .clientRefunded) :
    False := by
  cases h <;> simp_all

theorem channel_step_preserves_deal {s t : Channel}
    (h : ChannelStep s t) :
    s.dealId = t.dealId ∧ s.rootCommitment = t.rootCommitment := by
  cases h <;> simp

theorem channel_step_preserves_authorized_epoch {s t : Channel}
    (h : ChannelStep s t) (epoch : Nat)
    (already : epoch ∈ s.authorizedEpochs) :
    epoch ∈ t.authorizedEpochs := by
  cases h <;> simp_all

/-- Every increased signed payment corresponds to a positive amount and
nonempty valid evidence bound to this deal and an unused epoch ID. -/
theorem payment_increase_requires_accepted_epoch
    {s t : Channel} (h : ChannelStep s t)
    (increase : s.promisedProvider ≠ t.promisedProvider) :
    ∃ p : StorageProof, accepts p ∧ p.sampled ≠ [] ∧
      p.dealId = s.dealId ∧ p.rootCommitment = s.rootCommitment ∧
      p.epochId ∉ s.authorizedEpochs := by
  cases h with
  | authorize p _ _ valid nonempty deal root fresh _ _ _ _ =>
      exact ⟨p,valid,nonempty,deal,root,fresh⟩
  | close _ _ _ _ _ => exact False.elim (increase rfl)
  | timeoutRefund _ _ _ _ _ => exact False.elim (increase rfl)

inductive ChannelReach : Channel → Channel → Prop where
  | refl (s : Channel) : ChannelReach s s
  | advance {a b c : Channel} (history : ChannelReach a b)
      (step : ChannelStep b c) : ChannelReach a c

theorem channel_history_preserves_capacity {start finish : Channel}
    (h : ChannelReach start finish) :
    channelTotal start = channelTotal finish := by
  induction h with
  | refl => rfl
  | advance history step ih => exact ih.trans (step_preserves_channel_capacity step)

theorem channel_history_promised_monotone {start finish : Channel}
    (h : ChannelReach start finish) :
    start.promisedProvider ≤ finish.promisedProvider := by
  induction h with
  | refl => exact Nat.le_refl _
  | advance history step ih =>
      exact Nat.le_trans ih (signed_cumulative_value_is_monotone step)

theorem channel_history_remembers_epoch {start finish : Channel}
    (h : ChannelReach start finish) (epoch : Nat)
    (already : epoch ∈ start.authorizedEpochs) :
    epoch ∈ finish.authorizedEpochs := by
  induction h with
  | refl => exact already
  | advance history step ih =>
      exact channel_step_preserves_authorized_epoch step epoch ih

theorem channel_authorization_replay_excluded {start finish : Channel}
    (h : ChannelReach start finish) (epoch : Nat)
    (already : epoch ∈ start.authorizedEpochs) :
    ¬ (epoch ∉ finish.authorizedEpochs) := by
  intro claim
  exact claim (channel_history_remembers_epoch h epoch already)

/-- The script path and the client CLTV refund path both remain available
after the deadline until one spends the same channel UTXO. This is the
actual race to be resolved by transaction inclusion and service liveness. -/
def mayClose (s : Channel) (clientSigned providerSigned : Bool) : Prop :=
  s.phase = .open ∧ clientSigned = true ∧ providerSigned = true

def mayRefund (s : Channel) (deadlineReached clientSigned : Bool) : Prop :=
  s.phase = .open ∧ deadlineReached = true ∧ clientSigned = true

theorem refund_maturity_does_not_disable_provider_close
    (s : Channel) (hOpen : s.phase = .open) :
    mayClose s true true ∧ mayRefund s true true := by
  simp [mayClose, mayRefund, hOpen]

end BlossomFormal
