# LayerTree MID ↔ FROST Taproot: authorization gap

**Research note — 24 October 2026.** Scope: `blossom-storage-bonds` draft PR #5,
`patrickdugan/sapio` PR #1 (pinned `34363851a11d0f2b3ddb27c050537c1a2e5b7e9b`),
and Sapio's separate signed VTXO recovery PR #2.

## Demonstrated Bitcoin ledger

The physical B regtest is now a genuine P2TR keyspend funded with
100,000 sats, using ephemeral 2-of-3 `frost-secp256k1-tr=3.0.0`
shares, BIP341 sighashes, a correctly tweaked group key, and a
distinct Bitcoin Core fee sponsor. It confirms a refresh and
60,000/40,000-sat settlement. Each recipient subsequently confirms
an independently signed wallet PSBT (59k/39k sats after one 1k
satoshi beneficiary-spend fee each). The original pooled carrier
cannot be spent by either ordinary holder wallet without the threshold
authorization. All signing shares in this fixture still live in one
process; actual distributed custody is untested.

Two shares also authorize a **different** transaction redirecting the
entire 100k principal, valid under Bitcoin Core's mempool policy.
That transaction is **not** broadcast. This is not a cryptographic
failure of FROST: it is precisely what control of a threshold
aggregate key permits. The source Blossom Merkle verifier may
simultaneously have a valid proof of storage.

## Two independent authorization predicates

For the current FROST P2TR output, Bitcoin accepts a keypath spend
according to the authorized transaction's actual BIP341 signature:

```text
BitcoinAccept(tx) = VerifyBIP340(Q_tweaked, SIGHASH_BIP341(tx), signature_Q)
```

An experimental LayerTree MID state transition instead requires,
among other predicates, authenticated current leaf/root membership,
the owner's explicit authorized operation, conservation of the
Merkle-sum principal, a matching successor root, appropriate
lease/sequence constraints and exact outputs:

```text
MidAccept(state, tx, witness) =
  VerifyMemberProof ∧ Owner/OperatorAuthorization ∧
  PreserveMerkleSum ∧ VerifySuccessor ∧ MatchOutputs ∧
  EnforceLeaseAndVoucherPolicy
```

**There is no implication** from the first predicate to the second.
The present B wallet can sign arbitrary BIP341 transactions under
its FROST threshold. An OP_RETURN with an application state digest
does not turn that digest into a Bitcoin-enforced covenant.

Sapio's pinned MID guest does execute an experimental transition
predicate, but its actual Bitcoin wrapper remains signed by an
emulation oracle. Bitcoin does not directly execute the new opcodes.
If the wrapper's signer signs a transaction without a legitimate
guest verdict, consensus alone cannot detect that violation.

Likewise, putting MID wrapper leaves alongside an independently
spendable FROST **keypath** does not prevent the threshold from
bypassing the leaves. Excluding the keypath with an appropriate
NUMS construction avoids one bypass but is insufficient if a
malicious online oracle can independently authorize a wrapper leaf.

## Holder custody has two distinct states

| Stage | Alice | Bob | Material Bitcoin security condition |
| --- | --- | --- | --- |
| Shared 100k-sat carrier | Cannot authorize a solo keypath spend | Same | Threshold signature remains necessary under this design |
| After threshold-approved 60k/40k split | Can spend own 60k output | Can spend own 40k output | Each independent holder wallet signs its one-input PSBT |
| After quorum permanently disappears **before** split | Not demonstrated | Not demonstrated | Need prior frozen recovery witness, online replacement, or consensus-enforceable unilateral leaf |

The post-split independent spend satisfies **custody after
settlement** only. It is not a SaplingOS-style service-dead recovery
proof. A valid offline recovery requires preservation of signed
transaction ancestry, beneficiary scripts, the correct current VTXO
generation and fee funding after the federation disappears.

## Pinned Sapio MID test boundary

Sapio PR #1 contains actual guest tests for sequential 60k/40k
owner-signed EXITs, restart-persisted signing reservations and a
historical owner/nonce voucher-replay counterexample. Those tests
still employ its **online oracle**; they neither consume the
actual B FROST Bitcoin carrier nor bind a real storage-fault
proof to a consensus-enforced payout decision. The isolated
`layertree-mid-pinned-interop.yml` workflow tests this boundary
without blending it into the actual FROST result.

## Required next integration gates

1. Bind independently frozen Alice/Bob terms, producer deal IDs,
   exact beneficiary scripts and storage evidence hashes to the
   actual MID predecessor/successor roots. Re-derive the Merkle-sum
   total from those terms, rather than trusting an OP_RETURN or
   the B-only state-machine model.
2. Execute both legal exits and illegal historical voucher reuse
   through the pinned real MID guest. Require owner signatures and
   assert the unrelated owner's key is never needed, with the
   online oracle explicitly identified.
3. Audit *all* actual Bitcoin spend paths: threshold keypath,
   oracle wrapper leaves, change outputs, refunds, timelock
   alternatives and fee-sponsor input ownership. Find a physical
   Bitcoin-invalid unauthorized spend, not merely an application
   model that declines to sign.
4. Freeze real signed VTXO recovery evidence and prove post-outage
   independent claims in Bitcoin Core when the FROST and oracle
   processes are both unavailable, including shared-root ancestry
   and a third-party funded CPFP fee child.
5. Replace one-process trusted-dealer shares with authenticated
   independent signer processes, nonce round coordination and
   durable anti-rollback/anti-replay state.
6. Normalize A/B challenge timing, recipient-economic disposition
   and observed chain fees. Only then start controlled Signet trials
   with disposable funded wallets and a documented fee ceiling.

## Claims explicitly not established

- That Filecoin WindowPoSt absence is independently established by
  a Bitcoin consensus-verifiable witness
- That B's keypath is restricted to a valid LayerTree MID transition
- That two colluding FROST shares cannot steal pooled collateral
- That a holder can exit a shared P2TR carrier while every signer
  and Sapio oracle is offline
- That the reference A/B simulations predict comparable network
  transaction latency, fees or economically enforceable protection

Further engineering should preserve the already passing actual
FROST keypath and beneficiary-PSBT checks as adversarial fixtures,
not replace them with a fresh abstract model.
