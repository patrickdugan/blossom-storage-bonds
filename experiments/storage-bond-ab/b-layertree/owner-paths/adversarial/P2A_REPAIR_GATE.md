# Next experiment: fee-input-independent FROST owner exits with TRUC/P2A

Research handoff scoped to the proven [sponsor griefing CI](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40094681704),
not a claim of a working or safe replacement.

## Attack now confirmed in real Bitcoin Core

At generation 2, the FROST signer and sponsor pre-sign the exact
`[carrier_input, sponsor_input]` BIP341 transaction with
`TapSighashType::Default`. A noncooperating sponsor can later consume
its own UTXO. The signed carrier exit is no longer mempool-valid;
changing `sponsor_input` invalidates the BIP341 FROST signature.
Backing up only the *first* exit is insufficient if the sponsor
for the other-holder's signed successor exit can still be sabotaged.

## Preferred candidate: one-input zero-fee v3 parent

Use the repository's **already verified**
[A-side Bitcoin Core implementation](../../../../../regtest/src/main.rs)
as a precedent, but construct the B-side candidate independently:

```text
parent (FROST, presigned; no fee sponsor input)
  version = 3 (TRUC)
  vin[0] = exact current P2TR carrier UTXO
  vout[0] = exact other-owner P2TR successor (or terminal owner payout)
  vout[1] = exact current owner's 60k/40k beneficiary payout, if first exit
  vout[last] = 0 sat P2A anchor, script 51 02 4e 73
  fee = 0 sats; original principal 100% preserved
  BIP341 SIGHASH_DEFAULT binds every payout, anchor and current prevout

child (created **AFTER** the signer disappeared)
  version = 3 (TRUC)
  vin[0] = parent's zero-sat P2A output
  vin[1] = arbitrary fresh third-party fee UTXO
  vout[0] = sponsor change minus fee for parent+child package
  BIP341 / P2TR fee-input signature is supplied by that third party
  submit parent and child with Bitcoin Core submitpackage
```

The child may be provided by Alice, Bob, an independent fee payer or
a relay service without touching the pre-signed FROST parent.
However, if nobody can fund a fee child, no liveness guarantee
exists. This is fee **input replaceability**, not free Bitcoin fees.

Each first-owner ordering remains a mutually exclusive Bitcoin
spend of the same carrier input. The accepted parent commits a
specific P2TR successor outpoint for the other holder; their
separately pre-signed second parent must spend that *exact txid:vout*.
After the first parent+child confirms, the second owner supplies
a fresh child funding input to publish their own signed second parent.

## Full experimental matrix (no Signet before these pass)

| Case | Hard Bitcoin Core observation |
| --- | --- |
| Clean Alice-first, Bob-second | Two separately confirmed v3 parent+child packages; 60k then 40k exact payouts |
| Clean Bob-first, Alice-second | Same guarantee in reverse, with exact successor outpoint ancestry |
| Old sponsor UTXO deliberately spent after signer death | Different third-party UTXO pays the child; signed FROST parent unchanged **byte for byte** |
| Attacker spends first chosen child fee UTXO | A second independently funded child can replace the first; no new parent or FROST signature |
| All sponsor wallets unavailable | No fee child available; report recovery blocked, never imply unconditional liveness |
| Old generation after refresh | Parent+child package rejected, entire old exit remains invalid |
| Hostile second-hop fee payer | The other holder can replace the second child without an online FROST signer |
| Wrong payout or wrong successor | FROST signature fails Bitcoin Core transaction verification |
| Two malicious active FROST shares | A distinct P2TR keypath theft still passes Bitcoin Core; keep this a failing entitlement-security test |
| Missing frozen descendant package | Holders cannot rely on future quorum availability; per-owner durable package distribution remains required |

## Scope and code reuse

- The A reference `regtest/src/main.rs` already exercises zero-fee
  `Version(3)` presigned parents, script `51 02 4e 73`, a
  signed P2A child with a fresh fee UTXO, and `submitpackage`.
  Reuse its **verified rules**, not its source wallet secrets.
- Keep the existing funded P2TR/FROST witness and owner-branch
  recovery experiments as regressions rather than replacing them.
- Put the new runner in a parallel `p2a-fee-child/` folder.
  The FROST signer should create parent signatures in one process;
  the Node/Rust relay should build and fund children in another
  with no FROST key shares, after the signer is gone.
- At every stage, audit exact BIP341 prevouts, output scripts,
  value conservation, anchor script, mempool package responses,
  mined wtxids, fee provenance and confirmation depth.
- The unauthenticated oracle and Byzantine two-share keypath
  bypass are separate blockers. P2A does **not** repair them.

Stop if the zero-fee v3 parent/child cannot pass Bitcoin Core's
actual package policy, if the fresh sponsor child can siphon any
part of Alice/Bob principal, or if replacing a fee UTXO changes
the signed parent txid/wtxid. Do not substitute abstract JS acceptance.
