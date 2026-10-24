# Zero-fee FROST v3 parent + relay-time P2A fee child

Status: **funded Bitcoin Core 30.3 regtest result**; not a production
FROST vault, Bitcoin consensus MID covenant, or publicly funded Signet.

[Passing regtest #40098864825](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40098864825) validates
the repair to the concrete sponsor-input dependence discovered in
[the prior sponsor-sabotage PR #8](https://github.com/patrickdugan/blossom-storage-bonds/pull/8).

## Concrete implementation

The previous signed exit spent two inputs: the FROST carrier plus an
exact pre-chosen fee-sponsor UTXO. Spending the latter invalidated
recovery after the 2-of-3 signers disappeared. This branch changes
the actual FROST-signed parents, not just abstract policy scores.

`p2a_parent.rs` signs an **exact one-input BIP341 P2TR parent**,
transaction `Version(3)`, zero fee, all beneficiary sats preserved,
with a separate `0 sat` P2A anchor at script `51 02 4e 73`.
The parent commits no sponsor input, and no fee-payer private key
is used for its FROST signature.

At relay time, `core.mjs` chooses an available external wallet UTXO,
constructs a **v3** child spending both that coin and the parent's
P2A output, signs only the fee input and calls Bitcoin Core
`submitpackage` with the immutable signed parent and new child.
Fee funding is 3,000 sat per package; the signed parent spends
none of Alice's or Bob's 100,000 sat total entitlement.

`p2a_preparation.rs` freezes both alternative owner-first exits
and each other-owner successor exit for all three carrier generations.
Two zero-fee parent plus fee-child refresh packages are already
accepted and mined before the FROST preparation process exits.
The private signing shares are never exported.

`relay_p2a.mjs` checks the original file SHA256, both owner
payout scripts, every parent/descendant outpoint, zero parent fee
and unchanged exact witness bytes. It unloads the preparation
wallets; only an independent fee payer and disposable regtest miner
remain available. The original tentative fee-payer coin is
deliberately spent onchain **after** FROST signers disappear.
Another fee wallet supplies the child for that same frozen parent.

## Observed results

| Test | Actual regtest result |
| --- | --- |
| Alice-first then Bob-second | Two parent-child packages confirmed; 60k/40k complete |
| Bob-first then Alice-second | Two parent-child packages confirmed; same full entitlement |
| Original candidate fee coin spent | 1 confirmed spend per trial; new independent fee input chosen without re-signing FROST parent |
| Previous carrier refresh | Two v3/P2A refresh packages confirmed per trial |
| Frozen witness substitution | Corrupted copy rejected by original SHA256 seal |
| FROST group available during relay | No: preparer process ended |
| Beneficiary payout changed to pay fees | No: 3,000 sats per parent+child package from relay-time fee wallet |

Across the two independent Bitcoin Core histories: **four confirmed
recovery parents, four confirmed dynamic CPFP fee children**,
and two independently spent original fee candidates.
See [CI receipt artifact](https://github.com/patrickdugan/blossom-storage-bonds/actions/runs/40098864825/artifacts/12562300583).

Bitcoin Core 30.x `createrawtransaction` defaults to transaction v2.
The relay now explicitly passes version **3** as the fifth RPC argument;
earlier failed CI exposed this as a real regression. No policy
predicate was weakened to work around that failure.

## Execute

Requires disposable Bitcoin Core 30.3, Node 22+, Rust and the
checked-in `frost-secp256k1-tr=3.0.0` Cargo lockfile.

```bash
BITCOIND_EXEC=/absolute/path/bitcoind \
BITCOIN_CLI_EXEC=/absolute/path/bitcoin-cli \
BSB_P2A_RECEIPT_DIR=/new/private/regtest-results \
bash experiments/storage-bond-ab/b-layertree/p2a-fee-child/run_regtest.sh
```

CI: `.github/workflows/frost-p2a-dynamic-fee-regtest.yml`.

## Hard boundaries still unresolved

- **Somebody must pay Bitcoin fees.** Removing a fixed input lets
  an alternative payer select a fresh UTXO, but does not promise
  any payer is available or can beat time/fee volatility.
- This is Bitcoin Core **regtest package relay policy**. The
  v3/P2A topology and package pinning behavior need dedicated
  adversarial regtest and relay simulations before Signet.
- FROST remains generated in one trusted-dealer OS process;
  no distributed DKG or long-lived authenticated signer custody.
- First exits conflict, and any holder with the frozen files
  can relay either branch. They are **recipient-specific payouts,
  not owner-exclusive signatures**.
- A malicious active 2-of-3 FROST quorum can still sign a
  different BIP341 keypath spend and bypass the optional
  application-state commitment or both beneficiary payouts.
  Bitcoin consensus does not execute Sapio MID policy.
- The SHA256 seal detects substituted bytes in a received package.
  It does not prove the owner received the current frozen package,
  has an anti-rollback reference or can recover across unbounded
  monthly refresh generations.
- This lab does not authenticate a Filecoin WindowPoSt absence
  or enforce third-party storage faults on Bitcoin.

Next meaningful A/B test: use the matching 60k/40k PDP fixture
to compare genuine A sentinel v3/P2A recovery with this B FROST
variant on signers-offline and fee-wallet-unavailable traces,
while recording differences in Byzantine entitlement security.
