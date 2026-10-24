# FROST owner-first, then other-holder recovery DAG

**Experimental Bitcoin Core regtest only.** This is a child experiment
of the already passing [signed joint full-split PR #6](https://github.com/patrickdugan/blossom-storage-bonds/pull/6).
Unlike the joint split, the two complete signed recovery branches let
the *first* transaction release only the initiating beneficiary's
allocation, retaining the other person's full principal in a still
committed P2TR successor. The second beneficiary can then publish a
separately pre-signed follow-on transaction without obtaining a fresh
quorum signature.

## Capital and transaction graph

```text
Current 100,000 sat P2TR carrier
  |
  +-- Alice-first (fully signed, 3k separate sponsor fee)
  |      -> Alice payout: 60k
  |      -> P2TR successor: 40k
  |            -> Bob-second (previously signed, 3k distinct sponsor)
  |                 -> Bob payout: 40k
  |
  +-- Bob-first (conflicts at carrier, fully signed, 3k sponsor)
         -> Bob payout: 40k
         -> P2TR successor: 60k
               -> Alice-second (previously signed, 3k distinct sponsor)
                    -> Alice payout: 60k
```

The branch selected by Bitcoin consensus determines which second-owner
transaction is current. Both first-exit transactions are valid while
their parent carrier is unspent, but they cannot both confirm.
Each pre-signed second exit references its own first exit's exact
transaction ID and successor P2TR script, not an assumed future state.

The preparation harness creates three carrier generations. Before each
refresh it freezes both four-transaction alternative branches. Each
owner-first or owner-second transaction uses a **different already-
confirmed 10,000-sat fee sponsor UTXO**, whose 3,000-sat fee and
7,000-sat returned change do not reduce the owner's entitlement.
The two refresh transactions have their own fee sponsor inputs.
Overall fourteen independent sponsor UTXOs are preconfirmed.

## Two-phase execution

Preparation (Rust, FROST 2-of-3 and Bitcoin Core): trusted-dealer
shares in one process, actual BIP341 key-path signatures, independent
Bitcoin Core sponsor wallet signatures and byte-frozen complete
pre-signed transactions. Two carrier refreshes confirm; the final
generation's competing owner-first spends remain unbroadcast.
The preparation file is SHA-256 sealed with exclusive creation.
The signer process terminates; FROST shares are never serialized.

Relay (Node, no signing imports): unload Alice, Bob and sponsor wallets;
verify frozen bytes against the original SHA-256 seal, re-decode
every signed Bitcoin witness, inspect all parent and sponsor amounts,
and reject obsolete generations with Bitcoin Core.
Then the first owner publishes that holder's individual release,
mines confirmation, and a second transaction claims the remainder.
Bitcoin Core must reject the competing first owner branch after
the winner confirms and must confirm both outputs at depth six.

The CI runs Alice-first and Bob-first in **two independent regtest
histories**, ensuring both orderings really work. All original signer
secrets and pre-signed raw witnesses stay in disposable ephemeral
directories; only the sanitized receipts are uploaded.

## Execute

```bash
BITCOIND_EXEC=/abs/path/to/bitcoind \
BITCOIN_CLI_EXEC=/abs/path/to/bitcoin-cli \
BSB_OWNER_BRANCH_RECEIPT_DIR=/private/new-owner-branches \
bash experiments/storage-bond-ab/b-layertree/owner-paths/run_regtest.sh
```

CI: `.github/workflows/layertree-frost-owner-branch.yml`.

## Critical security limitations

- *Anyone holding the frozen signed bytes* can relay either first exit;
  the first beneficiary does not provide a Bitcoin-authorizing
  signature at publication. Thus **owner-specific payout, not owner-
  exclusive signing or control** is what is tested.
- A living malicious two-share FROST quorum can still bypass the
  signed DAG, sign a different key-path transaction and steal
  the shared carrier principal. Both branches use that same
  unrestricted threshold key-path. This prototype does not claim
  Byzantine noncustodial protection or enforce MID at consensus.
- A first claimant's exit must preserve the other holder's remainder
  under a second pre-signed path. A missing path or an unpublished
  branch package prevents that other claimant from recovering.
- Bounded three-generation coverage does not prove indefinite
  unattended monthly refresh. Every permitted generation refresh
  must deliver *both full branches* and every second exit
  before older witness packages become invalid.
- Fee UTXO availability matters at relay; all inputs here are
  **pre-funded and pre-signed**. A separate malicious spender of the
  fee input could invalidate recovery without touching bonded
  principal. Independent fee paths or dual fee sponsorship
  need additional tests.
- Fully authenticated, rollback-resistant distribution of packages
  to Alice and Bob is not implemented. One-process trusted dealer
  and public disposable recipient wallets are not realistic
  distributed signer custody.
- Independent Filecoin WindowPoSt/fault finality and proof absence
  remain separate unresolved evidence requirements.

## Acceptance distinction

Passing this scenario would improve upon the one-shot joint full
split: both owners can initiate their own *first* redemption, and
the other can redeem the remainder without an online quorum. It
does NOT prove that either beneficiary can unilaterally spend the
shared P2TR carrier without a previously participating threshold
or that two simultaneously malicious signers cannot race the
frozen exit. Keep it as a research draft, not a production bond.
