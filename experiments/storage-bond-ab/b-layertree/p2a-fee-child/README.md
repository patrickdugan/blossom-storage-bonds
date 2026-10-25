# FROST Taproot signer-dead recovery with relay-time P2A fees

**Status: real Bitcoin Core 30.3 regtest experiment; NOT production-safe.**

Research child [draft PR #10](https://github.com/patrickdugan/blossom-storage-bonds/pull/10)
extends the tested [sponsor sabotage PR #8](https://github.com/patrickdugan/blossom-storage-bonds/pull/8).
The earlier FROST P2TR owner-first recovery committed exact external
fee UTXOs into the BIP341 transaction sighash; after signing services
vanished, hostile sponsors could spend those UTXOs and strand holders.

## Change in spend graph

```text
Generation-2 carrier: 100,000 sats, P2TR keypath

  Alice-first FROST presigned parent, version 3, fee 0
    input 0: current P2TR carrier (100k)
    output 0: P2TR successor (Bob's 40k)
    output 1: Alice (60k)
    output 2: zero-value P2A anchor (51 02 4e 73)
           |
           +-- new after-outage child, version 3
                 input 0: zero-value parent anchor
                 input 1: ANY fresh fee wallet UTXO (100k in fixture)
                 output 0: change back to fee wallet (95k)
                 miner fee: 5,000 sats paid externally

  Bob-second FROST presigned parent, version 3, fee 0
    input 0: exact Alice-first successor (40k)
    output 0: Bob (40k)
    output 1: zero-value P2A anchor
           |
           +-- independent after-outage CPFP child using fresh fee wallet

Alternative first order: Bob-first (40k) -> Alice-second (60k)
```

All recovery parents preserve the entire original bonded principal.
Because they have **one input**, their frozen FROST signatures do not
commit to any sponsor UTXO. Bitcoin Core `submitpackage` accepts each
parent with its newly signed child. The child is a separate transaction;
replacing its fee input cannot alter the previously frozen parent
txid, wtxid or original beneficiary scripts.

## Two independent programs and three separate test histories

**Signer preparation:** Rust crate `frost-proof`, with Zcash
Foundation `frost-secp256k1-tr = 3.0.0` pinned by Cargo.lock.
Prepares Alice-first/Bob-first and both successor exits for each of
three carrier generations, signs BIP341 SIGHASH_DEFAULT using true
two-share aggregate Taproot signatures, stores zero-fee v3 parents
and SHA-256-frozen signed witness bytes. It then terminates.
Two preparatory carrier refreshes are funded and confirmed
**before** that outage using separate fixed sponsor UTXOs.

**Recovery:** a different Node worker, with FROST signers and
the original Alice/Bob/sponsor wallets all absent, can use newly
funded third-party Bitcoin Core wallets to sign the P2A fee children.
The worker does not import the FROST library or obtain its shares.
It validates all three frozen generations against the independent
manifest hash, exact UTXOs and owner scripts.

The trial matrix is:

| Trial | Owner order | Child sponsorship event | Required result |
| --- | --- | --- | --- |
| 1 | Alice -> Bob | First child's originally chosen fee input is spent | Alternative fresh input pays first package; second owner also exits |
| 2 | Bob -> Alice | Second child's originally chosen fee input is spent | Alternative fresh input pays second package without changing parent |
| 3 | Alice -> Bob | No attack | Clean control using fresh relay-time sponsors |

Each parent/child package uses an external 5,000-sat child fee.
Every confirmed exit preserves the full 60,000/40,000-sat
entitlements. The original owner-first alternatives conflict at
the P2TR carrier; only the winning branch can confirm.

The hardened verifier also requires Bitcoin Core to reject a
zero-fee v3 parent presented alone, and **four obsolete-generation
first parents offered with fully funded P2A children**. A fresh
fee child cannot resurrect an already-spent carrier outpoint.

## Reproduce

Requires Node 22, pinned Rust dependencies and a disposable
Bitcoin Core 30.3 regtest installation. Never use public Bitcoin
or production wallet material.

```bash
BITCOIND_EXEC=/absolute/path/bitcoind \
BITCOIN_CLI_EXEC=/absolute/path/bitcoin-cli \
BSB_P2A_RECEIPT_DIR=/private/new-p2a-proof \
bash experiments/storage-bond-ab/b-layertree/p2a-fee-child/run_regtest.sh
```

CI: `.github/workflows/frost-p2a-dynamic-fees.yml`.

## Security boundaries and remaining work

- The **fee input is replaceable**, but availability of any fee
  payer is not guaranteed. When no third party will pay the CPFP
  fee, the zero-fee parent will not relay under the tested policy.
- The two generation refreshes in the fixture still depend on
  sponsorship and signing while FROST is **online**. Long-lived
  unattended refresh or recovery across unknown future generations
  is not demonstrated.
- Exact successor ancestry is still required. Every refresh needs
  a newly frozen complete set of both orderings and second claims
  delivered to holders before old exits are invalidated.
- A malicious active 2-of-3 FROST quorum remains free to sign
  an unauthorized BIP341 keypath theft or false MID root. Neither
  P2A nor a good owner payout witness constrains that power.
- A holder needs durable access to signed recovery packages.
  Per-owner authenticated delivery, anti-rollback evidence,
  seed-independent recovery and partial-data/withheld-witness
  protections are outstanding.
- This work does not make the Sapio MID oracle into Bitcoin
  consensus, verify Filecoin WindowPoSt absence, or protect
  against every mempool/package pinning scenario.
- The recovery outputs are independently spendable only after
  they have been released. Possessing a presigned first-owner
  transaction allows anyone to relay that transaction; it
  is not an owner-exclusive Taproot signature path.

**Interpretation:** This fixes a concrete *fixed sponsor UTXO*
liveness vulnerability in the tested TRUC/P2A recovery graph.
It is not a proof of Byzantine quorum resistance, unconditional
offline recovery, or a permissionless BTC storage bond.
