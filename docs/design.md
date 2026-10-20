# Blossom storage bonds: Filecoin's job without a token, a chain of its own, or a committee

*The client is the verifier, so most of what Filecoin needs a chain for, this design does not.*

Design note, 2026-10-19; phase 1 and 1b results added 2026-10-20. The model is `model/storage_bonds.ts`
(`node --test model/*.test.ts`, 15 passing). Layer 1 runs end to end on localhost in `layer1/` (12 more
tests, Lightning stubbed; see the README). The regtest harness in `regtest/` runs the same bond chain as
real transactions against Bitcoin Core 31.1 (21 checks passing, results in `results/regtest.json`). It
starts from a
pasted sketch that proposes Nostr for coordination, Blossom for bytes, zk-SNARK storage proofs, and BitVM
to enforce payouts and slashing. This note keeps the goal, moves BitVM to the last phase, and puts a
mechanism that runs on mainnet today at the front. The sketch's claims about BitVMX mainnet runs and the
BitVM3 break were not checked here.

## What "not web 2.5" has to mean

A layer is web 2.5 if a party outside the deal can take the money or stop the deal. The table lists
who each layer relies on.

| Layer | Job | Relies on |
| --- | --- | --- |
| Blossom (BUD-01/02) | Hold and serve bytes by SHA-256 | The provider, for availability only |
| Nostr | Deal offers, acceptance, epoch challenges and answers | Any one relay that carries the messages; both sides can run their own |
| Lightning | Pay each epoch after the proof checks | Channel peers, for routing only |
| Bitcoin, sentinel bond | Forfeit the provider's collateral if it cannot show a chunk | Bitcoin consensus only |
| Bitcoin, BitVM bond (phase 3) | One bond backing many clients, publicly checked | The BitVM setup committee (1-of-n honest), one honest online challenger, and the header-chain proof |

Phases 0–2 trust no committee, no oracle and no auditor. Phase 3 brings a committee back in. That is its
cost, and it is worth paying only for what phases 0–2 cannot do: one bond pooled across many clients.

## Findings

1. **The client is the verifier, so client randomness is the challenge.** In a two-party deal no third
   party has to be convinced that the challenges were fair. "Challenge authenticity" and Bitcoin
   block-hash randomness only matter once a public verifier enters, in phase 3.
2. **Pay per proof already makes deletion unprofitable.** If the client pays each epoch only after
   checking q random chunks, a provider that keeps a fraction f of the blob earns f^q of the revenue and
   saves (1 − f) of the cost. While price ≥ cost that never pays, for any q ≥ 1 (test 5). The bond
   compensates the client for losing the data, priced by the client. Its job is not to deter
   cost-cutting.
3. **The real threat is outsourcing, and per-replica encryption stops it.** A provider can keep nothing
   and fetch chunks from another copy when challenged. If each provider stores its own ciphertext, under
   a key derived from (client secret, blob, provider), then answering from another provider's copy fails
   against its own root (test 3). This replaces Filecoin's PoRep sealing. It works because the data owner
   defines the replicas. It does not prove that the replicas sit on different hardware.
4. **An enforceable storage bond fits in plain tapscript on mainnet today.** The bond is a chain of
   precommitted salted-hash challenges (Juels–Kaliski sentinels). Revealing a 16-byte r_i forces the
   provider to publish r_i ‖ window[idx(r_i)], one 80-byte item that `OP_SHA256` checks. Silence for Δ
   blocks forfeits the bond. It needs no OP_CAT, no covenant and no BitVM (§2). Every path was
   broadcast and mined on regtest through the normal mempool.
4a. **Relay policy caps the answer at 80 bytes, not 520.** The first version of this note answered with
   one 520-byte element (MAX_SCRIPT_ELEMENT_SIZE) and claimed tapscript had no per-item standardness
   limit. That was wrong. Core rejects any tapscript stack item over 80 bytes as
   `bad-witness-nonstandard` (MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE). Regtest scenario S4 shows the
   520-byte answer is valid by consensus: it mines through `generateblock`, and 521 bytes fails with
   `Push value size limit exceeded`. A provider that depended on it would need a miner willing to take
   non-standard transactions, which is a trusted party. So the window is 64 bytes, after a 16-byte
   (128-bit) r. Window size does not change detection, which depends only on the fraction of the data
   kept.
5. **The bond's weak point is the client, not the provider.** The provider cannot check a sentinel
   without learning which chunk it names. A client could plant a bad h_i, challenge it, and take a bond
   the provider could never save. Cut and choose fixes this cheaply: commit to M sentinels, let the
   provider open all but k, and use the k that remain. Theft has negative expected value once
   M ≳ k·(1 + αB/setup), about 6,500 for k = 10, a 1M-sat bond and a 1,540-sat setup (test 14). A small
   zk proof at setup is the clean version (§2.3). This is where zk earns its place in the early phases:
   off-chain and small.
6. **On-chain cost is 308 vB per bond on the happy path and 696 vB per challenge actually issued,
   measured on regtest.** At 5 sat/vB that is about 1,540 sats to open and close, and 3,480 sats per
   challenge. So bonds go per
   (client, provider) pair over the whole collection, not per blob, and roll over by one cooperative
   spend into the next bond (§2.4).
7. **The sketch's burden is upside down.** "A challenger proves fault" needs a fault proof, which is the
   hard part. Make the provider prove in order to keep the bond: the sentinel bond does this for
   challenges the client picked in advance, and a BitVM bond would do it with the provider asserting
   "all epochs proved", open to challenge (§4).
8. **Proof of possession is not retrieval.** A provider can answer every challenge and still refuse to
   serve the file. The bond cannot force retrieval. Pay-per-retrieval over Lightning and erasure coding
   across providers limit the damage; nothing here removes the hostage case (§5).
9. **One window per challenge is too weak; one r should open many windows.** In the phase 2 run with one
   window per sentinel, a provider that had zeroed 10% of its chunks answered all four on-chain
   challenges and kept its bond, although layer 1 had caught it in three epochs. It survives each
   one-window challenge with probability 0.9, and four of them 66% of the time. A multi-window sentinel
   fixes this cheaply. One revealed r derives m window indices, and the respond leaf checks each
   80-byte item r ‖ window_j with its own `SHA256 <h_j> EQUALVERIFY`. Every item stays within the
   80-byte relay limit, and each extra window adds 35 bytes of leaf and 81 bytes of witness, about
   27 vB. At m = 16 the answer is 639 vB (measured). A 10% deleter survives one challenge 18.5% of the
   time and four 0.12% (model test 12). With m = 1 every script and size is unchanged from phase 1.

## 1. Layer 1: pay per proof

Upload. The client encrypts the blob once per provider, `AES-256-CTR(K_p)` with
`K_p = H("bsb/replica-key" ‖ secret ‖ blob ‖ provider)`, splits it into 4 KiB chunks, and builds a
SHA-256 chunk tree with domain-separated leaves and nodes. The root R_p binds the chunk count. Blossom
names a blob by the SHA-256 of the whole file, which cannot open a single chunk, so R_p is a separate
commitment. The client computes it, the provider recomputes it from the bytes it received, and both
sign it in the deal.

Each epoch. The client sends a 32-byte nonce in an encrypted Nostr DM. The provider answers with q chunks
at `idx_j = H("bsb/epoch" ‖ nonce ‖ j) mod n` and their Merkle paths. The client checks them against
R_p and pays the epoch's invoice. The client keeps 32 bytes per replica. The provider risks one epoch of
unpaid work, and the client risks nothing beyond the epoch it prepaid, if it prepays at all.

A provider that kept half the chunks passes a q = 4 epoch about 1/16 of the time (test 4). At q = 20,
keeping 99% of the blob loses 18% of the revenue to save 1% of the cost.

## 2. Layer 2: the sentinel bond

### 2.1 States and leaves

The bond is a chain of k states. Each state is a two-leaf taproot output whose internal key is
MuSig2(P, C), so the cooperative close is a keypath spend.

```
Bond_i        challenge:  <C> CHECKSIGVERIFY <P> CHECKSIGVERIFY SHA256 <s_i> EQUAL        s_i = SHA256(r_i)
              refund:     <T_end> CLTV DROP <P> CHECKSIG
Challenged_i  respond:    <P> CHECKSIGVERIFY <C> CHECKSIGVERIFY SHA256 <h_i> EQUAL        h_i = SHA256(r_i ‖ window[idx(r_i)])
              forfeit:    <Δ> CSV DROP <C> CHECKSIG
```

At setup the provider presigns each `Challenge_i: Bond_i → Challenged_i`, and the client presigns each
`Respond_i: Challenged_i → Bond_{i+1}`. Segwit txids do not cover witnesses, so the whole chain is known
before anything is broadcast. Every presigned transaction is a zero-fee TRUC (v3) parent with a P2A
anchor, bumped by a child at broadcast time.

- The client challenges by cosigning `Challenge_i` and revealing r_i in the witness. The index is a
  64-byte window, `H("bsb/idx" ‖ r_i) mod 64n` (64 windows per 4 KiB chunk), so it stays hidden until
  the reveal and the leaves say nothing about which data to keep (test 11).
- The provider has Δ blocks to spend `respond` with the 80-byte item r_i ‖ window. 80 bytes is the
  largest tapscript stack item Core relays (finding 4a). The client's presignature sends the bond on to
  `Bond_{i+1}`.
- If the provider stays silent, the client takes the bond with `forfeit` after Δ (test 9). There is no
  refund leaf in `Challenged_i`, so a challenge confirmed one block before `T_end` still has to be
  answered.
- After `T_end` the provider can refund alone. Before then, the client can challenge at most k times.

The model runs these leaves in an interpreter for the opcodes they use, with the BIP342 rules that
matter here: the 520-byte consensus limit, the empty-signature rule and the clean stack. It checks the
80-byte relay limit separately. Tests 6–10 cover the right and wrong r, missing and replayed
presignatures, the wrong window, 81- and 521-byte items, and both timelocks.

Regtest (`regtest/`, Core 31.1) does the same with real transactions: BIP341 sighashes, a MuSig2
internal key, the full k = 3 chain presigned before anything is broadcast, and every presigned step
submitted as a zero-fee TRUC parent plus CPFP child through `submitpackage`. The node's verdicts:

| Scenario | Accepted | Rejected, with Core's reason |
| --- | --- | --- |
| S1 | fund; Challenge_0; Respond_0 (bond re-armed as Bond_1); Challenge_1; Forfeit_1 at Δ | wrong r (false top stack); no client signature (`OP_CHECKSIGVERIFY`); Challenge_1's presignature on Challenge_0 (invalid Schnorr signature); same window of the next chunk (false top stack); 81-byte item (`bad-witness-nonstandard`); Forfeit one block early (`non-BIP68-final`) |
| S2 | refund at `T_end` | refund one block before (`non-final`) |
| S3 | cooperative close, MuSig2 keypath under the taproot tweak | — |
| S4 | 520-byte answer mined directly by `generateblock` | 520-byte answer through the mempool (`bad-witness-nonstandard`); 521 bytes mined directly (`Push value size limit exceeded`) |

### 2.2 Who can grief whom

| Move | Cost to the mover | Effect |
| --- | --- | --- |
| Client challenges an honest provider | Challenge tx and child, 340 vB | The provider pays 356 vB to answer; at most k times per bond |
| Provider deletes the chunk holding a sentinel's window | — | Forfeits the bond if that sentinel is challenged |
| Provider fetches the chunk from another replica | — | Fails: wrong ciphertext |
| Client plants a bad h_i | Its setup cost if the plant is opened | Steals the bond if it survives (finding 5) |
| Client goes offline | — | Nothing: the provider refunds at `T_end` |
| Provider goes offline during a challenge | — | Forfeits after Δ |

Answering costs about the same as challenging (356 vB against 340 vB), and k caps the number of
challenges. Set the fee split in the deal, or have the client prepay the provider's answer fees in the
epoch invoices.

### 2.3 Cut and choose, and the zk version

The client commits to M pairs (s_j, h_j) under a Merkle root. The provider picks M − k to open, checks
each `h_j = SHA256(r_j ‖ window[idx(r_j)])` in 80 bytes of hashing, and the bond is built on the other k.
One planted sentinel survives with probability k/M. The theft has negative expected value when
(k/M)·α·B < (1 − k/M)·setup, where α is the share of a forfeit paid to the client rather than burned.
That gives M ≳ k·(1 + αB/setup): 6,500 at k = 10, B = 1M sats and setup = 1,540 sats. That is 416 KB of
commitments and 0.5 MB of hashing, both trivial.

The zk version proves at setup, for each of the k sentinels, the statement "s = SHA256(r),
h = SHA256(r ‖ w), and w is window `H(r) mod 64n` of a chunk under R_p", with r and the path hidden.
It costs about 70 SHA-256 compressions (the 4 KiB leaf hash dominates) plus a log n Merkle path per
sentinel. Any modern prover handles
that in seconds on a CPU. It removes the theft outright and lets α = 1.

### 2.4 Cost and granularity

Measured on regtest; each matched the model's prediction exactly.

| Transaction | vB |
| --- | --- |
| Fund (provider, one keypath input) | 154 |
| Cooperative close (MuSig2 keypath) | 154 |
| Challenge_i (script path, 16 + 64 + 64 stack, 103-byte leaf, depth 1) | 187 |
| Respond_i (80 + 64 + 64 stack) | 203 |
| CPFP child for either | 153 |
| Forfeit_i (client, after Δ) | 138 |
| Refund (provider, after `T_end`) | 138 |
| *Non-standard 520-byte version: Challenge_i / Respond_i* | *191 / 314* |

A bond that is never challenged costs 308 vB. Each challenge that is actually issued adds 696 vB. At
5 sat/vB a bond is worth opening only if its term's revenue is well above ~1,540 sats, which a 2 MB Nostr
image never reaches. Bond per (client, provider) pair over a root of the client's blob roots, with k
sized to the term. To add blobs, spend the old bond cooperatively straight into a new one: one
transaction per rollover.

## 2.5 Phase 2: both layers, end to end (`layer1/bonded.ts`)

Real Blossom servers and a real bond per provider on Core 31.1 regtest. Lightning is still the in-memory
stub.

1. Four providers run Blossom servers. The client uploads a 1 MiB blob encrypted per provider. While it
   still holds each ciphertext, it commits to M = 64 sentinels of 16 windows each.
2. Cut and choose runs over HTTP (`POST /bond/<sha>/commit`, `/reveal`). Each provider opens 60 of the
   64, chosen from its own secret key so the client cannot grind the choice. It checks all 16 windows of
   each against the bytes it stores. The bond is built on the 4 it did not open.
3. `bsb-bond fund` locks 1 BTC per provider and presigns the chain.
4. Ten paid epochs run at q = 8. From epoch 4 one provider zeroes 10% of its chunks, one 50%, and one
   deletes its replica and answers from the honest provider's copy.
5. The client challenges each provider that failed an epoch on its sentinels in turn, and the honest one
   once as a spot check. The provider's agent fetches r ‖ window for all 16 windows from its own server
   (`GET /sentinel/<sha>?r=&m=16`) and submits them. The tool does not compare the answer with h first,
   so Core's script check is the only verifier. A rejected answer is followed by Δ = 144 blocks and the
   forfeit leaf.

Results (`results/bonded.json`):

| Provider | Failed epochs (of 10) | Paid | On-chain challenges | Core's verdict | 1 BTC bond |
| --- | --- | --- | --- | --- | --- |
| honest | 0 | 2,560 msat | 1 | accepted (639 vB) | closed by MuSig2 keypath to the provider |
| deletes 10% | 3 | 1,792 msat | 2 | accepted, then `OP_EQUALVERIFY` failed | forfeited to the client |
| deletes 50% | 7 | 768 msat | 1 | `OP_EQUALVERIFY` failed | forfeited to the client |
| outsources | 7 | 768 msat | 1 | `OP_EQUALVERIFY` failed | forfeited to the client |

All four final transactions were checked on the node: one keypath spend to the provider's address, and
three forfeit-leaf spends with nSequence 144 to the client's address. The same run with one window per
sentinel let the 10% deleter keep its bond (finding 9).

What this demo does not show. One process plays both parties' on-chain agents, with keys derived from
seeds in the deal file. The challenges run after the epochs rather than interleaved with them. The bond
is 1 BTC against a 1 MiB blob, sized to make the outcome readable, not priced.

## 3. Replicas

Per-replica encryption gives every provider a distinct blob (distinct Blossom hashes too), so r
replicas really are r copies of the bytes somewhere. It does not prove that they are on r machines: one
operator can run three provider identities on one disk. Erasure-code across providers (any m of r
recover), choose providers by Nostr reputation and by announced failure domain, and price the bond as if
correlated failure is possible. A slow per-replica encoding (depth-robust labelling, the PoRep idea)
would tie each replica to its own seal time. That is a later option. The model does not attempt it.

## 4. Where BitVM fits (phase 3)

The sentinel bond is one provider against one client, with k challenges fixed in advance. BitVM buys
three things it cannot do:

- One provider bond backing many clients, so small clients share the on-chain cost.
- Unbounded challenges, drawn from Bitcoin headers, so nobody has to precommit.
- Anyone can enforce, not only the client.

The right shape is the BitVM2 operator-claim shape with the burden on the provider. The bond is
unlocked at term end only by an assertion "for every epoch e in the term, the provider answered the
header-seeded challenge for every deal in registry root D_e". The assertion is open to an
anyone-can-challenge window. Not asserting means the bond goes to the forfeit path. What has to be
solved:

1. **The registry.** The deal set must be something the SNARK can read: the provider commits D_e on chain
   each epoch, and the statement includes the inclusion proofs.
2. **Header randomness.** The statement includes a header-chain proof. A ZeroSync-style `chain_segment`
   proof is the existing building block. Grinding costs a block reward per try.
3. **The committee.** BitVM2 graphs are presigned by a setup committee per collateral UTXO. That
   committee is this design's only web-2.5 residue, and it is why phase 3 comes last.
4. **Proof cost.** An aggregated proof over N deals × q chunks per epoch. The open research question is
   the one the sketch names: whether it secures pooled BTC collateral more cheaply than per-pair
   sentinel bonds.

## 5. Retrieval

Possession proofs do not make the provider serve the file. What helps:

- Pay per retrieval over Lightning, so serving earns money.
- Erasure-code across providers, so one holdout cannot hold the data hostage.
- Each answered challenge publishes one 64-byte window of ciphertext on chain, which is not retrieval.

A provider that answers every challenge and refuses every download keeps its bond. That is the honest
limit of this design.

## 6. Nostr and Blossom surface (draft, event kinds to be assigned)

- **Provider offer** (replaceable, signed by P): price per GiB-epoch, epoch length, q, bond multiple,
  Δ, Blossom server URL, Lightning offer or NWC hint, failure-domain claim.
- **Deal** (signed by both): blob ids, per-replica roots R_p and lengths, term, k, the cut-and-choose
  commitment root, the bond's funding outpoint, and the taproot merkle root of `Bond_0`.
- **Epoch challenge and answer**: NIP-17/NIP-44 DMs carrying the nonce, then the chunks and paths.
  Answers can be large (q × (4096 + 32·log n) bytes), so the provider can serve them from a Blossom
  sidecar endpoint and send only a hash over Nostr.
- **Receipt**: the client signs a per-epoch "proved and paid". It feeds reputation and costs nothing to
  publish. Layer 1 uses kind 8242 as a placeholder, with tags `p` (provider), `x` (replica), `root`,
  `n`, `epoch`, `nonce`, `q` and `result` (`proved-paid`, `proved-unpaid`, `failed` or `unreachable`).
  A paid receipt adds `amount`, `invoice` and `preimage`, so a reader can check the payment against
  the hash without trusting either party. A reader cannot check the proof itself without the chunks.

Blossom servers already authorize uploads with kind 24242 events, and users list their servers in kind
10063. Neither needs to change. The PDP answer is a new endpoint beside them.

## 7. Plan

| Phase | Deliverable | Status |
| --- | --- | --- |
| 0 | This model: replica encryption, chunk tree, epoch PDP, sentinel leaves, cut and choose, sizes | Done, 15 tests |
| 1 | Regtest with real transactions: BIP341 sighashes, MuSig2 internal key, TRUC + P2A, the full presigned chain, challenge/respond/forfeit/refund/close all broadcast (rust-bitcoin 0.32.7, musig2 0.4.1, Core 31.1) | Done, 21 checks; found the 80-byte limit (finding 4a) |
| 1b | Blossom sidecar: `/pdp/<sha256>?nonce=` answering from stored replicas, plus a client that runs epochs, pays an invoice and publishes a receipt | Done on localhost, 12 tests; Lightning is an in-memory hash-lock stub behind an interface, and the nonce goes over HTTP rather than NIP-44 |
| 2a | Both layers end to end: cut and choose over HTTP, a real bond per deal funded on regtest, paid epochs, and on-chain enforcement from each provider's stored bytes (`layer1/bonded.ts`, `bsb-bond`); multi-window sentinels | Done: every cheater forfeits, the honest provider closes (§2.5) |
| 2 | zk setup proof for sentinels (SHA-256 + Merkle path, CPU prover), replacing cut and choose | Next |
| 3 | BitVM2-shaped pooled bond: registry, header-seeded challenges, aggregated proof; measure cost per deal against phase 1 | Research |

## What is and is not tested

The TypeScript model signs a stand-in digest, uses a placeholder for the MuSig2 key, and sums transaction
sizes from parts. The regtest harness replaces all three with the real thing, and Core 31.1 accepts and
rejects exactly as the model predicts.

What neither covers yet:
- Mainnet relay beyond Core defaults. Other node policies and pinning across a real network are
  untested.
- Fee spikes during Δ.
- Cut and choose between separate parties. It runs over HTTP (§2.5), but both sides are in one process
  with test keys.
- Lightning. Layer 1 runs a real Blossom server, PDP sidecar and Nostr relay on localhost (`layer1/`),
  but payment is an in-memory stub with hash locks, not a Lightning node.
- NIP-17/NIP-44 delivery of the nonce, offer and deal events, and any relay other than the bundled
  minimal one.

The fixed keys and MuSig2 nonce seeds in `regtest/` are test values. Never use them for real funds.
