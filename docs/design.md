# Blossom storage bonds: Filecoin's job without a token, a chain of its own, or a committee

*The client is the verifier, so most of what Filecoin needs a chain for, this design does not.*

Design note, 2026-10-19; phase 1, 1b, 2a, 2b, 3a (§4.1, `zk/`) and 3b (§4.3) results added 2026-10-20, and the phase 6 BitVM2 spike (§4.6) the same day. The model is `model/storage_bonds.ts`
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
| Bitcoin, BitVM bond (phase 3) | One bond backing many clients, publicly checked | The BitVM setup committee (1-of-n honest), one honest online challenger, the header-chain proof, the Groth16 key's phase-2 contributors, and a miner for non-standard dispute transactions (§4.6) |

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

10. **NIP-44's 65,535-byte limit decides how answers travel.** At q = 8 an answer is about 49 kB and goes
    inline. At q = 64 it is over 256 kB. The provider then holds it for one GET at an unguessable URL,
    and sends that URL and the answer's SHA-256 inside the encrypted, signed reply (layer1 tests).

11. **A public aggregated proof is cheap to verify and cheap to prove only with a Blake2s tree.** One
    Stwo proof covers every deal a provider holds. It is 11–14 MB, verifies in about 20 ms, and has
    no proof unless every challenged chunk is held (§4.1). On an 8-core, 31 GB box, proving costs
    7.6 s and 1.7 GB per challenged chunk on the protocol's SHA-256 tree, against 0.21 s and 50 MB on
    a Blake2s tree. A 1 TiB provider in 1 GiB deals at q = 8 needs 18 h of that box per epoch with
    SHA-256 and 31 min with Blake2s. Bitcoin can enforce the proof only through BitVM2 (a committee
    and a Groth16 wrap) or OP_CAT (a soft fork) (§4.2).

12. **BitVM2 can carry the storage proof, but not yet with anything a bond should trust.** Proved
    again in RISC Zero, where SHA-256 is an accelerator, the holdings statement costs about 14,100
    cycles per challenged chunk, so q = 64 over 64 deals is 8 minutes and 9.1 GiB on four cores.
    Bound to a proven regtest header chain and wrapped through risc0-to-bitvm2, a three-epoch term
    becomes one 256-byte Groth16 proof with one public input. BitVM's chunked verifier accepts it,
    and BitVM's own bridge test mined a disprove of a wrong assertion of it on regtest. A contested
    term costs about 610,000 vB, against 696 vB per sentinel challenge. What stops it is trust more
    than cost: the proving key in risc0-to-bitvm2's prover image records one phase-2 contribution
    and a public beacon, upstream's glue let a forged chain through and signed assertions under the
    wrong keys, and the largest assert transaction and every disprove are past the standard size, so
    a dispute needs a miner (§4.6).

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

## 2.5 Phase 2: the market, with every party in its own process (`layer1/market.ts`)

Bitcoin Core 31.1 regtest carries all the money, and a Nostr relay carries all the coordination. Four
provider processes (`layer1/provider.ts`) and the client process each hold only their own keys: a Nostr
key, a bond and channel key, and a fee wallet funded by its own coinbases. They see each other only
through HTTP, the relay and the chain.

1. Storage. The client uploads a 1 MiB blob, encrypted per provider, to each provider's Blossom server
   (BUD-02 with kind-24242 auth). While it still holds each ciphertext, it commits to M = 64 sentinels of
   16 windows each.
2. Bond. Cut and choose runs over HTTP. Each provider opens 60 of the 64, choosing them from its own
   secret key, and checks every window against its stored bytes. The provider writes the deal from its
   own record of the 4 unopened sentinels, funds a 1 BTC bond from its own wallet, and presigns every
   Challenge_i. The client checks that the deal matches its own, that the bond output is confirmed at
   the script both sides derive, and every provider signature, before it presigns the Respond_i
   transactions. The provider then checks those signatures before it treats the bond as live. The
   internal key is the BIP341 NUMS point, so there is no keypath.
3. Payment. The client funds a 50,000-sat one-way channel to each provider (`layer1/channel.ts`, Spilman
   style: a 2-of-2 leaf, and a client refund after `t_refund`). The provider checks the funding output on
   chain. Each paid epoch is a new client-signed state for the running total, exchanged for the
   invoice's preimage. The provider verifies each signature before releasing the preimage.
4. Epochs. The nonce goes to the provider as a NIP-44 v2 encrypted event (kind 21242). The answer comes
   back as one too (kind 21243). Answers over 60 kB carry an encrypted URL and SHA-256 instead, because
   NIP-44 caps a message at 65,535 bytes. The client checks the answer against its own root and pays
   only if it holds. From epoch 4 one provider zeroes 10% of its chunks, one 50%, and one deletes its
   replica and answers from the honest provider's copy.
5. Enforcement. The client reveals sentinels on chain and mines a block about every 150 ms. Each
   provider's own process polls the chain. When a challenge confirms, it reads r from that
   transaction's witness, takes the 16 windows from its own Blossom server, and submits Respond_i. Core's
   script check is the only verifier. After Δ = 144 blocks with no valid answer, the client spends the
   forfeit leaf.
6. Settlement. Each provider closes its channel on chain with the latest state. The honest provider
   refunds its bond at `t_end`.

Results (`results/market.json`), all read back from the node:

| Provider | Failed epochs (of 10) | Paid on chain | Its own agent's answers | 1 BTC bond |
| --- | --- | --- | --- | --- |
| honest | 0 | 5,120 sats | challenge 0 accepted 2 blocks after the challenge | refunded to the provider at `t_end` |
| deletes 10% | 2 | 4,096 sats | challenge 0 accepted; challenge 1 rejected (`OP_EQUALVERIFY`) | forfeited to the client |
| deletes 50% | 7 | 1,536 sats | challenge 0 rejected (`OP_EQUALVERIFY`) | forfeited to the client |
| outsources | 7 | 1,536 sats | challenge 0 rejected (`OP_EQUALVERIFY`) | forfeited to the client |

Every channel close was checked to pay the provider exactly the total the client signed. The relay
held 40 receipts, and the 24 paid ones each carry a preimage that opens their invoice.

What this run does not show. The parties are separate processes on one machine and one regtest node.
The orchestrator also mines, and makes the providers misbehave through a token-protected admin port.
Challenges run after the epochs rather than interleaved with them. The bond is 1 BTC against a 1 MiB
blob, sized to make the outcome readable, not priced. Payment here is a one-way Bitcoin channel. §2.6
runs the same market over Lightning.

## 2.6 Phase 2b: pay per proof over Lightning (`node layer1/market.ts --pay ln`)

Same market, same seeded nonces, same bonds and enforcement. Only the money path changes. The client
process and each provider process run their own lnd (v0.21.4-beta) on the one regtest bitcoind, each
with its own wallet, node key, TLS certificate and admin macaroon (`layer1/lnd.ts`, LND's REST API).
lnd polls bitcoind over RPC, so the node needs no ZMQ.

- Channels. The client's node is funded with four coinbases of its own and opens a private 50,000-sat
  anchor channel to each provider's node (one confirmation). The provider's own node then checks that
  the channel exists, that the client funded it, and that it is active, before the provider accepts it.
- Invoices. Each epoch's answer carries a BOLT 11 invoice for 512,000 msat from the provider's node.
  The provider checks that lnd's invoice matches the request (hash, amount, its own node id) before
  sending it. The client decodes the invoice itself (`layer1/bolt11.ts`: Bech32 without the length
  cap, amount multipliers, tagged fields, and ECDSA public-key recovery of the payee, checked against
  every valid and invalid example in the BOLT 11 spec). It refuses another network, a missing amount,
  an amount over the price, an expired invoice, or a payee that is not the provider's node from its
  offer. Only then does it pay, with `/v2/router/send`, and it checks the preimage lnd returns against
  the payment hash.
- Receipts. A paid receipt carries the BOLT 11 string and the preimage. Anyone can decode the invoice,
  recover the payee from its signature, and check that SHA-256(preimage) equals its payment hash, with
  no node and no network.
- Settlement. Right after the last epoch, each provider closes cooperatively from its own node, and
  then every lnd stops; the bond phase runs as in §2.5. The client checks that the closing transaction
  spends that channel's funding outpoint and has an output of exactly the sum of the invoices it paid
  that provider. The funder pays the close fee, so the provider's output is exact.

Results (`results/market-ln.json`, a fresh regtest chain, 161 s), read back from the node:

| Provider | Failed epochs (of 10) | BOLT 11 invoices paid | Provider's output in the cooperative close | 1 BTC bond |
| --- | --- | --- | --- | --- |
| honest | 0 | 10 × 512 sats | 5,120 sats | refunded to the provider at `t_end` |
| deletes 10% | 2 | 8 | 4,096 sats | forfeited to the client |
| deletes 50% | 7 | 3 | 1,536 sats | forfeited to the client |
| outsources | 7 | 3 | 1,536 sats | forfeited to the client |

Every outcome matches §2.5 exactly, since the nonces are seeded and the bond phase is unchanged. Each
channel's funding transaction is 165 vB. Each cooperative close is 193 vB, spends its funding outpoint,
and pays a 1,093-sat fee out of the client's side. The relay held 40 receipts, and the 24 paid ones
each carry a BOLT 11 invoice whose payment hash their preimage opens. Each payment took about 250 ms
over a direct channel. No lnd process outlived the run.

Four things lnd does that the code has to allow for:

1. Load on bitcoind. lnd's RPC client opens a new TCP connection for every call. Each node fetches
   every block with `getblockhash` and `getblock`, and a fresh wallet rescans from genesis, because
   every regtest block falls inside its birthday margin. Each connection then sits in TIME_WAIT for two
   minutes. The first full run kept all five nodes up through enforcement (a block every 150 ms) and
   failed partway through, when `bsb-bond` could not connect to bitcoind (Windows error 10048): 13,806
   sockets to the RPC port were in TIME_WAIT. The polling interval barely matters, since the cost is
   per block. So the market closes the channels when pay per proof ends, and stops every node before
   the bond phase and the ~1,500-block jump to `t_end`. The bond phase is near the limit on its own: a
   channel-mode run with no lnd at all ends with about 14,000 sockets in TIME_WAIT, from `bsb-bond`
   polling. With a block every ten minutes none of this arises. It comes from five nodes on one host
   following a chain mined every 150 ms.
2. A fundee that is behind refuses the channel, and tells the funder only "funding failed due to
   internal error". This happened once, when the client opened a channel right after mining a block.
   Before each open, the provider's node now confirms it has reached the current height
   (`POST /channel/prepare`), and so does the client's.
3. A channel that lnd has just reported active can still show zero outbound balance to its router for
   a moment. A payment sent then fails as `INSUFFICIENT_BALANCE` before any HTLC leaves. lnd lets a
   failed payment hash be sent again, so the payer retries that one reason for up to about five seconds,
   and nothing else.
4. A cooperative close sent right after a payment can find the last HTLC still on the commitment and be
   refused. The close is retried for up to ten seconds.

What Lightning changes, and what it does not. The provider is paid by preimage release under HTLC
rules, rather than trusted to release the preimage after taking a channel signature (§2.5's one-way
channel). And the client needs only a route, not a channel per provider. In this run each pair still
has a direct channel, so routing through a hub, and its fees and privacy, is not exercised. The nodes
share one host and one bitcoind. Their keys are separate, but nothing here tests separate machines.

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
   sentinel bonds. Phase 3a (§4.1) measures the proof side.

### 4.1 Phase 3a: an aggregated, publicly verifiable epoch proof (`zk/`)

The statement, for one provider and one epoch, is public: a challenge seed (a public input for now,
later a Bitcoin block hash), q, and a digest D of the deal list (each deal's chunk-tree root R_i and
chunk count n_i). The provider shows q chunks per deal at indices it cannot choose:

    nonce_i = H("bsb/zk-pdp/deal|" ‖ seed ‖ R_i)
    idx_ij  = u64le(H("bsb/zk-pdp/chal|" ‖ nonce_i ‖ u32le(j))[0..8]) mod n_i      for j < q

Each chunk at idx_ij must open to R_i in the `model/storage_bonds.ts` tree: 4 KiB chunks, a 0x00 leaf
prefix, a 0x01 node prefix, the last node paired with itself, and R = H(0x02 ‖ u64le(n) ‖ top). This is
layer 1's epoch with each deal's nonce derived from one public seed. `zk/cairo` is the Cairo program.
It recomputes the indices, hashes each chunk into its leaf, climbs the path, and outputs (seed, q,
number of deals, D). `zk/prover` (`bsb-zk`) proves the program with Stwo through stwo-cairo, in
direct mode with no bootloader, and verifies the result. The verifier pins the program's bytecode,
the security parameters (96-bit: pow 26, blowup 2, 70 queries), the preprocessed trace, the builtin
segments and the output segment, then compares the output with a statement it computed itself from
the deal list. `model/zk_pdp.ts` writes the witness and the statement, and every run cross-checks the
Cairo hashing against node's SHA-256. The chunks never leave the provider.

**Soundness checks** (`zk/adversarial.sh`, `results/zk-pdp-adversarial.jsonl`, both backends). The
honest proof verifies. A provider that lost one challenged chunk, but kept every leaf hash and so can
still send a valid Merkle path, gets no proof: the program aborts on `root mismatch`, and a panicking
run has no trace to prove. Each of the following is rejected:

- a valid proof for a seed the provider chose;
- the honest proof checked against a deal list that differs in one bit of D;
- the honest proof with its output edited to claim q + 1, checked against a statement edited to
  match (the STARK fails);
- the honest proof checked as the other backend's program.

**Benchmark** (`zk/bench.sh`, `results/zk-pdp.md`). The laptop is a Ryzen AI 9 365 running WSL capped
at 4.5 GB, with 4 prover threads and stwo-cairo's preprocessed trace bounded at 2^20 rows. "sha" is
the protocol's tree. "blake" is the same statement with Blake2s-256 in place of SHA-256, with domain
separation by personalization. stwo-cairo proves Blake2s with a native opcode, while SHA-256 here is
plain Cairo with no syscall. That SHA-256 is a rewrite of Raito's in bounded integers, which takes 39%
fewer steps, but it is still about 16k Cairo steps per compression, and one 4 KiB leaf takes 65
compressions.

| backend | deals × q = C | chunks/deal | Cairo steps | prove + execute | peak RSS | proof |
| --- | --- | --- | --- | --- | --- | --- |
| sha | 1 × 1 = 1 | 256 | 1.39 M | 30 s | 3.0 GB | 10.6 MB |
| sha | 1 × 2 = 2 | 256 | 2.71 M | 38 s | 4.0 GB | 10.5 MB |
| sha | 1 × 1 = 1 | 2^18 (1 GiB) | 1.71 M | 31 s | 3.3 GB | 10.5 MB |
| sha | 2 × 1, 1 × 3 | 256 | — | memory-bound (needs 2^21 rows) | | |
| blake | 1 × 1 = 1 | 256 | 26.5 k | 25 s | 2.0 GB | 10.7 MB |
| blake | 4 × 4 = 16 | 256 | 404 k | 28 s | 2.5 GB | 11.0 MB |
| blake | 16 × 4 = 64 | 256 | 1.62 M | 42 s | 4.0 GB | 11.3 MB |
| blake | 1 × 64 = 64 | 2^18 (1 GiB) | 1.99 M | 60 s | 4.0 GB | 11.1 MB |
| blake | C ≥ 128 | 256 | — | memory-bound | | |

Fitted over the verified laptop runs, a SHA-256 chunk costs 6.7 s and 0.8 GB per proof. A Blake2s
chunk costs 0.47 s and 31 MB. Each tree level adds 2.3% to a SHA-256 chunk. Every proof has a floor
of about 20 s and 2 GB. Proof size is about 11 MB, and the STARK verifies in 16–20 ms, plus about a
second to recompute the preprocessed root, which a verifier computes once and caches.

**Larger runs** (`results/zk-pdp-vps.md`) went on a rented box with 8 cores, 31 GB of RAM and no
swap, using 8 prover threads, the same binary and the same executables, and resident memory capped
at 28 GB. K grows as needed, up to 2^23 rows:

| backend | C | chunks/deal | K | prove + execute | peak RSS | proof |
| --- | --- | --- | --- | --- | --- | --- |
| sha | 1 | 256 | 20 | 14 s | 3.1 GB | 10.6 MB |
| sha | 8 | 2^18 (1 GiB) | 23 | 88 s | 21.7 GB | 13.2 MB |
| sha | 16 | 256 | 23 | 122 s | 27.4 GB | 13.3 MB |
| sha | 32 | 256 | — | memory-bound at 28 GB | | |
| blake | 64 | 256 | 20 | 18 s | 4.2 GB | 11.3 MB |
| blake | 256 | 2^18 (1 GiB) | 22 | 68 s | 15.9 GB | 13.0 MB |
| blake | 512 | 256 | 23 | 116 s | 26.8 GB | 14.0 MB |
| blake | 1,024 | 256 | — | memory-bound at 28 GB | | |

On that box a SHA-256 chunk costs 7.6 s and 1.7 GB, and a Blake2s chunk 0.21 s and 50 MB: Blake2s is
about 36 times cheaper in both. Time is close to linear in Cairo steps for both backends, about
6–9 µs per step, so Blake2s's advantage comes from needing roughly 50 times fewer steps per chunk.
Memory per chunk is higher than on the laptop, because the preprocessed trace grows with K. Proofs
grow from 11 MB to 14 MB as K rises, and verification stays at 19–24 ms.

What sets the cost is the number of challenged chunks C = deals × q and the tree depth, not the bytes
stored. At q = 8, from the box's fits (`results/zk-pdp-vps.md` has the full extrapolation):

| per epoch | shape | sha | blake |
| --- | --- | --- | --- |
| 1 GiB or 1 TiB | 1 deal (C = 8) | 1 proof, about 90 s, 22 GB of RAM | 1 proof, about 10 s, 2 GB |
| 1 GiB | 1,024 deals of 1 MiB (C = 8,192) | 512 proofs, 18 h, 6.1 GB of proofs | 16 proofs, 31 min, 194 MB |
| 1 TiB | 1,024 deals of 1 GiB (C = 8,192) | the same: 18 h | the same: 31 min |
| 1 TiB | 2^20 deals of 1 MiB (C = 8.4 M) | 2.1 years of this box | 22 days |

Rows above 28 GB are split into the largest proofs that fit. On the laptop the same rows take 43 h
(sha) and 1.8 h (blake). A single proof at C = 8,192 would need, by the memory fit, about 13 TiB
(sha) or 400 GiB (blake). That is a linear extrapolation, not a measurement.

Three conclusions follow:

- **The tree's hash decides feasibility.** In Cairo, SHA-256 over 4 KiB leaves cannot keep up with a
  daily epoch past roughly a thousand deals per 8-core prover. Blake2s can, at about 0.2 s per
  challenged chunk. The chunk tree is only ever checked by the client and the provider, never by
  Bitcoin script (the sentinels hash separately, see §2), so moving it to Blake2s costs the protocol
  nothing. The alternative is a second Blake2s commitment signed in the deal next to R. If the zk
  path goes ahead, that change should come first.
- **Proofs must be per provider, not per byte.** Cost scales with deals × q. A provider should pool
  its deals into a few large ones, or sample q across the whole deal set instead of per deal (a
  different statement, not built), so that C stays in the hundreds.
- **One proof per epoch needs recursion.** Without it, a 1 TiB provider publishes 16 proofs per epoch
  (128 on the laptop) and a verifier checks each one. That is cheap off-chain (about 20 ms each) and
  hopeless on-chain. stwo-cairo can verify a Stwo proof inside Cairo, so these can fold into one
  proof. That was not built here.

What the proof does not give: Stwo proofs as configured here are succinct and public, but not hiding.
That is acceptable because the chunks are per-replica ciphertext, but it is not zero-knowledge in the
strict sense. The proof also says nothing about where the data sits. A provider can fetch the
challenged chunks from elsewhere at proving time, so per-replica encryption (§3) is still what stops
outsourcing. And it does not make the provider serve the data (§5).

### 4.2 Enforcing the proof on Bitcoin

Bitcoin script cannot check a 10 MB STARK, so the proof needs one of two routes on chain.

**BitVM2 (no soft fork).** The provider acts as the operator. At term end it asserts "every epoch's
proof verified for the deal digests D_e committed on chain", and anyone can disprove that within the
challenge window. With no assertion, the bond goes to the forfeit path. What it takes:

1. **Wrap the STARK in a SNARK.** BitVM2 implementations verify Groth16 over BN254. The epoch proofs
   (Blake2s Merkle channel, M31 field) must be folded by recursion and then wrapped in a
   Groth16-friendly verifier circuit. No off-the-shelf wrap for stwo-cairo proofs was found in this
   work.
2. **Pay BitVM's on-chain size.** Alpen Labs estimates a naive BN254 Groth16 verifier at about
   1.2 GB of script, split into roughly a thousand chunks. The BitVM3 paper puts BitVM2's assert and
   disprove transactions at about 2–4 MB each. These are their figures, not measured here.
3. **The setup committee.** It presigns the transaction graph for every bond UTXO, with 1-of-n
   honest (the web-2.5 residue of §4).
4. **Bind the inputs.** The statement needs D_e committed on chain before the seed block, so the
   provider cannot choose its deals after seeing the challenge, and a header-chain proof that the
   seed is the hash of block h_e. The ZeroSync-style `chain_segment` proof is the building block for
   the second.

**OP_CAT (BIP 347, a soft fork).** With OP_CAT, tapscript can verify a Circle STARK directly, with no
committee and no Groth16 wrap. StarkWare and L2 Iterative's "Bitcoin Wildlife Sanctuary" verified a
small Circle STARK (a Fibonacci-squared statement) on signet in July 2024, across a chain of
covenant transactions. For this proof that would take:

- a recursion step that shrinks it to a proof built for script: a Merkle channel on a hash script
  has (SHA-256, not Blake2s), and a larger blowup with fewer queries for a smaller proof;
- verification spread across covenant-chained transactions;
- the same commitment to D_e and seed binding as above;
- OP_CAT activation, which has not happened.

BitVM2 works today but brings a committee, operator liquidity and megabyte-sized disputes. OP_CAT is
trust-minimized and far smaller, but needs consensus that does not exist yet.

**What either route buys over sentinel bonds:**

- **Watchtower enforcement.** The statement is public (seed, q, D), so anyone holding the deal list
  can check the provider and act: disprove a false assertion under BitVM2, or trigger forfeit under
  OP_CAT. The client no longer has to be online and the only one who cares. Layer 1's receipts
  become checkable too, which §6 notes they are not today.
- **Pooled bonds.** One bond per provider covers every deal in D. It is sized to the provider's whole
  liability, and its setup cost is spread over all its clients, instead of one 308 vB bond and up to
  k presigned challenges per (client, provider) pair.
- **Unbounded, unplanted challenges.** Every block hash is a fresh seed, so there are no k
  precommitted sentinels to run out of. And the challenges are derived publicly rather than chosen
  by the client, so the client-plants-a-bad-h_i attack (finding 5) and the cut and choose that
  defends against it both go away.

Two limits remain. The proof shows knowledge of the chunks, not where they are stored or that they
are served (§3, §5). And per-epoch proving costs the provider real compute, about 0.2 s per
challenged chunk on 8 cores with a Blake2s tree, which it will price in.

### 4.3 Phase 3b: holdings mode, and public proofs in the running market (`layer1/public-pdp.ts`)

**Holdings mode.** Phase 3a gave every deal its own q, so cost grew with the number of deals: 1,024
small deals at q = 8 were 8,192 challenged chunks and about 31 minutes of proving per epoch. Mode 1
draws the q challenges across all of the provider's chunks at once:

    nonce = H_hold(seed ‖ D),   g_j = challenge_index(nonce, j, N),   N = Σ n_i

Here g_j falls in deal k at index g_j − (n_0 + … + n_(k-1)). Each opening names its deal, the program
checks that it is the deal g_j falls in, and the output carries the mode, so neither kind of proof can
pass as the other. Measured on the laptop (Blake2s, q = 8, 256-chunk deals, bounded prover):

| deals | Cairo steps | prove | peak RSS |
| --- | --- | --- | --- |
| 1 | 203 k | 74 s | 2.3 GB |
| 64 | 241 k | 70 s | 2.3 GB |

Sixty-four times the deals cost 19% more steps, all of it hashing the longer deal list into D. In
per-deal mode the same 64 deals at q = 8 would be 512 challenged chunks, which took 116 s and 27 GB
on the 8-core box (§4.1). The times here include writing the witness over /mnt/c; proving is about
20–25 s of each. The same checks as phase 3a hold. A missing challenged chunk gives no proof, since
the program aborts. A mode-1 proof checked against a mode-0 statement for the same deals and seed is
rejected, the outputs differing exactly at the mode felt. Fourteen model tests cover the statement,
the witness layout and the sampling.

The trade-off is per-deal coverage. A provider that dropped a fraction f of all its chunks passes an
epoch with probability (1 − f)^q, exactly as in one large deal. A small deal, though, is now sampled
only in proportion to its size: a 1 MiB deal among 1 TiB of holdings is touched about once in 125,000
challenges. Each client should therefore watch for its own deals being sampled over time, or pay a
provider for a small per-deal q on top. That is a pricing question, not a soundness one.

**Public proofs in the market.** Every party runs in its own process. The client never sends a
challenge:

1. Every 10 blocks, each provider (`layer1/provider.ts --zk`, `layer1/zk-provider.ts`) proves on its
   own. The seed is the boundary block's hash from its own bitcoind, and q = 8 challenges are drawn
   across all its deals. The proof (11.3–11.5 MB) goes onto its own Blossom server as a
   content-addressed blob, and a Nostr event (kind 4245, placeholder) announces the boundary height,
   q, the deal list and the proof's SHA-256 and URL. A provider that cannot prove publishes nothing.
2. The client checks that each of its deals is in the announced list with its own Blake2s root. It
   fetches the proof and checks its hash, rebuilds the statement from its own node's block hash, and
   verifies. It then asks for that epoch's invoice and pays it over its payment channel, and it pays
   nothing otherwise.
3. A watchtower (`layer1/watchtower.ts`), a separate party with its own node and key, verifies the
   same proofs from scratch and publishes signed attestations (kind 4246, placeholder): valid,
   invalid with a reason, or missing six blocks after the boundary. Anyone can act on them, and
   anyone who does not trust it can re-check them from public data.

On a fresh regtest chain, with three deals (1 MiB, 512 KiB and 256 KiB) per provider, three epochs,
and misbehaviour from epoch 2 (`results/public-pdp.json`):

| provider | epoch 1 | epoch 2 | epoch 3 | paid on chain |
| --- | --- | --- | --- | --- |
| honest | proved; client verified; tower valid | proved, verified, valid | proved, verified, valid | 1,536 sats |
| deletes 10% | proved, verified, valid | proved, verified, valid | could not prove; tower missing | 1,024 sats |
| outsources | proved, verified, valid | could not prove; tower missing | could not prove; tower missing | 512 sats |

The 10% deleter proving epoch 2 is the sampling working as designed. It holds 90% of its chunks, so
it passes an epoch with probability 0.9^8 ≈ 0.43, and that seed's eight challenges all missed its
gaps. In epoch 3 one did not. Each failed proof was the program rejecting the witness, not a crash.
Each provider closed its channel on chain, and each close pays exactly the total the client signed
for the epochs it verified. Verification itself takes about 5 s, most of it WSL start-up. Some
verify times in the log are longer because the client and the watchtower queued behind proving
under the single-prover lock.

What this run does not show. The seed is a regtest block hash, and nothing stops a miner from
grinding it, which on mainnet costs a block reward per try. Proofs are verified off chain; the
sentinel bonds of §2 remain the on-chain stick, and §4.2 is what a proof-based bond needs. Nostr
relays could withhold events, so a provider would publish to several relays and a watchtower read
from several. And one machine proved for all three providers, one proof at a time.

### 4.4 Phase 4: the whole stack in one run (`layer1/full-stack.ts`)

Phases 2a, 2b and 3b each had one part of the deal. 2a had the bond and its on-chain enforcement,
2b had Lightning, and 3b had public proofs and the watchtower. Phase 4 joins them so that a failed
public proof costs the provider its bond, with no client-chosen challenge anywhere in the epoch
phase.

Every party runs in its own process with its own keys, fee wallet and lnd: three providers
(`provider.ts --pay ln --zk`), one watchtower and the client, on one regtest bitcoind.

1. Each provider holds three deals (1 MiB, 512 KiB, 256 KiB). The 1 MiB deal carries a 1 BTC
   sentinel bond, set up by cut and choose (64 sentinels of 16 windows, 4 kept) with each side
   checking the other's presignatures. The client's lnd opens a private 50,000-sat channel to each
   provider's lnd.
2. Every 10 blocks each provider proves its holdings unprompted: seed = the boundary block's hash,
   q = 16 over all three deals. The STARK goes on its own Blossom server and is announced on Nostr.
3. The client verifies each proof against its own node and pays that epoch's BOLT 11 invoice over
   Lightning, after checking the payee and amount itself. Without a valid proof it pays nothing.
4. The watchtower verifies every proof on its own and attests valid, invalid or missing.
5. A missing or invalid attestation puts the provider on the client's list. After Lightning settles,
   the client reveals that provider's sentinels on chain. The provider's own process reads each
   revealed secret from the chain and answers from its own bytes. Bitcoin Core rejects a wrong answer,
   and after 144 blocks without a valid one the client spends the forfeit leaf. A provider with no
   adverse attestation is never challenged, and refunds its bond at `t_end`.

From epoch 2, one provider zeroes 10% of every replica and one reads the honest provider's copies.
The result, all read back from bitcoind (`results/full-stack.json`):

| provider | epochs proved and verified | paid over Lightning | watchtower | on-chain challenge | 1 BTC bond |
| --- | --- | --- | --- | --- | --- |
| honest | 3 / 3 | 1,536 sats | valid at 170, 180, 190 | none | refunded through the CLTV leaf at `t_end` (9b5886a2…) |
| deletes 10% | 1 / 3 | 512 sats | missing at 180 and 190 | sentinel 0; its answer rejected (`OP_EQUALVERIFY`) | forfeited through the CSV-144 leaf to the client (226a8d19…) |
| outsources | 1 / 3 | 512 sats | missing at 180 and 190 | sentinel 0; its answer rejected (`OP_EQUALVERIFY`) | forfeited through the CSV-144 leaf to the client (04d5479e…) |

Each Lightning close spends its channel's funding outpoint and has an output of exactly what the client
paid over it, which the run checks. All five paid epochs carry a preimage that opens its BOLT 11
payment hash. At q = 16 a 10% deleter passes an epoch with probability 0.9^16 ≈ 0.19, so being
caught at its first epoch of misbehaviour was the likely outcome, not a forced one. With 16 windows
per sentinel, one on-chain challenge then forfeits it with probability 1 − 0.9^16 ≈ 0.81 (0.9988 over
all four). Here the first did.

What this run does not show. Proofs are verified off chain, so the trigger is the watchtower's signed
attestation. The bond itself is still the two-party sentinel bond, enforced by Bitcoin script; making
the STARK itself the on-chain condition needs §4.2. Lightning settles before the bond phase, because
lnd's per-block RPC would exhaust Windows' ephemeral ports during the 144-block windows. It is one
machine and one regtest node, and the seeds are regtest block hashes.

### 4.5 Phase 5: on-chain payments with inclusion receipts (`full-stack.ts --pay onchain`)

Phase 4 makes "stored" a public fact: anyone can check an epoch's STARK against a block hash. "Paid"
stayed private, a Lightning preimage held by the client. Phase 5 adds a third pay-per-proof backend
(`layer1/onchain.ts`, behind the same `Payee`/`Payer` interfaces) in which payment is a public fact
too: a plain Bitcoin transaction, plus a receipt that anyone can check without a node.

**Binding a payment to an epoch.** The provider's invoice is signed with its Nostr key and carries a
random 32-byte payment hash, the amount, a memo naming the epoch (`bsb zk epoch <height>`), an expiry,
and an x-only pay key `P`. The client pays to the taproot output key

    Q = P + H_TapTweak(P ‖ m)·G,    m = H_bsb/pay(h_1 ‖ … ‖ h_n)

which is BIP341's tweak with `m` in place of a script-tree root. The output commits to the ordered list
of payment hashes it settles, and holds at least the sum of their invoices. The provider spends it on
the key path with `d + t`; in the run each provider imports `rawtr(d + t)` into a Core wallet of its
own and sweeps what it was paid. No OP_RETURN is needed: the commitment costs no bytes, and to anyone
without the invoices `Q` is an ordinary P2TR output. One transaction pays many epochs and many
providers, one output per provider.

**The receipt** (Nostr kind 4247, a placeholder) is the txid plus an inclusion proof: the raw
transaction, the invoices each output pays, the 80-byte block header and height, the transaction's
Merkle branch to the header's root, and the coinbase with its branch. All leaves sit at one depth, so
a real coinbase at leaf 0 pins the tree depth that the branch length claims, and 64-byte transactions
are refused (CVE-2017-12842), as in rust-bitcoin's `ProvenTip::verify_tx`. `verifyReceipt` checks it
against a header chain and asks no node. The client publishes receipts, but a receipt is
self-authenticating, so it does not matter who posts it.

**Where this differs from Lightning's hash lock.**

- Nothing is atomic. On Lightning the payee claims the money only by revealing the preimage, so payment
  and proof of payment are one event. Here the payment hash is only a tag the output commits to. Nobody
  needs or learns a preimage, so `pay()` resolves with an empty one, and the proof is the receipt, which
  exists once the transaction confirms.
- The proof is public and needs nothing from the payee. Once the transaction is buried under enough
  work, the payee cannot deny it and the payer cannot fake it. A preimage proves payment only to someone
  who trusts the invoice it opens, and it is private to the payer until published.
- It is not final at once. A block is ~10 minutes away and can be reorganised, so a verifier asks for
  depth. The run takes 1 confirmation; mainnet would want 3 to 6. Lightning settles in seconds.
- A bad payment cannot fail safe. Paying an expired or wrong invoice moves the coins anyway. The payer
  checks each invoice before paying (signature, network, expiry, amount, no repeats), and the receipt
  records the block time so a verifier can see a late payment.

**The header chain, and why the STARK is a stand-in here.** The receipt needs one more fact: that the
header is block `h` of the real chain. The goal is rust-bitcoin's ZeroSync-style light client (branch
`zk-client`, `zk/sync`). There, Stwo proofs of Raito's Cairo `chain_segment` program attest that batches
of 8 headers validly extend a committed chain state and block-hash MMR. The client links them from
genesis under pinned program id `f58bbd8f…` and preprocessed root `954bc5fe…` (k = 20), and applies the
shape gates: PCS config, preprocessed root, builtin slots, output segment at the final `ap`, program
hash, and a mandatory work floor. A receipt would then carry an MMR inclusion proof for its header in
place of the header chain below. **`chain_segment` cannot validate regtest headers as it stands**, so
this run uses the smallest honest stand-in: `layer1/headerchain.ts` replays the headers from genesis
under the same rules (link, BIP34/66/65 version, time above the median of 11, bits exactly the required
target, hash at or below it, cumulative work, plus the verifier's two-hour clock rule), with no STARK.
It checks against Core's genesis and all 2,101 mainnet headers in rust-bitcoin's fixture, including
the first retarget. What `chain_segment` would need for regtest:

1. The proof-of-work limit. `bits_to_target` (`consensus/src/validation/difficulty.cairo`) caps
   targets at mainnet's `MAX_TARGET = 0xffff·2^208` and rejects exponents 31 and 32 outright. Every
   regtest header has bits `0x207fffff` (target `0x7fffff·2^232`, powLimit `0x7fff…ff`), so every one
   fails `validate_bits`. It needs regtest's powLimit, and exponent 32 accepted.
2. No retargeting. `adjust_difficulty` retargets every 2016 blocks; regtest has `fPowNoRetargeting`,
   so bits stay `0x207fffff`. This only matters from height 2016, past this run.
3. The version rule. `chain_segment/src/lib.cairo` hard-codes BIP34/66/65 at 227,931 / 363,725 /
   388,381; regtest activates all three at height 1. Core's regtest blocks carry version `0x20000000`,
   so they pass either way, but the constants are wrong.
4. Genesis. The Cairo program takes its initial chain state as input, so genesis is not in Cairo, but
   `zk-sync` links from `genesis_state(Params::MAINNET)` (hard-coded in `prove` and `verify`). It needs
   a network option: regtest genesis `0f9188f1…2206`, time 1296688602, bits `0x207fffff`.
5. A new pin. A regtest build is a different program, so `CHAIN_SEGMENT_PROGRAM_ID` must be
   regenerated (`zk-sync constants`). The k = 20 preprocessed root depends only on the prover
   configuration and stays. The shape gates are unchanged.

On regtest the work floor means nothing, because a block costs about two hashes. So this run shows the
mechanism, not the security: anyone can mine a regtest chain with a fake payment in it. On mainnet, the
floor (a recent `nMinimumChainWork`) is what makes a verified chain *the* chain. Cost is the other
caveat. Without recursion the STARK is far larger than what it replaces: zk-sync proves 8 headers per
~15 MB proof. The 198 headers up to this run's last payment (block 197) would be 25 proofs and
~375 MB, against 16 kB of raw headers here, and about 3 minutes of proving in the 4.5 GB WSL. The STARK wins
only with recursion, one proof for the whole chain as Raito does it, which the fork does not have yet.
Mainnet has ~75 MB of headers, and that is the case recursion is for.

**Fees.** A taproot key-path input is 57.5 vB, a P2TR output 43 vB, and the overhead 10.5 vB. A batch
with one input, `n` provider outputs and change is `111 + 43n` vB (`batchVsize`; the run's
transactions match it to the vbyte). One payment for one epoch is 154 vB (with P2WPKH coins, 140.5 vB;
an OP_RETURN commitment would add 43 vB more). At 5 sat/vB that is 770 sats, more than the demo's
512-sat epoch. Batching providers into one transaction and, more importantly, epochs into one output
is what makes it pay:

| one transaction pays | vB | fee at 5 sat/vB | fee per epoch-payment | share of a 512-sat epoch |
| --- | --- | --- | --- | --- |
| 1 provider × 1 epoch | 154 | 770 | 770 | 150% |
| 3 providers × 1 epoch | 240 | 1,200 | 400 | 78% |
| 30 providers × 1 epoch | 1,401 | 7,005 | 234 | 46% |
| 3 providers × 10 epochs | 240 | 1,200 | 40 | 7.8% |
| 3 providers × 100 epochs | 240 | 1,200 | 4 | 0.8% |
| 30 providers × 10 epochs | 1,401 | 7,005 | 23 | 4.6% |

Batching providers alone has a floor: each provider output is 43 vB, 215 sats at 5 sat/vB, 42% of an
epoch's price, however large the batch. Only epochs per output amortise that. Paying every E epochs
turns pay-per-proof into pay-per-E-proofs, so the provider extends E epochs of credit (E × 512 sats per
client) and loses pay per proof's main property, that neither side is ever owed more than one epoch.
Every output must also clear the 330-sat taproot dust limit.

The payee pays too. Spending a taproot key-path output costs 57.5 vB, so each payment output costs
about 100 vB over its life: 43 to create and 57.5 to spend, about 500 sats at 5 sat/vB. The first run
hit this. Each cheater was paid one 512-sat output for epoch 1, and sweeping it alone is 111 vB, 555
sats at 5 sat/vB, so Core's `sendall` refused: the payment was worth less than spending it. The
provider sweep now falls back to Core's 1 sat/vB relay floor, and the results record it
(`uneconomic_at_fee_rate`). The honest provider's three outputs swept in one transaction, 226 vB for
1,536 sats. The 330-sat dust limit is a relay rule, not an economic one. An output is worth
having only if it holds well over a spend's cost at the fee rates the payee expects, which again means
many epochs per output. On-chain payment suits long epochs and large deals, say an epoch per day paid
weekly; Lightning suits small, frequent ones.

**Latency.** A Lightning payment settles in seconds after the proof verifies. On chain, a payment
waits for its batch (E epochs), then a block (about 10 minutes, with a long tail), then the depth the
verifier wants. A ZeroSync-style prover keeps up easily: about 7 s to prove 8 headers, against 80
minutes for 8 blocks. Like zk-sync, a verifier follows the tip natively above the proven height.

**Privacy.** On the chain alone, the payments are hard to spot: no OP_RETURN marker, a fresh-looking
P2TR key per output, no address reuse. But the inputs link a client to every provider it pays in a
batch, amounts are visible, and runs of equal outputs (E × 512 sats) are a fingerprint. Published
receipts give away the rest by design: client, provider, amount, epoch and txid, all linked. Public
verifiability and public linkage are the same thing. Lightning keeps payments between the two parties.
A middle course is to keep receipts private and publish one only when a provider claims it was not
paid. A receipt verifies just as well months later, as long as the headers can still be had.

**Paid is provable; unpaid is not.** A payment is proven by one Merkle branch (~12 hashes for a
3,000-transaction block) plus the header-chain proof. To prove that invoice `h` was not paid, you would
have to show that no output in any block since the invoice was issued commits to `h`. With
pay-to-contract, nobody without the invoices can even recognise such an output. And since `h` can be
batched with any other hashes, there is no finite set of candidate keys to rule out. So it would take a
proof over every transaction in every block of the window: Raito-style full block validation, at
billions of Cairo steps per segwit-era block, not 81k per header. Disputes therefore resolve one way. A
"paid" claim can be proven. An "unpaid" claim can only be refuted, by a receipt, never confirmed. The
watchtower therefore attests three things on the paid side: `paid`, `invalid`, and `no-receipt`. The
last means "no valid receipt was published by the deadline", which is a fact about publication, not
about the chain. The provider's remedy for non-payment is the one pay per proof always had: stop proving
for that client. Lightning has the same asymmetry. A preimage proves payment; nothing proves its absence.

**The run** (`node layer1/full-stack.ts --pay onchain`, fresh regtest, `results/full-stack-onchain.json`):
the same roles as §4.4, with no lnd anywhere. The watchtower ran with no bitcoind. It followed the
client's header mirror and checked every header from genesis, took each epoch's seed from that chain,
verified each STARK, and verified each receipt.

| provider | stored (watchtower) | paid (watchtower, from receipts) | on chain | 1 BTC bond |
| --- | --- | --- | --- | --- |
| honest | valid at 170, 180, 190 | paid at 170, 180, 190 | 3 outputs, 1,536 sats; swept in one 226-vB transaction at 5 sat/vB | refunded through the CLTV leaf (9b5886a2…) |
| deletes 10% | valid at 170; missing at 180, 190 | paid at 170 | 1 output, 512 sats; sweepable only at 1 sat/vB (111 vB) | forfeited through the CSV-144 leaf (226a8d19…) |
| outsources | valid at 170; missing at 180, 190 | paid at 170 | 1 output, 512 sats; sweepable only at 1 sat/vB (111 vB) | forfeited through the CSV-144 leaf (04d5479e…) |

| payment | epochs | provider outputs | vB (model) | fee at 5 sat/vB | receipt |
| --- | --- | --- | --- | --- | --- |
| be9e4f18… | 170 | 3 | 240 (240) | 1,205 sats | 3,307 B, checked in 433 ms against 178 headers |
| 4c1b9ea6… | 180 | 1 | 154 (154) | 775 sats | 1,959 B, 174 ms, 188 headers |
| 6e7698b4… | 190 | 1 | 154 (154) | 775 sats | 1,959 B, 123 ms, 198 headers |

Paying the run's five verified epochs one epoch at a time cost 2,755 sats in fees for 2,560 sats of
storage payments. A second fresh run with `--pay-every 3` (`results/full-stack-onchain-batched.json`)
paid every epoch in one transaction after epoch 3. This time the 10% deleter passed epoch 2 (a 0.19
chance at q = 16) and was caught at 190. The transaction was `2cad7cc2…`: 240 vB, fee 1,205 sats, with
three provider outputs committing to 3, 2 and 1 payment hashes (1,536, 1,024 and 512 sats). Six
epoch-payments cost 1,205 sats in fees, where the per-epoch run paid 2,755 for five. Its one 4,999-byte
receipt verified in 0.7 to 1.1 s, all six invoice signatures included. The honest provider's single
1,536-sat output then swept at 5 sat/vB (111 vB). The outsourcer's lone 512-sat output again could not
be swept at that rate. Both cheaters forfeited as before. The bond transactions are the same as §4.4's, since the parties' keys are seeded.
At the end, a fresh header chain built from the mirror (1,615 headers, as any third party would
build it) verified all three receipts again, at 1,418 to 1,438 confirmations. The run reads every
payment output back from bitcoind and checks that each provider's sweep spends it. Verification
time goes almost entirely to the invoices' BIP-340 signatures, which this repo checks in plain bigint
arithmetic (120 to 170 ms per invoice). The Merkle and header checks are a few dozen SHA-256 calls. The regtest blocks hold only the
coinbase and the payment, so every Merkle branch here has one hash.

What this run does not show. The header chain is checked by replay, not by a STARK (above). The work
floor is the regtest chain's own work at startup, which proves nothing. The mirror is the client's
own node, which a regtest verifier cannot tell apart from a forger. The payer is a Core wallet on the
shared node. The 1-confirmation depth would be unsafe on mainnet.

### 4.6 Phase 6: the storage proof through BitVM2, a feasibility spike (`zk/risc0`, `zk/bitvm-check`)

Both upstream projects say what they are, and everything in this section inherits it.
chainwayxyz/risc0-to-bitvm2: "This software is experimental and should not be used in production",
and its header chain "does not necessarily prevent the malicious actors to generate proofs for their
private forks". BitVM/BitVM: "DO NOT USE IN PRODUCTION!" Nothing here touched mainnet or real funds,
and every key in it, the Winternitz secrets included, is a test value.

§4.2 stopped at "wrap the STARK in a SNARK", with no wrap for stwo-cairo proofs to be found. The one
working path from a STARK to BitVM's Groth16 verifier is risc0-to-bitvm2, whose circuit verifies a
RISC Zero receipt and nothing else: RISC Zero's Circom STARK verifier, a Blake3 binding of the
claim, Citrea's proving key, rapidsnark in Docker. So the 11 MB Cairo proof cannot go through it,
and the spike proves the same statement again in RISC Zero, binds each epoch's seed to a proven
header chain, wraps the result in Groth16, and checks it with BitVM's verifier. Everything ran on an
Anthropic cloud VM with 4 vCPUs, 15 GB of RAM, no swap and no GPU; the numbers are in
`results/bitvm2-spike.json`.

**Milestone 1: the holdings guest** (`zk/risc0/methods/guest/src/bin/hold.rs`, risc0-zkvm 2.0.1, the
versions risc0-to-bitvm2 pins). It is mode 1 of §4.3 on the protocol's SHA-256 tree, with the "sha"
tags of `model/zk_pdp.ts`: D over the deal list, nonce = H_hold(seed ‖ D), g_j over N = Σ n_i mapped
to a deal and an index, and each 4 KiB chunk's path climbed with the `storage_bonds.ts` prefixes,
depth checked as `merkleVerify` checks it. Every hash goes through the zkVM's SHA-256 accelerator.
The journal is statementOutput's 19 felts, each a big-endian u32 (`zk_pdp.ts journalBytes`), so on
SHA-256 it reads seed ‖ q ‖ mode ‖ deal count ‖ D, 76 bytes with the seed and D as raw bytes.
`risc0Witness` writes the guest's input, and `zk/risc0/check-journal.ts` recomputes the expected
journal from the deal list alone and compares bytes.

| deals | q | cycles | segments | prove, composite | prove, succinct | peak RSS | seal, composite / succinct |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 8 | 117 k | 1 (2^18) | 79 s | 112 s | 2.3 GiB | 256 kB / 223 kB |
| 1 | 16 | 231 k | 1 (2^19) | 175 s | 202 s | 4.6 GiB | 268 kB / 223 kB |
| 1 | 64 | 909 k | 1 (2^20) | 367 s | 411 s | 9.1 GiB | 281 kB / 223 kB |
| 64 | 8 | 145 k | 1 (2^18) | 79 s | 108 s | 2.3 GiB | 256 kB / 223 kB |
| 64 | 16 | 262 k | 1 (2^19) | 168 s | 197 s | 4.6 GiB | 268 kB / 223 kB |
| 64 | 64 | 961 k | 2 (2^20 + 2^16) | 403 s | 484 s | 9.1 GiB | 502 kB / 223 kB |

Deals are 256 chunks (1 MiB) each; `zk/risc0/bench.sh`, `results/bitvm2-spike-m1.jsonl`. Every
journal matched `journalBytes` byte for byte, and `node --test model/*.test.ts` covers the encoding
and the witness layout (32 passing). A challenged chunk costs about 14,100 cycles, nearly all of it
the 65 compressions of its leaf, against roughly 1.4 M Cairo steps in §4.1, because SHA-256 here is
an accelerator call and not interpreted arithmetic. Sixty-four deals add 27 k cycles at q = 8, the
deal list hashed into D, and nothing else. Time and memory follow the padded segment size: a
2^18-cycle segment proves in about 80 s and 2.3 GiB, and each doubling doubles both, so q = 64 is 6
minutes and 9.1 GiB on four cores. Memory stops there, since RISC Zero splits longer runs into
2^20-cycle segments by default (the last row), so q can grow at a cost in time, not RAM. The
succinct receipt, which milestones 2 and 3 need, adds 30 to 80 s of recursion and is 223 kB whatever
q is. Against the Stwo proof on the 8-core box (§4.1, 7.6 s and 1.7 GB per SHA-256 chunk), q = 64
here is 5.7 s and 0.14 GiB per chunk on half the cores; a STARK of a VM with a SHA-256 circuit beats
one of SHA-256 written in Cairo, which is the point §4.1 made about Blake2s from the other side.

Two failing cases, both on 64 deals at q = 16 (`results/bitvm2-spike.json`, `m1.failing`):

- A provider that lost the chunk challenge 5 selects, and sends zeros with the right path in its
  place, gets no receipt. The guest panics with `root mismatch`, `exec-hold` and `prove-hold` both
  exit 1, and no receipt file is written.
- A provider that answers a seed of its choosing gets a valid receipt for it, whose journal differs
  from the statement built from the real seed in its first 32 bytes, so `check-journal.ts` rejects
  it from byte 0. The seed is public output, not something the proof can be checked against without
  a chain, which is what milestone 2 is for.

**Milestone 2: the seed is a block hash.** risc0-to-bitvm2 compiles one header-chain source per
network (`BITCOIN_NETWORK` at build time) and ships the ELFs. The regtest build fixes the target at
0x7fffff·2^232, requires bits 0x207fffff, never retargets, keeps the median-time rule, and is its
own pinned image: the first, second and fifth of the five things §4.5 found missing from
`chain_segment`. It checks no version rules on any network, so the third does not arise, and it pins
no genesis at all (below). So it does accept regtest headers. Its published
`elfs/regtest-header-chain-guest.bin` has image ID `5cb173ee…`, the value upstream's final-spv guest
pins for regtest, and the host refuses any other ELF. Run as published on a fresh Bitcoin Core v30.2
regtest chain (`zk/risc0/headers.ts` exports heights 0–200 over RPC), it proved all 201 headers in
1.15 M cycles, about 5,700 per header against roughly 81 k Cairo steps in §4.5's `chain_segment`:
two segments, 625 s to a succinct receipt, 9.2 GiB. Its journal ends at tip 200, hash `4ae51974…`,
total work 0x192, two per block, which is what regtest work is worth.

The term guest (`zk/risc0/methods/term/src/bin/term.rs`) takes that receipt and three holdings
receipts, for seeds equal to the hashes of blocks 170, 180 and 190 (3 deals, q = 16, as in §4.4;
3:15 and 4.6 GiB each), and proves in one receipt that:

- the header-chain receipt verifies under the pinned image, and its journal names that same image;
- leaf 0 of the chain's block-hash MMR is regtest's genesis;
- each holdings receipt verifies under the holdings image, with the term's q, mode 1, deal count and
  D;
- each seed, reversed into internal byte order (layer 1 seeds are RPC display-order hashes), is leaf
  h_i = 170 + 10·i of the MMR, at a position the path length and peak both follow from, so a block
  at another height cannot stand in for it;
- h_i + 6 ≤ the tip.

Its journal is SHA-256 of a 216-byte preimage carrying both image IDs, q, the deal count, D, the
first height, step, epoch count, depth, tip height, tip hash and total work, since the Groth16
circuit takes exactly 32 bytes. Composing four receipts costs 71 k cycles and 188 s, nearly all of
it resolving the assumptions, at 1.5 GiB. A holdings receipt for block 181 offered as epoch 180
panics with `seed is not the block hash at its height`, and a depth of 11 with `seed block too
shallow`.

Two checks in that list are there because upstream's own composition lacks them, and both gaps
reproduce with upstream's published regtest ELFs (`bsb-r0 forge-demo`):

1. The header-chain guest verifies its predecessor under the `method_id` its input carries and
   copies that value into its journal, and final-spv verifies the outer receipt under the pinned
   image without comparing the journal's `method_id` to it. A guest of a dozen lines (`forge.rs`)
   committed a chain state with total work 2^256 − 1 and a fabricated block at height 170; one step
   of the genuine image with that as its predecessor and zero headers produced a receipt that
   verifies under `5cb173ee…`. Upstream's regtest final-spv accepted, in the executor, a payment in
   the fabricated block on that chain. The term guest rejects the same receipt with `header chain
   proven under another image`.
2. final-spv calls `spv.verify(...)`, which returns whether the block is in the MMR, and discards
   the result. Over the honest chain, final-spv accepted a fabricated block whose MMR path is seven
   zero hashes. BitVM's copies of both guests have the same lines.

Neither is a flaw in BitVM2 or in RISC Zero. They are glue, which is where a statement like "this
seed is a block hash" is actually decided, and nothing on chain reads it.

**Milestone 3: Groth16.** `bsb-r0 groth16` takes the term receipt through risc0-to-bitvm2's pipeline
as its `host/src/docker.rs` (`stark_to_succinct`) runs it. `identity_p254` re-proves the succinct
receipt with Poseidon over BN254's scalar field, which the Circom verifier can afford (133 s); the
seal and the claim's pre-state, post-state, journal and control IDs become the circuit's input bits;
and the prover image runs the witness generator and rapidsnark against Citrea's proving key. The
image is pinned by digest (`ozancw/risc0-to-bitvm2-groth16-prover@sha256:840b8331…`, 8.2 GB
unpacked, the zkey alone 3.77 GB with SHA-256 `df6809b3…`). It ran in 79 s, and its cgroup's
high-water mark was 8.4 GiB, which counts the page cache of the zkey it reads as well as the
prover's own memory. `docker.rs` has no license, so `zk/risc0/host/src/wrap.rs` is written from the
circuit's inputs rather than copied; the proof it led to verifies with exactly the output the
formula below predicts, which a misplaced input bit would not give. The proof is the usual 256 bytes
(A and C in G1, B in G2), the whole step 3 min 32 s.

The one public output is the first 248 bits of

    Blake3( SHA256( bitrev(control_root) ‖ pre_state ‖ post_state ‖ id_bn254 ) ‖ journal )

where pre_state is the term guest's image ID (`b484d033…`), post_state the digest of a run that
halted normally, control_root the succinct verifier's root with each byte's bits reversed, id_bn254
the BN254 identity control ID, and journal the 32-byte term digest. For this run it is
`0x2afe4d2b…f7f602`. It was computed three ways and they agree: by the circuit (public.json); by the
host in Rust; and by `zk/risc0/check-groth16.ts` from public data alone, rebuilding the 216-byte
preimage from the deal list, the term parameters and the regtest block hashes, SHA-256 into the
journal, SHA-256 of the constants, and a 20-line Blake3 of the one 64-byte block. The verifying key
came out of the image's own zkey (`snarkjs zkey export verificationkey`) and matches all 18
coordinates of the constants in upstream's test; the key, the proof and its public input are in
`results/bitvm2-spike-groth16/`.

`zk/bitvm-check` then checks the proof with BitVM's code rather than the prover's: arkworks' Groth16
verifier as BitVM uses it (it accepts the proof, and rejects it for the public output of a journal
with one bit flipped), and BitVM's chunked verifier, which compiled Citrea's verifying key into 364
disprove tapscripts, 1.11 GB in all and 0.34 to 3.95 MB each (158 s). Signing the honest assertion
(15 field elements and 363 intermediate 16-byte Blake3 hashes, 286,771 bytes of Winternitz
signatures) and running it against all 364 took 214 s, and none of them succeeds, which is what
BitVM's "valid proof" means. Two invalid assertions were then caught, as BitVM2 needs them to be:

| asserted | caught at | disprove script + witness | runs |
| --- | --- | --- | --- |
| the same proof, for the public output of a journal with one bit flipped | tap 363, `PostMillerFinalVerify`, the final pairing check | 947,271 + 7,738 bytes | succeeds, 0.08 s |
| the honest assertion with intermediate hash 181 corrupted | tap 181, a Miller-loop point step | 3,472,345 + 3,339 bytes | succeeds, 0.15 s |

Both fit the 4 MB block less BitVM's 16 kB reserve. The whole check took 17 minutes and 5.7 GiB. It
runs in BitVM's script interpreter (rust-bitcoin-scriptexec), not in Bitcoin Core, so the step after
it is a mined disprove. BitVM's own regtest test `test_disprove_success` (kick-off 2, the four
assert transactions and a disprove, through esplora) was run with this proof, Citrea's key and its
public input in place of the test's dummy circuit (`zk/bitvm-check/bridge-regtest.patch`); as in
that test, the asserted proof has A replaced by a random point. Three things in the bridge at
7d1ca36 stood in the way, each a finding about that code:

1. The assert signer passes `hex(secret_key)` to a Winternitz signer that hex-encodes its input
   again, so it signs under keys connector E does not hold, and assert-commit-1 fails
   `OP_EQUALVERIFY` before it is broadcast. The unmodified test fails the same way with BitVM's own
   dummy proof. One line fixes it.
2. Connector C compiles its 364 disprove leaves from `RawProof::default()`, a fixed mock key,
   whatever key the graph is meant for, and its lock-script cache id leaves the key out. As written
   the bridge cannot disprove a proof under any other key. The patch compiles the leaves for the
   proof's own key.
3. Current esplora images answer 413 to request bodies over electrs' limit, and assert-commit-1 is
   1.13 MB; BitVM's script raises only nginx's limit. `zk/bitvm-check/esplora-relay.ts` hands
   `POST /tx` to the container's bitcoind, which also meant waiting for a block before the test looks up
   the reward.

With those, every transaction was mined on Bitcoin Core 30.2 regtest with `acceptnonstdtxn=1`. The
disprove spends connector C's leaf for tap 363 (`PostMillerFinalVerify`) with a 475-item witness and
pays the challenger's reward output, and with the reward lookup waiting for that block the test
passes (`test result: ok`, 8 min 17 s, 4.2 GiB). Sizes are in (c).

**(a) A bond as a BitVM2 graph.** BitVM2's bridge has an operator who fronts a withdrawal and is
reimbursed from the peg-in unless someone disproves its claim. A storage bond is the same machine
with the money pointed the other way: the collateral is the peg-in, and what the provider is
reimbursed with is its own bond.

1. Setup. The provider's collateral goes into an n-of-n MuSig2 output, and before it confirms the
   committee presigns that UTXO's graph: kick-off, challenge, assert, the 364 disprove leaves, take
   and timeout. The graph pins the statement. The term guest's image ID is the Groth16 pre-state,
   and the term preimage holds the holdings and header-chain image IDs, q, the deal count, D, the
   first epoch height, the step, the number of epochs and the depth.
2. During the term nothing changes. The provider proves each epoch, publishes it, and is paid per
   verified epoch (§2.6, §4.5). The bond is not touched.
3. At term end the provider folds the epoch receipts and a header-chain receipt into one term proof,
   wraps it, and kicks off. If challenged it asserts: Winternitz signatures over the Groth16 public
   input, the 14 field elements and 363 intermediate hashes of BitVM's chunked verifier, and the
   chain values the graph cannot know in advance (tip height, tip hash, total work). A graph could
   demand the assertion every term instead; that is the 370,000 vB of (c) whether or not anyone
   objects, which is why BitVM2 makes it the challenger's call.
4. Anyone who finds a chunk whose signed inputs and outputs disagree spends that disprove leaf, and
   the bond is slashed. A challenger who thinks the asserted chain is not the heaviest must be able
   to say so too (d).
5. If the provider has not kicked off by the deadline, a presigned, timelocked spend pays the bond
   to the client. With no successful disprove by the end of the window, the provider takes it back.

A provider that lost data in any epoch cannot make the term proof at all. At term end its choices
are silence, which times out to the client, or a false assertion, which is disproved. That is
stricter than the sentinel bond, where each on-chain challenge catches a 10% deleter with
probability 0.81 at m = 16 (§4.4), but it acts only at term end.

**(b) What BitVM's repository provides, and what is missing.** It provides the Groth16 verifier as
Bitcoin script ("around 1 GB"), the chunker that splits it into 364 disprove tapscripts with
Winternitz-committed intermediate values, and a bridge whose peg-in and peg-out graphs are presigned
by verifiers with MuSig2 and run on regtest against esplora. Its copies of the header-chain and
final-spv guests are Citrea's. Missing for this design:

- A storage graph. The bridge pays a withdrawer and reimburses an operator; a bond needs refund,
  slash and timeout-to-client around a term deadline, with the client as a party to the timeout.
- A binding of the public input to the statement. The chunker treats the public input as one
  committed value (NUM_PUBS = 1). Nothing in the script checks that it equals Blake3(constants ‖
  SHA256(term preimage)) for the graph's pinned constants and the committed chain values, so a graph
  needs one more leaf that does.
- Aggregation. The term guest here is that piece, for a fixed D and q: it verifies N epoch receipts
  as assumptions in one proof. Per-epoch deal digests D_e committed on chain before each seed block
  (§4.2) are not built.
- The chain-work challenge. The bridge's answer to a private fork is `disprove_chain` with a
  "superblock", and `find_superblock()` returns a hard-coded mainnet header under a TODO.
- The committee, which is a social object, not code: who the n signers are for a storage bond.

**(c) Dispute costs.** BitVM's README puts the Groth16 verifier at "around 1 GB" of script before
chunking. For Citrea's key the chunker produced 364 disprove tapscripts totalling 1.11 GB, the
largest 3.95 MB; they sit as leaves of one taproot output, and a dispute reveals one. The sizes
below were read back from the regtest run of BitVM's bridge test with this proof (milestone 3) as
weight / 4. Beside them is the fixed fee BitVM's bridge pays each transaction
(`bridge/src/transactions/base.rs`, at 1 sat/vB), which for the three large assertions is 2.6 to 6.7
times their size, and whether Core 30.2 with default policy would relay it (`testmempoolaccept` on a
node without the inputs, so only the checks before input lookup).

| transaction | vB, measured | BitVM's fixed fee, sats | default policy |
| --- | --- | --- | --- |
| kick-off 2 | 5,758 | 5,461 | passes |
| assert-initial (379 outputs) | 16,402 | 48,953 | passes |
| assert-commit-1 (300 inputs) | 282,371 | 739,137 | rejected, `tx-size` |
| assert-commit-2 (78 inputs) | 70,426 | 470,440 | passes |
| assert-final | 352 | 352 | passes |
| disprove, tap 363 | 239,057 | 238,785 | rejected, `tx-size` |

A contested term is about 370,000 vB of assertion and, at the cheapest leaf seen here, 239,000 vB of
disprove: 610,000 vB, about 880 sentinel challenges at 696 vB. An uncontested one is about 12,500 vB
by BitVM's constants (kick-off 1 6,231, start time 407, kick-off 2 5,461, take 1 380), against the
sentinel bond's 308. At 5 sat/vB the assertion costs about 1.85 M sats and the disprove 1.2 M. The
assertion Winternitz-signs 378 values, 15 of 256 bits and 363 of 128, and reveals the scripts that
check them; the signatures alone are 286,771 bytes. The provider pays for it, so a challenge has to
carry enough to cover it, as BitVM2's challenger does for its operator; otherwise anyone can make a
provider spend 0.02 BTC for the price of a challenge.

A disprove's size depends on which chunk is wrong. The two run off chain carry 0.96 MB and 3.48 MB
of script and witness, about 240,000 and 870,000 vB, and the largest of the 364 leaves alone is 3.95
MB, nearly a block; the 3.48 MB one costs about 4.3 M sats at 5 sat/vB. The provider chooses what to
assert, so it also chooses where its assertion is wrong, and with that what a challenger pays to
disprove it. The bond has to cover all of this before it is worth anything as a stick.

**(d) Trust.** Phases 0–2 trust no committee, no oracle and no auditor (the table at the top). This
route brings back four things, and the spike found the third weaker than assumed.

1. The committee. The graph is presigned by an n-of-n MuSig2 set for each bond UTXO. One honest
   signer who deletes its key keeps the graph the only way to spend the bond; all n together can
   sign it anywhere. Every member must also be online at setup, so any one of them can stall a bond
   from being made. Who those n are for a storage market (the client, the provider, some
   independents) is the open question §4 named.
2. One honest challenger, online within every window and funded to pay the disprove fee (about 1.2 M
   sats at 5 sat/vB for the leaf mined here, more for a larger one). The bond can pay the reward,
   but someone has to be watching, which is the watchtower's job today under a different name.
3. The Groth16 trusted setup. A Groth16 key is sound only if nobody kept the toxic waste of its
   circuit-specific phase 2. `run_ceremony.sh` in risc0-to-bitvm2 is a demonstration: one "pretend
   contribution" (`echo 'Entropy' | snarkjs zkey contribute`, which snarkjs mixes with system
   randomness, so whoever ran it holds the only secret) and a beacon from the fixed public value
   `0102…1f`, which adds nothing secret. A key made with it is forgeable by whoever ran it and kept
   that randomness. The key in the pinned prover image, which its Dockerfile downloads from
   static.testnet.citrea.xyz, records exactly that transcript in its own mpcParams
   (`zk/risc0/zkey-contributions.js`): one contribution named "1st Contributor Name", then the
   beacon "Final Beacon phase2" with hash `0102…1f` and 2^10 iterations (zkey SHA-256 `df6809b3…`).
   So the key is sound only if the one party that made that contribution discarded its randomness;
   if it did not, it can prove any public input, and a bond enforced with this key is as safe as
   that party. Whether Citrea now serves a different key could not be checked, because that host is
   not reachable from here; a real deployment needs a multi-party phase 2 that its committee, or
   anyone, can verify against the circuit.
4. The header chain. The circuit proves that a chain of headers has valid proof of work from an
   all-zero parent, not that it is Bitcoin's chain. The term guest pins regtest's genesis hash,
   which upstream's guests do not, but a fork from genesis is still a valid proof, and on regtest a
   block costs about two hashes. The term preimage therefore carries tip height, tip hash and total
   work, and the graph needs a challenge in which anyone shows a heavier chain; BitVM's version of
   that is the placeholder above. Upstream's README says as much ("does not necessarily prevent the
   malicious actors to generate proofs for their private forks").

Two more come from Bitcoin's relay policy, the point finding 4a made about 520-byte answers.
Assert-commit-1 (282,371 vB) and every disprove (239,057 vB at the cheapest leaf here) are over the
100,000 vB (400,000 WU) standard transaction limit, and Core 30.2 with default policy rejects both
for `tx-size`. BitVM's regtest script starts Core with `acceptnonstdtxn=1`, and the run here did the
same. On mainnet both would go to a miner directly, which is a trusted party for the length of the
window, and a disprove that cannot reach a miner in time is lost. And the glue around both upstream
projects had gaps that only running it showed: a receipt of the genuine header-chain image can carry
another image's chain state, final-spv drops the result of its MMR check (milestone 2), and the
bridge signs its assertions under the wrong keys and compiles its disprove leaves for a mock key
(milestone 3). None is a BitVM2 property, but they show how much of this route's security sits in a
few lines that nothing on chain reads.

**(e) Against the watchtower trigger.** Today (§4.4, §4.5) the watchtower verifies each epoch's
STARK off chain and signs valid, invalid or missing; a missing or invalid attestation makes the
client reveal sentinels, and Bitcoin Core enforces the answer to each one.

| | watchtower attestation + sentinel bond (today) | BitVM2 term bond (this spike) |
| --- | --- | --- |
| What Bitcoin checks | one 80-byte item per challenge against a precommitted hash | the Groth16 verifier, chunked, only if someone disputes |
| Who can trigger | the client, holding the sentinel secrets | anyone watching, without secrets |
| Catches a 10% deleter | an epoch fails with probability 1 − 0.9^16 = 0.81 at q = 16, then each challenge forfeits with 0.81 at m = 16 | the term proof cannot exist once any epoch failed: 1 − 0.9^(16E) over E epochs, 0.994 at E = 3 |
| When | in the epoch after the attestation, within Δ = 144 blocks | at term end, after the challenge window |
| Bonds | one per (client, provider) pair, 308 vB to open and close | one per provider for every deal in D |
| Cost of a dispute | 696 vB per challenge (§2.4) | about 370,000 vB to assert, then 239,000 to 990,000 vB to disprove |
| Relay | standard, every transaction through the mempool | assert-commit-1 and every disprove non-standard |
| Trusted | nobody but Bitcoin; the watchtower only for timeliness, and its claims are rechecked from public data | the committee (1 of n), one funded challenger, the Groth16 setup's one contributor, a miner for non-standard transactions, a chain-work challenge not yet built |
| Prover cost per epoch | STARK of the holdings statement (§4.3) | the same in RISC Zero (milestone 1), plus one term proof and one Groth16 wrap at term end |

BitVM2 takes the client out of enforcement, pools bonds across deals, and removes the precommitted
sentinels along with the cut and choose that guards them. It pays for that with four trusted
parties, one of which, as shipped, is a single contributor to a proving key, and with disputes in
transactions that Bitcoin's relay policy will not carry. The attestation trigger keeps every stick
in standard script and needs nothing from anyone but the client's being online. Until there is a
Groth16 key with a real phase 2, a storage graph with a public-input check and a chain-work
challenge, and a relay path for megabyte witnesses, the sentinel bond triggered by attestations is
the mechanism that works on mainnet, and BitVM2 is what would widen who can enforce it.

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
| 2a | The market: separate processes per party, NIP-44 epoch challenges (official vectors pass), a real 1 BTC bond per deal, one-way Bitcoin payment channels for pay per proof, and on-chain enforcement by each provider's own agent; multi-window sentinels | Done: every cheater forfeits, the honest provider is paid and refunded, all checked on chain (§2.5) |
| 2b | Lightning in place of the per-pair channels (regtest LND behind the same Payee/Payer interface) | Done: `--pay ln`, one lnd per party, BOLT 11 decoded and checked by the client, closes checked on chain (§2.6); the one-way channel stays the default |
| 2 | zk setup proof for sentinels (SHA-256 + Merkle path, CPU prover), replacing cut and choose | Next |
| 3 | BitVM2-shaped pooled bond: registry, header-seeded challenges, aggregated proof; measure cost per deal against phase 1 | Research |
| 3a | Aggregated epoch proof: one Cairo program over all of a provider's deals, proved and verified with Stwo, SHA-256 and Blake2s trees, soundness cases, cost table and extrapolation (§4.1); what on-chain enforcement takes (§4.2) | Done for the proof; recursion and on-chain verification not built |
| 3b | Holdings mode (cost independent of the number of deals) and public proofs in the market: block-hash seeds, proofs on Blossom, Nostr announcements, an independent watchtower, pay only for verified epochs (§4.3) | Done on regtest; proofs verified off chain |
| 4 | The whole stack in one run: bonds, public proofs, Lightning payment per verified epoch, and watchtower attestations that trigger on-chain sentinel challenges (§4.4) | Done on regtest: both cheaters forfeit, the honest provider is paid and refunded |
| 5 | On-chain pay per proof: signed invoices, pay-to-contract outputs committing to payment hashes, batching, receipts (txid + Merkle inclusion proof) checked from a header chain with no node; a watchtower that attests both "stored" and "paid" from public data (§4.5) | Done on regtest with a header-replay stand-in for the ZeroSync-style STARK; a regtest `chain_segment` is next |
| 6 | BitVM2 feasibility spike: the holdings statement in RISC Zero, seeds bound to risc0-to-bitvm2's regtest header-chain proof, one term proof, the Groth16 wrap, BitVM's verifier and chunked disprove; the bond as a BitVM2 graph (§4.6) | Done as a spike, regtest and test keys only: every milestone ran, and BitVM's bridge mined a disprove of a wrong assertion of this proof. The graph of §4.6(a) is not built |

## What is and is not tested

The TypeScript model signs a stand-in digest, uses a placeholder for the MuSig2 key, and sums transaction
sizes from parts. The regtest harness replaces all three with the real thing, and Core 31.1 accepts and
rejects exactly as the model predicts.

What neither covers yet:
- Mainnet relay beyond Core defaults. Other node policies and pinning across a real network are
  untested.
- Fee spikes during Δ.
- Lightning beyond direct channels. `--pay ln` pays real BOLT 11 invoices over regtest LND (§2.6),
  but over one direct private channel per pair, on one host. Multi-hop routing, fees, MPP, NWC and Core
  Lightning are untested. The in-memory stub is still the default in `layer1/demo.ts` and the unit
  tests, and the LND backend's own unit tests use a fake node.
- Separate machines. The parties are separate processes with separate keys and wallets, but they share
  one host and one regtest node.
- A STARK of the header chain behind payment receipts. `chain_segment` cannot take regtest headers
  (§4.5), so receipts are checked against a replayed header chain, and on regtest the work floor proves
  nothing. On-chain payments are untested on any network but regtest, and at depths beyond 1.
- BitVM2 on anything but regtest, and the storage graph of §4.6(a), which is not built. The disprove
  that was mined went through BitVM's peg-out graph with three local fixes (§4.6, milestone 3), and
  through a relay because esplora would not take the assert transactions. The Groth16 key is
  Citrea's, which records one phase-2 contribution (§4.6 d), and the header chain proves work, not
  canonicality.
- NIP-17 gift wrapping, offers and deals as Nostr events, and any relay other than the bundled minimal
  one. The epoch challenge and answer are NIP-44 v2 events (§2.5).

The fixed keys and MuSig2 nonce seeds in `regtest/`, and the Winternitz secrets in `zk/bitvm-check`, are test values. Never use them for real funds.
