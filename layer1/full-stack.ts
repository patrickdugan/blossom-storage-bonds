// Phase 4: the whole stack in one run, with every party in its own process. Phase 7: the same run on
// signet, and with providers and a watchtower on other machines.
//
//   scripts/regtest-node.sh <datadir> <bitcoind>      (another shell; RPC on 127.0.0.1:18543)
//   node layer1/full-stack.ts [--epochs 3] [--from-epoch 2] [--q 16] [--out results/full-stack.json]
//                             [--pay ln|onchain] [--pay-every 1] [--fee-rate 5]
//                             [--network regtest|signet] [--confs N] [--relays <ws url,...>]
//                             [--epoch-blocks 10] [--deadline 6] [--term 1500] [--first <height>]
//                             [--bond-sats N] [--capacity 50000] [--ln-open direct|none] [--ln-fee-budget-msat N]
//                             [--providers <pubkey,...>] [--watchtower <pubkey>] [--dir <dir>] [--print-key]
//
// This process is the client (and, on regtest, the miner). Three provider processes run with their own
// keys, fee wallets and lnd (layer1/provider.ts --pay ln --zk), and one watchtower process watches them.
//
//   1. Deals and bonds. The client reads each provider's offer from the relays (layer1/deals.ts),
//      uploads three blobs (1 MiB, 512 KiB, 256 KiB), encrypted per provider, to its Blossom server, and
//      registers all three as deals for public proofs. On the 1 MiB deal it runs cut and choose (64
//      sentinels of 16 windows, 4 kept), then proposes the bond over Nostr. The provider funds it from its
//      own wallet and accepts with its presignatures; the client checks the bond on chain at the
//      network's depth and seals with its own; the provider says the bond is live.
//   2. Lightning. The client's lnd opens a private 50,000-sat channel to each provider's lnd.
//   3. Public epoch proofs. Every 10 blocks each provider proves its holdings unprompted: the seed is
//      the boundary block's hash, and q challenges are drawn across all three deals. It stores the STARK
//      on its own Blossom server and announces it on Nostr.
//   4. Payment. The client checks that its deals are in the announced list, verifies the proof against
//      its own node's block hash, and pays that epoch's BOLT 11 invoice over Lightning. It pays nothing
//      without a valid proof.
//   5. Attestation. The watchtower verifies every proof on its own and attests valid, invalid or
//      missing. From --from-epoch on, one provider zeroes 10% of every replica, and one reads the honest
//      provider's copies instead of its own.
//   6. Enforcement. A missing or invalid attestation puts that provider on the client's list. Once
//      Lightning is settled, the client challenges each listed provider's bond on chain, revealing its
//      sentinels. The provider's own process reads the revealed secret from the chain and answers from
//      its own bytes. If Core rejects every answer, or none comes within 144 blocks, the client forfeits
//      the bond. A provider with no adverse attestation is not challenged, and refunds its bond at the
//      term's end.
//
// Every outcome is read back from the chain into results/full-stack.json: bond funding, each challenge,
// response, forfeit and refund, each Lightning channel's funding and close, and the attestations.
//
// With --pay onchain (layer1/onchain.ts) there is no lnd. Step 2 is a Core wallet for the client, and
// step 4 pays on chain: every --pay-every epochs the client pays all it owes in one transaction, one
// taproot output per provider committing to the payment hashes of the invoices it settles, then
// publishes a receipt (kind 4247): the txid, the invoices, and the transaction's Merkle inclusion proof.
// The watchtower then runs without a node. It follows an untrusted header mirror served by this process
// and checks every header from genesis (layer1/headerchain.ts, the stand-in for a ZeroSync-style STARK
// of the header chain), takes each epoch's seed from that chain, and attests both sides of every epoch
// from public data alone: "stored" from the STARK, "paid" from the receipt. At the end each provider
// sweeps what it was paid with its own key, and the results go to results/full-stack-onchain.json.
//
// Off regtest (net.ts): nothing mines. Each wait is for real blocks, every party's keys are fresh for the
// run, every party's wallet must be funded before setup goes on (the run prints what each needs and
// waits), outputs count at --confs, fees are estimated, bonds are --bond-sats (default 100,000 sats), the
// providers refund their own bonds at the term's end and say so on Nostr, and the bonds of all flagged
// providers are enforced at once rather than one after another. docs/signet-pilot.md is the runbook.
//
// --providers <pubkey,...> uses providers already running elsewhere (each started by its operator with
// layer1/provider.ts) instead of starting three here: they are found by their offers, nobody can make
// them misbehave from here, and the client closes Lightning channels from its own node. --watchtower
// <pubkey> trusts an outside watchtower's attestations instead of starting one.

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { keyFromSeed } from "../model/schnorr.ts";
import { CHUNK, encryptReplica, replicaKey, sentinelSurvival } from "../model/storage_bonds.ts";
import { BondTool, rpc } from "./bondtool.ts";
import { StorageClient, type BondSentinel, type Replica } from "./client.ts";
import { KIND_DEAL, findOffers, parseDeal, proposeDeal, type ProviderOffer } from "./deals.ts";
import { HeaderChain, paramsFor, serveHeaders, syncFrom } from "./headerchain.ts";
import { LndNode, LndPayer, lndExe } from "./lnd.ts";
import { advance, confirm, feeRate, partySeed, storageSecret, untilHeight, useNetwork, waitHeight } from "./net.ts";
import { now, signEvent, type NostrEvent } from "./nostr.ts";
import { KIND_PAYMENT_RECEIPT, OnchainPayer, batchVsize, buildReceipt, receiptTags, verifyReceipt, type BatchPayment, type OnchainInvoice, type PaymentReceipt } from "./onchain.ts";
import { RelayPool, startRelay, type Relay } from "./relay.ts";
import { defaultZk, statementFor, verifyProof, zkTree } from "./zk.ts";
import { KIND_ATTESTATION, KIND_EPOCH_PROOF } from "./zk-provider.ts";

const here = dirname(fileURLToPath(import.meta.url));
const NET = useNetwork();
const SLOW = !NET.canMine;
const arg = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const EPOCHS = Number(arg("epochs", "3")), FROM_EPOCH = Number(arg("from-epoch", "2")), Q = Number(arg("q", "16"));
const EPOCH = Number(arg("epoch-blocks", "10")), DEADLINE = Number(arg("deadline", "6")), DELTA = 144;
const TERM = Number(arg("term", "1500"));
const M = 64, K = 4, W = 16;
const PAY = arg("pay", "ln");
if (PAY !== "ln" && PAY !== "onchain") throw new Error("--pay must be ln or onchain");
const ONCHAIN = PAY === "onchain";
const PAY_EVERY = Number(arg("pay-every", "1")), FEE_RATE = Number(arg("fee-rate", "5"));
const LND = arg("lnd", lndExe());
const OUT = arg("out", join(here, "..", "results", `full-stack${ONCHAIN ? "-onchain" : ""}${SLOW ? `-${NET.name}` : ""}.json`));
const RPC = process.env.BSB_RPC!;
const WALLET = "bsb-full-stack-client";
const wallet = (m: string, p: unknown[] = []) => rpc(m, p, `${RPC}/wallet/${WALLET}`);
const PRICE_MSAT = 512_000;       // per verified epoch, per provider
const CAPACITY = Number(arg("capacity", "50000"));
const BOND_SATS = Number(arg("bond-sats", SLOW ? "100000" : "100000000"));
const LN_OPEN = arg("ln-open", "direct");
const LN_FEE_BUDGET = Number(arg("ln-fee-budget-msat", SLOW ? "5000" : "0"));
const REMOTE = arg("providers", "").split(",").filter(Boolean);
const TOWER = arg("watchtower", "");
const SIZES = [256, 128, 64];     // chunks: the bonded 1 MiB deal, then 512 KiB and 256 KiB
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const say = (s: string) => console.log(`${SLOW ? `[${new Date().toISOString().slice(11, 19)}] ` : ""}${s}`);

function blobOf(label: string, chunks: number): Buffer {
  const out = Buffer.alloc(chunks * CHUNK);
  for (let o = 0, i = 0; o < out.length; o += 32, i++) createHash("sha256").update(`${label} ${i}`).digest().copy(out, o);
  return out;
}
function pick(n: number, f: number, seed: string): number[] {
  const order = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = createHash("sha256").update(`${seed}|${i}`).digest().readUInt32LE(0) % (i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order.slice(0, Math.ceil(f * n));
}

interface Role { name: string; slug: string; kept?: number }
const ROLES: Role[] = REMOTE.length
  ? REMOTE.map((pk, i) => ({ name: `provider ${i + 1}`, slug: `p${i + 1}-${pk.slice(0, 8)}` }))
  : [{ name: "honest", slug: "honest", kept: 1 }, { name: "deletes 10%", slug: "deletes10", kept: 0.9 }, { name: "outsources", slug: "outsources", kept: 0 }];

/** A provider as this process knows it: from its offer, plus its process and admin port when it runs here. */
interface Proc { child?: ChildProcess; url: string; admin?: string; nostr: string; bond_x: string; fee_address?: string; ln?: string; pid?: number; log: any[]; waiters: ((ev: any) => void)[] }

function spawnLogged(name: string, args: string[], show: (ev: any) => void = () => {}): Promise<Proc> {
  const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "inherit"] });
  const p = { child, pid: child.pid!, log: [] as any[], waiters: [] as ((ev: any) => void)[] } as Proc;
  return new Promise((ok, bad) => {
    const t = setTimeout(() => bad(new Error(`${name} did not start`)), SLOW ? 600_000 : 60_000);
    createInterface({ input: child.stdout! }).on("line", (line) => {
      let ev: any; try { ev = JSON.parse(line); } catch { return; }
      p.log.push(ev);
      for (const w of [...p.waiters]) w(ev);
      if (ev.ready) { clearTimeout(t); Object.assign(p, ev); ok(p); } else show(ev);
    });
    child.on("exit", (c) => { clearTimeout(t); if (c) bad(new Error(`${name} exited ${c}`)); });
  });
}
const waitLog = (p: Proc, pred: (ev: any) => boolean, ms: number) => new Promise<any>((ok, bad) => {
  const hit = p.log.find(pred);
  if (hit) return ok(hit);
  const f = (ev: any) => { if (pred(ev)) { clearTimeout(t); p.waiters = p.waiters.filter((w) => w !== f); ok(ev); } };
  const t = setTimeout(() => { p.waiters = p.waiters.filter((w) => w !== f); bad(new Error("timed out waiting for a log line")); }, ms);
  p.waiters.push(f);
});
const post = async (url: string, body: unknown, headers: Record<string, string> = {}) => {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  if (r.status !== 200) throw new Error(`${url}: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
  return r.json() as Promise<any>;
};
const waiting = (what: string) => (h: number, want: number) => say(`  waiting for block ${want} (${what}); at ${h}`);
/** Regtest mines; elsewhere this waits for the blocks. */
const mine = (n: number, addr: string, what = "") => advance(NET, n, addr, SLOW ? waiting(what) : undefined);
const tx = (txid: string) => rpc("getrawtransaction", [txid, true]);
/** Until `pred` holds, polling every `ms`, for at most `budgetMs`. */
async function until(pred: () => boolean, budgetMs: number, ms = 250) { for (const t0 = Date.now(); !pred() && Date.now() - t0 < budgetMs;) await sleep(ms); }

/** Off regtest a wallet is funded by hand (a faucet, or another party); wait until it holds `sats`. */
async function funded(who: string, addr: string, sats: number, balance: () => Promise<number>) {
  if (!SLOW) return;
  let shown = false;
  for (;;) {
    const have = await balance().catch(() => 0);
    if (have >= sats) { say(`  ${who}: ${have} sats confirmed at ${addr}`); return; }
    if (!shown) { say(`  ${who}: send at least ${sats} sats (${NET.name}) to ${addr}; it has ${have}. Waiting.`); shown = true; }
    await sleep(30_000);
  }
}
const scanned = async (addr: string) => Math.round(((await rpc("scantxoutset", ["start", [`addr(${addr})`]])).total_amount ?? 0) * 1e8);

let height0: number;
try { height0 = (await rpc("getblockchaininfo")).blocks; } catch (e) {
  console.error(`No ${NET.name} node (${(e as Error).message}). ${NET.canMine ? "Start one with scripts/regtest-node.sh <datadir> <bitcoind>." : "See docs/signet-pilot.md."}`);
  process.exit(1);
}

const dir = arg("dir", "") || mkdtempSync(join(tmpdir(), "bsb-full-stack-"));
mkdirSync(dir, { recursive: true });
if (process.argv.includes("--print-key")) {
  // This run's client keys, made now and kept in --dir: the Nostr key for the providers' --uploaders,
  // and the fee address to fund.
  const seed = partySeed(NET, join(dir, "client"), "bsb/client/full-stack");
  const info = await new BondTool(seed).run("info");
  console.log(JSON.stringify({ network: NET.name, nostr: keyFromSeed(`nostr|${seed}`).x, bond_x: info.x, fee_address: info.fee_address, dir }));
  process.exit(0);
}
const token = randomBytes(16).toString("hex");
const RELAY_URLS = RelayPool.parse(arg("relays", ""));
const relay: Relay | undefined = RELAY_URLS.length ? undefined : await startRelay();
const relays = RELAY_URLS.length ? RELAY_URLS : [relay!.url];
const procs: Proc[] = [];
let tower: Proc | undefined;
let clientLn: LndNode | undefined;
let finished = false;
// The header mirror: anyone's node will do, since the watchtower checks every header it is served.
const mirrorHandler = serveHeaders((m, p) => rpc(m, p));
const mirror = createServer((req, res) => { const u = new URL(req.url ?? "/", "http://x"); if (u.pathname === "/headers") void mirrorHandler(req, res, u); else res.writeHead(404).end(); });
await new Promise<void>((r) => mirror.listen(0, "127.0.0.1", r));
const MIRROR = `http://127.0.0.1:${(mirror.address() as { port: number }).port}/headers`;
try {
  // Keys: fixed labels on regtest, as in phases 4 to 6; fresh for this run anywhere else (net.ts).
  const SEED = partySeed(NET, join(dir, "client"), "bsb/client/full-stack");
  const tool = new BondTool(SEED);
  const me = await tool.run("info");
  const nostrKey = keyFromSeed(`nostr|${SEED}`);
  const secret = storageSecret(NET, SEED, "full-stack client storage secret");
  if (!SLOW) await mine(1, me.fee_address);   // lnd waits until Core has a recent block
  let payAddr = "";
  if (ONCHAIN) {
    try { await rpc("createwallet", [WALLET]); } catch (e) { if (!SLOW || !/already exists/.test((e as Error).message)) throw e; await rpc("loadwallet", [WALLET]).catch(() => undefined); }
    payAddr = await wallet("getnewaddress", ["", "bech32m"]);
  }
  // Setup mines about 125 blocks on regtest; public proofs start at the first boundary well after that.
  // Off regtest setup waits for funding and then, provider after provider, for each bond (and channel)
  // to be --confs deep, so the first boundary is fixed only once setup is over, and the watchtower starts
  // then; local providers prove from whenever they hold deals, and the client counts from FIRST. An
  // explicit --first (needed with remote providers and watchtower, whose operators chose it) is kept.
  let FIRST = Number(arg("first", "0")) || (SLOW ? 0 : Math.ceil((height0 + 170) / EPOCH) * EPOCH);

  // ── parties ──
  const show = (slug: string) => (ev: any) => {
    if (ev.event === "zk-epoch") say(`    [${slug}] block ${ev.height}: ${ev.proved ? `proved (${(ev.bytes / 1e6).toFixed(1)} MB, ${ev.seconds.toFixed(0)} s)` : "could not prove"}`);
    else if (ev.event === "bond-respond" && ev.status !== "idle") say(`    [${slug}] saw sentinel ${ev.i} revealed on chain: ${ev.status}${ev.error ? ` (${String(ev.error).replace(/^transaction failed: /, "").slice(0, 80)})` : ""}`);
    else if (ev.event === "relay-down" || ev.event === "relay-closed" || ev.event === "deal-error" || ev.event === "refund-error") say(`    [${slug}] ${ev.event}: ${ev.url ?? ev.error ?? ""}`);
  };
  const started = await Promise.all([
    ONCHAIN ? Promise.resolve(undefined) : LndNode.start({ bin: LND, dir: join(dir, "client-lnd"), alias: "bsb-client", network: NET.name, chanConfs: NET.confs }),
    ...(REMOTE.length ? [] : ROLES.map((r) => spawnLogged(r.slug, [join(here, "provider.ts"), "--name", r.slug, ...(SLOW ? [] : ["--seed", `bsb/provider/${r.slug}`]), "--dir", join(dir, r.slug),
      "--relays", relays.join(","), "--admin-token", token, ...(ONCHAIN ? ["--pay", "onchain"] : ["--pay", "ln", "--lnd", LND]),
      ...(SLOW ? ["--bond-max-sats", String(BOND_SATS), "--min-term", String(Math.min(300, TERM))] : []),
      "--zk", "--epoch-blocks", String(EPOCH), "--zk-q", String(Q), "--zk-from", String(SLOW ? 0 : FIRST), "--zk-price", String(PRICE_MSAT)], show(r.slug)))),
  ]);
  clientLn = started[0] as LndNode | undefined;
  procs.push(...(started.slice(1) as Proc[]));
  const rc = await RelayPool.connect(relays, (ev) => say(`  relay: ${ev.event} ${ev.url ?? ""}`));
  // Every provider is found by its offer, whether it runs here or elsewhere.
  const offerKeys = REMOTE.length ? REMOTE : procs.map((p) => p.nostr);
  const offers = await findOffers(rc, NET.name, offerKeys, SLOW ? 300_000 : 30_000);
  const offerOf: ProviderOffer[] = offerKeys.map((k) => offers.get(k)!);
  if (REMOTE.length) for (const o of offerOf) procs.push({ url: o.offer.url, nostr: o.pubkey, bond_x: o.terms.bond.x, ln: o.terms.pay.ln_uri, log: [], waiters: [] });
  for (const [i, o] of offerOf.entries()) {
    if (o.terms.zk && (o.terms.zk.epoch_blocks !== EPOCH || o.terms.zk.q < Q)) throw new Error(`${ROLES[i].slug}: offers proofs every ${o.terms.zk.epoch_blocks} blocks at q ${o.terms.zk.q}, not ${EPOCH} at ${Q}`);
    if (o.terms.bond.max_sats < BOND_SATS) throw new Error(`${ROLES[i].slug}: bonds at most ${o.terms.bond.max_sats} sats`);
    if (TERM < o.terms.bond.min_term_blocks || TERM > (o.terms.bond.max_term_blocks ?? Infinity)) throw new Error(`${ROLES[i].slug}: takes terms of ${o.terms.bond.min_term_blocks} to ${o.terms.bond.max_term_blocks} blocks, not ${TERM}`);
  }
  // On chain, the watchtower has no node: a work floor (here the chain's work now; on mainnet a recent
  // nMinimumChainWork) and the mirror are all it gets. Off regtest it starts once FIRST is fixed.
  let RECEIPT_DEADLINE = 0;
  let towerNostr = TOWER;
  async function startTower() {
    RECEIPT_DEADLINE = DEADLINE + EPOCH * PAY_EVERY + 2 + (NET.confs - 1);
    if (!TOWER) {
      const minWork: string = (await rpc("getblockchaininfo")).chainwork;
      tower = await spawnLogged("watchtower", [join(here, "watchtower.ts"), "--relays", relays.join(","), "--providers", procs.map((p) => p.nostr).join(","),
        "--epoch-blocks", String(EPOCH), "--from", String(FIRST), "--deadline", String(DEADLINE), "--min-q", String(Q), "--dir", join(dir, "watchtower"),
        ...(ONCHAIN ? ["--headers", MIRROR, "--min-work", minWork, "--receipt-deadline", String(RECEIPT_DEADLINE)] : [])]);
      towerNostr = tower.nostr;
    }
    say(`watchtower           ${tower ? `pid ${String(tower.pid).padEnd(6)}` : "remote    "} nostr ${towerNostr.slice(0, 16)}…  (verifies every proof itself; no stake in any deal${ONCHAIN && tower ? `; no node: headers from ${MIRROR}` : ""})`);
  }
  say(`${NET.name} height ${height0}; public proofs every ${EPOCH} blocks from ${SLOW ? "the first boundary after funding and setup" : FIRST}, q = ${Q}; relays ${relays.join(", ")}; payment ${ONCHAIN ? `on chain, every ${PAY_EVERY} epoch(s), ${SLOW ? "estimated fee" : `${FEE_RATE} sat/vB`}` : "Lightning"}${SLOW ? `; ${NET.confs} confirmations` : ""}`);
  say(`client (pid ${process.pid}): bond key ${me.x.slice(0, 16)}…  ${clientLn ? `lnd ${clientLn.pubkey.slice(0, 16)}…` : `wallet ${WALLET} (${payAddr.slice(0, 16)}…)`}`);
  for (const [i, p] of procs.entries()) say(`provider ${ROLES[i].name.padEnd(12)} ${p.pid ? `pid ${String(p.pid).padEnd(6)}` : "remote    "} ${p.url}  bond key ${p.bond_x.slice(0, 16)}…  ${p.ln ? `lnd ${p.ln.slice(0, 16)}…` : `nostr ${p.nostr.slice(0, 16)}…`}`);
  if (!SLOW) await startTower();

  // ── coins: mined on regtest; funded by hand anywhere else ──
  if (!SLOW) {
    for (const p of procs) await mine(2, p.fee_address!);
    await mine(3, me.fee_address);
    await mine(ROLES.length, ONCHAIN ? payAddr : await clientLn!.newAddress());
    await mine(100, me.fee_address);
    await clientLn?.waitSynced(await rpc("getblockcount"));
  } else {
    const fee = await feeRate(NET, FEE_RATE);
    say(`\nfunding (${NET.name}, ${fee} sat/vB now): every party pays its own fees and bonds`);
    // The client: CPFP children for K challenges per provider, and forfeits come out of the bonds.
    await funded("client fee wallet", me.fee_address, ROLES.length * K * 400 * fee + 20_000, () => scanned(me.fee_address));
    for (const [i, p] of procs.entries()) if (p.fee_address) await funded(`${ROLES[i].name} fee wallet`, p.fee_address, BOND_SATS + K * 800 * fee + 20_000, () => scanned(p.fee_address!));
    if (clientLn && LN_OPEN === "direct") {
      const a = await clientLn.newAddress();
      await funded("client lnd wallet", a, ROLES.length * (CAPACITY + 2_000), async () => Number((await clientLn!.rest("GET", "/v1/balance/blockchain")).confirmed_balance));
    }
    if (ONCHAIN) await funded("client payment wallet", payAddr, ROLES.length * EPOCHS * (PRICE_MSAT / 1000) + 20_000, async () => Math.round((await wallet("getbalances")).mine.trusted * 1e8));
    // Off regtest the client challenges every flagged provider at once, and each CPFP child needs a
    // confirmed coin of its own (bsb-bond takes the largest one nothing in the mempool spends yet).
    const coins = ((await rpc("scantxoutset", ["start", [`addr(${me.fee_address})`]])).unspents ?? []).length;
    if (coins < ROLES.length * 2) {
      const s = await tool.run("fee-split", String(ROLES.length * 2), String(Math.max(2_000, 1_000 * fee)));
      say(`  client fee wallet split into ${ROLES.length * 2} coins and change (${s.txid.slice(0, 12)}…)`);
      await confirm(NET, s.txid, me.fee_address);
    }
    await clientLn?.waitSynced(await rpc("getblockcount"));
  }

  const payer = ONCHAIN ? new OnchainPayer(wallet, NET.name, SLOW ? () => feeRate(NET, FEE_RATE) : FEE_RATE, WALLET) : new LndPayer(clientLn!, NET.lnHrp);
  const client = new StorageClient({ key: nostrKey, secret, payer });

  // ── deals, bonds, channels ──
  say(`\nsetup: 3 deals per provider (${SIZES.join(" + ")} chunks); a ${BOND_SATS / 1e8} BTC sentinel bond on the first (M = ${M}, k = ${K}, ${W} windows); ${ONCHAIN ? "payment on chain" : `${CAPACITY}-sat Lightning channels`}`);
  const blobs = SIZES.map((n, k) => blobOf(`full-stack blob ${k}`, n));
  const reps: Replica[][] = [], roots: { root: string; n: number }[][] = [], kept: BondSentinel[][] = [];
  const deals: string[] = [], fundTx: string[] = [], chans: string[] = [], payees: string[] = [], payKeys: string[] = [], dealEvents: Record<string, string>[] = [];
  const tEnd = (await rpc("getblockcount")) + TERM;
  for (const [i, p] of procs.entries()) {
    const o = offerOf[i];
    const rs: Replica[] = [], rr: { root: string; n: number }[] = [];
    for (const [k, blob] of blobs.entries()) {
      const rep = await client.store(blob, o.offer, 8, "application/octet-stream", k === 0 ? M : 0, W);
      const ours = zkTree(encryptReplica(blob, replicaKey(secret, rep.blobId, o.offer.pubkey)));
      const reg = await post(`${p.url}/zk/register`, { sha256: rep.sha256 });
      if (reg.zk_root !== ours.root.toString("hex") || reg.n !== ours.n) throw new Error(`${ROLES[i].slug}: zk root differs from ours`);
      rs.push(rep); rr.push({ root: reg.zk_root, n: reg.n });
    }
    // The sentinel bond on the first deal: cut and choose on the provider's server, then the deal on Nostr.
    const ks = await client.bond(rs[0], K);
    const dealPath = join(dir, `client-deal-${ROLES[i].slug}.json`);
    const d = await proposeDeal({
      relays: rc, key: nostrKey, net: NET, offer: o, rep: rs[0], kept: ks, tEnd, bondSats: BOND_SATS, clientX: me.x, tool, dealPath, minerAddr: me.fee_address,
      timeoutMs: SLOW ? 1_800_000 : 120_000, onWait: SLOW ? (s) => say(`  ${ROLES[i].name}: ${s}`) : undefined,
    });
    if (ONCHAIN) {
      if (o.terms.pay.kind !== "onchain" || !o.terms.pay.onchain_key || o.terms.pay.payee !== o.pubkey) throw new Error(`${ROLES[i].slug}: no on-chain pay key in its offer`);
      reps.push(rs); roots.push(rr); kept.push(ks); deals.push(dealPath); fundTx.push(d.fund_txid); payees.push(o.terms.pay.payee); payKeys.push(o.terms.pay.onchain_key); dealEvents.push(d.events);
      say(`  ${ROLES[i].name.padEnd(12)} zk roots match; bond ${d.fund_txid.slice(0, 12)}… (${d.checked.provider_signatures} signatures checked; deal ${d.events.live.slice(0, 12)}… live); pay key ${o.terms.pay.onchain_key.slice(0, 12)}…`);
      continue;
    }
    // The Lightning channel.
    const ln = clientLn!;
    const lnUri = o.terms.pay.ln_uri;
    if (!lnUri?.startsWith(o.terms.pay.payee + "@")) throw new Error(`${ROLES[i].slug}: no Lightning node in its offer`);
    let point = "";
    if (LN_OPEN === "direct") {
      await ln.connect(lnUri);
      await ln.waitSynced(await rpc("getblockcount"));
      await post(`${p.url}/channel/prepare`, {});
      const sat = SLOW ? await feeRate(NET, 2) : 2;
      for (let tries = 0; !point; tries++) {
        try { point = await ln.openChannel(o.terms.pay.payee, CAPACITY, sat); }
        catch (e) { if (tries > 40 || !/sync/i.test((e as Error).message)) throw e; await sleep(250); }
      }
      if (SLOW) await confirm(NET, point.split(":")[0], me.fee_address, (c, w) => say(`  ${ROLES[i].name}: channel ${point.slice(0, 12)}… has ${c}/${w} confirmations`));
      else await mine(1, me.fee_address);
      await ln.waitActive(point, SLOW ? 3_600_000 : 60_000);
      await post(`${p.url}/channel/open`, { channel_point: point, client_pubkey: ln.pubkey });
    }
    reps.push(rs); roots.push(rr); kept.push(ks); deals.push(dealPath); fundTx.push(d.fund_txid); chans.push(point); payees.push(o.terms.pay.payee); dealEvents.push(d.events);
    say(`  ${ROLES[i].name.padEnd(12)} zk roots match; bond ${d.fund_txid.slice(0, 12)}… (${d.checked.provider_signatures} signatures checked; deal ${d.events.live.slice(0, 12)}… live); ${point ? `ln channel ${point.slice(0, 12)}…` : "paid over existing Lightning routes"}`);
  }
  if (SLOW && !FIRST) {
    FIRST = Math.ceil(((await rpc("getblockcount")) + 2) / EPOCH) * EPOCH;
    say(`setup done: public proofs counted from block ${FIRST}`);
  }
  if ((await rpc("getblockcount")) >= FIRST) throw new Error(`setup ran past the first boundary ${FIRST}; pass a later --first`);
  if (SLOW) await startTower();

  // ── the client: verify each announced proof, then pay it (over Lightning at once; on chain, in the
  //    next batch) ──
  type Row = { proof?: string; client?: string; paidSats?: number; payment?: { hash: string; preimage: string }; tower?: string; towerEvent?: string; providerSays?: string;
    payTx?: string; towerPaid?: string; towerPaidEvent?: string; towerPaidWhy?: string; paidCheck?: Record<string, unknown> };
  const table = new Map<string, Row>();
  const row = (i: number, h: number) => { const k = `${i}|${h}`; if (!table.has(k)) table.set(k, {}); return table.get(k)!; };
  const byNostr = new Map(procs.map((p, i) => [p.nostr, i]));
  const adverse = new Map<number, { height: number; result: string; event: string; why?: string }>();
  const attestations: any[] = [];
  let pending = Promise.resolve();
  let paying = true;
  let owed: { i: number; height: number; pr: string }[] = [];
  const batches: (BatchPayment & { epochs: number[]; receipt: PaymentReceipt; receiptEvent: string })[] = [];
  rc.subscribe([{ kinds: [KIND_EPOCH_PROOF], authors: procs.map((p) => p.nostr) }], (e: NostrEvent) => {
    if (!paying) return;
    pending = pending.then(async () => {
      const i = byNostr.get(e.pubkey)!;
      const c = JSON.parse(e.content);
      if (c.height < FIRST) return;
      const r = row(i, c.height);
      // One payment per provider and epoch: a provider restarted mid-epoch may announce it again.
      if (r.client === "verified") return;
      r.proof = c.proof.sha256;
      if (!roots[i].every((m) => c.deals.some((d: any) => d.root === m.root && d.n === m.n))) { r.client = "rejected: deals not covered"; return; }
      const seed = Buffer.from(await rpc("getblockhash", [c.height]), "hex");
      const proof = Buffer.from(await (await fetch(c.proof.url)).arrayBuffer());
      if (createHash("sha256").update(proof).digest("hex") !== c.proof.sha256) { r.client = "rejected: proof bytes differ"; return; }
      const v = await verifyProof(defaultZk(), join(dir, "client-verify"), proof, statementFor(seed, Number(c.q), c.deals));
      if (!v.ok) { r.client = `rejected: ${v.why.slice(0, 50)}`; return; }
      r.client = "verified";
      const inv = (await (await fetch(`${procs[i].url}/zk/invoice/${c.height}?client=${me.x}`)).json()) as { paymentRequest: string };
      const d = payer.decode(inv.paymentRequest);
      if (d.payee !== payees[i] || d.amountMsat !== PRICE_MSAT) { r.client = "verified; invoice refused"; return; }
      if (ONCHAIN) {
        if ((d as OnchainInvoice).payKey !== payKeys[i]) { r.client = "verified; invoice refused"; return; }
        owed.push({ i, height: c.height, pr: inv.paymentRequest });
        return;
      }
      const { preimage } = await payer.pay(inv.paymentRequest, PRICE_MSAT + LN_FEE_BUDGET);
      r.paidSats = PRICE_MSAT / 1000;
      r.payment = { hash: d.paymentHash, preimage };
    }).catch((err) => { say(`  client: ${(err as Error).message}`); });
  });
  rc.subscribe([{ kinds: [KIND_ATTESTATION], authors: [towerNostr] }], (e: NostrEvent) => {
    const c = JSON.parse(e.content);
    const i = byNostr.get(c.provider);
    if (i === undefined || c.height < FIRST) return;
    attestations.push({ event: "attest", id: e.id, ...c });
    const r = row(i, c.height);
    if (c.side === "paid") {
      r.towerPaid = c.result; r.towerPaidEvent = e.id; r.towerPaidWhy = c.why;
      if (c.result === "paid") r.paidCheck = { txid: c.txid, vout: c.vout, block: c.block, confirmations: c.confirmations, receipt_bytes: c.receipt_bytes, verify_ms: c.verify_ms, chain: c.chain };
      return;
    }
    r.tower = c.result; r.towerEvent = e.id;
    if ((c.result === "missing" || c.result === "invalid") && !adverse.has(i)) adverse.set(i, { height: c.height, result: c.result, event: e.id, why: c.why });
  });

  /** Pay everything owed in one transaction, confirm it, publish the receipt, and wait for the
   *  watchtower to check it from its own header chain. */
  async function settleOnChain(epoch: number) {
    const due = owed;
    owed = [];
    if (due.length === 0) return;
    const b = await (payer as OnchainPayer).payBatch(due.map((o) => ({ paymentRequest: o.pr, maxMsat: PRICE_MSAT })));
    await confirm(NET, b.txid, me.fee_address, SLOW ? (c, w) => say(`  payment ${b.txid.slice(0, 12)}… has ${c}/${w} confirmations`) : undefined);
    const receipt = await buildReceipt((m, p) => rpc(m, p), NET.name, b.txid, b.outputs.map((o) => ({ vout: o.vout, invoices: o.invoices })), { kind: "headers-standin", mirror: MIRROR });
    const ev = signEvent(nostrKey, { created_at: now(), kind: KIND_PAYMENT_RECEIPT, tags: receiptTags(receipt), content: JSON.stringify(receipt) });
    await rc.publish(ev);
    const epochs = [...new Set(due.map((o) => o.height))];
    batches.push({ ...b, epochs, receipt, receiptEvent: ev.id });
    for (const o of due) { const r = row(o.i, o.height); r.paidSats = PRICE_MSAT / 1000; r.payTx = b.txid; }
    say(`  paid on chain after epoch ${epoch}: ${due.length} invoice(s) for ${epochs.length} epoch(s) in ${b.txid.slice(0, 16)}…, ${b.outputs.length} provider output(s), ${b.vsize} vB, fee ${b.feeSats} sats; receipt ${ev.id.slice(0, 12)}… (${Buffer.byteLength(ev.content)} B)`);
    await until(() => !due.some((o) => !row(o.i, o.height).towerPaid), SLOW ? 3_600_000 : 60_000);
  }

  // ── epochs ──
  say(`\nepochs: providers prove on their own at each boundary; the client verifies and pays ${ONCHAIN ? `on chain every ${PAY_EVERY} epoch(s)` : "over Lightning"}`);
  for (let e = 1; e <= EPOCHS; e++) {
    const b = FIRST + (e - 1) * EPOCH;
    if (e === FROM_EPOCH && !REMOTE.length) {
      for (const k of SIZES.keys()) {
        await post(`${procs[1].admin}/admin/misbehave`, { kind: "delete", sha: reps[1][k].sha256, indices: pick(reps[1][k].n, 0.1, `lazy ${k}`) }, { "x-admin-token": token });
        await post(`${procs[2].admin}/admin/misbehave`, { kind: "outsource", sha: reps[2][k].sha256, from: { url: procs[0].url, sha256: reps[0][k].sha256 } }, { "x-admin-token": token });
      }
      say(`  from epoch ${e}: "deletes 10%" zeroes a tenth of each replica; "outsources" reads the honest provider's copies`);
    }
    await untilHeight(NET, b, me.fee_address, SLOW ? waiting(`epoch ${e} boundary`) : undefined);
    say(`  epoch ${e}: boundary block ${b}, seed ${String(await rpc("getblockhash", [b])).slice(0, 16)}…`);
    if (!REMOTE.length) {
      // On signet the proof comes once the boundary is --confs deep, and proving takes minutes.
      const said = await Promise.all(procs.map((p) => waitLog(p, (ev) => ev.event === "zk-epoch" && ev.height === b, SLOW ? 6 * 3_600_000 : 900_000)));
      said.forEach((ev, i) => { row(i, b).providerSays = ev.proved ? "proved" : "could not prove"; });
    }
    await mine(DEADLINE, me.fee_address, `epoch ${e} deadline`);
    await pending;
    await until(() => !procs.some((_, i) => !row(i, b).tower), SLOW ? 3_600_000 : 150_000);
    await pending;
    if (ONCHAIN && (e % PAY_EVERY === 0 || e === EPOCHS)) await settleOnChain(e);
  }
  // The epoch phase is over: no more proofs, payments or attestations while the bond phase mines.
  paying = false;
  for (const p of procs) if (p.admin) await post(`${p.admin}/admin/zk-stop`, {}, { "x-admin-token": token });
  await pending;
  if (ONCHAIN) await settleOnChain(EPOCHS);
  tower?.child?.kill("SIGTERM");

  const via = ONCHAIN ? "paid (chain)" : "paid (LN)";
  console.log(`\n${"provider".padEnd(12)} ${"epoch".padEnd(6)} ${"provider".padEnd(16)} ${"client".padEnd(12)} ${via.padEnd(13)} watchtower${ONCHAIN ? ": stored / paid" : ""}`);
  for (const [i, r] of ROLES.entries()) for (let e = 1; e <= EPOCHS; e++) {
    const x = row(i, FIRST + (e - 1) * EPOCH);
    console.log(`${r.name.padEnd(12)} ${String(e).padEnd(6)} ${(x.providerSays ?? "—").padEnd(16)} ${(x.client ?? "nothing").slice(0, 12).padEnd(12)} ${String(x.paidSats ?? 0).padEnd(13)} ${x.tower ?? "—"}${ONCHAIN ? ` / ${x.towerPaid ?? "—"}` : ""}`);
  }

  // ── Lightning settlement, before the long mining of the bond phase (lnd's per-block RPC would
  //    exhaust Windows' ephemeral ports at a block every 150 ms) ──
  const lnCloses: string[] = [];
  const sweeps: ({ txid: string; outputs: { txid: string; vout: number; sats: number }[]; sats: number; feeRate: number; uneconomicAt?: number } | null)[] = [];
  if (ONCHAIN) {
    say("\non-chain settlement: each provider spends what the receipts paid it, with its own pay key plus each output's tweak");
    for (const [i, p] of procs.entries()) {
      if (payer.paidMsatTo(payees[i]) === 0) { sweeps.push(null); say(`  ${ROLES[i].name.padEnd(12)} paid nothing; nothing to sweep`); continue; }
      if (!p.admin) { sweeps.push(null); say(`  ${ROLES[i].name.padEnd(12)} runs elsewhere: its operator sweeps (POST /admin/sweep on its own machine)`); continue; }
      const s = await post(`${p.admin}/admin/sweep`, { fee_rate: SLOW ? await feeRate(NET, FEE_RATE) : FEE_RATE }, { "x-admin-token": token });
      await confirm(NET, s.txid, me.fee_address);
      sweeps.push(s);
      say(`  ${ROLES[i].name.padEnd(12)} sweep ${s.txid.slice(0, 16)}… spends ${s.outputs.length} payment output(s), ${s.sats} sats, to its fee address at ${s.feeRate} sat/vB${s.uneconomicAt ? ` (worth less than its spend at ${s.uneconomicAt} sat/vB)` : ""}`);
    }
  } else if (LN_OPEN === "direct") say(`\nLightning settlement: each channel closes cooperatively${REMOTE.length ? ", from the client's node" : " from each provider's own node"}`);
  for (const [i, p] of ONCHAIN || LN_OPEN !== "direct" ? [] : procs.entries()) {
    const close = p.admin ? (await post(`${p.admin}/admin/close-channel`, { peer: clientLn!.pubkey }, { "x-admin-token": token })).txid as string
      : await clientLn!.closeChannel(chans[i], SLOW ? await feeRate(NET, 2) : 2);
    await confirm(NET, close, me.fee_address);
    lnCloses.push(close);
    say(`  ${ROLES[i].name.padEnd(12)} close ${close.slice(0, 16)}…  (${payer.paidMsatTo(payees[i]) / 1000} sats paid over Lightning)`);
  }
  if (!ONCHAIN) for (const p of procs) if (p.admin) await post(`${p.admin}/admin/ln-stop`, {}, { "x-admin-token": token });
  await clientLn?.stop();

  // ── enforcement: driven by the watchtower's attestations ──
  say(`\nenforcement: a missing or invalid attestation sends the client to that provider's bond`);
  /** Challenge sentinel after sentinel until one goes unanswered for Δ blocks, then forfeit. On regtest
   *  each step mines one block, as in phases 4 to 6; elsewhere it waits for blocks, rebroadcasts a
   *  challenge or forfeit that a reorg dropped, and counts the forfeit at the network's depth. */
  async function enforce(i: number) {
    const role = ROLES[i];
    const cause = adverse.get(i)!;
    say(`  ${role.name.padEnd(12)} attested ${cause.result} at block ${cause.height} (event ${cause.event.slice(0, 12)}…): challenging its bond`);
    const steps: Record<string, unknown>[] = [];
    let forfeit: string | null = null;
    let gone = "";          // off regtest: why this bond can no longer be enforced, if it cannot
    for (let j = 0; j < K && !forfeit && !gone; j++) {
      const c = await tool.run("bond-challenge", deals[i], String(j), kept[i][j].r);
      if (!SLOW) await mine(1, me.fee_address);
      let answeredAt = -1, resendFails = 0;
      for (let b = 1; ; b++) {
        if (!SLOW) await sleep(150);
        const st = await tool.run("bond-status", deals[i]);
        if ((st.states[j].respond ?? 0) >= 1) { answeredAt = SLOW ? st.states[j].challenge ?? b : b; break; }
        if (SLOW && st.states[j].challenge === null) {
          // Dropped by a reorg: send it again. If its input is gone for good (the provider refunded at
          // t_end first), there is nothing left to enforce.
          try { await tool.run("bond-challenge", deals[i], String(j), kept[i][j].r); resendFails = 0; say(`    ${role.name}: sentinel ${j}'s challenge was dropped (reorg?); sent again`); }
          catch (e) { if (++resendFails >= 3) { gone = `challenge ${j} cannot be sent again: ${(e as Error).message.slice(0, 120)}`; break; } }
        }
        if (!SLOW ? b >= DELTA : (st.states[j].challenge ?? 0) >= DELTA) break;
        if (!SLOW) await mine(1, me.fee_address);
        else await waitHeight(NET, st.height + 1);
      }
      if (gone) { say(`    ${role.name}: ${gone}`); steps.push({ sentinel: j, challenge_txid: c.txid, answered_after_blocks: null, forfeit_txid: null, gone }); break; }
      if (answeredAt < 0) {
        try { forfeit = (await tool.run("bond-forfeit", deals[i], String(j))).txid; } catch (e) { say(`    forfeit refused: ${(e as Error).message}`); }
        if (forfeit && !SLOW) await mine(1, me.fee_address);
        // Off regtest the forfeit counts at depth. Dropped by a reorg, it is sent again, unless a late
        // answer took the output first (then the sentinel was answered after all).
        for (let fails = 0; forfeit && SLOW;) {
          const t = await tx(forfeit).catch(() => undefined);
          if ((t?.confirmations ?? 0) >= NET.confs) break;
          if (!t) {
            const st = await tool.run("bond-status", deals[i]);
            if ((st.states[j].respond ?? 0) >= 1) { answeredAt = st.states[j].challenge ?? DELTA; forfeit = null; break; }
            try { forfeit = (await tool.run("bond-forfeit", deals[i], String(j))).txid; fails = 0; }
            catch (e) { if (++fails >= 3) { gone = `forfeit ${j} cannot be sent again: ${(e as Error).message.slice(0, 120)}`; forfeit = null; break; } }
          }
          await waitHeight(NET, (await rpc("getblockcount")) + 1);
        }
        if (forfeit) say(`    ${role.name}: sentinel ${j}: no valid answer in ${DELTA} blocks → forfeit ${forfeit.slice(0, 16)}…`);
        else if (!SLOW) await mine(1, me.fee_address);
        else if (gone) say(`    ${role.name}: ${gone}`);
      }
      if (answeredAt >= 0) say(`    ${role.name}: sentinel ${j}: answered on chain after ${answeredAt} block(s)`);
      steps.push({ sentinel: j, challenge_txid: c.txid, answered_after_blocks: answeredAt < 0 ? null : answeredAt, forfeit_txid: forfeit, ...(gone ? { gone } : {}) });
    }
    return { role: role.name, cause, steps, forfeit };
  }
  const enforcement: { role: string; cause: unknown; steps: any[]; forfeit: string | null }[] = ROLES.map((r) => ({ role: r.name, cause: null, steps: [], forfeit: null }));
  for (const [i, role] of ROLES.entries()) if (!adverse.get(i)) say(`  ${role.name.padEnd(12)} no adverse attestation: not challenged`);
  const flagged = ROLES.map((_, i) => i).filter((i) => adverse.has(i));
  if (SLOW) (await Promise.all(flagged.map((i) => enforce(i)))).forEach((r, k) => { enforcement[flagged[k]] = r; });
  else for (const i of flagged) enforcement[i] = await enforce(i);

  // ── bond refunds at the term's end: the orchestrator asks on regtest; elsewhere each provider refunds
  //    on its own and says so on Nostr ──
  const refunds: (string | null)[] = [];
  const settled = new Map<string, string>();
  const settledSub = rc.subscribe([{ kinds: [KIND_DEAL], "#p": [nostrKey.x] }], (e) => { const d = parseDeal(e, NET.name); if (d?.stage === "settled") settled.set(e.pubkey, d.content.refund_txid); });
  for (const [i, p] of procs.entries()) {
    if (enforcement[i].forfeit) { refunds.push(null); continue; }
    if (!SLOW) {
      const h = await rpc("getblockcount");
      if (h < tEnd) await mine(tEnd - h, me.fee_address);
      refunds.push((await post(`${p.admin}/admin/refund`, { sha: reps[i][0].sha256 }, { "x-admin-token": token })).txid);
      await mine(1, me.fee_address);
      continue;
    }
    await untilHeight(NET, tEnd, me.fee_address, waiting("the term's end"));
    await until(() => settled.has(p.nostr), 6 * 3_600_000, 5_000);
    const t = settled.get(p.nostr) ?? null;
    if (t) await confirm(NET, t, me.fee_address);
    refunds.push(t);
  }
  settledSub.close();

  // ── read every outcome back from the chain ──
  // A third party's re-check at the end: a fresh header chain from the mirror, every receipt against it.
  const finalChain = new HeaderChain(paramsFor(NET.name));
  if (ONCHAIN) await syncFrom(finalChain, MIRROR);
  const finalChecks = batches.map((b) => {
    const t = process.hrtime.bigint();
    const v = verifyReceipt(b.receipt, finalChain, { network: NET.name, minConf: NET.confs });
    return { txid: b.txid, ok: v.ok, ...(v.ok ? { confirmations: v.confirmations, payments: v.payments.length } : { why: v.why }), verify_ms: Number(process.hrtime.bigint() - t) / 1e6 };
  });

  say("\nfrom the chain:");
  const summary = [];
  for (const [i, role] of ROLES.entries()) {
    const fund = await tx(fundTx[i]);
    const bondOut = fund.vout[0];
    const paid = payer.paidMsatTo(payees[i]) / 1000;
    let lightning: Record<string, unknown> | undefined, onchain: Record<string, unknown> | undefined, payNote: string;
    if (ONCHAIN) {
      // Each payment output: confirmed, worth what was paid, and spent by the provider's sweep.
      const ours = batches.flatMap((b) => b.outputs.filter((o) => o.payee === payees[i]).map((o) => ({ b, o })));
      const sweep = sweeps[i];
      const st = sweep ? await tx(sweep.txid) : undefined;
      const payments = [];
      for (const { b, o } of ours) {
        const t = await tx(b.txid);
        if (t.confirmations < 1 || Math.round(t.vout[o.vout].value * 1e8) !== o.sats) throw new Error(`${role.slug}: payment output ${b.txid}:${o.vout} not as paid`);
        if (sweep && !st?.vin.some((x: any) => x.txid === b.txid && x.vout === o.vout)) throw new Error(`${role.slug}: sweep does not spend ${b.txid}:${o.vout}`);
        payments.push({ txid: b.txid, vout: o.vout, sats: o.sats, epochs: o.invoices.length, confirmations: t.confirmations, script: t.vout[o.vout].scriptPubKey.hex });
      }
      onchain = { payments, paid_sats: paid, sweep: sweep && { txid: sweep.txid, confirmations: st.confirmations, inputs: st.vin.length, vsize: st.vsize, fee_rate: sweep.feeRate, ...(sweep.uneconomicAt ? { uneconomic_at_fee_rate: sweep.uneconomicAt } : {}), output_sats: Math.round(st.vout[0].value * 1e8), to: st.vout[0].scriptPubKey.address } };
      payNote = `${payments.length} payment output(s) for ${paid} sats${sweep ? `, swept by ${sweep.txid.slice(0, 12)}…` : ""}`;
    } else if (lnCloses[i]) {
      const close = await tx(lnCloses[i]);
      const [ftxid, fvout] = chans[i].split(":");
      if (close.confirmations < 1 || close.vin.length !== 1 || close.vin[0].txid !== ftxid || close.vin[0].vout !== Number(fvout)) throw new Error(`${role.slug}: close does not spend its channel`);
      const outs = close.vout.map((o: any) => Math.round(o.value * 1e8));
      if (paid > 0 && !outs.includes(paid)) throw new Error(`${role.slug}: close has no ${paid}-sat output (${outs.join(", ")})`);
      lightning = { channel_point: chans[i], close_txid: lnCloses[i], close_confirmations: close.confirmations, close_outputs_sats: outs, paid_sats: paid };
      payNote = `ln close ${lnCloses[i].slice(0, 12)}… pays ${paid} sats`;
    } else {
      lightning = { channel_point: null, paid_sats: paid, note: "paid over routes the operators set up (--ln-open none); nothing to close here" };
      payNote = `${paid} sats paid over Lightning`;
    }
    const settleTxid = enforcement[i].forfeit ?? refunds[i];
    const settle = settleTxid ? await tx(settleTxid) : undefined;
    if (settleTxid && settle.confirmations < 1) throw new Error(`${role.slug}: bond settlement unconfirmed`);
    if (settle && settle.vin[0].txid !== (enforcement[i].forfeit ? enforcement[i].steps.at(-1).challenge_txid : settle.vin[0].txid)) throw new Error(`${role.slug}: forfeit does not spend the challenge`);
    const leaf = !settle ? "not settled when the run ended" : settle.vin[0].sequence === DELTA ? `forfeit leaf (CSV ${DELTA}), to the client` : "refund leaf (CLTV t_end), to the provider";
    const challenges = [];
    for (const s of enforcement[i].steps as any[]) {
      const ct = await tx(s.challenge_txid);
      challenges.push({ ...s, challenge_confirmations: ct.confirmations, revealed_r: ct.vin[0].txinwitness[0] });
    }
    say(`  ${role.name.padEnd(12)} bond ${fundTx[i].slice(0, 12)}… ${Math.round(bondOut.value * 1e8)} sats → ${settleTxid ? `${settleTxid.slice(0, 12)}… via ` : ""}${leaf}; ${payNote}`);
    const epochs = Array.from({ length: EPOCHS }, (_, e) => ({ epoch: e + 1, height: FIRST + e * EPOCH, ...row(i, FIRST + e * EPOCH) }));
    summary.push({
      role: role.name, pid: procs[i].pid ?? null, nostr: procs[i].nostr, offer: offerOf[i].event.id, deal_events: dealEvents[i],
      epochs,
      ...(lightning ? { lightning } : { onchain }),
      bond: { fund_txid: fundTx[i], value_sats: Math.round(bondOut.value * 1e8), settled_by: settleTxid, settle_confirmations: settle?.confirmations ?? null, leaf, to: enforcement[i].forfeit ? "client" : settle ? "provider" : null },
      enforcement: { cause: enforcement[i].cause, challenges },
      ...(role.kept === undefined ? {} : {
        p_detect_10pct_per_epoch: role.kept === 1 ? 0 : 1 - Math.pow(role.kept, Q),
        p_forfeit_given_challenge: role.kept === 1 ? 0 : 1 - sentinelSurvival(role.kept, W, K),
      }),
      providerLog: procs[i].log.filter((ev) => ["zk-epoch", "bond-respond", "ln-channel", "onchain-sweep", "bond-refund"].includes(ev.event)),
    });
  }
  rc.close();

  console.log(`\n${"provider".padEnd(12)} ${"proofs ok".padEnd(10)} ${via.padEnd(13)} ${"attested".padEnd(22)} bond (${BOND_SATS / 1e8} BTC)`);
  for (const s of summary) {
    const ok = s.epochs.filter((e) => e.client === "verified").length;
    const att = s.enforcement.cause ? `${(s.enforcement.cause as any).result} @ ${(s.enforcement.cause as any).height}` : "valid throughout";
    const paidSats = ((s as any).lightning ?? (s as any).onchain).paid_sats;
    console.log(`${s.role.padEnd(12)} ${`${ok}/${EPOCHS}`.padEnd(10)} ${String(paidSats).padEnd(13)} ${att.padEnd(22)} ${s.bond.to === "client" ? "forfeited to the client" : s.bond.to === "provider" ? "refunded to the provider" : "not settled"}`);
  }
  if (ONCHAIN) {
    say(`\non-chain payments (${SLOW ? "estimated fee rates" : `${FEE_RATE} sat/vB`}):`);
    for (const b of batches) say(`  ${b.txid.slice(0, 16)}… epochs ${b.epochs.join(", ")}: ${b.outputs.length} output(s), ${b.outputs.reduce((a, o) => a + o.invoices.length, 0)} invoice(s), ${b.vsize} vB (model ${batchVsize(b.outputs.length)}), fee ${b.feeSats} sats`);
    say(`  a third party's re-check from ${finalChain.height + 1} mirrored headers: ${finalChecks.filter((c) => c.ok).length}/${finalChecks.length} receipts verify`);
  }

  const height1 = await rpc("getblockcount");
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({
    generated: new Date().toISOString(),
    note: ONCHAIN
      ? `One ${NET.name} run: every party a separate process with its own keys and wallet. Offers and deals as Nostr events. Public STARK epoch proofs seeded by block hashes; verified epochs paid on chain to taproot outputs committing to the invoices' payment hashes, batched; a receipt (txid + Merkle inclusion proof) per payment, checked by a watchtower with no node against a header chain it validated from genesis (the stand-in for a ZeroSync-style STARK of that chain); a missing or invalid attestation triggers on-chain sentinel challenges; every txid here was read back from bitcoind.`
      : `One ${NET.name} run: every party a separate process with its own keys, wallet and lnd. Offers and deals as Nostr events. Public STARK epoch proofs seeded by block hashes; each verified epoch paid by BOLT 11 over Lightning; a missing or invalid watchtower attestation triggers on-chain sentinel challenges; every txid here was read back from bitcoind.`,
    params: { network: NET.name, confs: NET.confs, relays: RELAY_URLS.length ? RELAY_URLS : "bundled", remoteProviders: REMOTE.length > 0, epochs: EPOCHS, misbehaviourFromEpoch: REMOTE.length ? null : FROM_EPOCH, q: Q, epochBlocks: EPOCH, deadline: DEADLINE, firstBoundary: FIRST, term: TERM, deals: SIZES, bondSats: BOND_SATS, sentinels: { M, k: K, windows: W }, delta: DELTA, priceSatsPerEpoch: PRICE_MSAT / 1000,
      ...(ONCHAIN ? { pay: "onchain", payEvery: PAY_EVERY, feeRateSatPerVb: SLOW ? "estimated" : FEE_RATE, receiptDeadline: RECEIPT_DEADLINE, watchtowerNode: "none: header mirror + work floor" } : { pay: "ln", channelSats: CAPACITY, lnOpen: LN_OPEN }) },
    [NET.name]: { heightBefore: height0, heightAfter: height1 },
    summary,
    ...(ONCHAIN ? {
      payments: batches.map((b) => ({ txid: b.txid, epochs: b.epochs, vsize: b.vsize, vsize_model: batchVsize(b.outputs.length), fee_sats: b.feeSats, fee_rate: b.feeRate,
        outputs: b.outputs.map((o) => ({ vout: o.vout, payee: o.payee, invoices: o.invoices.length, sats: o.sats })), receipt_event: b.receiptEvent, receipt_bytes: Buffer.byteLength(JSON.stringify(b.receipt)), receipt: b.receipt })),
      final_check: { headers: finalChain.height + 1, total_work: "0x" + finalChain.totalWork.toString(16), receipts: finalChecks },
    } : {}),
    watchtower: tower ? tower.log.filter((ev) => ev.event === "attest") : attestations,
  }, null, 2) + "\n");
  say(`\n${NET.name} height ${height0} → ${height1}; wrote ${OUT}`);
  finished = true;
} finally {
  await Promise.all(procs.filter((p) => p.admin).map((p) => fetch(`${p.admin}/admin/stop`, { method: "POST", headers: { "x-admin-token": token } }).catch(() => undefined)));
  await clientLn?.stop().catch(() => undefined);
  for (let i = 0; i < 40 && procs.some((p) => p.child && p.child.exitCode === null); i++) await sleep(250);
  for (const p of procs) p.child?.kill("SIGTERM");
  tower?.child?.kill("SIGTERM");
  await sleep(300);
  await relay?.close();
  mirror.close();
  // Off regtest the run directory holds the parties' fresh keys: it is kept, whatever happened.
  if (finished && !SLOW && !arg("dir", "")) rmSync(dir, { recursive: true, force: true });
  else console.error(`${finished ? "run finished" : "run failed"}; kept ${dir}`);
}
