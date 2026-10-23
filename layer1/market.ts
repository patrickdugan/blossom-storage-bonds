// The storage market on a Bitcoin stack, end to end on regtest, with every party in its own process.
//
//   scripts/regtest-node.sh <datadir> <bitcoind>      (another shell; RPC on 127.0.0.1:18543)
//   node layer1/market.ts [--pay channel|ln] [--epochs 10] [--q 8] [--from 4] [--m 64] [--k 4] [--windows 16] [--out <file>]
//                         [--network regtest|signet|testnet4] [--confs N] [--relays <ws url,...>] [--bond-sats N] [--term 1500]
//
// This process is the client, with its own Nostr key, bond and channel key, and fee wallet. Four provider
// processes (layer1/provider.ts) run beside it, each with its own keys and wallet. A Nostr relay carries
// the epoch challenges and answers as NIP-44 encrypted events. Bitcoin Core regtest carries the money:
//
//   1. Storage: the client uploads a 1 MiB blob, encrypted per provider, to each provider's Blossom server.
//   2. Bonds: cut and choose over HTTP, then the provider funds a 1 BTC bond from its own wallet and
//      presigns the challenges. The client checks the bond on chain and the provider's signatures before
//      it presigns the responses, and the provider checks those before it relies on them.
//   3. Payments: the client funds a 50,000-sat payment channel to each provider. Each epoch that proves
//      is paid with a new client-signed channel state, in exchange for the invoice preimage. With
//      --pay ln the channel is a Lightning channel instead: the client and every provider each run their
//      own lnd (layer1/lnd.ts), the client opens a private channel from its node to each provider's
//      node, and each epoch is paid by a BOLT 11 invoice from the provider's node.
//   4. Epochs: the nonce goes out as NIP-44, and the answer comes back the same way and is checked against
//      the client's own root. From epoch 4 one provider zeroes 10% of its chunks, one 50%, and one
//      deletes its replica and answers from the honest provider's copy.
//   5. Enforcement: the client reveals sentinels on chain and mines a block every ~150 ms. Each provider's
//      own process sees the challenge, reads r from the chain, answers from its own bytes, or fails.
//      After Δ = 144 blocks without a valid answer, the client forfeits the bond.
//   6. Settlement: every provider closes its channel on chain with the latest state, and the honest
//      provider refunds its bond once the term ends. With --pay ln the closes are cooperative, from each
//      provider's own node, and happen right after the last epoch; then every lnd stops (see below).
//
// The default payment is the one-way Bitcoin channel (layer1/channel.ts); --pay ln uses Lightning.
//
// Offers and deals go over Nostr (layer1/deals.ts). Off regtest (net.ts) nothing mines: every wait is for
// real blocks, keys and nonces are fresh, each party's wallet must be funded by hand before setup goes on,
// and bonds are --bond-sats (default 100,000). Enforcement then takes up to Δ = 144 blocks per sentinel,
// about a day on public networks; layer1/full-stack.ts is the pilot run (docs/signet-pilot.md).

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { keyFromSeed } from "../model/schnorr.ts";
import { sentinelSurvival } from "../model/storage_bonds.ts";
import { BondTool, forfeitRates, forfeitWithPolicy, rpc, runWith } from "./bondtool.ts";
import { readEnforceState, writeEnforceState } from "./enforce.ts";
import { findOffers, proposeDeal, type ProviderOffer } from "./deals.ts";
import { advance, confirm, partySeed, storageSecret, txConfirmations, untilHeight, useNetwork, waitHeight } from "./net.ts";
import { ChannelPayer } from "./channel.ts";
import type { Payer } from "./lightning.ts";
import { LndNode, LndPayer, assertLndNetwork, lndExe } from "./lnd.ts";
import { StorageClient, KIND_EPOCH_RECEIPT, checkReceipt, type BondSentinel, type EpochResult, type Offer, type Replica } from "./client.ts";
import { nostrTransport } from "./nostr-pdp.ts";
import { RelayPool, startRelay, type Relay } from "./relay.ts";

const here = dirname(fileURLToPath(import.meta.url));
const NET = useNetwork();
const SLOW = !NET.canMine;
const arg = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const EPOCHS = Number(arg("epochs", "10")), Q = Number(arg("q", "8")), FROM = Number(arg("from", "4"));
const M = Number(arg("m", "64")), K = Number(arg("k", "4")), W = Number(arg("windows", "16"));
const PAY = arg("pay", "channel");
if (PAY !== "channel" && PAY !== "ln") { console.error("--pay must be channel or ln"); process.exit(2); }
if (PAY === "ln") assertLndNetwork(NET.name);
const LN = PAY === "ln";
const LND = arg("lnd", lndExe());
const OUT = arg("out", join(here, "..", "results", LN ? "market-ln.json" : "market.json"));
const PRICE = 2000;            // msat per chunk-epoch: 512 sats per epoch for a 1 MiB blob
const CAPACITY = 50_000;       // sats per channel
const DELTA = 144;
const BOND_SATS = Number(arg("bond-sats", SLOW ? "100000" : "100000000")), TERM = Number(arg("term", "1500"));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function demoBlob(bytes = 1 << 20): Buffer {
  const out = Buffer.alloc(bytes);
  for (let o = 0, i = 0; o < bytes; o += 32, i++) createHash("sha256").update(`bsb demo blob ${i}`).digest().copy(out, o);
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

interface Role { name: string; slug: string; kept: number; misbehave?: (rep: Replica, honest: Replica) => Record<string, unknown> }
const ROLES: Role[] = [
  { name: "honest", slug: "honest", kept: 1 },
  { name: "deletes 10%", slug: "deletes10", kept: 0.9, misbehave: (rep) => ({ kind: "delete", sha: rep.sha256, indices: pick(rep.n, 0.1, "lazy") }) },
  { name: "deletes 50%", slug: "deletes50", kept: 0.5, misbehave: (rep) => ({ kind: "delete", sha: rep.sha256, indices: pick(rep.n, 0.5, "half") }) },
  { name: "outsources", slug: "outsources", kept: 0, misbehave: (rep, honest) => ({ kind: "outsource", sha: rep.sha256, from: { url: honest.offer.url, sha256: honest.sha256 } }) },
];
// Phase 7C: with --retrieval-probe the client pays only epochs whose challenged chunk it can also
// download, and a fifth provider keeps every byte and proves every epoch but refuses downloads.
const PROBE = process.argv.includes("--retrieval-probe");
if (PROBE) ROLES.push({ name: "withholds", slug: "withholds", kept: 1, misbehave: (rep) => ({ kind: "withhold", sha: rep.sha256 }) });

interface Proc { child: ChildProcess; url: string; admin: string; nostr: string; bond_x: string; fee_address: string; pid: number; ln?: string; log: any[] }

async function startProviderProcess(role: Role, relayUrl: string, dir: string, token: string, extra: string[] = []): Promise<Proc> {
  const child = spawn(process.execPath, [join(here, "provider.ts"), "--name", role.slug, ...(SLOW ? ["--no-auto-refund", "--bond-max-sats", String(BOND_SATS)] : ["--seed", `bsb/provider/${role.slug}`]),
    "--dir", join(dir, role.slug), "--relays", relayUrl, "--admin-token", token, "--price", String(PRICE), "--pay", PAY, ...(LN ? ["--lnd", LND] : []), ...extra],
    { stdio: ["ignore", "pipe", "inherit"] });
  const log: any[] = [];
  return new Promise((ok, bad) => {
    const t = setTimeout(() => bad(new Error(`${role.slug} did not start`)), SLOW ? 600_000 : LN ? 120_000 : 20_000);
    createInterface({ input: child.stdout! }).on("line", (line) => {
      let ev: any; try { ev = JSON.parse(line); } catch { return; }
      log.push(ev);
      if (ev.ready) { clearTimeout(t); ok({ child, log, ...ev }); }
      else if (ev.event === "watch-error" || ev.event === "pdp-error") console.log(`    [${role.slug}] ${ev.event}: ${String(ev.error).slice(0, 160)}`);
      else if (ev.event === "bond-respond" && ev.status !== "idle") console.log(`    [${role.slug} pid ${ev.pid ?? child.pid}] saw challenge ${ev.i} on chain, r = ${String(ev.r).slice(0, 8)}…: ${ev.status}${ev.error ? ` (${String(ev.error).replace(/^transaction failed: /, "").slice(0, 90)})` : ""}`);
    });
    child.on("exit", (c) => { clearTimeout(t); if (c) bad(new Error(`${role.slug} exited ${c}`)); });
  });
}

const admin = async (p: Proc, token: string, path: string, body: unknown) => {
  const r = await fetch(`${p.admin}${path}`, { method: "POST", headers: { "x-admin-token": token }, body: JSON.stringify(body) });
  if (r.status !== 200) throw new Error(`${path}: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
  return r.json() as Promise<any>;
};
const post = async (url: string, body: unknown) => {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (r.status !== 200) throw new Error(`${url}: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
  return r.json() as Promise<any>;
};
/** Regtest mines; elsewhere this waits for the blocks. */
const mine = (n: number, addr: string) => advance(NET, n, addr, SLOW ? (h, want) => console.log(`  waiting for block ${want}; at ${h}`) : undefined);
const tx = (txid: string) => rpc("getrawtransaction", [txid, true]);

let height0: number;
try { height0 = (await rpc("getblockchaininfo")).blocks; } catch (e) {
  console.error(`No ${NET.name} node (${(e as Error).message}). ${SLOW ? "See docs/signet-pilot.md." : "Start one with scripts/regtest-node.sh <datadir> <bitcoind>."}`);
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), "bsb-market-"));
const token = randomBytes(16).toString("hex");
const RELAY_URLS = RelayPool.parse(arg("relays", ""));
const relay: Relay | undefined = RELAY_URLS.length ? undefined : await startRelay();
const relayList = (RELAY_URLS.length ? RELAY_URLS : [relay!.url]).join(",");
const procs: Proc[] = [];
let clientLn: LndNode | undefined;
let finished = false;
try {
  // ── parties ──
  const SEED = partySeed(NET, join(dir, "client"), "bsb/client/market");
  const tool = new BondTool(SEED);
  const me = await tool.run("info");
  if (LN) {
    // Core reports initial block download until it sees a recent block, and lnd waits for that.
    if (!SLOW) await mine(1, me.fee_address);
    const started = await Promise.all([
      LndNode.start({ bin: LND, dir: join(dir, "client-lnd"), alias: "bsb-client", network: NET.name, chanConfs: NET.confs }),
      ...ROLES.map((role) => startProviderProcess(role, relayList, dir, token)),
    ]);
    clientLn = started[0] as LndNode;
    procs.push(...(started.slice(1) as Proc[]));
  } else {
    for (const role of ROLES) procs.push(await startProviderProcess(role, relayList, dir, token));
  }
  const nostrKey = keyFromSeed(`nostr|${SEED}`);
  console.log(`${NET.name} height ${height0}; relays ${relayList}`);
  console.log(`client (this process, pid ${process.pid}): bond key ${me.x.slice(0, 16)}…  wallet ${me.fee_address.slice(0, 20)}…`);
  if (clientLn) console.log(`client lnd (pid ${clientLn.child.pid}): node ${clientLn.pubkey.slice(0, 16)}…`);
  for (const [i, p] of procs.entries()) console.log(`provider ${ROLES[i].name.padEnd(12)} pid ${String(p.pid).padEnd(6)} ${p.url}  bond key ${p.bond_x.slice(0, 16)}…  wallet ${p.fee_address.slice(0, 20)}…${p.ln ? `  lnd ${p.ln.slice(0, 16)}…` : ""}`);

  // Every party gets its own coins: two coinbases each, matured by 100 more blocks. Off regtest each
  // wallet is funded by hand first (docs/signet-pilot.md).
  if (!SLOW) {
    for (const p of procs) await mine(2, p.fee_address);
    await mine(3, me.fee_address);
    // With Lightning, the client's node gets its own coins: one coinbase per channel it will fund.
    if (clientLn) await mine(ROLES.length, await clientLn.newAddress());
    await mine(100, me.fee_address);
  }
  if (clientLn) await clientLn.waitSynced(await rpc("getblockcount"));

  const rc = await RelayPool.connect(relayList.split(","));
  const offers = await findOffers(rc, NET.name, procs.map((p) => p.nostr), SLOW ? 300_000 : 30_000);
  const chanPayer = clientLn ? undefined : new ChannelPayer(me.x, tool, join(dir, "client-payments.ledger"));
  const lnPayer = clientLn && new LndPayer(clientLn);
  const payer: Payer = lnPayer ?? chanPayer!;
  /** sats paid to a provider so far, by either backend. */
  const paidSats = (payee: string) => (lnPayer ? lnPayer.paidMsatTo(payee) / 1000 : chanPayer!.paidTo(payee));
  // Seeded nonces make the regtest demo reproducible; anywhere else they are random.
  const client = new StorageClient({
    key: nostrKey, secret: storageSecret(NET, SEED, "market client storage secret"),
    payer, relay: rc, ...(SLOW ? {} : { nonceSeed: "market" }), transport: nostrTransport(rc, nostrKey), retrievalProbe: PROBE,
  });
  const blob = demoBlob();

  // ── storage, bonds, channels ──
  console.log(`\nsetup: 1 MiB blob, M = ${M} sentinels of ${W} windows, k = ${K}; ${BOND_SATS / 1e8} BTC bonds; ${CAPACITY}-sat ${LN ? "Lightning" : "payment"} channels`);
  const reps: Replica[] = [], kept: BondSentinel[][] = [], deals: string[] = [], chans: string[] = [], fundTx: string[] = [], chanTx: string[] = [];
  const tEnd = (await rpc("getblockcount")) + TERM;
  for (const [i, p] of procs.entries()) {
    const o: ProviderOffer = offers.get(p.nostr)!;
    if (o.terms.price_msat_per_chunk_epoch !== PRICE) throw new Error(`${ROLES[i].slug}: offers another price`);
    const offer: Offer = o.offer;
    const info = { bond_x: o.terms.bond.x, channel_payee: o.terms.pay.payee, ln_uri: o.terms.pay.ln_uri };
    const rep = await client.store(blob, offer, Q, "application/octet-stream", M, W);
    const ks = await client.bond(rep, K);
    // The deal over Nostr: the provider builds it from its own records, funds the bond and presigns;
    // proposeDeal checks it matches ours, waits for the bond's depth, checks it on chain and seals.
    const dealPath = join(dir, `client-deal-${ROLES[i].slug}.json`);
    const d = await proposeDeal({ relays: rc, key: nostrKey, net: NET, offer: o, rep, kept: ks, tEnd, bondSats: BOND_SATS, clientX: me.x, tool, dealPath, minerAddr: me.fee_address, timeoutMs: SLOW ? 1_800_000 : 120_000 });
    let chanTxid: string;
    if (clientLn) {
      // A private Lightning channel from the client's node to this provider's node, which then checks
      // it from its own side. Both nodes must have seen the latest block, or lnd refuses the funding.
      if (!info.ln_uri || !info.ln_uri.startsWith(info.channel_payee + "@")) throw new Error(`${ROLES[i].slug}: no Lightning node in its info`);
      await clientLn.connect(info.ln_uri);
      await clientLn.waitSynced(await rpc("getblockcount"));
      await post(`${p.url}/channel/prepare`, {});
      let point = "";
      for (let tries = 0; !point; tries++) {
        try { point = await clientLn.openChannel(info.channel_payee, CAPACITY); }
        catch (e) { if (tries > 40 || !/sync/i.test((e as Error).message)) throw e; await sleep(250); }
      }
      if (SLOW) await confirm(NET, point.split(":")[0], me.fee_address);
      else await mine(1, me.fee_address);
      await clientLn.waitActive(point, SLOW ? 3_600_000 : 60_000);
      await post(`${p.url}/channel/open`, { channel_point: point, client_pubkey: clientLn.pubkey });
      chans.push(point); chanTxid = point.split(":")[0];
    } else {
      const chanPath = join(dir, `client-chan-${ROLES[i].slug}.json`);
      const ch = await chanPayer!.open(chanPath, { provider_x: info.bond_x, client_x: me.x, capacity_sats: CAPACITY, t_refund: tEnd + 1000 });
      await confirm(NET, ch.funding_txid!, me.fee_address);
      await post(`${p.url}/channel/open`, ch);
      chans.push(chanPath); chanTxid = ch.funding_txid!;
    }
    reps.push(rep); kept.push(ks); deals.push(dealPath); fundTx.push(d.fund_txid); chanTx.push(chanTxid);
    // Phase 7C condition 1: what enforcement needs, on disk from the moment the bond exists, so a crash of
    // this process cannot cost the enforcement window (layer1/enforce.ts resumes from it).
    writeEnforceState(join(dir, `enforce-${ROLES[i].slug}.json`), { deal: dealPath, kept: ks.map((s) => ({ r: s.r })), delta: DELTA, bondSats: BOND_SATS, challenges: [], forfeits: [] });
    console.log(`  ${ROLES[i].name.padEnd(12)} replica ${rep.sha256.slice(0, 12)}…  kept [${ks.map((s) => s.j).join(", ")}]  bond ${d.fund_txid.slice(0, 12)}… (${d.checked.provider_signatures} signatures checked)  ${LN ? "ln " : ""}channel ${chanTxid.slice(0, 12)}…`);
  }

  // ── epochs: NIP-44 challenges, channel payments ──
  const results: EpochResult[][] = ROLES.map(() => []);
  const crashReport: Record<string, unknown>[] = [];
  const mark: Record<string, string> = { "proved-paid": "pass", "failed": "FAIL", "proved-unpaid": "unpaid", "unreachable": "down" };
  console.log(`\nepoch  ${ROLES.map((r) => r.name.padEnd(12)).join(" ")}   (nonce and answer over NIP-44; paid by ${LN ? "BOLT 11 over Lightning" : "channel state"})`);
  // Phase 7C: --crash-honest <epoch> kills the honest provider (SIGKILL: no shutdown, no flush) before
  // that epoch and restarts it on the same port from the same data directory. The honest outcome must
  // hold: its channel state comes back from its payment ledger, and its deals and bonds from disk.
  const CRASH = Number(arg("crash-honest", "0"));
  // Phase 7C condition 1: --enforce-external runs flagged enforcement in layer1/enforce.ts; with
  // --crash-enforcer, the first enforcer is killed mid-job and resumed from its state file.
  const EXTERNAL = process.argv.includes("--enforce-external");
  const CRASH_ENFORCER = process.argv.includes("--crash-enforcer");
  let enforcerCrashed = false;
  if (CRASH && LN) throw new Error("--crash-honest needs the channel backend (a killed provider would orphan its lnd)");
  for (let e = 1; e <= EPOCHS; e++) {
    if (e === CRASH) {
      const port = new URL(procs[0].url).port;
      const gone = new Promise((r) => procs[0].child.once("exit", r));
      procs[0].child.kill("SIGKILL");
      await gone;
      procs[0] = await startProviderProcess(ROLES[0], relayList, dir, token, ["--port", port]);
      const resumed = procs[0].log.filter((ev) => ev.event === "bond-resumed").length;
      console.log(`  ← honest provider killed (SIGKILL) and restarted on port ${port} as pid ${procs[0].pid}; ${resumed} bond(s) resumed from disk`);
      crashReport.push({ epoch: e, port, pid: procs[0].pid, bondsResumed: resumed });
    }
    if (e === FROM) for (const [i, role] of ROLES.entries()) if (role.misbehave) await admin(procs[i], token, "/admin/misbehave", role.misbehave(reps[i], reps[0]));
    const row: string[] = [];
    for (const [i, rep] of reps.entries()) { const r = await client.runEpoch(rep, e); results[i].push(r); row.push(mark[r.outcome].padEnd(12)); }
    console.log(`${String(e).padStart(5)}  ${row.join(" ")}${e === FROM ? "  ← misbehaviour starts" : ""}`.trimEnd());
  }

  // ── Lightning settlement ──
  // Pay per proof is over, so with Lightning each provider closes its channel now, from its own node, and
  // every lnd stops. lnd opens a new RPC connection for every call and fetches every block, so five nodes
  // following the ~1,500 blocks still to come (a block every 150 ms, then the jump to t_end) would exhaust
  // Windows' ephemeral ports. The bond phase needs no Lightning.
  const lnCloses: (string | null)[] = [];
  if (clientLn) {
    console.log("\nLightning settlement: each provider closes its channel cooperatively from its own node");
    for (const [i, p] of procs.entries()) {
      const close = await admin(p, token, "/admin/close-channel", { peer: clientLn.pubkey });
      await mine(1, me.fee_address);
      lnCloses.push(close.txid);
      console.log(`  ${ROLES[i].name.padEnd(12)} close ${close.txid.slice(0, 16)}…  (${paidSats(reps[i].offer.lightningNodeId)} sats paid over Lightning)`);
    }
    for (const p of procs) await admin(p, token, "/admin/ln-stop", {});
    await clientLn.stop();
  }

  // ── enforcement ──
  console.log(`\nenforcement: the client reveals sentinels; each provider's own process must answer within ${DELTA} blocks`);
  const enforcement = [];
  for (const [i, role] of ROLES.entries()) {
    // Phase 7C sentinel discipline: each bond has only K sentinels, and every answered challenge spends
    // one. Spend them only on epochs whose possession proof failed or never came. An epoch that proved
    // but was not paid (a retrieval-probe failure, an off-deal invoice) is a service problem: the bond
    // cannot punish it, and the payment gate already handles it.
    const failed = results[i].filter((r) => r.outcome === "failed" || r.outcome === "unreachable").length;
    const unpaid = results[i].filter((r) => r.outcome === "proved-unpaid").length;
    const n = failed > 0 ? K : 1;
    const steps = [];
    let forfeit: string | undefined;
    if (EXTERNAL && failed > 0) {
      // --enforce-external: hand the flagged deal to layer1/enforce.ts, a separate process. With
      // --crash-enforcer, the first one is SIGKILLed right after its first challenge and started again
      // from the same state file; it must finish the job.
      const stateFile = join(dir, `enforce-${role.slug}.json`);
      const s = readEnforceState(stateFile);
      s.flagged = { cause: `${failed} failed epoch(s)`, at: await rpc("getblockcount") };
      writeEnforceState(stateFile, s);
      const runOnce = (killAfterChallenge: boolean) => new Promise<{ result?: any; killed: boolean }>((ok, bad) => {
        const child = spawn(process.execPath, [join(here, "enforce.ts"), "--state", stateFile, "--mine-to", me.fee_address], { env: { ...process.env, BSB_SEED: SEED }, stdio: ["ignore", "pipe", "inherit"] });
        let result: any, killed = false;
        createInterface({ input: child.stdout! }).on("line", (line) => {
          let ev: any; try { ev = JSON.parse(line); } catch { return; }
          if (ev.result) result = ev.result;
          else console.log(`    [enforcer ${role.slug} pid ${child.pid}] ${ev.event}${ev.j !== undefined ? ` sentinel ${ev.j}` : ""}${ev.txid ? ` ${String(ev.txid).slice(0, 12)}…` : ""}`);
          if (killAfterChallenge && ev.event === "challenge" && !killed) { killed = true; child.kill("SIGKILL"); }
        });
        child.on("exit", (c) => (killed || c === 0 ? ok({ result, killed }) : bad(new Error(`enforcer exited ${c}`))));
      });
      let r = await runOnce(CRASH_ENFORCER && !enforcerCrashed);
      const crashedHere = r.killed;
      if (r.killed) {
        enforcerCrashed = true;
        console.log(`  ← enforcer for ${role.name} killed (SIGKILL) after its first challenge; restarting from ${stateFile}`);
        r = await runOnce(false);
      }
      const done = readEnforceState(stateFile);
      for (const c of done.challenges) steps.push({ i: c.j, challenge_txid: c.txid ?? null, answered_after_blocks: null, forfeit_txid: done.result?.outcome === "forfeited" && done.forfeits.at(-1)?.j === c.j ? done.result.txid : null, external: true });
      if (done.result?.outcome === "forfeited") forfeit = done.result.txid;
      console.log(`  ${role.name.padEnd(12)} enforced by layer1/enforce.ts: ${done.result?.outcome}${forfeit ? ` → forfeit ${forfeit.slice(0, 16)}…` : ""}${crashedHere ? " (survived a crash)" : ""}`);
      enforcement.push({ role: role.name, failedEpochs: failed, unpaidEpochs: unpaid, challenged: steps.length, steps, forfeit, external: true, enforcerCrashed: crashedHere });
      continue;
    }
    for (let j = 0; j < n && !forfeit; j++) {
      const c = await tool.run("bond-challenge", deals[i], String(j), kept[i][j].r);
      await mine(1, me.fee_address);
      // Respond_j's txid is fixed by the deal, so on regtest each block asks the node directly instead of
      // spawning bsb-bond bond-status (a process and a TCP connection per block).
      const respondTxid: string = (await tool.run("bond-status", deals[i])).states[j].respond_txid;
      let answeredAt = -1, dropped: number | undefined;
      for (let b = 1; b < DELTA; b++) {
        await sleep(SLOW ? 1000 : 150);
        if (!SLOW) {
          if (((await txConfirmations(respondTxid)) ?? 0) >= 1) { answeredAt = b; break; }
          await mine(1, me.fee_address);
          continue;
        }
        const st = await tool.run("bond-status", deals[i]);
        if ((st.states[j].respond ?? 0) >= 1) { answeredAt = b; break; }
        // Off regtest: wait for blocks, and count them from the challenge's own confirmations. A challenge
        // a reorg dropped is sent again; if that keeps failing, its input is gone and there is nothing to
        // enforce.
        if (st.states[j].challenge === null) {
          const again = await tool.run("bond-challenge", deals[i], String(j), kept[i][j].r).then(() => true, () => false);
          if (!again && (dropped = (dropped ?? 0) + 1) >= 3) { console.log(`  ${role.name.padEnd(12)} challenge ${j} cannot be sent again; stopping`); break; }
        }
        if ((st.states[j].challenge ?? 0) >= DELTA) break;
        b = Math.max(1, st.states[j].challenge ?? 1);
        await waitHeight(NET, st.height + 1);
      }
      if (answeredAt < 0) {
        // Phase 7C fee policy: bid at the first eligible block (at the node's rate), then re-bid one
        // step higher each block the forfeit is unconfirmed, so a late answer must keep outbidding.
        const rates = forfeitRates(Number(process.env.BSB_FEE_RATE ?? "2"), BOND_SATS);
        const o = await forfeitWithPolicy({
          rates,
          // Every bid at an explicit rate from the capped schedule, the first included, so an inherited
          // BSB_FEE_RATE above the cap can never make the forfeit's fee exceed the bond.
          broadcast: async (rate) => (await runWith(tool, { BSB_FEE_RATE: String(rate) }, "bond-forfeit", deals[i], String(j))).txid,
          nextBlock: () => mine(1, me.fee_address),
          confirmations: async (t) => (await txConfirmations(t)) ?? 0,
          answered: async () => ((await txConfirmations(respondTxid)) ?? 0) >= 1,
          maxBlocks: SLOW ? 24 : 6,
        });
        if (o.won) forfeit = o.txid;
        else console.log(`    forfeit not confirmed (${o.why}, ${o.bids} bid(s))`);
        if (o.won && o.bids > 1) console.log(`    forfeit confirmed after ${o.bids} bids, at ${o.rate} sat/vB`);
        if (forfeit) console.log(`  ${role.name.padEnd(12)} challenge ${j}: no valid answer in ${DELTA} blocks → forfeit ${forfeit.slice(0, 16)}…`);
      } else {
        console.log(`  ${role.name.padEnd(12)} challenge ${j}: answered on chain after ${answeredAt} block(s)`);
      }
      steps.push({ i: j, challenge_txid: c.txid, answered_after_blocks: answeredAt < 0 ? null : answeredAt, forfeit_txid: forfeit ?? null });
    }
    enforcement.push({ role: role.name, failedEpochs: failed, unpaidEpochs: unpaid, challenged: steps.length, steps, forfeit });
  }

  // ── settlement ──
  console.log("\nsettlement");
  const settlement = [];
  for (const [i, p] of procs.entries()) {
    const paid = paidSats(reps[i].offer.lightningNodeId);
    const close = LN ? { txid: lnCloses[i] } : paid > 0 ? await admin(p, token, "/admin/close-channel", { client_x: me.x }) : null;
    if (!LN) await mine(1, me.fee_address);
    let refund: string | null = null;
    if (!enforcement[i].forfeit) {
      await untilHeight(NET, tEnd, me.fee_address);
      refund = (await admin(p, token, "/admin/refund", { sha: reps[i].sha256 })).txid;
      await mine(1, me.fee_address);
    }
    settlement.push({ role: ROLES[i].name, channelClose: close?.txid ?? null, paidSats: paid, bondRefund: refund });
  }

  // ── verify everything on chain ──
  console.log("\nprovider      failed  paid on chain (sats)  bond (1 BTC)                        P(forfeit | k)");
  const summary = [];
  for (const [i, role] of ROLES.entries()) {
    const s = settlement[i], en = enforcement[i];
    let paidOnChain = 0;
    if (s.channelClose && LN) {
      // The cooperative close must spend this channel's funding output and pay the provider exactly the
      // sum of the invoices the client paid; the client, as funder, pays the closing fee.
      const t = await tx(s.channelClose);
      const [ftxid, fvout] = chans[i].split(":");
      if (t.confirmations < 1 || t.vin.length !== 1 || t.vin[0].txid !== ftxid || t.vin[0].vout !== Number(fvout)) throw new Error(`${role.slug}: close does not spend the channel`);
      const outs = t.vout.map((o: any) => Math.round(o.value * 1e8));
      paidOnChain = s.paidSats > 0 ? (outs.includes(s.paidSats) ? s.paidSats : -1) : 0;
      if (paidOnChain < 0) throw new Error(`${role.slug}: channel close has no output of ${s.paidSats} sats (${outs.join(", ")})`);
    } else if (s.channelClose) {
      const t = await tx(s.channelClose);
      paidOnChain = Math.round(t.vout[0].value * 1e8);
      if (t.confirmations < 1 || paidOnChain !== s.paidSats) throw new Error(`${role.slug}: channel close does not pay what was signed`);
    }
    const bondTxid = en.forfeit ?? s.bondRefund!;
    const bt = await tx(bondTxid);
    const bondTo = en.forfeit ? "client (forfeit leaf)" : "provider (refund at term end)";
    if (bt.confirmations < 1) throw new Error(`${role.slug}: bond settlement not confirmed`);
    const pForfeit = role.kept === 1 ? 0 : 1 - sentinelSurvival(role.kept, W, K);
    console.log(`${role.name.padEnd(13)} ${String(en.failedEpochs).padStart(6)}  ${String(paidOnChain).padStart(20)}  ${bondTo.padEnd(34)}  ${pForfeit.toPrecision(4).padStart(14)}`);
    summary.push({
      role: role.name, pid: procs[i].pid, failedEpochs: en.failedEpochs, unpaidEpochs: en.unpaidEpochs, paidSats: s.paidSats, paidOnChainSats: paidOnChain,
      channel: { funding: chanTx[i], close: s.channelClose }, bond: { funding: fundTx[i], settlement: bondTxid, to: en.forfeit ? "client" : "provider", confirmations: bt.confirmations },
      enforcement: en.steps, pForfeitIfAllChallenged: pForfeit, ...(en.external ? { enforcedExternally: true, enforcerCrashed: !!en.enforcerCrashed } : {}),
      providerAgentLog: procs[i].log.filter((ev) => ev.event === "bond-respond" || ev.event === "watch-error"),
    });
  }

  const receipts = await rc.query({ kinds: [KIND_EPOCH_RECEIPT], authors: [nostrKey.x] });
  const checked = receipts.map((ev) => checkReceipt(ev, payer));
  console.log(`\nrelay holds ${receipts.length} signed receipts; ${checked.filter((c) => c.ok && c.paid).length} carry a preimage that opens their invoice${LN ? "'s BOLT 11 payment hash" : ""}`);
  rc.close();

  const height1 = await rpc("getblockcount");
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({
    generated: new Date().toISOString(),
    note: LN
      ? "Every party is a separate process with its own keys and wallet, and its own lnd. Payments are BOLT 11 invoices paid over a private Lightning channel from the client's node to each provider's node. Nonces are seeded."
      : "Every party is a separate process with its own keys and wallet. Payments are a one-way Bitcoin payment channel per provider, not Lightning. Nonces are seeded.",
    params: { pay: PAY, epochs: EPOCHS, q: Q, misbehaviourFrom: FROM, m: M, k: K, windows: W, bondBtc: 1, delta: DELTA, priceMsatPerChunkEpoch: PRICE, channelSats: CAPACITY, blobBytes: blob.length },
    [NET.name]: { heightBefore: height0, heightAfter: height1 },
    summary,
    crash: crashReport,
    receipts: { onRelay: receipts.length, paidWithPreimage: checked.filter((c) => c.ok && c.paid).length },
  }, null, 2) + "\n");
  console.log(`${NET.name} height ${height0} → ${height1}; wrote ${OUT}`);
  finished = true;
} finally {
  // Ask each provider to stop (and stop its lnd) before killing it: on Windows kill() skips its handlers.
  await Promise.all(procs.map((p) => fetch(`${p.admin}/admin/stop`, { method: "POST", headers: { "x-admin-token": token } }).catch(() => undefined)));
  await clientLn?.stop();
  for (let i = 0; i < 40 && procs.some((p) => p.child.exitCode === null); i++) await sleep(250);
  for (const p of procs) p.child.kill("SIGTERM");
  await sleep(300);
  await relay?.close();
  // A failed run keeps its directory: every lnd log and provider file is in it.
  if (finished && !SLOW) rmSync(dir, { recursive: true, force: true });
  else console.error(`run failed; kept ${dir}`);
}
