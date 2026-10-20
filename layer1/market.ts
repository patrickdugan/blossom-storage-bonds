// The storage market on a Bitcoin stack, end to end on regtest, with every party in its own process.
//
//   scripts/regtest-node.sh <datadir> <bitcoind>      (another shell; RPC on 127.0.0.1:18543)
//   node layer1/market.ts [--epochs 10] [--q 8] [--from 4] [--m 64] [--k 4] [--windows 16] [--out results/market.json]
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
//      is paid with a new client-signed channel state, in exchange for the invoice preimage.
//   4. Epochs: the nonce goes out as NIP-44, and the answer comes back the same way and is checked against
//      the client's own root. From epoch 4 one provider zeroes 10% of its chunks, one 50%, and one
//      deletes its replica and answers from the honest provider's copy.
//   5. Enforcement: the client reveals sentinels on chain and mines a block every ~150 ms. Each provider's
//      own process sees the challenge, reads r from the chain, answers from its own bytes, or fails.
//      After Δ = 144 blocks without a valid answer, the client forfeits the bond.
//   6. Settlement: every provider closes its channel on chain with the latest state, and the honest
//      provider refunds its bond once the term ends.
//
// Only Lightning is missing: payment is a one-way Bitcoin channel instead (layer1/channel.ts).

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { keyFromSeed } from "../model/schnorr.ts";
import { sentinelSurvival } from "../model/storage_bonds.ts";
import { BondTool, rpc } from "./bondtool.ts";
import { ChannelPayer } from "./channel.ts";
import { StorageClient, KIND_EPOCH_RECEIPT, checkReceipt, type BondSentinel, type EpochResult, type Offer, type Replica } from "./client.ts";
import { nostrTransport } from "./nostr-pdp.ts";
import { RelayClient, startRelay } from "./relay.ts";

const here = dirname(fileURLToPath(import.meta.url));
const arg = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const EPOCHS = Number(arg("epochs", "10")), Q = Number(arg("q", "8")), FROM = Number(arg("from", "4"));
const M = Number(arg("m", "64")), K = Number(arg("k", "4")), W = Number(arg("windows", "16"));
const OUT = arg("out", join(here, "..", "results", "market.json"));
const PRICE = 2000;            // msat per chunk-epoch: 512 sats per epoch for a 1 MiB blob
const CAPACITY = 50_000;       // sats per channel
const DELTA = 144;
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

interface Proc { child: ChildProcess; url: string; admin: string; bond_x: string; fee_address: string; pid: number; log: any[] }

async function startProviderProcess(role: Role, relayUrl: string, dir: string, token: string): Promise<Proc> {
  const child = spawn(process.execPath, [join(here, "provider.ts"), "--name", role.slug, "--seed", `bsb/provider/${role.slug}`,
    "--dir", join(dir, role.slug), "--relay", relayUrl, "--admin-token", token, "--price", String(PRICE)], { stdio: ["ignore", "pipe", "inherit"] });
  const log: any[] = [];
  return new Promise((ok, bad) => {
    const t = setTimeout(() => bad(new Error(`${role.slug} did not start`)), 20_000);
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
const mine = (n: number, addr: string) => rpc("generatetoaddress", [n, addr]);
const tx = (txid: string) => rpc("getrawtransaction", [txid, true]);

let height0: number;
try { height0 = (await rpc("getblockchaininfo")).blocks; } catch (e) {
  console.error(`No regtest node (${(e as Error).message}). Start one with scripts/regtest-node.sh <datadir> <bitcoind>.`);
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), "bsb-market-"));
const token = randomBytes(16).toString("hex");
const relay = await startRelay();
const procs: Proc[] = [];
try {
  // ── parties ──
  for (const role of ROLES) procs.push(await startProviderProcess(role, relay.url, dir, token));
  const SEED = "bsb/client/market";
  const tool = new BondTool(SEED);
  const me = await tool.run("info");
  const nostrKey = keyFromSeed(`nostr|${SEED}`);
  console.log(`regtest height ${height0}; relay ${relay.url}`);
  console.log(`client (this process, pid ${process.pid}): bond key ${me.x.slice(0, 16)}…  wallet ${me.fee_address.slice(0, 20)}…`);
  for (const [i, p] of procs.entries()) console.log(`provider ${ROLES[i].name.padEnd(12)} pid ${String(p.pid).padEnd(6)} ${p.url}  bond key ${p.bond_x.slice(0, 16)}…  wallet ${p.fee_address.slice(0, 20)}…`);

  // Every party gets its own coins: two coinbases each, matured by 100 more blocks.
  for (const p of procs) await mine(2, p.fee_address);
  await mine(3, me.fee_address);
  await mine(100, me.fee_address);

  const rc = await RelayClient.connect(relay.url);
  const payer = new ChannelPayer(me.x, tool);
  const client = new StorageClient({
    key: nostrKey, secret: createHash("sha256").update("market client storage secret").digest(),
    payer, relay: rc, nonceSeed: "market", transport: nostrTransport(rc, nostrKey),
  });
  const blob = demoBlob();

  // ── storage, bonds, channels ──
  console.log(`\nsetup: 1 MiB blob, M = ${M} sentinels of ${W} windows, k = ${K}; 1 BTC bonds; ${CAPACITY}-sat channels`);
  const reps: Replica[] = [], kept: BondSentinel[][] = [], deals: string[] = [], chans: string[] = [], fundTx: string[] = [], chanTx: string[] = [];
  const tEnd = (await rpc("getblockcount")) + 1500;
  for (const [i, p] of procs.entries()) {
    const info = (await (await fetch(`${p.url}/`)).json()) as { pubkey: string; bond_x: string; channel_payee: string };
    const offer: Offer = { url: p.url, pubkey: info.pubkey, lightningNodeId: info.channel_payee, priceMsatPerChunkEpoch: PRICE };
    const rep = await client.store(blob, offer, Q, "application/octet-stream", M, W);
    const ks = await client.bond(rep, K);
    const f = await post(`${p.url}/bond/${rep.sha256}/fund`, { client_x: me.x, t_end: tEnd });
    // The provider wrote the deal from its own records; it must match ours exactly.
    const want = ks.map((s) => ({ s: s.s, h: s.h, hs: s.hs }));
    if (JSON.stringify(f.deal.sentinels) !== JSON.stringify(want) || f.deal.client_x !== me.x || f.deal.provider_x !== info.bond_x || f.deal.t_end !== tEnd) {
      throw new Error(`${ROLES[i].slug}: the provider's deal differs from ours`);
    }
    const dealPath = join(dir, `client-deal-${ROLES[i].slug}.json`);
    writeFileSync(dealPath, JSON.stringify(f.deal, null, 2));
    writeFileSync(dealPath.replace(".json", ".p.json"), JSON.stringify({ fund_txid: f.fund_txid, sig_p_challenge: f.sig_p_challenge }));
    await mine(1, me.fee_address);
    const c = await tool.run("bond-presign", dealPath);   // checks the bond on chain and every provider signature
    await post(`${p.url}/bond/${rep.sha256}/presigs`, { sig_c_respond: c.sig_c_respond });
    const chanPath = join(dir, `client-chan-${ROLES[i].slug}.json`);
    const ch = await payer.open(chanPath, { provider_x: info.bond_x, client_x: me.x, capacity_sats: CAPACITY, t_refund: tEnd + 1000 });
    await mine(1, me.fee_address);
    await post(`${p.url}/channel/open`, ch);
    reps.push(rep); kept.push(ks); deals.push(dealPath); chans.push(chanPath); fundTx.push(f.fund_txid); chanTx.push(ch.funding_txid!);
    console.log(`  ${ROLES[i].name.padEnd(12)} replica ${rep.sha256.slice(0, 12)}…  kept [${ks.map((s) => s.j).join(", ")}]  bond ${f.fund_txid.slice(0, 12)}… (${c.checked.provider_signatures} signatures checked)  channel ${ch.funding_txid!.slice(0, 12)}…`);
  }

  // ── epochs: NIP-44 challenges, channel payments ──
  const results: EpochResult[][] = ROLES.map(() => []);
  const mark: Record<string, string> = { "proved-paid": "pass", "failed": "FAIL", "proved-unpaid": "unpaid", "unreachable": "down" };
  console.log(`\nepoch  ${ROLES.map((r) => r.name.padEnd(12)).join(" ")}   (nonce and answer over NIP-44; paid by channel state)`);
  for (let e = 1; e <= EPOCHS; e++) {
    if (e === FROM) for (const [i, role] of ROLES.entries()) if (role.misbehave) await admin(procs[i], token, "/admin/misbehave", role.misbehave(reps[i], reps[0]));
    const row: string[] = [];
    for (const [i, rep] of reps.entries()) { const r = await client.runEpoch(rep, e); results[i].push(r); row.push(mark[r.outcome].padEnd(12)); }
    console.log(`${String(e).padStart(5)}  ${row.join(" ")}${e === FROM ? "  ← misbehaviour starts" : ""}`.trimEnd());
  }

  // ── enforcement ──
  console.log(`\nenforcement: the client reveals sentinels; each provider's own process must answer within ${DELTA} blocks`);
  const enforcement = [];
  for (const [i, role] of ROLES.entries()) {
    const failed = results[i].filter((r) => r.outcome !== "proved-paid").length;
    const n = failed > 0 ? K : 1;
    const steps = [];
    let forfeit: string | undefined;
    for (let j = 0; j < n && !forfeit; j++) {
      const c = await tool.run("bond-challenge", deals[i], String(j), kept[i][j].r);
      await mine(1, me.fee_address);
      let answeredAt = -1;
      for (let b = 1; b < DELTA; b++) {
        await sleep(150);
        const st = await tool.run("bond-status", deals[i]);
        if ((st.states[j].respond ?? 0) >= 1) { answeredAt = b; break; }
        await mine(1, me.fee_address);
      }
      if (answeredAt < 0) {
        try { forfeit = (await tool.run("bond-forfeit", deals[i], String(j))).txid; }
        catch (e) { console.log(`    forfeit refused (${(e as Error).message}); rechecking`); }
        await mine(1, me.fee_address);
        if (forfeit) console.log(`  ${role.name.padEnd(12)} challenge ${j}: no valid answer in ${DELTA} blocks → forfeit ${forfeit.slice(0, 16)}…`);
      } else {
        console.log(`  ${role.name.padEnd(12)} challenge ${j}: answered on chain after ${answeredAt} block(s)`);
      }
      steps.push({ i: j, challenge_txid: c.txid, answered_after_blocks: answeredAt < 0 ? null : answeredAt, forfeit_txid: forfeit ?? null });
    }
    enforcement.push({ role: role.name, failedEpochs: failed, challenged: steps.length, steps, forfeit });
  }

  // ── settlement ──
  console.log("\nsettlement");
  const settlement = [];
  for (const [i, p] of procs.entries()) {
    const paid = payer.paidTo(reps[i].offer.lightningNodeId);
    const close = paid > 0 ? await admin(p, token, "/admin/close-channel", { client_x: me.x }) : null;
    await mine(1, me.fee_address);
    let refund: string | null = null;
    if (!enforcement[i].forfeit) {
      const h = await rpc("getblockcount");
      if (h < tEnd) await mine(tEnd - h, me.fee_address);
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
    if (s.channelClose) {
      const t = await tx(s.channelClose);
      const provAddr = t.vout[0].scriptPubKey.address;
      paidOnChain = Math.round(t.vout[0].value * 1e8);
      if (t.confirmations < 1 || paidOnChain !== s.paidSats) throw new Error(`${role.slug}: channel close does not pay what was signed`);
      void provAddr;
    }
    const bondTxid = en.forfeit ?? s.bondRefund!;
    const bt = await tx(bondTxid);
    const bondTo = en.forfeit ? "client (forfeit leaf)" : "provider (refund at term end)";
    if (bt.confirmations < 1) throw new Error(`${role.slug}: bond settlement not confirmed`);
    const pForfeit = role.kept === 1 ? 0 : 1 - sentinelSurvival(role.kept, W, K);
    console.log(`${role.name.padEnd(13)} ${String(en.failedEpochs).padStart(6)}  ${String(paidOnChain).padStart(20)}  ${bondTo.padEnd(34)}  ${pForfeit.toPrecision(4).padStart(14)}`);
    summary.push({
      role: role.name, pid: procs[i].pid, failedEpochs: en.failedEpochs, paidSats: s.paidSats, paidOnChainSats: paidOnChain,
      channel: { funding: chanTx[i], close: s.channelClose }, bond: { funding: fundTx[i], settlement: bondTxid, to: en.forfeit ? "client" : "provider", confirmations: bt.confirmations },
      enforcement: en.steps, pForfeitIfAllChallenged: pForfeit,
      providerAgentLog: procs[i].log.filter((ev) => ev.event === "bond-respond" || ev.event === "watch-error"),
    });
  }

  const receipts = await rc.query({ kinds: [KIND_EPOCH_RECEIPT], authors: [nostrKey.x] });
  const checked = receipts.map((ev) => checkReceipt(ev, payer));
  console.log(`\nrelay holds ${receipts.length} signed receipts; ${checked.filter((c) => c.ok && c.paid).length} carry a preimage that opens their invoice`);
  rc.close();

  const height1 = await rpc("getblockcount");
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({
    generated: new Date().toISOString(),
    note: "Every party is a separate process with its own keys and wallet. Payments are a one-way Bitcoin payment channel per provider, not Lightning. Nonces are seeded.",
    params: { epochs: EPOCHS, q: Q, misbehaviourFrom: FROM, m: M, k: K, windows: W, bondBtc: 1, delta: DELTA, priceMsatPerChunkEpoch: PRICE, channelSats: CAPACITY, blobBytes: blob.length },
    regtest: { heightBefore: height0, heightAfter: height1 },
    summary,
    receipts: { onRelay: receipts.length, paidWithPreimage: checked.filter((c) => c.ok && c.paid).length },
  }, null, 2) + "\n");
  console.log(`regtest height ${height0} → ${height1}; wrote ${OUT}`);
} finally {
  for (const p of procs) p.child.kill("SIGTERM");
  await sleep(300);
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
