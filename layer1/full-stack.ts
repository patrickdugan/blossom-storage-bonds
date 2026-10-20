// Phase 4: the whole stack in one regtest run, with every party in its own process.
//
//   scripts/regtest-node.sh <datadir> <bitcoind>      (another shell; RPC on 127.0.0.1:18543)
//   node layer1/full-stack.ts [--epochs 3] [--from-epoch 2] [--q 16] [--out results/full-stack.json]
//
// This process is the client (and the miner). Three provider processes run with their own keys, fee
// wallets and lnd (layer1/provider.ts --pay ln --zk), and one watchtower process watches them.
//
//   1. Deals and bonds. The client uploads three blobs (1 MiB, 512 KiB, 256 KiB), encrypted per
//      provider, to each provider's Blossom server and registers all three as deals for public proofs.
//      On the 1 MiB deal it runs cut and choose (64 sentinels of 16 windows, 4 kept). The provider then
//      funds a 1 BTC sentinel bond from its own wallet, and both sides check the other's presignatures.
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

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { keyFromSeed } from "../model/schnorr.ts";
import { CHUNK, encryptReplica, replicaKey, sentinelSurvival } from "../model/storage_bonds.ts";
import { BondTool, rpc } from "./bondtool.ts";
import { StorageClient, type BondSentinel, type Offer, type Replica } from "./client.ts";
import { LndNode, LndPayer, lndExe } from "./lnd.ts";
import type { NostrEvent } from "./nostr.ts";
import { RelayClient, startRelay } from "./relay.ts";
import { defaultZk, statementFor, verifyProof, zkTree } from "./zk.ts";
import { KIND_ATTESTATION, KIND_EPOCH_PROOF } from "./zk-provider.ts";

const here = dirname(fileURLToPath(import.meta.url));
const arg = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const EPOCHS = Number(arg("epochs", "3")), FROM_EPOCH = Number(arg("from-epoch", "2")), Q = Number(arg("q", "16"));
const EPOCH = 10, DEADLINE = 6, DELTA = 144;
const M = 64, K = 4, W = 16;
const LND = arg("lnd", lndExe());
const OUT = arg("out", join(here, "..", "results", "full-stack.json"));
const PRICE_MSAT = 512_000;       // per verified epoch, per provider
const CAPACITY = 50_000;
const SIZES = [256, 128, 64];     // chunks: the bonded 1 MiB deal, then 512 KiB and 256 KiB
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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

interface Role { name: string; slug: string; kept: number }
const ROLES: Role[] = [{ name: "honest", slug: "honest", kept: 1 }, { name: "deletes 10%", slug: "deletes10", kept: 0.9 }, { name: "outsources", slug: "outsources", kept: 0 }];

interface Proc { child: ChildProcess; url: string; admin: string; nostr: string; bond_x: string; fee_address: string; ln?: string; pid: number; log: any[]; waiters: ((ev: any) => void)[] }

function spawnLogged(name: string, args: string[], show: (ev: any) => void = () => {}): Promise<Proc> {
  const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "inherit"] });
  const p = { child, pid: child.pid!, log: [] as any[], waiters: [] as ((ev: any) => void)[] } as Proc;
  return new Promise((ok, bad) => {
    const t = setTimeout(() => bad(new Error(`${name} did not start`)), 60_000);
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
const mine = (n: number, addr: string) => (n > 0 ? rpc("generatetoaddress", [n, addr]) : Promise.resolve());
const tx = (txid: string) => rpc("getrawtransaction", [txid, true]);

let height0: number;
try { height0 = (await rpc("getblockchaininfo")).blocks; } catch (e) {
  console.error(`No regtest node (${(e as Error).message}). Start one with scripts/regtest-node.sh <datadir> <bitcoind>.`);
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), "bsb-full-stack-"));
const token = randomBytes(16).toString("hex");
const relay = await startRelay();
const procs: Proc[] = [];
let tower: Proc | undefined;
let clientLn: LndNode | undefined;
let finished = false;
try {
  const SEED = "bsb/client/full-stack";
  const tool = new BondTool(SEED);
  const me = await tool.run("info");
  const nostrKey = keyFromSeed(`nostr|${SEED}`);
  const secret = createHash("sha256").update("full-stack client storage secret").digest();
  await mine(1, me.fee_address);             // lnd waits until Core has a recent block
  // Setup mines about 125 blocks; public proofs start at the first boundary well after that.
  const FIRST = Math.ceil((height0 + 170) / EPOCH) * EPOCH;

  // ── parties ──
  const show = (slug: string) => (ev: any) => {
    if (ev.event === "zk-epoch") console.log(`    [${slug}] block ${ev.height}: ${ev.proved ? `proved (${(ev.bytes / 1e6).toFixed(1)} MB, ${ev.seconds.toFixed(0)} s)` : "could not prove"}`);
    else if (ev.event === "bond-respond" && ev.status !== "idle") console.log(`    [${slug}] saw sentinel ${ev.i} revealed on chain: ${ev.status}${ev.error ? ` (${String(ev.error).replace(/^transaction failed: /, "").slice(0, 80)})` : ""}`);
  };
  const started = await Promise.all([
    LndNode.start({ bin: LND, dir: join(dir, "client-lnd"), alias: "bsb-client" }),
    ...ROLES.map((r) => spawnLogged(r.slug, [join(here, "provider.ts"), "--name", r.slug, "--seed", `bsb/provider/${r.slug}`, "--dir", join(dir, r.slug),
      "--relay", relay.url, "--admin-token", token, "--pay", "ln", "--lnd", LND,
      "--zk", "--epoch-blocks", String(EPOCH), "--zk-q", String(Q), "--zk-from", String(FIRST), "--zk-price", String(PRICE_MSAT)], show(r.slug))),
  ]);
  clientLn = started[0] as LndNode;
  procs.push(...(started.slice(1) as Proc[]));
  tower = await spawnLogged("watchtower", [join(here, "watchtower.ts"), "--relay", relay.url, "--providers", procs.map((p) => p.nostr).join(","),
    "--epoch-blocks", String(EPOCH), "--from", String(FIRST), "--deadline", String(DEADLINE), "--min-q", String(Q), "--dir", join(dir, "watchtower")]);
  console.log(`regtest height ${height0}; public proofs every ${EPOCH} blocks from ${FIRST}, q = ${Q}; relay ${relay.url}`);
  console.log(`client (pid ${process.pid}): bond key ${me.x.slice(0, 16)}…  lnd ${clientLn.pubkey.slice(0, 16)}…`);
  for (const [i, p] of procs.entries()) console.log(`provider ${ROLES[i].name.padEnd(12)} pid ${String(p.pid).padEnd(6)} ${p.url}  bond key ${p.bond_x.slice(0, 16)}…  lnd ${p.ln?.slice(0, 16)}…`);
  console.log(`watchtower           pid ${String(tower.pid).padEnd(6)} nostr ${tower.nostr.slice(0, 16)}…  (verifies every proof itself; no stake in any deal)`);

  for (const p of procs) await mine(2, p.fee_address);
  await mine(3, me.fee_address);
  await mine(ROLES.length, await clientLn.newAddress());
  await mine(100, me.fee_address);
  await clientLn.waitSynced(await rpc("getblockcount"));

  const rc = await RelayClient.connect(relay.url);
  const payer = new LndPayer(clientLn);
  const client = new StorageClient({ key: nostrKey, secret, payer });

  // ── deals, bonds, channels ──
  console.log(`\nsetup: 3 deals per provider (${SIZES.join(" + ")} chunks); a 1 BTC sentinel bond on the first (M = ${M}, k = ${K}, ${W} windows); ${CAPACITY}-sat Lightning channels`);
  const blobs = SIZES.map((n, k) => blobOf(`full-stack blob ${k}`, n));
  const reps: Replica[][] = [], roots: { root: string; n: number }[][] = [], kept: BondSentinel[][] = [];
  const deals: string[] = [], fundTx: string[] = [], chans: string[] = [], payees: string[] = [];
  const tEnd = (await rpc("getblockcount")) + 1500;
  for (const [i, p] of procs.entries()) {
    const info = (await (await fetch(`${p.url}/`)).json()) as { pubkey: string; bond_x: string; channel_payee: string; ln_uri?: string };
    const offer: Offer = { url: p.url, pubkey: info.pubkey, lightningNodeId: info.channel_payee, priceMsatPerChunkEpoch: 1000 };
    const rs: Replica[] = [], rr: { root: string; n: number }[] = [];
    for (const [k, blob] of blobs.entries()) {
      const rep = await client.store(blob, offer, 8, "application/octet-stream", k === 0 ? M : 0, W);
      const ours = zkTree(encryptReplica(blob, replicaKey(secret, rep.blobId, offer.pubkey)));
      const reg = await post(`${p.url}/zk/register`, { sha256: rep.sha256 });
      if (reg.zk_root !== ours.root.toString("hex") || reg.n !== ours.n) throw new Error(`${ROLES[i].slug}: zk root differs from ours`);
      rs.push(rep); rr.push({ root: reg.zk_root, n: reg.n });
    }
    // The sentinel bond on the first deal.
    const ks = await client.bond(rs[0], K);
    const f = await post(`${p.url}/bond/${rs[0].sha256}/fund`, { client_x: me.x, t_end: tEnd });
    if (JSON.stringify(f.deal.sentinels) !== JSON.stringify(ks.map((s) => ({ s: s.s, h: s.h, hs: s.hs }))) || f.deal.client_x !== me.x || f.deal.provider_x !== info.bond_x) {
      throw new Error(`${ROLES[i].slug}: the provider's deal differs from ours`);
    }
    const dealPath = join(dir, `client-deal-${ROLES[i].slug}.json`);
    writeFileSync(dealPath, JSON.stringify(f.deal, null, 2));
    writeFileSync(dealPath.replace(".json", ".p.json"), JSON.stringify({ fund_txid: f.fund_txid, sig_p_challenge: f.sig_p_challenge }));
    await mine(1, me.fee_address);
    const c = await tool.run("bond-presign", dealPath);
    await post(`${p.url}/bond/${rs[0].sha256}/presigs`, { sig_c_respond: c.sig_c_respond });
    // The Lightning channel.
    if (!info.ln_uri?.startsWith(info.channel_payee + "@")) throw new Error(`${ROLES[i].slug}: no Lightning node in its info`);
    await clientLn.connect(info.ln_uri);
    await clientLn.waitSynced(await rpc("getblockcount"));
    await post(`${p.url}/channel/prepare`, {});
    let point = "";
    for (let tries = 0; !point; tries++) {
      try { point = await clientLn.openChannel(info.channel_payee, CAPACITY); }
      catch (e) { if (tries > 40 || !/sync/i.test((e as Error).message)) throw e; await sleep(250); }
    }
    await mine(1, me.fee_address);
    await clientLn.waitActive(point);
    await post(`${p.url}/channel/open`, { channel_point: point, client_pubkey: clientLn.pubkey });
    reps.push(rs); roots.push(rr); kept.push(ks); deals.push(dealPath); fundTx.push(f.fund_txid); chans.push(point); payees.push(info.channel_payee);
    console.log(`  ${ROLES[i].name.padEnd(12)} zk roots match; bond ${f.fund_txid.slice(0, 12)}… (${c.checked.provider_signatures} signatures checked); ln channel ${point.slice(0, 12)}…`);
  }
  if ((await rpc("getblockcount")) >= FIRST) throw new Error(`setup ran past the first boundary ${FIRST}`);

  // ── the client: verify each announced proof, then pay it over Lightning ──
  type Row = { proof?: string; client?: string; paidSats?: number; payment?: { hash: string; preimage: string }; tower?: string; towerEvent?: string; providerSays?: string };
  const table = new Map<string, Row>();
  const row = (i: number, h: number) => { const k = `${i}|${h}`; if (!table.has(k)) table.set(k, {}); return table.get(k)!; };
  const byNostr = new Map(procs.map((p, i) => [p.nostr, i]));
  const adverse = new Map<number, { height: number; result: string; event: string; why?: string }>();
  let pending = Promise.resolve();
  let paying = true;
  rc.subscribe([{ kinds: [KIND_EPOCH_PROOF], authors: procs.map((p) => p.nostr) }], (e: NostrEvent) => {
    if (!paying) return;
    pending = pending.then(async () => {
      const i = byNostr.get(e.pubkey)!;
      const c = JSON.parse(e.content);
      const r = row(i, c.height);
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
      const { preimage } = await payer.pay(inv.paymentRequest, PRICE_MSAT);
      r.paidSats = PRICE_MSAT / 1000;
      r.payment = { hash: d.paymentHash, preimage };
    }).catch((err) => { console.log(`  client: ${(err as Error).message}`); });
  });
  rc.subscribe([{ kinds: [KIND_ATTESTATION], authors: [tower.nostr] }], (e: NostrEvent) => {
    const c = JSON.parse(e.content);
    const i = byNostr.get(c.provider);
    if (i === undefined) return;
    const r = row(i, c.height);
    r.tower = c.result; r.towerEvent = e.id;
    if ((c.result === "missing" || c.result === "invalid") && !adverse.has(i)) adverse.set(i, { height: c.height, result: c.result, event: e.id, why: c.why });
  });

  // ── epochs ──
  console.log(`\nepochs: providers prove on their own at each boundary; the client verifies and pays over Lightning`);
  for (let e = 1; e <= EPOCHS; e++) {
    const b = FIRST + (e - 1) * EPOCH;
    if (e === FROM_EPOCH) {
      for (const k of SIZES.keys()) {
        await post(`${procs[1].admin}/admin/misbehave`, { kind: "delete", sha: reps[1][k].sha256, indices: pick(reps[1][k].n, 0.1, `lazy ${k}`) }, { "x-admin-token": token });
        await post(`${procs[2].admin}/admin/misbehave`, { kind: "outsource", sha: reps[2][k].sha256, from: { url: procs[0].url, sha256: reps[0][k].sha256 } }, { "x-admin-token": token });
      }
      console.log(`  from epoch ${e}: "deletes 10%" zeroes a tenth of each replica; "outsources" reads the honest provider's copies`);
    }
    await mine(b - (await rpc("getblockcount")), me.fee_address);
    console.log(`  epoch ${e}: boundary block ${b}, seed ${String(await rpc("getblockhash", [b])).slice(0, 16)}…`);
    const said = await Promise.all(procs.map((p) => waitLog(p, (ev) => ev.event === "zk-epoch" && ev.height === b, 900_000)));
    said.forEach((ev, i) => { row(i, b).providerSays = ev.proved ? "proved" : "could not prove"; });
    await mine(DEADLINE, me.fee_address);
    await pending;
    for (let k = 0; k < 600 && procs.some((_, i) => !row(i, b).tower); k++) await sleep(250);
    await pending;
  }
  // The epoch phase is over: no more proofs, payments or attestations while the bond phase mines.
  paying = false;
  for (const p of procs) await post(`${p.admin}/admin/zk-stop`, {}, { "x-admin-token": token });
  await pending;
  const attestations = tower.log.filter((ev) => ev.event === "attest");
  tower.child.kill("SIGTERM");

  console.log(`\n${"provider".padEnd(12)} ${"epoch".padEnd(6)} ${"provider".padEnd(16)} ${"client".padEnd(12)} ${"paid (LN)".padEnd(10)} watchtower`);
  for (const [i, r] of ROLES.entries()) for (let e = 1; e <= EPOCHS; e++) {
    const x = row(i, FIRST + (e - 1) * EPOCH);
    console.log(`${r.name.padEnd(12)} ${String(e).padEnd(6)} ${(x.providerSays ?? "—").padEnd(16)} ${(x.client ?? "nothing").slice(0, 12).padEnd(12)} ${String(x.paidSats ?? 0).padEnd(10)} ${x.tower ?? "—"}`);
  }

  // ── Lightning settlement, before the long mining of the bond phase (lnd's per-block RPC would
  //    exhaust Windows' ephemeral ports at a block every 150 ms) ──
  console.log("\nLightning settlement: each provider closes its channel cooperatively from its own node");
  const lnCloses: string[] = [];
  for (const [i, p] of procs.entries()) {
    const close = await post(`${p.admin}/admin/close-channel`, { peer: clientLn.pubkey }, { "x-admin-token": token });
    await mine(1, me.fee_address);
    lnCloses.push(close.txid);
    console.log(`  ${ROLES[i].name.padEnd(12)} close ${close.txid.slice(0, 16)}…  (${payer.paidMsatTo(payees[i]) / 1000} sats paid over Lightning)`);
  }
  for (const p of procs) await post(`${p.admin}/admin/ln-stop`, {}, { "x-admin-token": token });
  await clientLn.stop();

  // ── enforcement: driven by the watchtower's attestations ──
  console.log(`\nenforcement: a missing or invalid attestation sends the client to that provider's bond`);
  const enforcement = [];
  for (const [i, role] of ROLES.entries()) {
    const cause = adverse.get(i);
    if (!cause) { console.log(`  ${role.name.padEnd(12)} no adverse attestation: not challenged`); enforcement.push({ role: role.name, cause: null, steps: [], forfeit: null }); continue; }
    console.log(`  ${role.name.padEnd(12)} attested ${cause.result} at block ${cause.height} (event ${cause.event.slice(0, 12)}…): challenging its bond`);
    const steps = [];
    let forfeit: string | null = null;
    for (let j = 0; j < K && !forfeit; j++) {
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
        try { forfeit = (await tool.run("bond-forfeit", deals[i], String(j))).txid; } catch (e) { console.log(`    forfeit refused: ${(e as Error).message}`); }
        await mine(1, me.fee_address);
        if (forfeit) console.log(`    sentinel ${j}: no valid answer in ${DELTA} blocks → forfeit ${forfeit.slice(0, 16)}…`);
      } else console.log(`    sentinel ${j}: answered on chain after ${answeredAt} block(s)`);
      steps.push({ sentinel: j, challenge_txid: c.txid, answered_after_blocks: answeredAt < 0 ? null : answeredAt, forfeit_txid: forfeit });
    }
    enforcement.push({ role: role.name, cause, steps, forfeit });
  }

  // ── bond refunds at the term's end ──
  const refunds: (string | null)[] = [];
  for (const [i, p] of procs.entries()) {
    if (enforcement[i].forfeit) { refunds.push(null); continue; }
    const h = await rpc("getblockcount");
    if (h < tEnd) await mine(tEnd - h, me.fee_address);
    refunds.push((await post(`${p.admin}/admin/refund`, { sha: reps[i][0].sha256 }, { "x-admin-token": token })).txid);
    await mine(1, me.fee_address);
  }

  // ── read every outcome back from the chain ──
  console.log("\nfrom the chain:");
  const summary = [];
  for (const [i, role] of ROLES.entries()) {
    const fund = await tx(fundTx[i]);
    const bondOut = fund.vout[0];
    const close = await tx(lnCloses[i]);
    const [ftxid, fvout] = chans[i].split(":");
    if (close.confirmations < 1 || close.vin.length !== 1 || close.vin[0].txid !== ftxid || close.vin[0].vout !== Number(fvout)) throw new Error(`${role.slug}: close does not spend its channel`);
    const paid = payer.paidMsatTo(payees[i]) / 1000;
    const outs = close.vout.map((o: any) => Math.round(o.value * 1e8));
    if (paid > 0 && !outs.includes(paid)) throw new Error(`${role.slug}: close has no ${paid}-sat output (${outs.join(", ")})`);
    const settleTxid = enforcement[i].forfeit ?? refunds[i]!;
    const settle = await tx(settleTxid);
    if (settle.confirmations < 1) throw new Error(`${role.slug}: bond settlement unconfirmed`);
    const leaf = settle.vin[0].sequence === DELTA ? "forfeit leaf (CSV 144), to the client" : "refund leaf (CLTV t_end), to the provider";
    const challenges = [];
    for (const s of enforcement[i].steps as any[]) {
      const ct = await tx(s.challenge_txid);
      challenges.push({ ...s, challenge_confirmations: ct.confirmations, revealed_r: ct.vin[0].txinwitness[0] });
    }
    console.log(`  ${role.name.padEnd(12)} bond ${fundTx[i].slice(0, 12)}… ${Math.round(bondOut.value * 1e8)} sats → ${settleTxid.slice(0, 12)}… via ${leaf}; ln close ${lnCloses[i].slice(0, 12)}… pays ${paid} sats`);
    const epochs = Array.from({ length: EPOCHS }, (_, e) => ({ epoch: e + 1, height: FIRST + e * EPOCH, ...row(i, FIRST + e * EPOCH) }));
    summary.push({
      role: role.name, pid: procs[i].pid,
      epochs,
      lightning: { channel_point: chans[i], close_txid: lnCloses[i], close_confirmations: close.confirmations, close_outputs_sats: outs, paid_sats: paid },
      bond: { fund_txid: fundTx[i], value_sats: Math.round(bondOut.value * 1e8), settled_by: settleTxid, settle_confirmations: settle.confirmations, leaf, to: enforcement[i].forfeit ? "client" : "provider" },
      enforcement: { cause: enforcement[i].cause, challenges },
      p_detect_10pct_per_epoch: role.kept === 1 ? 0 : 1 - Math.pow(role.kept, Q),
      p_forfeit_given_challenge: role.kept === 1 ? 0 : 1 - sentinelSurvival(role.kept, W, K),
      providerLog: procs[i].log.filter((ev) => ["zk-epoch", "bond-respond", "ln-channel"].includes(ev.event)),
    });
  }
  rc.close();

  console.log(`\n${"provider".padEnd(12)} ${"proofs ok".padEnd(10)} ${"paid (LN)".padEnd(10)} ${"attested".padEnd(22)} bond (1 BTC)`);
  for (const s of summary) {
    const ok = s.epochs.filter((e) => e.client === "verified").length;
    const att = s.enforcement.cause ? `${s.enforcement.cause.result} @ ${s.enforcement.cause.height}` : "valid throughout";
    console.log(`${s.role.padEnd(12)} ${`${ok}/${EPOCHS}`.padEnd(10)} ${String(s.lightning.paid_sats).padEnd(10)} ${att.padEnd(22)} ${s.bond.to === "client" ? "forfeited to the client" : "refunded to the provider"}`);
  }

  const height1 = await rpc("getblockcount");
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({
    generated: new Date().toISOString(),
    note: "One regtest run: every party a separate process with its own keys, wallet and lnd. Public STARK epoch proofs seeded by block hashes; each verified epoch paid by BOLT 11 over Lightning; a missing or invalid watchtower attestation triggers on-chain sentinel challenges; every txid here was read back from bitcoind.",
    params: { epochs: EPOCHS, misbehaviourFromEpoch: FROM_EPOCH, q: Q, epochBlocks: EPOCH, deadline: DEADLINE, firstBoundary: FIRST, deals: SIZES, bondSats: 100_000_000, sentinels: { M, k: K, windows: W }, delta: DELTA, priceSatsPerEpoch: PRICE_MSAT / 1000, channelSats: CAPACITY },
    regtest: { heightBefore: height0, heightAfter: height1 },
    summary,
    watchtower: attestations,
  }, null, 2) + "\n");
  console.log(`\nregtest height ${height0} → ${height1}; wrote ${OUT}`);
  finished = true;
} finally {
  await Promise.all(procs.map((p) => fetch(`${p.admin}/admin/stop`, { method: "POST", headers: { "x-admin-token": token } }).catch(() => undefined)));
  await clientLn?.stop().catch(() => undefined);
  for (let i = 0; i < 40 && procs.some((p) => p.child.exitCode === null); i++) await sleep(250);
  for (const p of procs) p.child.kill("SIGTERM");
  tower?.child.kill("SIGTERM");
  await sleep(300);
  await relay.close();
  if (finished) rmSync(dir, { recursive: true, force: true });
  else console.error(`run failed; kept ${dir}`);
}
