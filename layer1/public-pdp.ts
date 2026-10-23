// Phase 3b: public epoch proofs, end to end on regtest, every party in its own process.
//
//   scripts/regtest-node.sh <datadir> <bitcoind>      (another shell; RPC on 127.0.0.1:18543)
//   node layer1/public-pdp.ts [--epochs 3] [--from-epoch 2] [--q 8] [--epoch-blocks 10] [--out results/public-pdp.json]
//
// This process is the client, and it also mines blocks to drive time. Three provider processes run
// with --zk (layer1/provider.ts), and one watchtower process watches them all (layer1/watchtower.ts).
// The client never sends a challenge:
//
//   1. It uploads three blobs (1 MiB, 512 KiB, 256 KiB), encrypted per provider, to each provider,
//      registers them as deals, and checks each provider's Blake2s zk root against its own. It opens
//      a 50,000-sat payment channel to each provider.
//   2. Every 10 blocks each provider proves its holdings with no prompt. The seed is the boundary
//      block's hash and q = 8 challenges are drawn across all its deals. The proof goes on its own
//      Blossom server and is announced on Nostr.
//   3. The client checks that its deals are in each announced deal list, verifies each proof itself
//      against its own node's block hash, and pays that epoch over the channel only if the proof holds.
//   4. The watchtower verifies the same proofs independently and attests valid, invalid or missing.
//   5. From --from-epoch on, one provider zeroes 10% of its chunks, and one deletes its replicas and
//      reads from the honest provider's copies. Neither can make a valid proof for a seed whose
//      challenges hit what it lacks, so it publishes nothing and is not paid.
//
// At the end each provider closes its channel on chain, and the run checks every close against what
// the client paid. Proving runs one proof at a time through WSL (layer1/zk.ts).

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { keyFromSeed } from "../model/schnorr.ts";
import { CHUNK, encryptReplica, replicaKey } from "../model/storage_bonds.ts";
import { BondTool, rpc } from "./bondtool.ts";
import { ChannelPayer } from "./channel.ts";
import { StorageClient, type Offer, type Replica } from "./client.ts";
import { type NostrEvent } from "./nostr.ts";
import { RelayClient, startRelay } from "./relay.ts";
import { defaultZk, statementFor, verifyProof, zkTree } from "./zk.ts";
import { KIND_ATTESTATION, KIND_EPOCH_PROOF } from "./zk-provider.ts";

const here = dirname(fileURLToPath(import.meta.url));
const arg = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const EPOCHS = Number(arg("epochs", "3")), FROM_EPOCH = Number(arg("from-epoch", "2")), Q = Number(arg("q", "8"));
const EPOCH = Number(arg("epoch-blocks", "10")), DEADLINE = 6;
const OUT = arg("out", join(here, "..", "results", "public-pdp.json"));
const PRICE_MSAT = 512_000;      // per verified epoch, per provider
const CAPACITY = 50_000;
const SIZES = [256, 128, 64];    // chunks per blob: 1 MiB, 512 KiB, 256 KiB
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

interface Role { name: string; slug: string }
const ROLES: Role[] = [{ name: "honest", slug: "honest" }, { name: "deletes 10%", slug: "deletes10" }, { name: "outsources", slug: "outsources" }];

interface Proc { child: ChildProcess; url?: string; admin?: string; nostr: string; bond_x?: string; fee_address?: string; pid: number; log: any[]; waiters: ((ev: any) => void)[] }

function spawnLogged(name: string, args: string[]): Promise<Proc> {
  const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "inherit"] });
  const p: Proc = { child, nostr: "", pid: child.pid!, log: [], waiters: [] };
  return new Promise((ok, bad) => {
    const t = setTimeout(() => bad(new Error(`${name} did not start`)), 30_000);
    createInterface({ input: child.stdout! }).on("line", (line) => {
      let ev: any; try { ev = JSON.parse(line); } catch { return; }
      p.log.push(ev);
      for (const w of [...p.waiters]) w(ev);
      if (ev.ready) { clearTimeout(t); Object.assign(p, ev); ok(p); }
    });
    child.on("exit", (c) => { clearTimeout(t); if (c) bad(new Error(`${name} exited ${c}`)); });
  });
}
const waitLog = (p: Proc, pred: (ev: any) => boolean, ms: number) => new Promise<any>((ok, bad) => {
  const hit = p.log.find(pred);
  if (hit) return ok(hit);
  const t = setTimeout(() => { p.waiters = p.waiters.filter((w) => w !== f); bad(new Error("timed out waiting for a log line")); }, ms);
  const f = (ev: any) => { if (pred(ev)) { clearTimeout(t); p.waiters = p.waiters.filter((w) => w !== f); ok(ev); } };
  p.waiters.push(f);
});
const post = async (url: string, body: unknown, headers: Record<string, string> = {}) => {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  if (r.status !== 200) throw new Error(`${url}: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
  return r.json() as Promise<any>;
};
const mine = (n: number, addr: string) => (n > 0 ? rpc("generatetoaddress", [n, addr]) : Promise.resolve());

let height0: number;
try { height0 = (await rpc("getblockchaininfo")).blocks; } catch (e) {
  console.error(`No regtest node (${(e as Error).message}). Start one with scripts/regtest-node.sh <datadir> <bitcoind>.`);
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), "bsb-public-pdp-"));
const token = randomBytes(16).toString("hex");
const relay = await startRelay();
const procs: Proc[] = [];
let tower: Proc | undefined;
try {
  // Setup mines about 110 blocks; proofs start at the first boundary after that.
  const FIRST = Math.ceil((height0 + 130) / EPOCH) * EPOCH;
  for (const r of ROLES) {
    procs.push(await spawnLogged(r.slug, [join(here, "provider.ts"), "--name", r.slug, "--seed", `bsb/provider/${r.slug}`, "--dir", join(dir, r.slug),
      "--relay", relay.url, "--admin-token", token, "--zk", "--epoch-blocks", String(EPOCH), "--zk-q", String(Q), "--zk-from", String(FIRST), "--zk-price", String(PRICE_MSAT)]));
  }
  tower = await spawnLogged("watchtower", [join(here, "watchtower.ts"), "--relay", relay.url, "--providers", procs.map((p) => p.nostr).join(","),
    "--epoch-blocks", String(EPOCH), "--from", String(FIRST), "--deadline", String(DEADLINE), "--min-q", String(Q), "--dir", join(dir, "watchtower")]);

  const SEED = "bsb/client/public-pdp";
  const tool = new BondTool(SEED);
  const me = await tool.run("info");
  const nostrKey = keyFromSeed(`nostr|${SEED}`);
  const secret = createHash("sha256").update("public-pdp client storage secret").digest();
  console.log(`regtest height ${height0}; proofs every ${EPOCH} blocks from ${FIRST}; q = ${Q}; relay ${relay.url}`);
  for (const [i, p] of procs.entries()) console.log(`provider ${ROLES[i].name.padEnd(12)} pid ${String(p.pid).padEnd(6)} ${p.url}  nostr ${p.nostr.slice(0, 12)}…`);
  console.log(`watchtower           pid ${String(tower.pid).padEnd(6)} nostr ${tower.nostr.slice(0, 12)}…  (a separate party; verifies every proof itself)`);
  await mine(3, me.fee_address);
  await mine(100, me.fee_address);

  const rc = await RelayClient.connect(relay.url);
  const payer = new ChannelPayer(me.x, tool, join(dir, "client-payments.ledger"));
  const client = new StorageClient({ key: nostrKey, secret, payer });

  // ── storage and channels ──
  const blobs = SIZES.map((n, k) => blobOf(`public-pdp blob ${k}`, n));
  const reps: Replica[][] = [];
  const myRoots: { root: string; n: number }[][] = [];
  for (const [i, p] of procs.entries()) {
    const info = (await (await fetch(`${p.url}/`)).json()) as { pubkey: string; bond_x: string; channel_payee: string };
    const offer: Offer = { url: p.url!, pubkey: info.pubkey, lightningNodeId: info.channel_payee, priceMsatPerChunkEpoch: 1000 };
    const rs: Replica[] = [], roots: { root: string; n: number }[] = [];
    for (const blob of blobs) {
      const rep = await client.store(blob, offer, Q);
      const mine_ = zkTree(encryptReplica(blob, replicaKey(secret, rep.blobId, offer.pubkey)));
      const reg = await post(`${p.url}/zk/register`, { sha256: rep.sha256 });
      if (reg.zk_root !== mine_.root.toString("hex") || reg.n !== mine_.n) throw new Error(`${ROLES[i].slug}: zk root differs from ours`);
      rs.push(rep); roots.push({ root: reg.zk_root, n: reg.n });
    }
    const ch = await payer.open(join(dir, `chan-${ROLES[i].slug}.json`), { provider_x: info.bond_x, client_x: me.x, capacity_sats: CAPACITY, t_refund: height0 + 5000 });
    await mine(1, me.fee_address);
    await post(`${p.url}/channel/open`, ch);
    reps.push(rs); myRoots.push(roots);
    console.log(`  ${ROLES[i].name.padEnd(12)} 3 deals (${SIZES.join(" + ")} chunks), zk roots match; channel ${ch.funding_txid!.slice(0, 12)}…`);
  }

  // ── the client's view: verify each announced proof, pay if it holds ──
  type Row = { proof?: string; client?: string; paid?: number; tower?: string; providerSays?: string };
  const table = new Map<string, Row>();     // `${i}|${height}`
  const row = (i: number, h: number) => { const k = `${i}|${h}`; if (!table.has(k)) table.set(k, {}); return table.get(k)!; };
  let pending = Promise.resolve();
  const byNostr = new Map(procs.map((p, i) => [p.nostr, i]));
  rc.subscribe([{ kinds: [KIND_EPOCH_PROOF], authors: procs.map((p) => p.nostr) }], (e: NostrEvent) => {
    pending = pending.then(async () => {
      const i = byNostr.get(e.pubkey)!;
      const c = JSON.parse(e.content);
      const r = row(i, c.height);
      r.proof = c.proof.sha256;
      const covered = myRoots[i].every((m) => c.deals.some((d: any) => d.root === m.root && d.n === m.n));
      if (!covered) { r.client = "rejected: our deals are not in its list"; return; }
      const seed = Buffer.from(await rpc("getblockhash", [c.height]), "hex");
      const proof = Buffer.from(await (await fetch(c.proof.url)).arrayBuffer());
      if (createHash("sha256").update(proof).digest("hex") !== c.proof.sha256) { r.client = "rejected: proof bytes differ from the event"; return; }
      const v = await verifyProof(defaultZk(), join(dir, "client-verify"), proof, statementFor(seed, Number(c.q), c.deals));
      if (!v.ok) { r.client = `rejected: ${v.why.slice(0, 60)}`; return; }
      r.client = "verified";
      const inv = await (await fetch(`${procs[i].url}/zk/invoice/${c.height}?client=${me.x}`)).json() as { paymentRequest: string };
      await payer.pay(inv.paymentRequest, PRICE_MSAT);
      r.paid = PRICE_MSAT / 1000;
    }).catch((err) => { console.log(`  client: ${(err as Error).message}`); });
  });
  rc.subscribe([{ kinds: [KIND_ATTESTATION], authors: [tower.nostr] }], (e: NostrEvent) => {
    const c = JSON.parse(e.content);
    const i = byNostr.get(c.provider);
    if (i !== undefined) row(i, c.height).tower = c.result + (c.why ? ` (${String(c.why).slice(0, 50)})` : "");
  });

  // ── epochs ──
  console.log(`\nepochs: each provider proves on its own at each boundary; the client mines and watches`);
  for (let e = 1; e <= EPOCHS; e++) {
    const b = FIRST + (e - 1) * EPOCH;
    if (e === FROM_EPOCH) {
      for (const k of SIZES.keys()) {
        await post(`${procs[1].admin}/admin/misbehave`, { kind: "delete", sha: reps[1][k].sha256, indices: pick(reps[1][k].n, 0.1, `lazy ${k}`) }, { "x-admin-token": token });
        await post(`${procs[2].admin}/admin/misbehave`, { kind: "outsource", sha: reps[2][k].sha256, from: { url: procs[0].url, sha256: reps[0][k].sha256 } }, { "x-admin-token": token });
      }
      console.log(`  (from epoch ${e}: deletes 10% zeroes a tenth of every replica; outsources reads the honest provider's copies)`);
    }
    const h = await rpc("getblockcount");
    await mine(b - h, me.fee_address);
    const t0 = Date.now();
    const said = await Promise.all(procs.map((p) => waitLog(p, (ev) => ev.event === "zk-epoch" && ev.height === b, 600_000)));
    said.forEach((ev, i) => { row(i, b).providerSays = ev.proved ? `proved in ${ev.seconds.toFixed(0)} s` : `could not prove`; });
    await mine(DEADLINE, me.fee_address);
    await pending;
    await waitLog(tower, (ev) => ev.event === "attest" && ev.height === b && ev.provider === procs[procs.length - 1].nostr.slice(0, 12), 120_000).catch(() => {});
    for (let k = 0; k < 40 && procs.some((_, i) => !row(i, b).tower); k++) await sleep(250);
    console.log(`  epoch ${e} (block ${b}, seed ${String(await rpc("getblockhash", [b])).slice(0, 12)}…) done in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
  }

  // ── table ──
  console.log(`\n${"provider".padEnd(12)} ${"epoch".padEnd(6)} ${"provider".padEnd(20)} ${"client".padEnd(22)} ${"paid".padEnd(6)} watchtower`);
  for (const [i, r] of ROLES.entries()) for (let e = 1; e <= EPOCHS; e++) {
    const x = row(i, FIRST + (e - 1) * EPOCH);
    console.log(`${r.name.padEnd(12)} ${String(e).padEnd(6)} ${(x.providerSays ?? "—").padEnd(20)} ${(x.client ?? "no proof to check").slice(0, 22).padEnd(22)} ${String(x.paid ?? 0).padEnd(6)} ${x.tower ?? "—"}`);
  }

  // ── settlement ──
  console.log("\nsettlement: each provider closes its channel with the latest state the client signed");
  const settled = [];
  for (const [i, p] of procs.entries()) {
    const paid = payer.paidTo(`bsbch:${(await (await fetch(`${p.url}/`)).json() as any).bond_x}`);
    let close: string | null = null, onChain = 0;
    if (paid > 0) {
      close = (await post(`${p.admin}/admin/close-channel`, { client_x: me.x }, { "x-admin-token": token })).txid;
      await mine(1, me.fee_address);
      const t = await rpc("getrawtransaction", [close, true]);
      onChain = Math.round(t.vout[0].value * 1e8);
      if (t.confirmations < 1 || onChain !== paid) throw new Error(`${ROLES[i].slug}: close pays ${onChain}, client paid ${paid}`);
    }
    console.log(`  ${ROLES[i].name.padEnd(12)} paid ${String(paid).padStart(5)} sats${close ? `, close ${close.slice(0, 16)}… confirmed, pays exactly that` : ", nothing to close"}`);
    settled.push({ role: ROLES[i].name, paidSats: paid, close, paidOnChainSats: onChain });
  }
  rc.close();

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({
    generated: new Date().toISOString(),
    note: "Every party is a separate process. Seeds are regtest block hashes. Proofs are Stwo STARKs of the holdings-mode Cairo program (Blake2s tree), proved in WSL. Payment is a one-way Bitcoin channel per provider.",
    params: { epochs: EPOCHS, misbehaviourFromEpoch: FROM_EPOCH, q: Q, epochBlocks: EPOCH, deadline: DEADLINE, firstBoundary: FIRST, dealsPerProvider: SIZES.length, chunks: SIZES, priceSatsPerEpoch: PRICE_MSAT / 1000 },
    epochs: ROLES.map((r, i) => ({ role: r.name, epochs: Array.from({ length: EPOCHS }, (_, e) => ({ epoch: e + 1, height: FIRST + e * EPOCH, ...row(i, FIRST + e * EPOCH) })) })),
    settlement: settled,
    providerLogs: procs.map((p, i) => ({ role: ROLES[i].name, zk: p.log.filter((ev) => String(ev.event ?? "").startsWith("zk")) })),
    watchtower: tower.log.filter((ev) => ev.event === "attest"),
  }, null, 2) + "\n");
  console.log(`\nwrote ${OUT}`);
} finally {
  for (const p of procs) p.child.kill("SIGTERM");
  tower?.child.kill("SIGTERM");
  await sleep(300);
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
