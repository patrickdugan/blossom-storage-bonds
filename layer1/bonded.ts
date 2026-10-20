// Phase 2, both layers end to end: Blossom storage with pay-per-proof epochs, and a Bitcoin bond per
// provider that is enforced on regtest from the bytes each provider actually stores.
//
//   scripts/regtest-node.sh <datadir> <bitcoind>      (in another shell; RPC on 127.0.0.1:18543)
//   node layer1/bonded.ts [--epochs 10] [--q 8] [--from 4] [--m 64] [--k 4] [--windows 16] [--out results/bonded.json]
//
// 1. Four providers run Blossom servers. The client uploads a 1 MiB blob encrypted per provider and,
//    while it still holds each ciphertext, commits to M sentinels of W windows each. One revealed r
//    opens all W windows, and the respond leaf checks every one.
// 2. Cut and choose over HTTP: each provider opens M − k of them, checks them against its stored bytes,
//    and the bond is built on the k it did not open.
// 3. bsb-bond funds a 1 BTC bond per provider on regtest and presigns its chain.
// 4. Ten epochs of pay per proof, as in layer1/demo.ts. From epoch 4 one provider zeroes 10% of its
//    chunks, one 50%, and one deletes its replica and answers from the honest provider's copy.
// 5. Enforcement: the client challenges every provider that failed an epoch on all k sentinels, and the
//    honest provider once as a spot check. For each challenge the provider's agent fetches r ‖ window from
//    its own Blossom server and submits it on chain. Bitcoin Core accepts it or rejects it. A rejected or
//    missing answer is followed by Δ = 144 blocks and the forfeit leaf.
//
// Lightning is still the in-memory stub (layer1/lightning.ts). Bitcoin is real: Core 31.1 on regtest.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { keyFromSeed } from "../model/schnorr.ts";
import { sentinelSurvival } from "../model/storage_bonds.ts";
import { startProvider, type Provider } from "./blossom.ts";
import { StorageClient, type BondSentinel, type EpochResult, type Offer, type Replica } from "./client.ts";
import { StubNetwork } from "./lightning.ts";
import { RelayClient, startRelay } from "./relay.ts";

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const arg = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const EPOCHS = Number(arg("epochs", "10")), Q = Number(arg("q", "8")), FROM = Number(arg("from", "4"));
const M = Number(arg("m", "64")), K = Number(arg("k", "4")), W = Number(arg("windows", "16"));
const OUT = arg("out", join(here, "..", "results", "bonded.json"));
const RPC = process.env.BSB_RPC ?? "http://127.0.0.1:18543";
const PRICE = 1;

function bondExe(): string {
  const cands = [
    process.env.BSB_BOND,
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "cargo-target", "blossom-storage-bonds", "release", "bsb-bond.exe"),
    process.env.CARGO_TARGET_DIR && join(process.env.CARGO_TARGET_DIR, "release", process.platform === "win32" ? "bsb-bond.exe" : "bsb-bond"),
    join(here, "..", "regtest", "target", "release", process.platform === "win32" ? "bsb-bond.exe" : "bsb-bond"),
  ].filter((x): x is string => !!x);
  const hit = cands.find((p) => existsSync(p));
  if (!hit) throw new Error(`bsb-bond not found; build it with cargo build --release in regtest/ (looked in ${cands.join(", ")})`);
  return hit;
}

async function nodeHeight(): Promise<number> {
  const r = await fetch(RPC, {
    method: "POST", headers: { Authorization: "Basic " + Buffer.from("bsb:bsb-regtest-only").toString("base64") },
    body: JSON.stringify({ jsonrpc: "1.0", id: "bonded", method: "getblockchaininfo", params: [] }),
  });
  const v = (await r.json()) as { result: { chain: string; blocks: number } };
  if (v.result.chain !== "regtest") throw new Error("not regtest");
  return v.result.blocks;
}

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

interface Role { name: string; slug: string; kept: number; misbehave?: (p: Provider, rep: Replica, honest: { url: string; sha256: string }) => void }
const ROLES: Role[] = [
  { name: "honest", slug: "honest", kept: 1 },
  { name: "deletes 10%", slug: "deletes10", kept: 0.9, misbehave: (p, rep) => p.deleteChunks(rep.sha256, pick(rep.n, 0.1, "lazy")) },
  { name: "deletes 50%", slug: "deletes50", kept: 0.5, misbehave: (p, rep) => p.deleteChunks(rep.sha256, pick(rep.n, 0.5, "half")) },
  { name: "outsources", slug: "outsources", kept: 0, misbehave: (p, rep, honest) => p.outsource(rep.sha256, honest) },
];

let height0: number;
try { height0 = await nodeHeight(); } catch (e) {
  console.error(`No regtest node at ${RPC} (${(e as Error).message}). Start one with scripts/regtest-node.sh <datadir> <bitcoind>.`);
  process.exit(1);
}
const BOND_EXE = bondExe();
const dataDir = mkdtempSync(join(tmpdir(), "bsb-bonded-"));
const relay = await startRelay();
const ln = new StubNetwork();
const providers: Provider[] = [];
try {
  for (const [i, role] of ROLES.entries()) {
    providers.push(await startProvider({ dir: join(dataDir, `p${i}`), key: keyFromSeed(`bonded provider ${role.slug}`), payee: ln.node(`ln-${role.slug}`), priceMsatPerChunkEpoch: PRICE }));
  }
  const rc = await RelayClient.connect(relay.url);
  const client = new StorageClient({
    key: keyFromSeed("bonded client"), secret: createHash("sha256").update("bonded client storage secret").digest(),
    payer: ln.node("ln-client", 1_000_000_000), relay: rc, nonceSeed: "phase-2-bonded",
  });
  const blob = demoBlob();
  const offers: Offer[] = providers.map((p) => ({ url: p.url, pubkey: p.pubkey, lightningNodeId: p.config.payee.nodeId, priceMsatPerChunkEpoch: PRICE }));

  console.log(`regtest node at height ${height0}; bond tool ${BOND_EXE}`);
  console.log(`blob ${blob.length} bytes; M = ${M} sentinels per replica, k = ${K} kept, ${W} windows each; q = ${Q}; misbehaviour from epoch ${FROM}\n`);

  // 1–3: upload, cut and choose, fund.
  const reps: Replica[] = [];
  const deals: { path: string; kept: BondSentinel[]; fund: Record<string, unknown> }[] = [];
  for (const [i, o] of offers.entries()) {
    const rep = await client.store(blob, o, Q, "application/octet-stream", M, W);
    const kept = await client.bond(rep, K);
    const path = join(dataDir, `deal-${ROLES[i].slug}.json`);
    writeFileSync(path, JSON.stringify({
      name: ROLES[i].name, provider_url: o.url, sha256: rep.sha256,
      provider_seed: `bsb/provider/${ROLES[i].slug}`, client_seed: "bsb/client/bonded-demo",
      sentinels: kept.map(({ r, s, h, hs }) => ({ r, s, h, hs })),
    }, null, 2));
    const { stdout } = await run(BOND_EXE, ["fund", path], { env: { ...process.env, BSB_RPC: RPC } });
    const fund = JSON.parse(stdout.trim().split("\n").pop()!) as Record<string, unknown>;
    reps.push(rep);
    deals.push({ path, kept, fund });
    console.log(`  ${ROLES[i].name.padEnd(12)} replica ${rep.sha256.slice(0, 12)}…  opened ${M - K}/${M}, kept [${kept.map((s) => s.j).join(", ")}]  bond ${String(fund.fund_txid).slice(0, 16)}… (1 BTC)`);
  }

  // 4: epochs.
  const results: EpochResult[][] = ROLES.map(() => []);
  const mark: Record<string, string> = { "proved-paid": "pass", "failed": "FAIL", "proved-unpaid": "unpaid", "unreachable": "down" };
  console.log(`\nepoch  ${ROLES.map((r) => r.name.padEnd(12)).join(" ")}`.trimEnd());
  for (let e = 1; e <= EPOCHS; e++) {
    if (e === FROM) ROLES.forEach((role, i) => role.misbehave?.(providers[i], reps[i], { url: reps[0].offer.url, sha256: reps[0].sha256 }));
    const row: string[] = [];
    for (const [i, rep] of reps.entries()) { const r = await client.runEpoch(rep, e); results[i].push(r); row.push(mark[r.outcome].padEnd(12)); }
    console.log(`${String(e).padStart(5)}  ${row.join(" ")}${e === FROM ? "  ← misbehaviour starts" : ""}`.trimEnd());
  }

  // 5: enforcement on chain.
  console.log("\nenforcement on regtest (Core decides every answer)");
  const summary = [];
  for (const [i, role] of ROLES.entries()) {
    const failed = results[i].filter((r) => r.outcome !== "proved-paid").length;
    const n = failed > 0 ? K : 1;
    const { stdout } = await run(BOND_EXE, ["enforce", deals[i].path, String(n)], { env: { ...process.env, BSB_RPC: RPC }, maxBuffer: 1 << 24 });
    const res = JSON.parse(stdout.trim().split("\n").pop()!) as {
      outcome: string; bond_to: string; final_txid: string; final_confirmations: number;
      challenges: { i: number; answer: string; challenge_txid: string; challenge_vsize: number; respond_txid?: string; respond_vsize?: number; forfeit_txid?: string }[];
    };
    for (const c of res.challenges) {
      const size = c.respond_vsize ? ` (challenge ${c.challenge_vsize} vB, answer ${c.respond_vsize} vB)` : "";
      console.log(`  ${role.name.padEnd(12)} challenge ${c.i}: ${c.answer}${size}${c.forfeit_txid ? `  → forfeit ${c.forfeit_txid.slice(0, 16)}…` : ""}`);
    }
    const earned = results[i].reduce((a, r) => a + r.paidMsat, 0);
    summary.push({
      role: role.name, failedEpochs: failed, earnedMsat: earned, keptFraction: role.kept,
      sentinelsKept: deals[i].kept.map((s) => s.j), challenged: n,
      pForfeitIfAllChallenged: role.kept === 1 ? 0 : 1 - sentinelSurvival(role.kept, W, K),
      bond: { funded: deals[i].fund.fund_txid, outcome: res.outcome, to: res.bond_to, finalTxid: res.final_txid, confirmations: res.final_confirmations },
      challenges: res.challenges,
    });
  }

  console.log("\nprovider      failed epochs  earned msat  challenged  answered  P(forfeit | k challenges)  bond (1 BTC)");
  for (const s of summary) {
    const answered = s.challenges.filter((c) => c.respond_txid).length;
    console.log(`${s.role.padEnd(13)} ${String(s.failedEpochs).padStart(13)}  ${String(s.earnedMsat).padStart(11)}  ${String(s.challenged).padStart(10)}  ${String(answered).padStart(8)}  ${s.pForfeitIfAllChallenged.toPrecision(4).padStart(24)}  ${s.bond.outcome} → ${s.bond.to}`);
  }
  rc.close();

  const height1 = await nodeHeight();
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({
    generated: new Date().toISOString(),
    note: "Bitcoin is real (Core regtest); Lightning is the in-memory stub. Nonces are seeded. One process plays both parties' on-chain agents with test keys.",
    params: { epochs: EPOCHS, q: Q, misbehaviourFrom: FROM, m: M, k: K, windows: W, bondBtc: 1, delta: 144, blobBytes: blob.length, chunks: reps[0].n },
    regtest: { heightBefore: height0, heightAfter: height1 },
    summary,
  }, null, 2) + "\n");
  console.log(`\nregtest height ${height0} → ${height1}; wrote ${OUT}`);
} finally {
  for (const p of providers) await p.close();
  await relay.close();
  rmSync(dataDir, { recursive: true, force: true });
}
