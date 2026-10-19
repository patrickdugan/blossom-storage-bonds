// Phase 1b end to end on localhost: one relay, four Blossom providers with PDP sidecars, one client.
//
//   node layer1/demo.ts [--epochs 10] [--q 8] [--from 4] [--random] [--out results/layer1.json]
//
// The client uploads one 1 MiB blob, encrypted per provider, then runs the epochs. From epoch --from on,
// three providers misbehave: one zeroes 10% of its chunks, one zeroes 50%, and one deletes its replica
// and answers from the honest provider's copy. All of them keep their leaf hashes, so they can still send
// Merkle paths. Nonces are derived from a fixed seed so the run is reproducible; --random draws them
// fresh. Lightning is the in-memory stub from layer1/lightning.ts.

import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { epochPass } from "../model/storage_bonds.ts";
import { keyFromSeed } from "../model/schnorr.ts";
import { startProvider, type Provider } from "./blossom.ts";
import { StorageClient, KIND_EPOCH_RECEIPT, checkReceipt, type EpochResult, type Offer, type Replica } from "./client.ts";
import { StubNetwork } from "./lightning.ts";
import { RelayClient, startRelay } from "./relay.ts";

const arg = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const EPOCHS = Number(arg("epochs", "10"));
const Q = Number(arg("q", "8"));
const FROM = Number(arg("from", "4"));
const RANDOM = process.argv.includes("--random");
const OUT = arg("out", join(dirname(fileURLToPath(import.meta.url)), "..", "results", "layer1.json"));
const PRICE = 1;          // msat per chunk-epoch: 256 msat per epoch for a 1 MiB blob

/** A deterministic 1 MiB blob, so the replica hashes are the same on every run. */
function demoBlob(bytes = 1 << 20): Buffer {
  const out = Buffer.alloc(bytes);
  for (let o = 0, i = 0; o < bytes; o += 32, i++) createHash("sha256").update(`bsb demo blob ${i}`).digest().copy(out, o);
  return out;
}

/** The first ⌈f·n⌉ indices of a seeded shuffle of 0..n-1. */
function pick(n: number, f: number, seed: string): number[] {
  const order = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = createHash("sha256").update(`${seed}|${i}`).digest().readUInt32LE(0) % (i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order.slice(0, Math.ceil(f * n));
}

interface Role { name: string; kept: number; misbehave?: (p: Provider, rep: Replica, honest: { url: string; sha256: string }) => void }
const ROLES: Role[] = [
  { name: "honest", kept: 1 },
  { name: "deletes 10%", kept: 0.9, misbehave: (p, rep) => p.deleteChunks(rep.sha256, pick(rep.n, 0.1, "lazy")) },
  { name: "deletes 50%", kept: 0.5, misbehave: (p, rep) => p.deleteChunks(rep.sha256, pick(rep.n, 0.5, "half")) },
  { name: "outsources", kept: 0, misbehave: (p, rep, honest) => p.outsource(rep.sha256, honest) },
];

const dataDir = mkdtempSync(join(tmpdir(), "bsb-layer1-"));
const relay = await startRelay();
const ln = new StubNetwork();
const providers: Provider[] = [];
try {
  for (const [i, role] of ROLES.entries()) {
    providers.push(await startProvider({
      dir: join(dataDir, `p${i}`), key: keyFromSeed(`demo provider ${i}`), payee: ln.node(`ln-provider-${i}`),
      priceMsatPerChunkEpoch: PRICE,
    }));
    void role;
  }
  const rc = await RelayClient.connect(relay.url);
  const clientKey = keyFromSeed("demo client");
  const client = new StorageClient({
    key: clientKey, secret: createHash("sha256").update("demo client storage secret").digest(),
    payer: ln.node("ln-client", 1_000_000_000), relay: rc, nonceSeed: RANDOM ? undefined : "phase-1b-demo",
  });

  const blob = demoBlob();
  const offers: Offer[] = providers.map((p) => ({ url: p.url, pubkey: p.pubkey, lightningNodeId: p.config.payee.nodeId, priceMsatPerChunkEpoch: PRICE }));
  const reps: Replica[] = [];
  for (const o of offers) reps.push(await client.store(blob, o, Q));

  console.log(`relay ${relay.url}`);
  console.log(`blob ${blob.length} bytes, ${reps[0].n} chunks of 4 KiB, q = ${Q}, ${PRICE * reps[0].n} msat per epoch, misbehaviour from epoch ${FROM}`);
  console.log(`nonces: ${RANDOM ? "random" : "seeded (pass --random for fresh ones)"}\n`);
  for (const [i, r] of reps.entries()) console.log(`  ${ROLES[i].name.padEnd(12)} ${r.offer.url}  replica ${r.sha256.slice(0, 16)}…  root ${r.root.slice(0, 16)}…`);
  const distinct = new Set(reps.map((r) => r.sha256)).size;
  console.log(`  ${distinct} distinct replicas; the client keeps ${reps.length} × 32-byte roots and no ciphertext\n`);

  const results: EpochResult[][] = ROLES.map(() => []);
  const mark: Record<string, string> = { "proved-paid": "pass", "failed": "FAIL", "proved-unpaid": "unpaid", "unreachable": "down" };
  console.log(`epoch  ${ROLES.map((r) => r.name.padEnd(12)).join(" ")}`.trimEnd());
  for (let e = 1; e <= EPOCHS; e++) {
    if (e === FROM) ROLES.forEach((role, i) => role.misbehave?.(providers[i], reps[i], { url: reps[0].offer.url, sha256: reps[0].sha256 }));
    const row: string[] = [];
    for (const [i, rep] of reps.entries()) {
      const r = await client.runEpoch(rep, e);
      results[i].push(r);
      row.push(mark[r.outcome].padEnd(12));
    }
    console.log(`${String(e).padStart(5)}  ${row.join(" ")}${e === FROM ? "  ← misbehaviour starts" : ""}`.trimEnd());
  }

  console.log("\nprovider      passed before  passed after  P(pass) after = kept^q  earned msat  balance msat");
  const summary = ROLES.map((role, i) => {
    const before = results[i].filter((r) => r.epoch < FROM), after = results[i].filter((r) => r.epoch >= FROM);
    const pass = (rs: EpochResult[]) => rs.filter((r) => r.outcome === "proved-paid").length;
    const earned = results[i].reduce((a, r) => a + r.paidMsat, 0);
    const s = {
      role: role.name, url: reps[i].offer.url, replica: reps[i].sha256, root: reps[i].root,
      passedBefore: `${pass(before)}/${before.length}`, passedAfter: `${pass(after)}/${after.length}`,
      expectedPassAfter: epochPass(role.kept, Q), earnedMsat: earned, balanceMsat: ln.balances.get(reps[i].offer.lightningNodeId) ?? 0,
    };
    console.log(`${role.name.padEnd(13)} ${s.passedBefore.padStart(13)}  ${s.passedAfter.padStart(12)}  ${s.expectedPassAfter.toPrecision(3).padStart(22)}  ${String(earned).padStart(11)}  ${String(s.balanceMsat).padStart(12)}`);
    return s;
  });

  // Anyone can read the receipts back and check them: signature, and for paid ones, preimage against hash.
  const receipts = await rc.query({ kinds: [KIND_EPOCH_RECEIPT], authors: [clientKey.x] });
  const checked = receipts.map((ev) => checkReceipt(ev, ln.node("ln-reader")));
  const good = checked.filter((c) => c.ok).length;
  const paid = checked.filter((c) => c.ok && c.paid).length;
  console.log(`\nrelay holds ${receipts.length} receipts (kind ${KIND_EPOCH_RECEIPT}) from the client; ${good} check, ${paid} carry a matching preimage`);

  const back = await client.retrieve(reps[0]);
  console.log(`retrieve from honest provider: ${back.equals(blob) ? "decrypts to the original blob" : "MISMATCH"}`);
  const fromDropper = await client.retrieve(reps[2]).then(() => "decrypts", (e) => `fails: ${(e as Error).message}`);
  console.log(`retrieve from the 50% deleter: ${fromDropper}`);
  rc.close();

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({
    generated: new Date().toISOString(),
    note: "Lightning is the in-memory stub (layer1/lightning.ts), not a Lightning node. Nonces are seeded unless random is true.",
    params: { epochs: EPOCHS, q: Q, misbehaviourFrom: FROM, random: RANDOM, blobBytes: blob.length, chunks: reps[0].n, msatPerEpoch: PRICE * reps[0].n },
    summary,
    epochs: results.map((rs, i) => ({ role: ROLES[i].name, outcomes: rs.map((r) => ({ epoch: r.epoch, outcome: r.outcome, nonce: r.nonce, receipt: r.receipt?.id })) })),
    receipts: { onRelay: receipts.length, verified: good, paidWithPreimage: paid },
  }, null, 2) + "\n");
  console.log(`\nwrote ${OUT}`);
} finally {
  for (const p of providers) await p.close();
  await relay.close();
  rmSync(dataDir, { recursive: true, force: true });
}
