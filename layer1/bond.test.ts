// Layer 2 support on the Blossom server: cut and choose before a bond, and sentinel answers after one.
// These run without a Bitcoin node; layer1/bonded.ts puts the same answers on regtest.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keyFromSeed, sha256 } from "../model/schnorr.ts";
import { WINDOWS_PER_CHUNK, sentinelIndex } from "../model/storage_bonds.ts";
import { StubNetwork } from "./lightning.ts";
import { startProvider, type Provider } from "./blossom.ts";
import { StorageClient, type Offer, type Replica } from "./client.ts";

const BLOB = Buffer.from(Array.from({ length: 150_000 }, (_, i) => (i * 7 + (i >> 8)) & 0xff));   // 37 chunks
const M = 32, K = 4;

let dir: string;
let ln: StubNetwork;
const started: Provider[] = [];

async function provider(name: string): Promise<{ p: Provider; offer: Offer }> {
  const p = await startProvider({ dir: join(dir, name), key: keyFromSeed(`bond provider ${name}`), payee: ln.node(`ln-${name}`), priceMsatPerChunkEpoch: 1 });
  started.push(p);
  return { p, offer: { url: p.url, pubkey: p.pubkey, lightningNodeId: `ln-${name}`, priceMsatPerChunkEpoch: 1 } };
}
const client = () => new StorageClient({ key: keyFromSeed("bond client"), secret: Buffer.alloc(32, 9), payer: ln.node("ln-client", 1e9) });

async function answer(rep: Replica, r: string): Promise<{ status: number; item?: Buffer }> {
  const res = await fetch(`${rep.offer.url}/sentinel/${rep.sha256}?r=${r}`);
  if (res.status !== 200) return { status: res.status };
  return { status: 200, item: Buffer.from(((await res.json()) as { item: string }).item, "hex") };
}

before(() => { dir = mkdtempSync(join(tmpdir(), "bsb-bond-test-")); ln = new StubNetwork(); });
after(async () => { for (const p of started) await p.close(); rmSync(dir, { recursive: true, force: true }); });

test("cut and choose: an honest pair keeps k sentinels, and each answer hashes to its h", async () => {
  const { offer } = await provider("honest");
  const c = client();
  const rep = await c.store(BLOB, offer, 4, "application/octet-stream", M);
  assert.equal(rep.commitments!.length, M);
  const kept = await c.bond(rep, K);
  assert.equal(kept.length, K);
  for (const s of kept) {
    assert.ok(sha256(Buffer.from(s.r, "hex")).equals(Buffer.from(s.s, "hex")));
    const a = await answer(rep, s.r);
    assert.equal(a.status, 200);
    assert.equal(a.item!.length, 80, "one standard tapscript item");
    assert.ok(sha256(a.item!).equals(Buffer.from(s.h, "hex")), `sentinel ${s.j}`);
  }
});

test("cut and choose: a client that plants M − k + 1 bad sentinels is always caught", async () => {
  const { offer } = await provider("planted");
  const c = client();
  const rep = await c.store(BLOB, offer, 4, "application/octet-stream", M);
  // Pigeonhole: with M − k + 1 bad commitments, at least one lands in the M − k the provider opens.
  rep.commitments = rep.commitments!.map((x, j) => (j <= M - K ? { ...x, h: "00".repeat(32), hs: ["00".repeat(32)] } : x));
  await assert.rejects(c.bond(rep, K), /rejected opened sentinels/);
});

test("cut and choose: the opened set depends on the provider's secret key, not only on public data", async () => {
  const a = await provider("chooser-a"), b = await provider("chooser-b");
  const c = client();
  const ra = await c.store(BLOB, a.offer, 4, "application/octet-stream", M);
  const rb = await c.store(BLOB, b.offer, 4, "application/octet-stream", M);
  const ka = (await c.bond(ra, K)).map((s) => s.j), kb = (await c.bond(rb, K)).map((s) => s.j);
  assert.notDeepEqual(ka, kb, "two providers keep different sentinels (fails with probability 1/C(32,4))");
});

test("sentinel answers: zeroing the chunk that holds a window makes the answer hash to something else", async () => {
  const { p, offer } = await provider("deleter");
  const c = client();
  const rep = await c.store(BLOB, offer, 4, "application/octet-stream", M);
  const [s] = await c.bond(rep, K);
  const before = await answer(rep, s.r);
  assert.ok(sha256(before.item!).equals(Buffer.from(s.h, "hex")));
  p.deleteChunks(rep.sha256, [Math.floor(sentinelIndex(Buffer.from(s.r, "hex"), rep.n) / WINDOWS_PER_CHUNK)]);
  const afterDelete = await answer(rep, s.r);
  assert.equal(afterDelete.status, 200, "the deleter still answers, with zeros");
  assert.ok(!sha256(afterDelete.item!).equals(Buffer.from(s.h, "hex")));
});

test("sentinel answers: an outsourcing provider answers from the wrong ciphertext", async () => {
  const honest = await provider("source"), lazy = await provider("outsourcer");
  const c = client();
  const src = await c.store(BLOB, honest.offer, 4);
  const rep = await c.store(BLOB, lazy.offer, 4, "application/octet-stream", M);
  const kept = await c.bond(rep, K);
  lazy.p.outsource(rep.sha256, { url: src.offer.url, sha256: src.sha256 });
  for (const s of kept) {
    const a = await answer(rep, s.r);
    assert.equal(a.status, 200);
    assert.ok(!sha256(a.item!).equals(Buffer.from(s.h, "hex")), `sentinel ${s.j}`);
  }
});

test("multi-window: the provider checks all m windows in cut and choose, and answers all m after a reveal", async () => {
  const { p, offer } = await provider("multi");
  const c = client();
  const rep = await c.store(BLOB, offer, 4, "application/octet-stream", M, 16);
  const kept = await c.bond(rep, K);
  assert.ok(kept.every((s) => s.hs.length === 16));
  const res = await fetch(`${rep.offer.url}/sentinel/${rep.sha256}?r=${kept[0].r}&m=16`);
  const { items } = (await res.json()) as { items: string[] };
  assert.equal(items.length, 16);
  items.forEach((x, w) => assert.ok(sha256(Buffer.from(x, "hex")).equals(Buffer.from(kept[0].hs[w], "hex")), `window ${w}`));
  // Corrupting one window's commitment in an opened sentinel is caught.
  const rep2 = await c.store(BLOB, offer, 4, "application/octet-stream", M, 16);
  rep2.commitments = rep2.commitments!.map((x, j) => (j <= M - K ? { ...x, hs: x.hs.map((h, w) => (w === 9 ? "00".repeat(32) : h)) } : x));
  await assert.rejects(c.bond(rep2, K), /rejected opened sentinels/);
  void p;
});

test("sentinel endpoint: rejects a malformed r and an unknown blob", async () => {
  const { offer } = await provider("strict");
  const rep = await client().store(BLOB, offer, 4);
  assert.equal((await answer(rep, "zz")).status, 400);
  assert.equal((await answer(rep, "00".repeat(32))).status, 400, "r is 16 bytes, not 32");
  assert.equal((await answer({ ...rep, sha256: "ab".repeat(32) }, "00".repeat(16))).status, 404);
});
