import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keyFromSeed } from "../model/schnorr.ts";
import { epochIndices, verifyEpoch } from "../model/storage_bonds.ts";
import { authHeader, blossomAuth, checkBlossomAuth, signEvent, verifyEvent, now, KIND_BLOSSOM_AUTH } from "./nostr.ts";
import { StubNetwork, preimageMatches } from "./lightning.ts";
import { RelayClient, startRelay, type Relay } from "./relay.ts";
import { startProvider, type PdpAnswer, type Provider } from "./blossom.ts";
import { KIND_EPOCH_RECEIPT, StorageClient, checkReceipt, type Offer } from "./client.ts";

const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const ALICE = keyFromSeed("test client");
const BLOB = Buffer.from(Array.from({ length: 150_000 }, (_, i) => (i * 7 + (i >> 8)) & 0xff));   // 37 chunks
const PRICE = 2;

let dir: string;
let relay: Relay;
let rc: RelayClient;
let ln: StubNetwork;
const started: Provider[] = [];

async function provider(name: string, opts: { price?: number; uploaders?: string[] } = {}): Promise<{ p: Provider; offer: Offer }> {
  const p = await startProvider({
    dir: join(dir, name), key: keyFromSeed(`test provider ${name}`), payee: ln.node(`ln-${name}`),
    priceMsatPerChunkEpoch: opts.price ?? PRICE, uploaders: opts.uploaders,
  });
  started.push(p);
  return { p, offer: { url: p.url, pubkey: p.pubkey, lightningNodeId: `ln-${name}`, priceMsatPerChunkEpoch: PRICE } };
}

const client = (seed?: string) => new StorageClient({
  key: ALICE, secret: Buffer.alloc(32, 7), payer: ln.node("ln-alice", 1e9), relay: rc, nonceSeed: seed,
});

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "bsb-test-"));
  relay = await startRelay();
  rc = await RelayClient.connect(relay.url);
  ln = new StubNetwork();
});
after(async () => {
  rc.close();
  for (const p of started) await p.close();
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
});

// ───────────────────────────── Nostr and BUD-11 ─────────────────────────────

test("NIP-01: a signed event verifies; any edit to it does not", () => {
  const e = signEvent(ALICE, { created_at: now(), kind: 1, tags: [["t", "x"]], content: "hello \"quoted\" ✓" });
  assert.ok(verifyEvent(e));
  assert.ok(!verifyEvent({ ...e, content: "hellp" }));
  assert.ok(!verifyEvent({ ...e, tags: [] }));
  assert.ok(!verifyEvent({ ...e, sig: e.sig.replace(/^./, (c) => (c === "0" ? "1" : "0")) }));
  assert.ok(!verifyEvent({ ...e, pubkey: keyFromSeed("other").x }));
});

test("BUD-11: every server-side check on the kind-24242 token", () => {
  const x = "ab".repeat(32);
  const ok = blossomAuth(ALICE, "upload", { x: [x] });
  const want = { verb: "upload" as const, x, xRequired: true };
  assert.equal(checkBlossomAuth(authHeader(ok), want).ok, true);
  // standard base64, as older clients send
  assert.equal(checkBlossomAuth("Nostr " + Buffer.from(JSON.stringify(ok)).toString("base64"), want).ok, true);
  const why = (h: string | undefined, w = want) => { const r = checkBlossomAuth(h, w); return r.ok ? "ok" : r.why; };
  assert.match(why(undefined), /missing/);
  assert.match(why("Bearer abc"), /scheme/);
  assert.match(why(authHeader({ ...ok, content: "edited" })), /signature/);
  const t = now();
  const mk = (tags: string[][], created_at = t - 1, kind = KIND_BLOSSOM_AUTH) => authHeader(signEvent(ALICE, { created_at, kind, tags, content: "x" }));
  assert.match(why(mk([["t", "upload"], ["x", x], ["expiration", String(t + 60)]], t - 1, 1)), /kind/);
  assert.match(why(mk([["t", "upload"], ["x", x], ["expiration", String(t + 60)]], t + 120)), /future/);
  assert.match(why(mk([["t", "upload"], ["x", x]])), /expiration/);
  assert.match(why(mk([["t", "upload"], ["x", x], ["expiration", String(t - 5)]])), /expired/);
  assert.match(why(mk([["t", "get"], ["x", x], ["expiration", String(t + 60)]])), /t tag/);
  assert.match(why(mk([["t", "upload"], ["x", "cd".repeat(32)], ["expiration", String(t + 60)]])), /x tag/);
  assert.match(why(mk([["t", "upload"], ["expiration", String(t + 60)]])), /x tag/);
  const scoped = mk([["t", "upload"], ["x", x], ["expiration", String(t + 60)], ["server", "cdn.example.com"]]);
  assert.match(why(scoped, { ...want, domain: "127.0.0.1" } as typeof want), /another server/);
  assert.equal(why(scoped, { ...want, domain: "cdn.example.com" } as typeof want), "ok");
});

// ───────────────────────────── Lightning stub ─────────────────────────────

test("Lightning stub: pays once, reveals the preimage, refuses forged, over-max and repeated payments", async () => {
  const net = new StubNetwork();
  const bob = net.node("bob"), carol = net.node("carol", 1000);
  const inv = await bob.createInvoice(300, "epoch");
  assert.equal(carol.decode(inv.paymentRequest).amountMsat, 300);
  await assert.rejects(carol.pay(inv.paymentRequest, 299), /over max/);
  // same hash, smaller amount: the ledger only honours its own copy of the invoice
  const forged = "lnstub1" + Buffer.from(JSON.stringify({ h: inv.paymentHash, a: 1, p: "bob", m: "", x: inv.expiresAt })).toString("base64url");
  await assert.rejects(carol.pay(forged, 1000), /unknown invoice/);
  const { preimage } = await carol.pay(inv.paymentRequest, 300);
  assert.ok(preimageMatches(inv.paymentHash, preimage));
  assert.ok(!preimageMatches(inv.paymentHash, "00".repeat(32)));
  await assert.rejects(carol.pay(inv.paymentRequest, 300), /already paid/);
  assert.equal(net.balances.get("carol"), 700);
  assert.equal(net.balances.get("bob"), 300);
  await assert.rejects(carol.pay((await bob.createInvoice(800, "")).paymentRequest, 800), /insufficient/);
});

// ───────────────────────────── relay ─────────────────────────────

test("relay: stores and serves signed events, filters by kind/author/tag, rejects bad signatures, takes 64 KiB+ frames", async () => {
  const e1 = signEvent(ALICE, { created_at: now(), kind: 7001, tags: [["p", "aa".repeat(32)]], content: "one" });
  const e2 = signEvent(ALICE, { created_at: now(), kind: 7002, tags: [], content: "two" });
  assert.deepEqual(await rc.publish(e1), { accepted: true, message: "" });
  assert.equal((await rc.publish(e1)).message.startsWith("duplicate"), true);
  assert.equal((await rc.publish(e2)).accepted, true);
  assert.equal((await rc.publish({ ...e2, id: e1.id })).accepted, false);
  assert.deepEqual((await rc.query({ kinds: [7001] })).map((e) => e.id), [e1.id]);
  assert.deepEqual((await rc.query({ "#p": ["aa".repeat(32)] })).map((e) => e.id), [e1.id]);
  assert.equal((await rc.query({ authors: [keyFromSeed("nobody").x], kinds: [7001, 7002] })).length, 0);
  const big = signEvent(ALICE, { created_at: now(), kind: 7003, tags: [], content: "z".repeat(100_000) });
  assert.equal((await rc.publish(big)).accepted, true);
  assert.equal((await rc.query({ kinds: [7003] }))[0].content.length, 100_000);
});

// ───────────────────────────── Blossom server ─────────────────────────────

test("Blossom: BUD-02 upload needs a matching token; BUD-01 GET/HEAD/Range/extension; CORS", async () => {
  const { p } = await provider("http");
  const body = randomBytes(10_000), x = sha(body);
  const put = (headers: Record<string, string>, b: Buffer = body) => fetch(`${p.url}/upload`, { method: "PUT", headers, body: b });
  const tok = (xs: string[]) => authHeader(blossomAuth(ALICE, "upload", { x: xs }));
  assert.equal((await put({ "X-SHA-256": x })).status, 401);
  assert.equal((await put({ "X-SHA-256": x, Authorization: tok(["cd".repeat(32)]) })).status, 401);
  assert.equal((await put({ Authorization: tok([x]) })).status, 400);
  const lie = randomBytes(10_000);
  assert.equal((await put({ "X-SHA-256": x, Authorization: tok([x]) }, lie)).status, 409);
  const r1 = await put({ "X-SHA-256": x, Authorization: tok([x]), "Content-Type": "text/plain" });
  assert.equal(r1.status, 201);
  assert.equal(r1.headers.get("access-control-allow-origin"), "*");
  const d = await r1.json();
  assert.equal(d.sha256, x); assert.equal(d.size, 10_000); assert.equal(d.type, "text/plain");
  assert.equal(d.url, `${p.url}/${x}.txt`); assert.equal(d.bsb.n, 3);
  assert.equal((await put({ "X-SHA-256": x, Authorization: tok([x]) })).status, 200);

  const g = await fetch(`${p.url}/${x}`);
  assert.equal(g.status, 200); assert.equal(g.headers.get("content-type"), "text/plain");
  assert.ok(Buffer.from(await g.arrayBuffer()).equals(body));
  assert.ok(Buffer.from(await (await fetch(`${p.url}/${x}.pdf`)).arrayBuffer()).equals(body));
  const h = await fetch(`${p.url}/${x}`, { method: "HEAD" });
  assert.equal(h.headers.get("content-length"), "10000"); assert.equal((await h.arrayBuffer()).byteLength, 0);
  const rg = await fetch(`${p.url}/${x}`, { headers: { Range: "bytes=4096-8191" } });
  assert.equal(rg.status, 206); assert.equal(rg.headers.get("content-range"), "bytes 4096-8191/10000");
  assert.ok(Buffer.from(await rg.arrayBuffer()).equals(body.subarray(4096, 8192)));
  assert.equal((await fetch(`${p.url}/${x}`, { headers: { Range: "bytes=20000-" } })).status, 416);
  assert.equal((await fetch(`${p.url}/${"0".repeat(64)}`)).status, 404);
  const pre = await fetch(`${p.url}/upload`, { method: "OPTIONS" });
  assert.equal(pre.status, 204); assert.match(pre.headers.get("access-control-allow-methods") ?? "", /PUT/);
});

test("Blossom: an upload allowlist refuses other pubkeys with 403", async () => {
  const { p } = await provider("allow", { uploaders: [keyFromSeed("someone else").x] });
  const body = randomBytes(100), x = sha(body);
  const r = await fetch(`${p.url}/upload`, { method: "PUT", headers: { "X-SHA-256": x, Authorization: authHeader(blossomAuth(ALICE, "upload", { x: [x] })) }, body });
  assert.equal(r.status, 403);
});

test("PDP sidecar: validates its inputs; an honest answer opens against the client's root", async () => {
  const { p, offer } = await provider("pdp");
  const rep = await client().store(BLOB, offer, 5);
  assert.equal(rep.n, 37);
  const bad = (qs: string) => fetch(`${p.url}/pdp/${rep.sha256}?${qs}`).then((r) => r.status);
  const nonce = "11".repeat(32);
  assert.equal(await bad(`nonce=abc&q=5`), 400);
  assert.equal(await bad(`nonce=${nonce}&q=0`), 400);
  assert.equal(await bad(`nonce=${nonce}&q=257`), 400);
  assert.equal(await bad(`nonce=${nonce}&q=5&epoch=-1`), 400);
  assert.equal((await fetch(`${p.url}/pdp/${"0".repeat(64)}?nonce=${nonce}&q=5`)).status, 404);
  const a = (await (await fetch(`${p.url}/pdp/${rep.sha256}?nonce=${nonce}&q=5`)).json()) as PdpAnswer;
  assert.deepEqual(a.indices, epochIndices(Buffer.from(nonce, "hex"), 37, 5));
  const proof = { chunks: a.chunks.map((c) => Buffer.from(c, "base64")), paths: a.paths.map((pp) => pp.map((h) => Buffer.from(h, "hex"))) };
  assert.ok(verifyEpoch(Buffer.from(rep.root, "hex"), rep.n, Buffer.from(nonce, "hex"), 5, proof));
  assert.ok(!verifyEpoch(Buffer.from(rep.root, "hex"), rep.n, Buffer.from("22".repeat(32), "hex"), 5, proof));
});

// ───────────────────────────── client, end to end ─────────────────────────────

test("end to end: an honest provider passes and is paid every epoch; receipts land on the relay and check", async () => {
  const { offer } = await provider("honest");
  const c = client();
  const rep = await c.store(BLOB, offer, 6);
  for (let e = 1; e <= 10; e++) {
    const r = await c.runEpoch(rep, e);
    assert.equal(r.outcome, "proved-paid", `epoch ${e}: ${r.detail}`);
    assert.equal(r.paidMsat, PRICE * rep.n);
    assert.equal(r.published, true);
  }
  assert.equal(ln.balances.get("ln-honest"), 10 * PRICE * rep.n);
  const rs = await rc.query({ kinds: [KIND_EPOCH_RECEIPT], "#x": [rep.sha256] });
  assert.equal(rs.length, 10);
  assert.ok(rs.every((ev) => { const k = checkReceipt(ev, ln.node("reader")); return k.ok && k.paid; }));
  const forged = signEvent(ALICE, { ...rs[0], tags: rs[0].tags.map((t) => (t[0] === "preimage" ? ["preimage", "00".repeat(32)] : t)) });
  assert.equal(checkReceipt(forged, ln.node("reader")).ok, false);
  assert.ok((await c.retrieve(rep)).equals(BLOB));
});

test("end to end: after deleting chunks, an epoch passes exactly when every selected chunk was kept", async () => {
  const { p, offer } = await provider("deleter");
  const c = client("deleter-seed");
  const rep = await c.store(BLOB, offer, 4);
  const deleted = new Set([0, 3, 5, 8, 13, 21, 22, 30, 34, 36, 1, 2, 4, 6, 7, 9, 10, 11]);   // 18 of 37
  for (let e = 1; e <= 3; e++) assert.equal((await c.runEpoch(rep, e)).outcome, "proved-paid");
  p.deleteChunks(rep.sha256, [...deleted]);
  let fails = 0;
  const before = ln.balances.get("ln-deleter")!;
  for (let e = 4; e <= 30; e++) {
    const r = await c.runEpoch(rep, e);
    const kept = epochIndices(Buffer.from(r.nonce, "hex"), rep.n, 4).every((i) => !deleted.has(i));
    assert.equal(r.outcome, kept ? "proved-paid" : "failed", `epoch ${e}`);
    if (!kept) fails++;
  }
  assert.ok(fails > 0, "with 18 of 37 chunks gone, some of 27 epochs must fail");
  assert.equal(ln.balances.get("ln-deleter")! - before, (27 - fails) * PRICE * rep.n, "failed epochs are never paid");
  await assert.rejects(c.retrieve(rep), /other bytes/);
});

test("end to end: answering from another provider's replica fails every epoch (per-replica encryption)", async () => {
  const a = await provider("orig"), b = await provider("copycat");
  const c = client();
  const ra = await c.store(BLOB, a.offer, 3), rb = await c.store(BLOB, b.offer, 3);
  assert.notEqual(ra.sha256, rb.sha256);
  assert.equal((await c.runEpoch(rb, 1)).outcome, "proved-paid");
  b.p.outsource(rb.sha256, { url: a.p.url, sha256: ra.sha256 });
  for (let e = 2; e <= 6; e++) assert.equal((await c.runEpoch(rb, e)).outcome, "failed");
  assert.equal((await c.runEpoch(ra, 7)).outcome, "proved-paid");
});

test("end to end: a valid proof with an invoice off the deal is recorded but not paid", async () => {
  const { offer } = await provider("greedy", { price: PRICE * 3 });
  const c = client();
  const rep = await c.store(BLOB, offer, 3);
  const r = await c.runEpoch(rep, 1);
  assert.equal(r.outcome, "proved-unpaid");
  assert.match(r.detail, /deal says/);
  assert.equal(ln.balances.get("ln-greedy"), 0);
});

test("end to end: an unreachable provider is recorded as such", async () => {
  const { p, offer } = await provider("gone");
  const c = client();
  const rep = await c.store(BLOB, offer, 3);
  await p.close();
  const r = await c.runEpoch(rep, 1);
  assert.equal(r.outcome, "unreachable");
  assert.equal(r.published, true);
});
