// Phase 7: what a signet pilot changes, tested without a signet node. The network profile and its
// refusals (net.ts), fresh party keys, fees and block waits against a stubbed bitcoind, the signet
// header and address parameters, offers and deal events (deals.ts), and several relays as one
// (relay.ts RelayPool), including a relay that goes down and comes back.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { keyFromSeed } from "../model/schnorr.ts";
import { KIND_DEAL, KIND_OFFER, commitmentsRoot, dealEvent, findOffers, offerEvent, parseDeal, parseOffer, type OfferTerms } from "./deals.ts";
import { HeaderChain, SIGNET, paramsFor } from "./headerchain.ts";
import { advance, assertFreshSeed, confirm, currentNet, feeRate, partySeed, rpcAuth, storageSecret, untilHeight, useNetwork } from "./net.ts";
import { signEvent, now } from "./nostr.ts";
import { HRP, taprootAddress } from "./onchain.ts";
import { RelayClient, RelayPool, startRelay } from "./relay.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const regtest = currentNet({});
const signet = currentNet({ BSB_NETWORK: "signet" });

// ── the network profile ──

test("regtest is the default and keeps every phase 1-6 value; signet waits, wants depth 3, and tb/lntbs", () => {
  assert.deepEqual([regtest.name, regtest.confs, regtest.canMine, regtest.hrp, regtest.lnHrp], ["regtest", 1, true, "bcrt", "bcrt"]);
  assert.deepEqual([signet.name, signet.confs, signet.canMine, signet.hrp, signet.lnHrp], ["signet", 3, false, "tb", "tbs"]);
  assert.equal(currentNet({ BSB_NETWORK: "signet", BSB_CONFS: "6" }).confs, 6);
  for (const bad of ["mainnet", "main", "bitcoin", "testnet"]) assert.throws(() => currentNet({ BSB_NETWORK: bad }), /never mainnet/);
  assert.throws(() => currentNet({ BSB_NETWORK: "signet", BSB_CONFS: "0" }), /at least 1/);
  // useNetwork writes what it read back into the environment, so bsb-bond and child processes agree.
  const env: NodeJS.ProcessEnv = { BSB_RPC_USER: "u", BSB_RPC_PASS: "pw" };
  const n = useNetwork(["node", "x", "--network", "signet", "--confs", "4"], env);
  assert.deepEqual([n.name, n.confs, env.BSB_NETWORK, env.BSB_CONFS, env.BSB_RPC], ["signet", 4, "signet", "4", "http://127.0.0.1:38332"]);
  const r: NodeJS.ProcessEnv = {};
  useNetwork(["node", "x"], r);
  assert.deepEqual([r.BSB_NETWORK, r.BSB_RPC], ["regtest", "http://127.0.0.1:18543"]);
});

test("RPC login: the fixed test login only on regtest; off regtest a cookie or an explicit login, never the regtest password", () => {
  assert.equal(rpcAuth({}), "bsb:bsb-regtest-only");
  assert.throws(() => rpcAuth({ BSB_NETWORK: "signet" }), /BSB_RPC_COOKIE/);
  assert.throws(() => rpcAuth({ BSB_NETWORK: "signet", BSB_RPC_USER: "bsb", BSB_RPC_PASS: "bsb-regtest-only" }), /fixed regtest RPC password/);
  assert.throws(() => useNetwork(["node", "x", "--network", "signet"], {}), /BSB_RPC_COOKIE/);
  const cookie = join(mkdtempSync(join(tmpdir(), "bsb-cookie-")), ".cookie");
  writeFileSync(cookie, "__cookie__:5f1a\n");
  assert.equal(rpcAuth({ BSB_NETWORK: "signet", BSB_RPC_COOKIE: cookie }), "__cookie__:5f1a");
});

test("keys: fixed labels on regtest; off regtest fresh per party and run, kept for restarts, labels refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "bsb-seed-"));
  assert.equal(partySeed(regtest, dir, "bsb/provider/honest"), "bsb/provider/honest");
  const s1 = partySeed(signet, join(dir, "a"), "bsb/provider/honest");
  assert.match(s1, /^[0-9a-f]{64}$/);
  assert.equal(partySeed(signet, join(dir, "a"), "ignored"), s1, "a restarted party keeps its seed");
  assert.equal(readFileSync(join(dir, "a", "party.seed"), "utf8").trim(), s1);
  assert.notEqual(partySeed(signet, join(dir, "b"), "bsb/provider/honest"), s1, "another party or run gets another seed");
  for (const fixed of ["bsb/provider/honest", "bsb/client/full-stack", "bsb/watchtower", "01".repeat(32), "00".repeat(32)]) {
    assert.throws(() => assertFreshSeed(signet, fixed));
    assert.throws(() => partySeed(signet, join(dir, "c"), "x", fixed));
    assert.doesNotThrow(() => assertFreshSeed(regtest, fixed));
  }
  writeFileSync(join(dir, "a", "party.seed"), "bsb/provider/honest\n");
  assert.throws(() => partySeed(signet, join(dir, "a"), "x"), /fresh random/, "a planted fixed seed file is refused too");
  // The storage secret: the phase 4 value on regtest, from the fresh seed elsewhere.
  assert.deepEqual(storageSecret(regtest, "bsb/client/full-stack", "full-stack client storage secret"), createHash("sha256").update("full-stack client storage secret").digest());
  assert.notDeepEqual(storageSecret(signet, s1, "full-stack client storage secret"), storageSecret(regtest, s1, "full-stack client storage secret"));
});

/** A stub bitcoind: answers from `handler`, records every call. */
function stubRpc(handler: (method: string, params: any[]) => unknown) {
  const calls: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
    const { method, params } = JSON.parse(String(init?.body));
    calls.push(method);
    try { return new Response(JSON.stringify({ result: handler(method, params), error: null })); }
    catch (e) { return new Response(JSON.stringify({ result: null, error: { message: (e as Error).message } })); }
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = real; } };
}

test("fees: fixed on regtest; on signet estimatesmartfee, clamped to the cap (Core issue 35507), with a fallback", async () => {
  const saved = { ...process.env };
  try {
    process.env.BSB_NETWORK = "signet"; process.env.BSB_RPC_USER = "u"; process.env.BSB_RPC_PASS = "pw";
    delete process.env.BSB_FEE_RATE; delete process.env.BSB_MAX_FEE_RATE;
    assert.equal(await feeRate(regtest, 5), 5);
    let est: unknown = { feerate: 0.00012 };     // 12 sat/vB
    const s = stubRpc(() => { if (est instanceof Error) throw est; return est; });
    try {
      est = { feerate: 0.00003 }; assert.equal(await feeRate(signet, 5), 3);
      est = { feerate: 0.19 }; assert.equal(await feeRate(signet, 5), 10, "19,000 sat/vB is clamped to the default cap");
      est = { errors: ["Insufficient data or no feerate found"], blocks: 0 }; assert.equal(await feeRate(signet, 5), 2, "no estimate: the fallback");
      est = new Error("boom"); assert.equal(await feeRate(signet, 5), 2);
      process.env.BSB_FEE_RATE = "1"; assert.equal(await feeRate(signet, 5), 1, "BSB_FEE_RATE pins it");
    } finally { s.restore(); }
  } finally { process.env = saved; }
});

test("blocks: regtest mines; signet never calls generatetoaddress and waits for the chain instead", async () => {
  const saved = { ...process.env };
  try {
    process.env.BSB_NETWORK = "signet"; process.env.BSB_RPC_USER = "u"; process.env.BSB_RPC_PASS = "pw";
    let height = 100, confs = 0;
    const s = stubRpc((m) => {
      if (m === "getblockcount") { height++; return height; }
      if (m === "getrawtransaction") { confs++; return { confirmations: confs }; }
      throw new Error(`unexpected ${m}`);
    });
    const fast = { ...signet, pollMs: 1 };
    try {
      await advance(fast, 3, "tb1-not-used");
      assert.ok(height >= 104);
      assert.ok((await untilHeight(fast, height + 5, "tb1-not-used")) >= height - 1);
      confs = 0;
      await confirm(fast, "00".repeat(32), "tb1-not-used");
      assert.ok(confs >= 3);
      assert.ok(!s.calls.includes("generatetoaddress"));
    } finally { s.restore(); }
    const m = stubRpc((method, params) => { if (method === "generatetoaddress") return Array(params[0]).fill("h"); return 7; });
    try {
      process.env.BSB_NETWORK = "regtest";
      await advance(regtest, 2, "bcrt1x");
      await confirm(regtest, "00".repeat(32), "bcrt1x");
      assert.deepEqual(m.calls, ["generatetoaddress", "generatetoaddress"], "regtest: n blocks, then one block per confirmation, as before");
    } finally { m.restore(); }
  } finally { process.env = saved; }
});

// ── chain parameters ──

test("signet: the genesis header hashes to Core's signet genesis and passes its proof of work; tb addresses", () => {
  const h = Buffer.alloc(80);
  h.writeInt32LE(1, 0);
  Buffer.from("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", "hex").reverse().copy(h, 36);
  h.writeUInt32LE(1598918400, 68);
  h.writeUInt32LE(0x1e0377ae, 72);
  h.writeUInt32LE(52613770, 76);
  const c = new HeaderChain(SIGNET);
  c.ingest(0, h);
  assert.equal(c.height, 0);
  assert.equal(c.hashAt(0), SIGNET.genesis);
  assert.equal(paramsFor("signet"), SIGNET);
  const bad = Buffer.from(h); bad.writeUInt32LE(52613771, 76);
  assert.throws(() => new HeaderChain(SIGNET).ingest(0, bad));
  // BIP350's testnet vector: signet shares the tb prefix.
  assert.equal(HRP.signet, "tb");
  assert.equal(taprootAddress("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", "signet"), "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c");
});

// ── offers and deals ──

const pKey = keyFromSeed("test provider"), cKey = keyFromSeed("test client");
const terms = (network: string): OfferTerms => ({
  network, blossom: "https://p.example/", price_msat_per_chunk_epoch: 2000,
  bond: { x: "11".repeat(32), max_sats: 500_000, delta: 144, min_term_blocks: 300 },
  pay: { kind: "ln", payee: "02" + "22".repeat(32), ln_uri: "02" + "22".repeat(32) + "@p.example:9735" },
  zk: { epoch_blocks: 144, q: 16, price_msat: 512_000, hash: "blake", mode: 1 }, failure_domain: "eu-west, own hardware",
});

test("offer: an addressable event per network, checked on read", () => {
  const ev = offerEvent(pKey, terms("signet"));
  assert.equal(ev.kind, KIND_OFFER);
  assert.ok(KIND_OFFER >= 30000 && KIND_OFFER < 40000, "addressable, so a newer offer replaces it");
  const o = parseOffer(ev, "signet");
  assert.ok(!(o instanceof Error));
  assert.deepEqual(o.offer, { url: "https://p.example", pubkey: pKey.x, lightningNodeId: terms("signet").pay.payee, priceMsatPerChunkEpoch: 2000 });
  assert.match(String(parseOffer(ev, "regtest")), /not for regtest/);
  assert.match(String(parseOffer({ ...ev, content: ev.content.replace("2000", "1") }, "signet")), /not a signed offer/);
  const forged = signEvent(pKey, { created_at: now(), kind: KIND_OFFER, tags: [["d", "bsb-offer:signet"], ["network", "signet"]], content: JSON.stringify({ ...terms("signet"), network: "regtest" }) });
  assert.match(String(parseOffer(forged, "signet")), /another network/);
});

test("deal events: stage and network tags; the commitments root binds every commitment and their order", () => {
  const ev = dealEvent(cKey, "signet", "propose", { a: 1 }, [["p", pKey.x]]);
  assert.equal(ev.kind, KIND_DEAL);
  assert.deepEqual(parseDeal(ev, "signet"), { stage: "propose", content: { a: 1 } });
  assert.equal(parseDeal(ev, "regtest"), undefined);
  const cs = [{ s: "aa".repeat(32), h: "bb".repeat(32), hs: ["bb".repeat(32), "cc".repeat(32)] }, { s: "dd".repeat(32), h: "ee".repeat(32) }];
  const r = commitmentsRoot(cs);
  assert.match(r, /^[0-9a-f]{64}$/);
  assert.notEqual(commitmentsRoot([cs[1], cs[0]]), r);
  assert.notEqual(commitmentsRoot([{ ...cs[0], hs: ["bb".repeat(32)] }, cs[1]]), r);
});

// ── relays ──

test("the bundled relay keeps only the newest offer per provider and network (NIP-01 addressable)", async () => {
  const relay = await startRelay();
  const rc = await RelayClient.connect(relay.url);
  try {
    const a = offerEvent(pKey, terms("signet"));
    const older = signEvent(pKey, { created_at: a.created_at - 10, kind: KIND_OFFER, tags: a.tags, content: a.content });
    const b = signEvent(pKey, { created_at: a.created_at + 10, kind: KIND_OFFER, tags: a.tags, content: a.content.replace("2000", "3000") });
    const other = offerEvent(pKey, terms("regtest"));
    for (const e of [a, older, b, other]) assert.equal((await rc.publish(e)).accepted, true);
    const got = await rc.query({ kinds: [KIND_OFFER], authors: [pKey.x] });
    assert.deepEqual(got.map((e) => e.id).sort(), [b.id, other.id].sort());
  } finally { rc.close(); await relay.close(); }
});

test("RelayPool: several relays as one; a dead URL is tolerated, duplicates dropped, and a relay that comes back is resubscribed", async () => {
  const r1 = await startRelay(), r2 = await startRelay();
  const port2 = Number(new URL(r2.url).port);
  const dead = "ws://127.0.0.1:1";
  const logs: any[] = [];
  const pool = await RelayPool.connect([r1.url, r2.url, dead], (e) => logs.push(e));
  let r2b: Awaited<ReturnType<typeof startRelay>> | undefined;
  try {
    assert.deepEqual(pool.connected().sort(), [r1.url, r2.url].sort());
    assert.ok(logs.some((l) => l.event === "relay-down" && l.url === dead));
    const seen: string[] = [];
    const sub = pool.subscribe([{ kinds: [KIND_DEAL] }], (e) => seen.push(e.id));
    const e1 = dealEvent(cKey, "signet", "propose", { n: 1 }, []);
    const pub = await pool.publish(e1);
    assert.equal(pub.accepted, true);
    assert.equal(pub.relays.length, 2);
    await sleep(100);
    assert.deepEqual(seen, [e1.id], "on both relays, delivered once");
    assert.equal((await pool.query({ ids: [e1.id] })).length, 1);
    // r2 goes away: publishing still works through r1.
    await r2.close();
    await sleep(200);
    const e2 = dealEvent(cKey, "signet", "propose", { n: 2 }, []);
    assert.equal((await pool.publish(e2)).accepted, true);
    // r2 comes back on its port, empty: the pool reopens it and sends the subscription again.
    r2b = await startRelay(port2);
    for (let i = 0; i < 60 && !pool.connected().includes(r2.url); i++) await sleep(100);
    assert.ok(pool.connected().includes(r2.url), "reconnected");
    const direct = await RelayClient.connect(r2.url);
    const e3 = dealEvent(cKey, "signet", "seal", { n: 3 }, []);
    await direct.publish(e3);           // published to r2 only, by someone else
    direct.close();
    await sleep(200);
    assert.deepEqual(seen, [e1.id, e2.id, e3.id]);
    sub.close();
    // Offers through the pool: the newest per author.
    await pool.publish(offerEvent(pKey, terms("signet")));
    const offers = await findOffers(pool, "signet", [pKey.x], 5_000);
    assert.equal(offers.get(pKey.x)?.terms.blossom, "https://p.example/");
    await assert.rejects(findOffers(pool, "signet", [cKey.x], 300), /no signet offer/);
  } finally { pool.close(); await r1.close(); await r2b?.close(); }
});

test("relay probe: against the bundled relay every kind is kept and so is a 100 kB event", async () => {
  const { probeRelay } = await import("./relay-probe.ts");
  const relay = await startRelay();
  try {
    const r = await probeRelay(relay.url);
    assert.equal(r.connected, true);
    assert.deepEqual(r.kinds.map((k) => k.readBack), r.kinds.map(() => true));
    assert.equal(r.largestKept, 100_000);
    assert.equal((await probeRelay("ws://127.0.0.1:1")).connected, false);
  } finally { await relay.close(); }
});
