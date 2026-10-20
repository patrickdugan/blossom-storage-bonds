// The epoch challenge and answer over NIP-44 encrypted Nostr events, through the bundled relay. No
// Bitcoin node needed (payment is the stub here; layer1/market.ts runs the same path with channels).

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keyFromSeed } from "../model/schnorr.ts";
import { startProvider, type Provider } from "./blossom.ts";
import { decodeChannelInvoice } from "./channel.ts";
import { StorageClient } from "./client.ts";
import { StubNetwork } from "./lightning.ts";
import { KIND_PDP_ANSWER, KIND_PDP_CHALLENGE, nostrTransport, servePdpOverNostr } from "./nostr-pdp.ts";
import { RelayClient, startRelay, type Relay } from "./relay.ts";

const BLOB = Buffer.from(Array.from({ length: 150_000 }, (_, i) => (i * 7 + (i >> 8)) & 0xff));
let dir: string, relay: Relay, ln: StubNetwork, p: Provider;
let rcClient: RelayClient, rcProvider: RelayClient, spy: RelayClient;
const seen: { kind: number; content: string; tags: string[][] }[] = [];

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "bsb-nostr-pdp-"));
  relay = await startRelay();
  ln = new StubNetwork();
  const pk = keyFromSeed("nostr pdp provider");
  p = await startProvider({ dir, key: pk, payee: ln.node("ln-p"), priceMsatPerChunkEpoch: 1 });
  rcProvider = await RelayClient.connect(relay.url);
  servePdpOverNostr(rcProvider, pk, p.pdpAnswer, undefined, p.stash);
  rcClient = await RelayClient.connect(relay.url);
  spy = await RelayClient.connect(relay.url);
  spy.subscribe([{ kinds: [KIND_PDP_CHALLENGE, KIND_PDP_ANSWER] }], (e) => seen.push(e));
});
after(async () => { rcClient.close(); rcProvider.close(); spy.close(); await p.close(); await relay.close(); rmSync(dir, { recursive: true, force: true }); });

test("NIP-44 PDP: an epoch proves and pays over the relay, and the relay sees only ciphertext", async () => {
  const ck = keyFromSeed("nostr pdp client");
  const c = new StorageClient({ key: ck, secret: Buffer.alloc(32, 3), payer: ln.node("ln-c", 1e9), transport: nostrTransport(rcClient, ck) });
  const rep = await c.store(BLOB, { url: p.url, pubkey: p.pubkey, lightningNodeId: "ln-p", priceMsatPerChunkEpoch: 1 }, 4);
  const r = await c.runEpoch(rep, 1);
  assert.equal(r.outcome, "proved-paid", r.detail);
  await new Promise((ok) => setTimeout(ok, 50));
  const ch = seen.find((e) => e.kind === KIND_PDP_CHALLENGE)!, an = seen.find((e) => e.kind === KIND_PDP_ANSWER)!;
  assert.ok(ch && an, "a third party on the relay saw both events");
  assert.ok(!ch.content.includes(r.nonce) && !Buffer.from(ch.content, "base64").toString("hex").includes(r.nonce), "the nonce is not in the clear");
  assert.ok(!an.content.includes(rep.sha256), "the answer is not in the clear");
  assert.deepEqual(ch.tags, [["p", p.pubkey]]);
});

test("NIP-44 PDP: a q = 64 answer (over 256 kB) goes by encrypted reference and still proves", async () => {
  const ck = keyFromSeed("nostr pdp client 3");
  const c = new StorageClient({ key: ck, secret: Buffer.alloc(32, 5), payer: ln.node("ln-c3", 1e9), transport: nostrTransport(rcClient, ck) });
  const rep = await c.store(BLOB, { url: p.url, pubkey: p.pubkey, lightningNodeId: "ln-p", priceMsatPerChunkEpoch: 1 }, 64);
  const r = await c.runEpoch(rep, 1);
  assert.equal(r.outcome, "proved-paid", r.detail);
});

test("NIP-44 PDP: a provider that deleted its blob fails the epoch over the same path", async () => {
  const ck = keyFromSeed("nostr pdp client 2");
  const c = new StorageClient({ key: ck, secret: Buffer.alloc(32, 4), payer: ln.node("ln-c2", 1e9), transport: nostrTransport(rcClient, ck) });
  const rep = await c.store(BLOB, { url: p.url, pubkey: p.pubkey, lightningNodeId: "ln-p", priceMsatPerChunkEpoch: 1 }, 64);
  p.deleteChunks(rep.sha256, Array.from({ length: rep.n }, (_, i) => i));
  const r = await c.runEpoch(rep, 1);
  assert.equal(r.outcome, "failed");
});

test("channel invoices: decode and reject what is not one", () => {
  const pr = "bsbch1" + Buffer.from(JSON.stringify({ h: "ab".repeat(32), a: 512000, p: "bsbch:" + "cd".repeat(32), m: "epoch 1", x: 1, u: "http://127.0.0.1:1/channel/pay" })).toString("base64url");
  const inv = decodeChannelInvoice(pr);
  assert.equal(inv.amountMsat, 512000);
  assert.equal(inv.payUrl, "http://127.0.0.1:1/channel/pay");
  assert.throws(() => decodeChannelInvoice("lnstub1xyz"), /not a bsb channel invoice/);
});
