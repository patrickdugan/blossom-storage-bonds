// Phase 7C: payment authorization survives crashes. Each test restarts a party by building a fresh
// object from the same ledger file, the way a restarted process would, and attacks the gap.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { appendFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChannelPayee, ChannelPayer } from "./channel.ts";
import { Ledger } from "./ledger.ts";
import type { BondTool } from "./bondtool.ts";

const providerX = "ab".repeat(32);
const clientX = "cd".repeat(32);
// Stand-in for bsb-bond: a "signature" names the total it signs, and verification checks that.
const tool = { run: async (cmd: string, _path: string, paid?: string, sig?: string) => {
  if (cmd === "chan-sign") return { sig: `sig-${paid}` };
  if (cmd === "chan-verify") { if (sig !== `sig-${paid}`) throw new Error("bad signature"); return { ok: true }; }
  if (cmd === "chan-check" || cmd === "chan-open") return { ok: true };
  if (cmd === "chan-close") return { closed: Number(paid) };
  throw new Error(`unexpected ${cmd}`);
} } as unknown as BondTool;

async function serve(getPayee: () => ChannelPayee): Promise<{ base: string; server: Server }> {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    void getPayee().route(req, res, url).then((h) => { if (!h) { res.writeHead(404); res.end(); } });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
}

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "bsb-durable-"));
  return { dir, pLedger: join(dir, "provider.ledger"), cLedger: join(dir, "client.ledger"), chanPath: join(dir, "channel.json") };
}

async function openBoth(s: ReturnType<typeof setup>, base: string, payee: ChannelPayee) {
  payee.setBaseUrl(base);
  const payer = new ChannelPayer(clientX, tool, s.cLedger);
  const ch = { provider_x: providerX, client_x: clientX, capacity_sats: 50_000, t_refund: 900 };
  await payer.open(s.chanPath, ch);
  const r = await fetch(`${base}/channel/open`, { method: "POST", body: JSON.stringify(ch) });
  assert.equal(r.status, 200);
  return payer;
}

test("DU01: a restarted provider keeps the latest client state and can close with it", async () => {
  const s = setup();
  let payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
  const { base, server } = await serve(() => payee);
  try {
    const payer = await openBoth(s, base, payee);
    for (let i = 0; i < 3; i++) await payer.pay((await payee.createInvoice(512_000, `epoch ${i}`)).paymentRequest, 1_000_000);
    payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger); // crash and restart
    payee.setBaseUrl(base);
    assert.equal(payee.channels.get(clientX)?.paid, 1536);
    assert.deepEqual(await payee.close(clientX), { closed: 1536 });
  } finally { server.close(); }
});

test("DU02: after a provider restart, a replayed payment counts nothing twice", async () => {
  const s = setup();
  let payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
  const { base, server } = await serve(() => payee);
  try {
    const payer = await openBoth(s, base, payee);
    const inv = await payee.createInvoice(512_000, "epoch 1");
    await payer.pay(inv.paymentRequest, 1_000_000);
    payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
    payee.setBaseUrl(base);
    const exact = await fetch(`${base}/channel/pay`, { method: "POST", body: JSON.stringify({ paymentRequest: inv.paymentRequest, client_x: clientX, paid: 512, sig: "sig-512" }) });
    assert.equal(exact.status, 200, "an exact retry is answered");
    assert.equal(((await exact.json()) as { retry?: boolean }).retry, true);
    assert.equal(payee.channels.get(clientX)?.paid, 512, "and counted once");
    const higher = await fetch(`${base}/channel/pay`, { method: "POST", body: JSON.stringify({ paymentRequest: inv.paymentRequest, client_x: clientX, paid: 1024, sig: "sig-1024" }) });
    assert.equal(higher.status, 402, "a paid invoice cannot carry a new total");
    assert.match(higher.headers.get("x-reason") ?? (await higher.text()), /already paid/);
  } finally { server.close(); }
});

test("DU03: a restarted client refuses to pay an invoice it already paid", async () => {
  const s = setup();
  const payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
  const { base, server } = await serve(() => payee);
  try {
    const payer = await openBoth(s, base, payee);
    const inv = await payee.createInvoice(512_000, "epoch 1");
    await payer.pay(inv.paymentRequest, 1_000_000);
    const again = new ChannelPayer(clientX, tool, s.cLedger); // crash and restart
    assert.equal(again.paidTo(`bsbch:${providerX}`), 512);
    await assert.rejects(again.pay(inv.paymentRequest, 1_000_000), /already paid/);
  } finally { server.close(); }
});

test("DU04: an interrupted payment is resumed, not paid twice and not lost", async () => {
  const s = setup();
  const payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
  const { base, server } = await serve(() => payee);
  const payer = await openBoth(s, base, payee);
  const inv = await payee.createInvoice(512_000, "epoch 1");
  server.close(); // the provider goes away after the client signs
  await new Promise((r) => setTimeout(r, 50));
  await assert.rejects(payer.pay(inv.paymentRequest, 1_000_000));
  const restarted = new ChannelPayer(clientX, tool, s.cLedger);
  assert.equal(restarted.unsettled.size, 1, "the signed state is remembered as unsettled");
  assert.equal(restarted.paidTo(`bsbch:${providerX}`), 512, "and counted, since the provider may hold it");
  await assert.rejects(restarted.pay(inv.paymentRequest, 1_000_000), /already paid/);
  // The provider comes back on the same address; the client completes the same state.
  const port = Number(new URL(base).port);
  const back = createServer((req, res) => { void payee.route(req, res, new URL(req.url ?? "/", `http://${req.headers.host}`)); });
  await new Promise<void>((r) => back.listen(port, "127.0.0.1", r));
  try {
    const r = await restarted.resume();
    assert.deepEqual(r.failed, []);
    assert.equal(r.resumed.length, 1);
    assert.equal(payee.channels.get(clientX)?.paid, 512);
    assert.equal(new ChannelPayer(clientX, tool, s.cLedger).unsettled.size, 0, "settled for good");
  } finally { back.close(); }
});

test("DU05: a lost reply after the provider accepted is retried to the same preimage", async () => {
  const s = setup();
  const payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
  const { base, server } = await serve(() => payee);
  try {
    const payer = await openBoth(s, base, payee);
    const inv = await payee.createInvoice(512_000, "epoch 1");
    // Simulate: the client wrote its intent and the provider accepted, but the reply was lost.
    new Ledger(s.cLedger).append({ t: "intent", h: inv.paymentHash, pr: inv.paymentRequest, payee: `bsbch:${providerX}`, paid: 512, sig: "sig-512" });
    const accepted = await fetch(`${base}/channel/pay`, { method: "POST", body: JSON.stringify({ paymentRequest: inv.paymentRequest, client_x: clientX, paid: 512, sig: "sig-512" }) });
    const { preimage } = (await accepted.json()) as { preimage: string };
    const restarted = new ChannelPayer(clientX, tool, s.cLedger);
    const r = await restarted.resume();
    assert.equal(r.resumed.length, 1);
    assert.equal(payee.channels.get(clientX)?.paid, 512);
    const done = new Ledger(s.cLedger).replay().filter((x) => x.t === "done");
    assert.equal(done.at(-1)?.preimage, preimage);
    void payer;
  } finally { server.close(); }
});

test("DU06: a torn final ledger line is ignored; damage elsewhere stops the restart", () => {
  const s = setup();
  const l = new Ledger(s.pLedger);
  l.append({ t: "open", client_x: clientX, path: s.chanPath });
  appendFileSync(s.pLedger, '{"t":"paid","h":"00'); // crash mid-append
  assert.equal(l.replay().length, 1);
  writeFileSync(s.pLedger, 'not json\n{"t":"open"}\n');
  assert.throws(() => l.replay(), /damaged/);
});

test("DU07: a restarted provider rejects a lower or skipped total", async () => {
  const s = setup();
  let payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
  const { base, server } = await serve(() => payee);
  try {
    const payer = await openBoth(s, base, payee);
    await payer.pay((await payee.createInvoice(512_000, "epoch 1")).paymentRequest, 1_000_000);
    payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
    payee.setBaseUrl(base);
    const inv2 = await payee.createInvoice(512_000, "epoch 2");
    for (const paid of [512, 0, 2048]) {
      const r = await fetch(`${base}/channel/pay`, { method: "POST", body: JSON.stringify({ paymentRequest: inv2.paymentRequest, client_x: clientX, paid, sig: `sig-${paid}` }) });
      assert.equal(r.status, 402, `total ${paid} refused`);
    }
    const ok = await fetch(`${base}/channel/pay`, { method: "POST", body: JSON.stringify({ paymentRequest: inv2.paymentRequest, client_x: clientX, paid: 1024, sig: "sig-1024" }) });
    assert.equal(ok.status, 200);
  } finally { server.close(); }
});

test("DU08: invoices issued before a provider crash stay payable, and only once", async () => {
  const s = setup();
  let payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger);
  const { base, server } = await serve(() => payee);
  try {
    const payer = await openBoth(s, base, payee);
    const inv = await payee.createInvoice(512_000, "epoch 1");
    payee = new ChannelPayee(providerX, tool, s.dir, s.pLedger); // crash before the client pays
    payee.setBaseUrl(base);
    await payer.pay(inv.paymentRequest, 1_000_000);
    assert.equal(payee.channels.get(clientX)?.paid, 512);
    await assert.rejects(payer.pay(inv.paymentRequest, 1_000_000), /already paid/);
  } finally { server.close(); }
});
