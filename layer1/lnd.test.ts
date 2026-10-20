// The LND payer's own checks, against a fake node: these run before and after lnd is asked to pay, so
// they need no lnd binary. The real backend runs end to end in `node layer1/market.ts --pay ln`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { LndPayer, type LndNode } from "./lnd.ts";

// From the BOLT 11 spec examples (CC BY 4.0): 0.0025 BTC, payment hash 0001…0102, expiry 60 s from
// timestamp 1496314658, payee 03e7156a….
const COFFEE = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const DONATION = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
const MSAT = 250_000_000;

function fakeNode(replies: any[]) {
  const calls: any[] = [];
  const node = {
    pubkey: "02" + "11".repeat(32),
    async rest(method: string, path: string, body: any) { calls.push({ method, path, body }); return replies.shift(); },
  };
  return { node: node as unknown as LndNode, calls };
}
function at<T>(unixSec: number, f: () => Promise<T>): Promise<T> {
  const now = Date.now;
  Date.now = () => unixSec * 1000;
  return f().finally(() => { Date.now = now; });
}

test("LndPayer.decode: refuses another network and invoices without an amount", () => {
  assert.throws(() => new LndPayer(fakeNode([]).node).decode(COFFEE), /bc, not bcrt/);
  const mainnet = new LndPayer(fakeNode([]).node, "bc");
  assert.equal(mainnet.decode(COFFEE).amountMsat, MSAT);
  assert.throws(() => mainnet.decode(DONATION), /no amount/);
});

test("LndPayer.pay: checks amount and expiry before asking the node", async () => {
  const { node, calls } = fakeNode([]);
  const p = new LndPayer(node, "bc");
  await at(1496314658, () => assert.rejects(p.pay(COFFEE, MSAT - 1), /over max/));
  await at(1496314658 + 61, () => assert.rejects(p.pay(COFFEE, MSAT), /expired/));
  assert.equal(calls.length, 0);
});

test("LndPayer.pay: a preimage that does not open the hash is refused and not counted", async () => {
  const { node, calls } = fakeNode([{ status: "SUCCEEDED", payment_preimage: "00".repeat(32) }]);
  const p = new LndPayer(node, "bc");
  await at(1496314658, () => assert.rejects(p.pay(COFFEE, MSAT + 1000), /does not open the hash/));
  assert.equal(calls[0].path, "/v2/router/send");
  assert.equal(calls[0].body.fee_limit_msat, "1000");
  assert.equal(p.paidMsatTo("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"), 0);
});

test("LndPayer.pay: only INSUFFICIENT_BALANCE is retried", async () => {
  const a = fakeNode([{ status: "FAILED", failure_reason: "FAILURE_REASON_NO_ROUTE" }]);
  await at(1496314658, () => assert.rejects(new LndPayer(a.node, "bc").pay(COFFEE, MSAT), /NO_ROUTE/));
  assert.equal(a.calls.length, 1);
  const b = fakeNode([
    { status: "FAILED", failure_reason: "FAILURE_REASON_INSUFFICIENT_BALANCE" },
    { status: "FAILED", failure_reason: "FAILURE_REASON_INCORRECT_PAYMENT_DETAILS" },
  ]);
  await at(1496314658, () => assert.rejects(new LndPayer(b.node, "bc").pay(COFFEE, MSAT), /INCORRECT_PAYMENT_DETAILS/));
  assert.equal(b.calls.length, 2);
});
