// Phase 7C: on-chain payment state survives restarts (the provider's invoices, the client's sends).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OnchainPayee, OnchainPayer } from "./onchain.ts";
import { Ledger } from "./ledger.ts";
import { keyFromSeed } from "../model/schnorr.ts";

const nostr = keyFromSeed("nostr|od");
const pay = keyFromSeed("onchain|od");
const dir = () => mkdtempSync(join(tmpdir(), "bsb-onchain-durable-"));

test("OD01: a restarted provider can still sweep payments to invoices issued before the crash", async () => {
  const d = dir();
  const a = new OnchainPayee(nostr, pay, "regtest", join(d, "invoices.ledger"));
  const inv = await a.createInvoice(512_000, "epoch 1");
  const before = a.secretFor([inv.paymentHash]);
  const restarted = new OnchainPayee(nostr, pay, "regtest", join(d, "invoices.ledger"));
  assert.equal(restarted.secretFor([inv.paymentHash]), before, "same sweep key after restart");
  const amnesiac = new OnchainPayee(nostr, pay, "regtest");
  assert.throws(() => amnesiac.secretFor([inv.paymentHash]), /not our invoice/, "without the ledger the payment is unsweepable");
});

test("OD02: a provider ledger with another payee's invoice is refused", async () => {
  const d = dir();
  const other = new OnchainPayee(keyFromSeed("nostr|other"), keyFromSeed("onchain|other"), "regtest");
  const inv = await other.createInvoice(512_000, "e");
  new Ledger(join(d, "invoices.ledger")).append({ t: "invoice", pr: inv.paymentRequest });
  assert.throws(() => new OnchainPayee(nostr, pay, "regtest", join(d, "invoices.ledger")), /another payee/);
});

test("OD03: a restarted client counts written-ahead payments and refuses to pay them again", async () => {
  const d = dir();
  const payee = new OnchainPayee(nostr, pay, "regtest");
  const inv = await payee.createInvoice(512_000, "epoch 1");
  // The client wrote its send record, then crashed before (or during) the broadcast.
  new Ledger(join(d, "sends.ledger")).append({ t: "send", txid: "aa".repeat(32), hex: "00", outputs: [{ payee: inv.payee, hashes: [inv.paymentHash], sats: 512 }] });
  const calls: string[] = [];
  const rpc = async (m: string) => { calls.push(m); throw new Error("wallet must not be called"); };
  const restarted = new OnchainPayer(rpc as any, "regtest", 5, "w", join(d, "sends.ledger"));
  assert.equal(restarted.paidMsatTo(inv.payee), 512_000);
  await assert.rejects(restarted.payBatch([{ paymentRequest: inv.paymentRequest, maxMsat: 1e9 }]), /already paid/);
  assert.deepEqual(calls, [], "refused before touching the wallet");
});

test("OD04: rebroadcast sends the same transaction, and a known one counts as done", async () => {
  const d = dir();
  const l = new Ledger(join(d, "sends.ledger"));
  l.append({ t: "send", txid: "aa".repeat(32), hex: "0200", outputs: [] });
  l.append({ t: "send", txid: "bb".repeat(32), hex: "0201", outputs: [] });
  const sent: string[] = [];
  const rpc = async (m: string, params: unknown[]) => {
    assert.equal(m, "sendrawtransaction");
    sent.push(String(params[0]));
    if (params[0] === "0201") throw new Error("txn-already-known");
    return "ok";
  };
  const r = await new OnchainPayer(rpc as any, "regtest", 5, "w", join(d, "sends.ledger")).rebroadcast();
  assert.deepEqual(sent, ["0200", "0201"], "byte-identical rebroadcast, no new payment");
  assert.ok(r.every((x) => x.ok));
});
