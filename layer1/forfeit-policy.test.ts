// Phase 7C: the client's forfeit fee policy against a simulated mempool race.
import { test } from "node:test";
import assert from "node:assert/strict";
import { forfeitRates, forfeitWithPolicy } from "./bondtool.ts";

function sim(opts: { providerBidsUntil?: number; providerConfirmsAt?: number }) {
  let height = 0; const bids: number[] = []; let mempool: "forfeit" | "respond" | null = null; let confirmed: string | null = null;
  return {
    bids,
    policy: {
      rates: forfeitRates(4, 100_000),
      broadcast: async (rate: number) => { bids.push(rate); mempool = "forfeit"; return `forfeit@${rate}`; },
      nextBlock: async () => {
        height++;
        // A late provider re-bids above the client each block until providerBidsUntil.
        if ((opts.providerBidsUntil ?? 0) >= height) mempool = "respond";
        if (opts.providerConfirmsAt === height) { confirmed = "respond"; return; }
        if (mempool === "forfeit" && !confirmed) confirmed = `forfeit@${bids.at(-1)}`;
      },
      confirmations: async (txid: string) => (confirmed === txid ? 1 : 0),
      answered: async () => confirmed === "respond",
    },
  };
}

test("FP01: rates double from the base and stop at half the bond's worth of forfeit fee", async () => {
  const r = forfeitRates(4, 100_000);
  assert.deepEqual(r, [4, 8, 16, 32, 64, 128, 256]);
  assert.ok(r.at(-1)! * 138 <= 50_000);
  await assert.rejects(forfeitWithPolicy({ rates: [5, 5], broadcast: async () => "", nextBlock: async () => {}, confirmations: async () => 0, answered: async () => false }), /increasing/);
});

test("FP02: with no competing answer the first bid confirms", async () => {
  const s = sim({});
  const o = await forfeitWithPolicy(s.policy);
  assert.deepEqual(o, { won: true, txid: "forfeit@4", rate: 4, bids: 1 });
});

test("FP03: a late answer that stops bidding is outlasted by escalating re-bids", async () => {
  const s = sim({ providerBidsUntil: 3 });
  const o = await forfeitWithPolicy(s.policy);
  assert.equal(o.won, true);
  assert.deepEqual(s.bids, [4, 8, 16, 32]);
});

test("FP04: a late answer that confirms first is reported, not retried forever", async () => {
  const s = sim({ providerBidsUntil: 99, providerConfirmsAt: 2 });
  const o = await forfeitWithPolicy(s.policy);
  assert.deepEqual(o, { won: false, why: "answered", bids: 2 });
});
