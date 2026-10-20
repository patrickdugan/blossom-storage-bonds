// Reads back, from BitVM's esplora regtest API, the peg-out transactions of one run of the bridge
// test with our proof (bridge-regtest.patch): assert-initial (the test log's "Txid:" line, printed by
// its assert helper), the kick-off 2 it spends, and every transaction descending from it in a height
// range, labelled by what it spends.
//
//   node zk/bitvm-check/bridge-txs.ts <test.log> <from height> [esplora url] > bridge.json

import { readFileSync } from "node:fs";

const [logPath, fromArg, base = "http://localhost:8094/regtest/api"] = process.argv.slice(2);
const get = async (p: string) => {
  const r = await fetch(base + p);
  if (!r.ok) throw new Error(`${p}: ${r.status}`);
  return r.headers.get("content-type")?.includes("json") ? r.json() : r.text();
};
const log = readFileSync(logPath, "utf8");
const assertInitial = /Txid: ([0-9a-f]{64})\s+(?:Waiting[^\n]*\s+)?Assert initial tx result: Ok/.exec(log)?.[1];
const printed = Object.fromEntries([...log.matchAll(/txid: ([0-9a-f]{64}), (assert_commit_[12])_tx/g)].map((m) => [m[1], m[2]]));
const tip = Number(await get("/blocks/tip/height"));

const all = new Map<string, any>();
for (let h = Number(fromArg); h <= tip; h++) {
  const hash = await get(`/block-height/${h}`);
  const n = (await get(`/block/${hash}`)).tx_count;
  for (let i = 0; i < n; i += 25) for (const tx of await get(`/block/${hash}/txs/${i}`)) all.set(tx.txid, { ...tx, height: h });
}
const labels = new Map<string, string>();
if (assertInitial) {
  labels.set(assertInitial, "assert_initial");
  const kickOff2 = all.get(assertInitial)?.vin[0].txid;
  if (kickOff2) labels.set(kickOff2, "kick_off_2");
}
const parentLabels = (tx: any) => tx.vin.map((v: any) => labels.get(v.txid)).filter(Boolean);
for (let changed = true; changed;) {
  changed = false;
  for (const tx of all.values()) {
    if (labels.has(tx.txid)) continue;
    const p = parentLabels(tx);
    let l: string | undefined;
    if (printed[tx.txid]) l = printed[tx.txid];
    else if (p.includes("assert_final")) l = "disprove";
    else if (p.includes("assert_commit_1") || p.includes("assert_commit_2")) l = "assert_final";
    if (l && (p.length || printed[tx.txid])) { labels.set(tx.txid, l); changed = true; }
  }
}
const txs = [...all.values()].filter((t) => labels.has(t.txid)).map((t) => ({
  label: labels.get(t.txid), txid: t.txid, height: t.height, weight: t.weight, vsize: Math.ceil(t.weight / 4), size: t.size,
  fee: t.fee, inputs: t.vin.length, outputs: t.vout.length, max_witness_items: Math.max(...t.vin.map((v: any) => (v.witness ?? []).length)),
}));
console.log(JSON.stringify({
  test: "bridge::integration::peg_out::disprove::test_disprove_success", passed: /test result: ok\. 1 passed/.test(log),
  disprove_broadcast_ok: /Disprove tx result: Ok/.test(log), public_input_loaded: /bsb: Groth16 proof from .*public input (\d+)/.exec(log)?.[1],
  disprove_leaf: /disprove script \d+: tapindex (\d+), (\w+)/.exec(log.slice(log.lastIndexOf("Generating disprove witness")))?.slice(1),
  from_height: Number(fromArg), tip, txs,
}, null, 1));
