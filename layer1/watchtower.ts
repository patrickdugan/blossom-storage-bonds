// A watchtower for public epoch proofs (phase 3b): a third party with its own view of the chain (its own
// bitcoind, or with --headers none at all) and Nostr key that holds no stake in any deal.
//
//   node layer1/watchtower.ts --relays <ws url,...> --providers <pubkey,...> --epoch-blocks 10 --from <height>
//                             [--network regtest|signet|testnet4] [--confs N] [--deadline 6] [--min-q 8] [--rpc <url>] [--dir <dir>]
//                             [--headers <mirror url> --min-work <hex> --receipt-deadline <blocks>]
//
// Its Nostr key is the fixed label "bsb/watchtower" on regtest; on any other network it is made fresh on
// first start and kept in <dir>/party.seed (net.ts partySeed). A receipt counts once its transaction has
// the network's confirmation depth.
//
// For every proof event (kind 4245) from a listed provider it rebuilds the statement itself: the seed
// from its own node's block hash at the claimed boundary, never the event's copy, and q and the deal
// list from the event. It fetches the proof from the URL, checks its SHA-256, and verifies it with
// bsb-zk. Each verdict goes out as a signed attestation (kind 4246, placeholder): valid, or invalid
// with the reason. A provider with no proof for a boundary `deadline` blocks after it is attested
// missing. Anyone who trusts this watchtower can act on its attestations, and anyone who does not can
// re-check them, since everything they rest on is public.
//
// With --headers the watchtower runs with no bitcoind at all. It follows a header mirror (untrusted:
// layer1/headerchain.ts checks every header, and refuses to act below --min-work), and takes seeds and
// deadlines from that chain. It also checks every on-chain payment receipt (kind 4247, from anyone) and
// attests the paid side of each epoch (tag side=paid): "paid" for a receipt that verifies against its
// header chain, "invalid" for one that does not, and "no-receipt" for an epoch it attested valid that
// still has no receipt --receipt-deadline blocks after its boundary. "no-receipt" is a statement about
// what was published, not about the chain: non-payment cannot be shown from public data.

import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keyFromSeed } from "../model/schnorr.ts";
import { rpc } from "./bondtool.ts";
import { partySeed, useNetwork } from "./net.ts";
import { HeaderChain, paramsFor, syncFrom } from "./headerchain.ts";
import { KIND_PAYMENT_RECEIPT, decodeOnchainInvoice, verifyReceipt, type PaymentReceipt } from "./onchain.ts";
import { now, signEvent, type NostrEvent } from "./nostr.ts";
import { RelayPool } from "./relay.ts";
import { defaultZk, statementFor, verifyProof } from "./zk.ts";
import { KIND_ATTESTATION, KIND_EPOCH_PROOF } from "./zk-provider.ts";

const arg = (name: string, dflt?: string) => {
  const i = process.argv.indexOf(`--${name}`);
  if (i > 0) return process.argv[i + 1];
  if (dflt === undefined) throw new Error(`--${name} is required`);
  return dflt;
};
const NET = useNetwork();
const RELAYS = RelayPool.parse(arg("relays", arg("relay", ""))), PROVIDERS = arg("providers").split(",");
const EPOCH = Number(arg("epoch-blocks", "10")), FROM = Number(arg("from")), DEADLINE = Number(arg("deadline", "6"));
const MIN_Q = Number(arg("min-q", "8"));
const RPC = process.env.BSB_RPC!;
const DIR = arg("dir", join(tmpdir(), "bsb-watchtower"));
mkdirSync(DIR, { recursive: true });
const HEADERS = arg("headers", "");
const NETWORK = NET.name;
const MIN_WORK = BigInt("0x" + arg("min-work", "0"));
const RECEIPT_DEADLINE = Number(arg("receipt-deadline", String(DEADLINE + EPOCH)));
const chain = HEADERS ? new HeaderChain(paramsFor(NETWORK)) : undefined;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The chain's height, from the header chain in --headers mode (and -1 below the work floor). */
async function height(): Promise<number> {
  if (!chain) return rpc("getblockcount", [], RPC);
  return chain.totalWork >= MIN_WORK ? chain.height : -1;
}
/** The block hash at `h`: the seed of that boundary's challenges. */
async function blockHash(h: number): Promise<string> {
  if (!chain) return rpc("getblockhash", [h], RPC);
  for (let i = 0; i < 240 && (await height()) < h; i++) await sleep(NET.canMine ? 250 : NET.pollMs);
  const x = chain.hashAt(h);
  if ((await height()) < h || !x) throw new Error(`header chain has not reached ${h}`);
  return x;
}

const key = keyFromSeed(`nostr|${partySeed(NET, DIR, "bsb/watchtower")}`);
const log = (ev: Record<string, unknown>) => process.stdout.write(JSON.stringify({ t: Date.now(), watchtower: true, ...ev }) + "\n");
const rc = await RelayPool.connect(RELAYS, log);
const seen = new Set<string>();             // `${provider}|${height}` that have a proof event
const attested = new Set<string>();
const validEpochs = new Set<string>();      // `${provider}|${height}` attested valid on the stored side
let queue = Promise.resolve();

async function attest(provider: string, height: number, result: string, extra: Record<string, unknown> = {}, side: "stored" | "paid" = "stored") {
  // Anyone can post a receipt, so an invalid one is attested per receipt and does not take the epoch's
  // "paid" slot: a junk receipt published first cannot stop a valid one from counting.
  const k = side === "paid" && result === "invalid" && extra.receiptEvent ? `${provider}|${height}|paid|${extra.receiptEvent}` : `${provider}|${height}|${side}`;
  if (attested.has(k)) return;
  attested.add(k);
  const ref = extra.proofEvent ?? extra.receiptEvent;
  const ev = signEvent(key, {
    created_at: now(), kind: KIND_ATTESTATION,
    tags: [["p", provider], ["h", String(height)], ["result", result], ["side", side], ...(ref ? [["e", String(ref)]] : [])],
    content: JSON.stringify({ provider, height, side, result, ...extra }),
  });
  await rc.publish(ev);
  if (side === "stored" && result === "valid") validEpochs.add(`${provider}|${height}`);
  log({ event: "attest", provider: provider.slice(0, 12), height, side, result, ...extra });
}

async function check(e: NostrEvent) {
  let c: any;
  try { c = JSON.parse(e.content); } catch { return; }
  const height = Number(c.height);
  if (!Number.isSafeInteger(height) || height % EPOCH !== 0 || height < FROM) return;
  const base = { proofEvent: e.id, proof: c.proof?.sha256 };
  try {
    if (Number(c.q) < MIN_Q) return attest(e.pubkey, height, "invalid", { ...base, why: `q ${c.q} is below ${MIN_Q}` });
    if (c.mode !== 1 || c.hash !== "blake") return attest(e.pubkey, height, "invalid", { ...base, why: "unsupported proof kind" });
    const seed = Buffer.from(await blockHash(height), "hex");
    const r = await fetch(String(c.proof.url));
    const proof = Buffer.from(await r.arrayBuffer());
    if (createHash("sha256").update(proof).digest("hex") !== c.proof.sha256) return attest(e.pubkey, height, "invalid", { ...base, why: "proof bytes do not match the announced hash" });
    const v = await verifyProof(defaultZk(), DIR, proof, statementFor(seed, Number(c.q), c.deals));
    return attest(e.pubkey, height, v.ok ? "valid" : "invalid", { ...base, deals: c.deals.length, q: c.q, ...(v.ok ? {} : { why: v.why }), verify_s: v.seconds });
  } catch (err) {
    return attest(e.pubkey, height, "invalid", { ...base, why: (err as Error).message });
  }
}

rc.subscribe([{ kinds: [KIND_EPOCH_PROOF], authors: PROVIDERS }], (e) => {
  // Mark it seen on arrival, not when its turn in the queue comes, so a proof that waits behind
  // another's verification is never attested missing.
  try { seen.add(`${e.pubkey}|${Number(JSON.parse(e.content).height)}`); } catch { /* checked below */ }
  queue = queue.then(() => check(e));
});

// Payment receipts, from anyone: a receipt is self-authenticating, so who posts it does not matter.
async function checkReceipt(e: NostrEvent) {
  let r: PaymentReceipt;
  try { r = JSON.parse(e.content); } catch { return; }
  const named = new Map<string, number[]>();     // provider -> epoch heights its invoices name
  try {
    for (const o of r.outputs) for (const pr of o.invoices) {
      const i = decodeOnchainInvoice(pr);
      const m = /^bsb zk epoch (\d+)$/.exec(i.memo);
      if (PROVIDERS.includes(i.payee) && m) named.set(i.payee, [...(named.get(i.payee) ?? []), Number(m[1])]);
    }
  } catch { /* verifyReceipt reports it */ }
  // Anyone can post a receipt, so one claiming a block far beyond the tip is dropped rather than waited for.
  const claimed = Number(r.block?.height);
  if (!Number.isSafeInteger(claimed) || claimed > (await height()) + 6 + NET.confs) { log({ event: "receipt-dropped", id: e.id, why: `claims block ${r.block?.height}` }); return; }
  for (let i = 0; i < (NET.canMine ? 120 : 4320) && (await height()) < claimed + NET.confs - 1; i++) await sleep(NET.canMine ? 250 : NET.pollMs);
  const t = process.hrtime.bigint();
  const v = verifyReceipt(r, chain!, { network: NETWORK, minConf: NET.confs });
  const verify_ms = Number(process.hrtime.bigint() - t) / 1e6;
  if (!v.ok || (await height()) < 0) {
    const why = v.ok ? "header chain below the work floor" : v.why;
    for (const [p, hs] of named) for (const h of hs) await attest(p, h, "invalid", { receiptEvent: e.id, txid: r.txid, why }, "paid");
    log({ event: "receipt-invalid", id: e.id, why });
    return;
  }
  for (const pay of v.payments) {
    const m = /^bsb zk epoch (\d+)$/.exec(pay.memo);
    if (!PROVIDERS.includes(pay.payee) || !m) continue;
    await attest(pay.payee, Number(m[1]), "paid", {
      receiptEvent: e.id, txid: v.txid, vout: pay.vout, block: v.height, blockHash: v.blockHash, confirmations: v.confirmations,
      amount_msat: pay.amountMsat, paymentHash: pay.paymentHash, late: pay.late, receipt_bytes: v.bytes, verify_ms,
      chain: `headers-standin: ${chain!.height + 1} headers checked from genesis, work ${chain!.totalWork}`,
    }, "paid");
  }
}

if (chain) {
  (async () => {
    for (;;) {
      try { await syncFrom(chain, HEADERS); } catch (e) { log({ event: "headers-error", error: (e as Error).message }); }
      await sleep(300);
    }
  })();
  // Receipts wait for depth in a queue of their own, so they never hold up proof checks.
  let receipts = Promise.resolve();
  rc.subscribe([{ kinds: [KIND_PAYMENT_RECEIPT] }], (e) => { receipts = receipts.then(() => checkReceipt(e)).catch((err) => log({ event: "error", error: (err as Error).message })); });
}

// Missing proofs: a boundary that passed `deadline` blocks ago with no event from a provider. And, with
// receipts, an epoch attested valid whose receipt deadline passed with no valid receipt.
(async () => {
  for (;;) {
    try {
      const h = await height();
      for (let b = FROM; b + DEADLINE <= h; b += EPOCH) {
        for (const p of PROVIDERS) if (!seen.has(`${p}|${b}`)) queue = queue.then(() => attest(p, b, "missing", { why: `no proof ${DEADLINE} blocks after the boundary` }));
      }
      if (chain) for (const k of validEpochs) {
        const [p, b] = k.split("|");
        if (Number(b) + RECEIPT_DEADLINE <= h && !attested.has(`${p}|${b}|paid`)) {
          queue = queue.then(() => attest(p, Number(b), "no-receipt", { why: `no valid receipt ${RECEIPT_DEADLINE} blocks after the boundary; a statement about what was published, not a proof of non-payment` }, "paid"));
        }
      }
    } catch (e) { log({ event: "error", error: (e as Error).message }); }
    await sleep(500);
  }
})();

process.on("SIGTERM", () => { rc.close(); process.exit(0); });
log({ ready: true, network: NETWORK, relays: rc.connected(), nostr: key.x, providers: PROVIDERS.length, from: FROM, epoch: EPOCH, deadline: DEADLINE, node: chain ? "none (header mirror)" : RPC });
