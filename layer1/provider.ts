// One storage provider as its own OS process: a Blossom server with PDP, sentinel and cut-and-choose
// endpoints, NIP-44 epoch challenges over a Nostr relay, a payee, and an on-chain agent that watches its
// bonds and answers any challenge it finds on chain, reading the revealed r from the challenge
// transaction itself.
//
//   node layer1/provider.ts --name <slug> --seed <seed> --dir <dir> --relay <ws url> --admin-token <t>
//                           [--price <msat per chunk-epoch>] [--rpc <url>] [--pay channel|ln|onchain] [--lnd <path>]
//
// With --pay channel (the default) the payee is the one-way Bitcoin channel (layer1/channel.ts). With
// --pay ln this process starts its own lnd under <dir>/lnd, with its own wallet and macaroon, and bills
// each epoch with a BOLT 11 invoice from that node (layer1/lnd.ts). With --pay onchain it bills with
// invoices signed by its Nostr key and paid to taproot outputs tweaked from its own pay key
// (layer1/onchain.ts); /admin/sweep spends what the published receipts paid it into its fee address.
//
// It prints one JSON line, {"ready": true, ...}, and then one JSON line per event. Its keys come from
// --seed and never leave this process: the Nostr key, the bond and channel key (bsb-bond, BSB_SEED), and
// its fee wallet. Its Lightning node key lives in its own lnd.
//
// The admin port (127.0.0.1, token required) exists for the demo only. It lets the orchestrator make
// this provider misbehave, and tells it when to close its channel and refund its bond.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { keyFromSeed } from "../model/schnorr.ts";
import { fail, json, readBody, startProvider } from "./blossom.ts";
import { BondTool, rpc } from "./bondtool.ts";
import { ChannelPayee } from "./channel.ts";
import type { Payee } from "./lightning.ts";
import { LndNode, LndPayee, lndExe } from "./lnd.ts";
import { KIND_PAYMENT_RECEIPT, OnchainPayee, type PaymentReceipt } from "./onchain.ts";
import { servePdpOverNostr } from "./nostr-pdp.ts";
import { RelayClient } from "./relay.ts";
import { startZkEpochs } from "./zk-provider.ts";

const arg = (name: string, dflt?: string) => {
  const i = process.argv.indexOf(`--${name}`);
  if (i > 0) return process.argv[i + 1];
  if (dflt === undefined) throw new Error(`--${name} is required`);
  return dflt;
};
const NAME = arg("name"), SEED = arg("seed"), DIR = arg("dir"), RELAY = arg("relay"), TOKEN = arg("admin-token");
const PRICE = Number(arg("price", "2000"));
const PAY = arg("pay", "channel");
if (PAY !== "channel" && PAY !== "ln" && PAY !== "onchain") throw new Error("--pay must be channel, ln or onchain");
const NETWORK = arg("network", "regtest");
const RPC = arg("rpc", process.env.BSB_RPC ?? "http://127.0.0.1:18543");
// --zk: prove holdings every --epoch-blocks blocks from --zk-from on, with --zk-q challenges.
const ZK = process.argv.includes("--zk");
const ZK_EPOCH = Number(arg("epoch-blocks", "10")), ZK_Q = Number(arg("zk-q", "8")), ZK_FROM = Number(arg("zk-from", "0"));
const ZK_PRICE = Number(arg("zk-price", "512000"));
mkdirSync(DIR, { recursive: true });

const log = (ev: Record<string, unknown>) => process.stdout.write(JSON.stringify({ t: Date.now(), provider: NAME, ...ev }) + "\n");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const nostrKey = keyFromSeed(`nostr|${SEED}`);
const tool = new BondTool(SEED, RPC);
const me = await tool.run("info");
const lnNode = PAY === "ln" ? await LndNode.start({ bin: arg("lnd", lndExe()), dir: join(DIR, "lnd"), alias: `bsb-${NAME}` }) : undefined;
const lnPayee = lnNode && new LndPayee(lnNode);
const chainPayee = PAY === "onchain" ? new OnchainPayee(nostrKey, keyFromSeed(`onchain|${SEED}`), NETWORK) : undefined;
const chanPayee = PAY === "channel" ? new ChannelPayee(me.x, tool, DIR) : undefined;
const payee: Payee = lnPayee ?? chainPayee ?? chanPayee!;
const bonds = new Map<string, { path: string; next: number; k: number; last?: string }>();

let zk: ReturnType<typeof startZkEpochs> | undefined;

/** Lightning: before opening, the client asks this provider's node to catch up with the chain (lnd
 *  refuses funding while it is behind, and tells the peer only "internal error"). The client then opens
 *  the channel from its own node and names it here; this provider's node checks it is the client's,
 *  funded by the client, and active. */
async function lnRoute(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
  if (req.method === "POST" && url.pathname === "/channel/prepare") {
    try { await lnNode!.waitSynced((await rpc("getblockcount", [], RPC)) as number); json(res, 200, { synced: true }); }
    catch (e) { fail(res, 503, (e as Error).message); }
    return true;
  }
  if (req.method !== "POST" || url.pathname !== "/channel/open") return false;
  try {
    const body = JSON.parse(String(await readBody(req, 1 << 16)));
    const ok = await lnPayee!.accept(String(body.channel_point), String(body.client_pubkey));
    log({ event: "ln-channel", ...ok });
    json(res, 200, ok);
  } catch (e) { fail(res, 402, (e as Error).message); }
  return true;
}

async function bondRoute(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
  if (chanPayee ? await chanPayee.route(req, res, url) : lnNode ? await lnRoute(req, res, url) : false) return true;
  if (zk && (await zk.route(req, res, url))) return true;
  const m = /^\/bond\/([0-9a-f]{64})\/(fund|presigs)$/.exec(url.pathname);
  if (req.method !== "POST" || !m) return false;
  const sha = m[1];
  let body: any;
  try { body = JSON.parse(String(await readBody(req, 1 << 20))); } catch { fail(res, 400, "body must be JSON"); return true; }
  const path = join(DIR, `deal-${sha.slice(0, 16)}.json`);
  try {
    if (m[2] === "fund") {
      // The deal is built here from what this provider checked itself: the sentinels it left unopened.
      const terms = provider.bondTerms(sha);
      if (!terms) throw new Error("no completed cut and choose for this blob");
      const height = (await rpc("getblockcount", [], RPC)) as number;
      const tEnd = Number(body.t_end);
      if (!Number.isSafeInteger(tEnd) || tEnd < height + 300) throw new Error("t_end must be at least 300 blocks away");
      const deal = {
        name: NAME, sha256: sha, provider_url: provider.url, provider_x: me.x, client_x: String(body.client_x), t_end: tEnd,
        sentinels: terms.map((c) => ({ s: c.s, h: c.h, hs: c.hs ?? [c.h] })),
      };
      writeFileSync(path, JSON.stringify(deal, null, 2));
      const p = await tool.run("bond-fund", path);
      log({ event: "bond-funded", sha: sha.slice(0, 12), fund_txid: p.fund_txid });
      json(res, 200, { deal, ...p });
    } else {
      writeFileSync(path.replace(".json", ".c.json"), JSON.stringify({ sig_c_respond: body.sig_c_respond }));
      const ok = await tool.run("bond-accept", path);
      bonds.set(sha, { path, next: 0, k: provider.bondTerms(sha)!.length });
      log({ event: "bond-live", sha: sha.slice(0, 12), ...ok });
      json(res, 200, ok);
    }
  } catch (e) { fail(res, 409, (e as Error).message); }
  return true;
}

const provider = await startProvider({
  dir: join(DIR, "blobs"), key: nostrKey, payee, priceMsatPerChunkEpoch: PRICE, routes: bondRoute,
  info: { bond_x: me.x, channel_payee: payee.nodeId, ...(lnNode ? { ln_uri: lnNode.uri } : {}), ...(chainPayee ? { onchain_key: chainPayee.payKey.x, network: NETWORK } : {}) },
});
chanPayee?.setBaseUrl(provider.url);
const rc = await RelayClient.connect(RELAY);
servePdpOverNostr(rc, nostrKey, provider.pdpAnswer, log, provider.stash);
if (ZK) zk = startZkEpochs(provider, rc, nostrKey, payee, { epochBlocks: ZK_EPOCH, q: ZK_Q, fromHeight: ZK_FROM, priceMsat: ZK_PRICE, rpcUrl: RPC, workDir: join(DIR, "zk"), log });

// The on-chain agent: for each live bond, try the next sentinel. bsb-bond answers only once the challenge
// is confirmed, and reads r from it.
let stopping = false;
(async () => {
  while (!stopping) {
    for (const [sha, b] of bonds) {
      if (b.next >= b.k) continue;
      try {
        const r = await tool.run("bond-respond", b.path, String(b.next));
        if (r.status === "responded" || r.status === "already") {
          log({ event: "bond-respond", sha: sha.slice(0, 12), i: b.next, ...r });
          b.next++;
        } else if (r.status !== "idle") {
          const key = `${b.next}:${r.status}:${r.error ?? ""}`;
          if (b.last !== key) log({ event: "bond-respond", sha: sha.slice(0, 12), i: b.next, ...r });
          b.last = key;
        }
      } catch (e) { log({ event: "watch-error", error: (e as Error).message }); }
    }
    await sleep(150);
  }
})();

const admin = createServer(async (req, res) => {
  if (req.headers["x-admin-token"] !== TOKEN) return fail(res, 403, "admin token required");
  const u = new URL(req.url ?? "/", "http://x");
  try {
    const body = req.method === "POST" ? JSON.parse(String(await readBody(req, 1 << 22)) || "{}") : {};
    if (u.pathname === "/admin/misbehave") {
      if (body.kind === "delete") provider.deleteChunks(body.sha, body.indices);
      else if (body.kind === "outsource") provider.outsource(body.sha, body.from);
      else throw new Error("kind must be delete or outsource");
      log({ event: "misbehave", kind: body.kind });
      return json(res, 200, { ok: true });
    }
    if (u.pathname === "/admin/sweep") {
      // The receipts naming this provider, from the relay; the wallet's own rescan is the check that
      // each output exists.
      if (!chainPayee) throw new Error("not paid on chain");
      const evs = await rc.query({ kinds: [KIND_PAYMENT_RECEIPT], "#p": [nostrKey.x] });
      const receipts = evs.map((e) => JSON.parse(e.content) as PaymentReceipt);
      const wallet = `bsb-${NAME}-paid`;
      const s = await chainPayee.sweep((m, p) => rpc(m, p, RPC), (m, p) => rpc(m, p, `${RPC}/wallet/${wallet}`), wallet, receipts, me.fee_address, Number(body.fee_rate ?? 5));
      log({ event: "onchain-sweep", ...s, receipts: receipts.length });
      return json(res, 200, s);
    }
    if (u.pathname === "/admin/close-channel") return json(res, 200, chanPayee ? await chanPayee.close(String(body.client_x)) : await lnPayee!.close(String(body.peer)));
    if (u.pathname === "/admin/stop") { json(res, 200, { ok: true }); void shutdown(); return; }
    if (u.pathname === "/admin/zk-stop") { zk?.stop(); log({ event: "zk-stopped" }); return json(res, 200, { ok: true }); }
    if (u.pathname === "/admin/ln-stop") { await lnNode?.stop(); log({ event: "ln-stopped" }); return json(res, 200, { ok: true }); }
    if (u.pathname === "/admin/refund") {
      const b = bonds.get(String(body.sha));
      if (!b) throw new Error("no such bond");
      return json(res, 200, await tool.run("bond-refund", b.path, String(b.next)));
    }
    if (u.pathname === "/admin/state") {
      return json(res, 200, { bonds: [...bonds].map(([sha, b]) => ({ sha, answered: b.next, k: b.k })), channels: [...(chanPayee?.channels ?? [])].map(([c, ch]) => ({ client: c, paid: ch.paid })) });
    }
    fail(res, 404, "not found");
  } catch (e) { fail(res, 500, (e as Error).message); }
});
await new Promise<void>((r) => admin.listen(0, "127.0.0.1", r));
const adminAddr = admin.address();
if (!adminAddr || typeof adminAddr === "string") throw new Error("admin did not bind");

async function shutdown() {
  if (stopping) return;
  stopping = true; zk?.stop(); rc.close(); admin.close(); await provider.close();
  await lnNode?.stop();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
// On Windows the parent's kill() ends this process without a SIGTERM handler running, which would leave
// its lnd behind. The orchestrator asks /admin/stop first; this is the backstop if the parent dies.
setInterval(() => { try { process.kill(process.ppid, 0); } catch { void shutdown(); } }, 1000).unref();
log({ ready: true, url: provider.url, ln: lnNode?.uri, admin: `http://127.0.0.1:${adminAddr.port}`, nostr: nostrKey.x, bond_x: me.x, fee_address: me.fee_address, pid: process.pid });
