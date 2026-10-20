// One storage provider as its own OS process: a Blossom server with PDP, sentinel and cut-and-choose
// endpoints, NIP-44 epoch challenges over a Nostr relay, payment-channel payee, and an on-chain agent that
// watches its bonds and answers any challenge it finds on chain, reading the revealed r from the
// challenge transaction itself.
//
//   node layer1/provider.ts --name <slug> --seed <seed> --dir <dir> --relay <ws url> --admin-token <t>
//                           [--price <msat per chunk-epoch>] [--rpc <url>]
//
// It prints one JSON line, {"ready": true, ...}, and then one JSON line per event. Its keys come from
// --seed and never leave this process: the Nostr key, the bond and channel key (bsb-bond, BSB_SEED), and
// its fee wallet.
//
// The admin port (127.0.0.1, token required) exists for the demo only. It lets the orchestrator make
// this provider misbehave, and tells it when to close its channel and refund its bond.

import { createServer } from "node:http";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { keyFromSeed } from "../model/schnorr.ts";
import { fail, json, readBody, startProvider } from "./blossom.ts";
import { BondTool, rpc } from "./bondtool.ts";
import { ChannelPayee } from "./channel.ts";
import { servePdpOverNostr } from "./nostr-pdp.ts";
import { RelayClient } from "./relay.ts";

const arg = (name: string, dflt?: string) => {
  const i = process.argv.indexOf(`--${name}`);
  if (i > 0) return process.argv[i + 1];
  if (dflt === undefined) throw new Error(`--${name} is required`);
  return dflt;
};
const NAME = arg("name"), SEED = arg("seed"), DIR = arg("dir"), RELAY = arg("relay"), TOKEN = arg("admin-token");
const PRICE = Number(arg("price", "2000"));
const RPC = arg("rpc", process.env.BSB_RPC ?? "http://127.0.0.1:18543");
mkdirSync(DIR, { recursive: true });

const log = (ev: Record<string, unknown>) => process.stdout.write(JSON.stringify({ t: Date.now(), provider: NAME, ...ev }) + "\n");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const nostrKey = keyFromSeed(`nostr|${SEED}`);
const tool = new BondTool(SEED, RPC);
const me = await tool.run("info");
const payee = new ChannelPayee(me.x, tool, DIR);
const bonds = new Map<string, { path: string; next: number; k: number; last?: string }>();

async function bondRoute(req: Parameters<typeof payee.route>[0], res: Parameters<typeof payee.route>[1], url: URL): Promise<boolean> {
  if (await payee.route(req, res, url)) return true;
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
  info: { bond_x: me.x, channel_payee: payee.nodeId },
});
payee.setBaseUrl(provider.url);
const rc = await RelayClient.connect(RELAY);
servePdpOverNostr(rc, nostrKey, provider.pdpAnswer, log, provider.stash);

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
    if (u.pathname === "/admin/close-channel") return json(res, 200, await payee.close(String(body.client_x)));
    if (u.pathname === "/admin/refund") {
      const b = bonds.get(String(body.sha));
      if (!b) throw new Error("no such bond");
      return json(res, 200, await tool.run("bond-refund", b.path, String(b.next)));
    }
    if (u.pathname === "/admin/state") {
      return json(res, 200, { bonds: [...bonds].map(([sha, b]) => ({ sha, answered: b.next, k: b.k })), channels: [...payee.channels].map(([c, ch]) => ({ client: c, paid: ch.paid })) });
    }
    fail(res, 404, "not found");
  } catch (e) { fail(res, 500, (e as Error).message); }
});
await new Promise<void>((r) => admin.listen(0, "127.0.0.1", r));
const adminAddr = admin.address();
if (!adminAddr || typeof adminAddr === "string") throw new Error("admin did not bind");

process.on("SIGTERM", async () => { stopping = true; rc.close(); admin.close(); await provider.close(); process.exit(0); });
log({ ready: true, url: provider.url, admin: `http://127.0.0.1:${adminAddr.port}`, nostr: nostrKey.x, bond_x: me.x, fee_address: me.fee_address, pid: process.pid });
