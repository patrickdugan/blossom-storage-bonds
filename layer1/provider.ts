// One storage provider as its own OS process: a Blossom server with PDP, sentinel and cut-and-choose
// endpoints, NIP-44 epoch challenges over Nostr, a payee, and an on-chain agent that watches its bonds
// and answers any challenge it finds on chain, reading the revealed r from the challenge transaction
// itself.
//
//   node layer1/provider.ts --name <slug> --dir <dir> --relays <ws url,...> --admin-token <t>
//                           [--network regtest|signet|testnet4] [--confs N] [--seed <seed>] [--rpc <url>]
//                           [--host 127.0.0.1] [--port 0] [--public-url <url>] [--failure-domain <text>]
//                           [--price <msat per chunk-epoch>] [--bond-max-sats N] [--min-term <blocks>] [--max-term <blocks>]
//                           [--uploaders <pubkey,...>] [--no-auto-refund]
//                           [--pay channel|ln|onchain] [--lnd <path>] [--ln-listen host:port] [--ln-external host:port]
//                           [--zk --epoch-blocks 10 --zk-q 8 --zk-from <height> --zk-price <msat>] [--invoice-ttl <s>]
//
// With --pay channel (the default) the payee is the one-way Bitcoin channel (layer1/channel.ts). With
// --pay ln this process starts its own lnd under <dir>/lnd, with its own wallet and macaroon, and bills
// each epoch with a BOLT 11 invoice from that node (layer1/lnd.ts). With --pay onchain it bills with
// invoices signed by its Nostr key and paid to taproot outputs tweaked from its own pay key
// (layer1/onchain.ts); /admin/sweep spends what the published receipts paid it into its fee address.
//
// It publishes its offer on the relays (layer1/deals.ts) and makes deals over them: a client's proposal,
// after cut and choose on this server, is checked against this provider's own records, the bond is
// funded from its own wallet, and the acceptance names it; the client's seal carries its presignatures,
// and only then does `live` carry this provider's. Deal files and cut-and-choose records stay in <dir>,
// so a restarted provider resumes watching its bonds (sealed or not) and honours deals in flight. A bond
// whose client never seals is refunded at t_end like any other; --max-term caps how long that can be,
// and --uploaders limits who can store, and so propose, at all.
//
// Keys: on regtest they come from --seed, a fixed label, so runs reproduce. On any other network --seed
// is optional and must be 32 fresh random bytes in hex; without it the provider makes its own on first
// start and keeps it in <dir>/party.seed (net.ts partySeed). They never leave this process: the Nostr
// key, the bond and channel key (bsb-bond, BSB_SEED), and its fee wallet. Its Lightning key lives in its
// own lnd. Off regtest the provider also refunds its own bond once the term ends, and says so on Nostr.
//
// It prints one JSON line, {"ready": true, ...}, and then one JSON line per event. The admin port
// (127.0.0.1, token required) lets an operator or the demo orchestrator make it misbehave, close its
// channel, sweep, and refund.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { keyFromSeed } from "../model/schnorr.ts";
import { fail, json, readBody, startProvider } from "./blossom.ts";
import { BondTool, rpc } from "./bondtool.ts";
import { ChannelPayee } from "./channel.ts";
import { KIND_DEAL, dealEvent, offerEvent, parseDeal, publishSure, type OfferTerms, type Proposal } from "./deals.ts";
import type { Payee } from "./lightning.ts";
import { LndNode, LndPayee, assertLndNetwork, lndExe } from "./lnd.ts";
import { partySeed, txConfirmations, useNetwork } from "./net.ts";
import type { NostrEvent } from "./nostr.ts";
import { KIND_PAYMENT_RECEIPT, OnchainPayee, type PaymentReceipt } from "./onchain.ts";
import { servePdpOverNostr } from "./nostr-pdp.ts";
import { RelayPool } from "./relay.ts";
import { startZkEpochs, zkInvoiceTtlSec } from "./zk-provider.ts";

const opt = (name: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : undefined; };
const arg = (name: string, dflt?: string) => {
  const v = opt(name);
  if (v !== undefined) return v;
  if (dflt === undefined) throw new Error(`--${name} is required`);
  return dflt;
};
const NET = useNetwork();
const NAME = arg("name"), DIR = arg("dir"), TOKEN = arg("admin-token");
const RELAYS = RelayPool.parse(arg("relays", arg("relay", "")));
if (RELAYS.length === 0) throw new Error("--relays is required");
mkdirSync(DIR, { recursive: true });
const SEED = NET.canMine ? arg("seed") : partySeed(NET, DIR, "", opt("seed"));
const PRICE = Number(arg("price", "2000"));
const PAY = arg("pay", "channel");
if (PAY !== "channel" && PAY !== "ln" && PAY !== "onchain") throw new Error("--pay must be channel, ln or onchain");
if (PAY === "ln") assertLndNetwork(NET.name);
const RPC = process.env.BSB_RPC!;
const BOND_MAX = Number(arg("bond-max-sats", NET.canMine ? "100000000" : "1000000"));
const MIN_TERM = Number(arg("min-term", "300"));
// The longest a client may lock this provider's bond for (about 30 days on public networks).
const MAX_TERM = Number(arg("max-term", NET.canMine ? "100000" : "4320"));
// Who may upload, and so propose deals: anyone with a valid BUD-11 token unless listed.
const UPLOADERS = opt("uploaders")?.split(",").filter(Boolean);
const AUTO_REFUND = !NET.canMine && !process.argv.includes("--no-auto-refund");
// --zk: prove holdings every --epoch-blocks blocks from --zk-from on, with --zk-q challenges.
const ZK = process.argv.includes("--zk");
const ZK_EPOCH = Number(arg("epoch-blocks", "10")), ZK_Q = Number(arg("zk-q", "8")), ZK_FROM = Number(arg("zk-from", "0"));
const ZK_PRICE = Number(arg("zk-price", "512000"));
const INVOICE_TTL = zkInvoiceTtlSec(NET.name, opt("invoice-ttl"));

const log = (ev: Record<string, unknown>) => process.stdout.write(JSON.stringify({ t: Date.now(), provider: NAME, ...ev }) + "\n");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const nostrKey = keyFromSeed(`nostr|${SEED}`);
const tool = new BondTool(SEED, RPC);
const me = await tool.run("info");
const lnNode = PAY === "ln"
  ? await LndNode.start({ bin: arg("lnd", lndExe()), dir: join(DIR, "lnd"), alias: `bsb-${NAME}`, network: NET.name, listen: opt("ln-listen"), externalHost: opt("ln-external"), chanConfs: NET.confs })
  : undefined;
const lnPayee = lnNode && new LndPayee(lnNode, !NET.canMine);
const chainPayee = PAY === "onchain" ? new OnchainPayee(nostrKey, keyFromSeed(`onchain|${SEED}`), NET.name, join(DIR, "onchain-invoices.ledger")) : undefined;
const chanPayee = PAY === "channel" ? new ChannelPayee(me.x, tool, DIR, join(DIR, "channel-payments.ledger")) : undefined;
const payee: Payee = lnPayee ?? chainPayee ?? chanPayee!;

/** A funded bond: its deal file and term; once sealed, the next sentinel it may be challenged on; and
 *  its refund, which counts only at the network's depth. */
type Bond = {
  path: string; sealed: boolean; next: number; k: number; tEnd: number; client?: string; last?: string; refundTx?: string; waiting?: string; settled?: string;
  /** Each sentinel's Challenge_i and Respond_i txids. The deal fixes them (txids leave out the witness). */
  ids?: { challenge: string; respond: string }[];
  /** The chain tip at which the agent last looked at this bond: once per tip, since nothing it acts on
   *  (a confirmed challenge, an answer's depth) changes without one. A tip hash, not a height, so that a
   *  reorg to the same height is looked at too, and an answer it dropped is sent again. */
  checkedAt?: string;
};
const bonds = new Map<string, Bond>();
const dealPath = (sha: string) => join(DIR, `deal-${sha.slice(0, 16)}.json`);

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
    const ok = await lnPayee!.accept(String(body.channel_point), String(body.client_pubkey), NET.canMine ? 60_000 : 3_600_000);
    log({ event: "ln-channel", ...ok });
    json(res, 200, ok);
  } catch (e) { fail(res, 402, (e as Error).message); }
  return true;
}

async function routes(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
  if (chanPayee ? await chanPayee.route(req, res, url) : lnNode ? await lnRoute(req, res, url) : false) return true;
  if (zk && (await zk.route(req, res, url))) return true;
  return false;
}

const provider = await startProvider({
  dir: join(DIR, "blobs"), key: nostrKey, payee, priceMsatPerChunkEpoch: PRICE, routes,
  host: arg("host", "127.0.0.1"), port: Number(arg("port", "0")), publicUrl: opt("public-url"), uploaders: UPLOADERS,
  info: { bond_x: me.x, channel_payee: payee.nodeId, network: NET.name, ...(lnNode ? { ln_uri: lnNode.uri } : {}), ...(chainPayee ? { onchain_key: chainPayee.payKey.x } : {}) },
});
chanPayee?.setBaseUrl(provider.url);
const rc = await RelayPool.connect(RELAYS, log);
servePdpOverNostr(rc, nostrKey, provider.pdpAnswer, log, provider.stash);
if (ZK) {
  zk = startZkEpochs(provider, rc, nostrKey, payee, {
    epochBlocks: ZK_EPOCH, q: ZK_Q, fromHeight: ZK_FROM, priceMsat: ZK_PRICE, invoiceTtlSec: INVOICE_TTL, rpcUrl: RPC, workDir: join(DIR, "zk"), log,
    confs: NET.confs, pollMs: NET.canMine ? 400 : NET.pollMs,
  });
}

// ── the offer ──
const terms: OfferTerms = {
  network: NET.name, blossom: provider.url, price_msat_per_chunk_epoch: PRICE,
  bond: { x: me.x, max_sats: BOND_MAX, delta: 144, min_term_blocks: MIN_TERM, max_term_blocks: MAX_TERM },
  pay: { kind: PAY, payee: payee.nodeId, ...(lnNode ? { ln_uri: lnNode.uri } : {}), ...(chainPayee ? { onchain_key: chainPayee.payKey.x } : {}) },
  ...(ZK ? { zk: { epoch_blocks: ZK_EPOCH, q: ZK_Q, price_msat: ZK_PRICE, hash: "blake", mode: 1 } } : {}),
  ...(opt("failure-domain") ? { failure_domain: opt("failure-domain") } : {}),
};
const offer = offerEvent(nostrKey, terms);
await publishSure(rc, offer);
// Public relays drop old events; off regtest the offer is renewed every six hours.
if (!NET.canMine) setInterval(() => { void publishSure(rc, offerEvent(nostrKey, terms)).catch((e) => log({ event: "offer-error", error: (e as Error).message })); }, 6 * 3_600_000).unref();

// ── deals over Nostr ──
const HEX64 = /^[0-9a-f]{64}$/;
const reject = (ev: NostrEvent, why: string) =>
  publishSure(rc, dealEvent(nostrKey, NET.name, "reject", { why }, [["p", ev.pubkey], ["e", ev.id]])).then(() => log({ event: "deal-reject", why }));

/** A proposal: check it against this provider's own records, fund the bond, and accept. The provider's
 *  own presignatures come only with `live`, after it holds the client's (deals.ts). A proposal already
 *  funded (sent twice, or seen again after a restart) gets the same acceptance from the files in <dir>. */
async function onPropose(ev: NostrEvent, pr: Proposal) {
  const sha = String(pr.sha256);
  if (pr.network !== NET.name || !HEX64.test(sha) || !HEX64.test(String(pr.client_x))) return reject(ev, "malformed proposal");
  const tEnd = Number(pr.t_end), bondSats = Number(pr.bond_sats);
  const path = dealPath(sha);
  let p: Record<string, any>;
  let deal: Record<string, unknown>;
  if (existsSync(path.replace(".json", ".p.json"))) {
    deal = JSON.parse(readFileSync(path, "utf8"));
    if (deal.client_nostr !== ev.pubkey || deal.t_end !== tEnd || deal.bond_sats !== bondSats || deal.client_x !== pr.client_x) return reject(ev, "a different deal on this blob is already funded");
    p = JSON.parse(readFileSync(path.replace(".json", ".p.json"), "utf8"));
  } else {
    if (provider.uploader(sha) !== ev.pubkey) return reject(ev, "only the key that uploaded the blob can propose a deal on it");
    const kept = provider.bondTerms(sha), commit = provider.bondCommitment(sha);
    if (!kept || !commit) return reject(ev, "no completed cut and choose for this blob");
    if (commit.root !== pr.commitments_root || commit.m !== pr.m || commit.k !== pr.k) return reject(ev, "the commitments differ from those cut and choose ran on");
    const height = (await rpc("getblockcount", [], RPC)) as number;
    if (!Number.isSafeInteger(tEnd) || tEnd < height + MIN_TERM || tEnd > height + MAX_TERM) return reject(ev, `t_end must be ${MIN_TERM} to ${MAX_TERM} blocks away`);
    if (!Number.isSafeInteger(bondSats) || bondSats < 10_000 || bondSats > BOND_MAX) return reject(ev, `bond_sats must be within 10000..${BOND_MAX}`);
    // The deal is built here from what this provider checked itself: the sentinels it left unopened. Its
    // own copy names the server's loopback address, which its agent calls to answer a challenge.
    deal = {
      name: NAME, network: NET.name, sha256: sha, provider_url: provider.localUrl, provider_x: me.x, client_x: String(pr.client_x), client_nostr: ev.pubkey,
      t_end: tEnd, bond_sats: bondSats, sentinels: kept.map((c) => ({ s: c.s, h: c.h, hs: c.hs ?? [c.h] })),
    };
    writeFileSync(path, JSON.stringify(deal, null, 2));
    p = await tool.run("bond-fund", path);
    // Refunded at t_end whether or not the client ever seals.
    bonds.set(sha, { path, sealed: false, next: 0, k: kept.length, tEnd, client: ev.pubkey });
    log({ event: "bond-funded", sha: sha.slice(0, 12), fund_txid: p.fund_txid, bond_sats: bondSats });
  }
  const { sig_p_challenge: _held, ...funding } = p;
  const acc = dealEvent(nostrKey, NET.name, "accept", { deal: { ...deal, provider_url: provider.url }, ...funding }, [["p", ev.pubkey], ["e", ev.id], ["x", sha]]);
  await publishSure(rc, acc);
}

/** A seal: the client's presignatures. Check them (bond-accept), arm the bond, and only then hand over
 *  this provider's presignatures on every Challenge_i. A seal seen again gets the same answer. */
async function onSeal(ev: NostrEvent, content: any) {
  const sha = ev.tags.find((t) => t[0] === "x")?.[1] ?? "";
  const path = dealPath(sha);
  if (!HEX64.test(sha) || !existsSync(path) || !existsSync(path.replace(".json", ".p.json"))) return reject(ev, "no such deal");
  const deal = JSON.parse(readFileSync(path, "utf8"));
  if (deal.client_nostr !== ev.pubkey) return reject(ev, "seal from another key than the proposal's");
  const b = bonds.get(sha);
  if (!b?.sealed) {
    const cPath = path.replace(".json", ".c.json");
    writeFileSync(cPath, JSON.stringify({ sig_c_respond: content.sig_c_respond }));
    try { await tool.run("bond-accept", path); } catch (e) { rmSync(cPath, { force: true }); return reject(ev, (e as Error).message); }
    if (b) b.sealed = true;
    else bonds.set(sha, { path, sealed: true, next: 0, k: deal.sentinels.length, tEnd: deal.t_end, client: ev.pubkey });
    log({ event: "bond-live", sha: sha.slice(0, 12), respond_signatures: deal.sentinels.length });
  }
  const { sig_p_challenge } = JSON.parse(readFileSync(path.replace(".json", ".p.json"), "utf8"));
  await publishSure(rc, dealEvent(nostrKey, NET.name, "live", { ok: true, respond_signatures: deal.sentinels.length, sig_p_challenge }, [["p", ev.pubkey], ["e", ev.id], ["x", sha]]));
}

let dealQueue = Promise.resolve();
rc.subscribe([{ kinds: [KIND_DEAL], "#p": [nostrKey.x] }], (ev) => {
  const d = parseDeal(ev, NET.name);
  if (!d || (d.stage !== "propose" && d.stage !== "seal")) return;
  dealQueue = dealQueue.then(async () => {
    try {
      if (d.stage === "propose") await onPropose(ev, d.content);
      else await onSeal(ev, d.content);
    } catch (e) {
      // Say why, rather than leave the client waiting out its timeout.
      log({ event: "deal-error", stage: d.stage, error: (e as Error).message });
      await reject(ev, (e as Error).message.slice(0, 300)).catch(() => undefined);
    }
  });
});

// After a restart: every funded deal in <dir> is watched again. A sealed one from the first sentinel not
// yet answered (deep enough), and every one for its refund.
for (const f of readdirSync(DIR).filter((f) => /^deal-[0-9a-f]{16}\.p\.json$/.test(f))) {
  const path = join(DIR, f.replace(".p.json", ".json"));
  const deal = JSON.parse(readFileSync(path, "utf8"));
  if (bonds.has(deal.sha256) || existsSync(path.replace(".json", ".settled.json"))) continue;
  try {
    const sealed = existsSync(path.replace(".json", ".c.json"));
    let next = 0;
    if (sealed) {
      const st = await tool.run("bond-status", path);
      next = (st.states as any[]).findIndex((s) => !(s.respond >= NET.confs));
      if (next < 0) next = st.states.length;
    }
    const rf = path.replace(".json", ".refund.json");
    const refundTx = existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")).refund_txid : undefined;
    bonds.set(deal.sha256, { path, sealed, next, k: deal.sentinels.length, tEnd: deal.t_end, client: deal.client_nostr, refundTx });
    log({ event: "bond-resumed", sha: String(deal.sha256).slice(0, 12), sealed, next, refund: refundTx ?? null });
  } catch (e) { log({ event: "resume-error", path, error: (e as Error).message }); }
}

/** Broadcast the refund from Bond_<next>, once the term is over. It counts only at depth (settle). */
async function refund(sha: string, b: Bond) {
  const r = await tool.run("bond-refund", b.path, String(b.next));
  b.refundTx = r.txid;
  writeFileSync(b.path.replace(".json", ".refund.json"), JSON.stringify({ refund_txid: r.txid, from_state: b.next }));
  log({ event: "bond-refund", sha: sha.slice(0, 12), ...r });
  return r;
}

/** Once per block: a broadcast refund counts at the network's depth; one a reorg dropped, or that lost
 *  to a challenge, is cleared, and the respond loop goes on answering. Off regtest the agent broadcasts
 *  the refund itself at t_end. A bond ends only refunded at depth, or after Δ with a challenge it did
 *  not answer (the client can forfeit it then). */
async function settle(sha: string, b: Bond, h: number) {
  if (b.settled) return;
  if (b.refundTx) {
    const t = await rpc("getrawtransaction", [b.refundTx, true], RPC).catch(() => undefined);
    if (t && (t.confirmations ?? 0) >= NET.confs) {
      b.settled = b.refundTx;
      writeFileSync(b.path.replace(".json", ".settled.json"), JSON.stringify({ refund_txid: b.refundTx, confirmations: t.confirmations }));
      log({ event: "bond-settled", sha: sha.slice(0, 12), refund_txid: b.refundTx, confirmations: t.confirmations });
      if (b.client) await publishSure(rc, dealEvent(nostrKey, NET.name, "settled", { refund_txid: b.refundTx, sha256: sha }, [["p", b.client], ["x", sha]])).catch(() => undefined);
      return;
    }
    if (t) return;
    log({ event: "refund-dropped", sha: sha.slice(0, 12), refund_txid: b.refundTx });
    b.refundTx = undefined;
  }
  if (!AUTO_REFUND || h < b.tEnd) return;
  try { await refund(sha, b); b.waiting = undefined; }
  catch (e) {
    const m = (e as Error).message;
    if (!/missingorspent|missing-inputs/.test(m)) { log({ event: "refund-error", sha: sha.slice(0, 12), error: m }); return; }
    // Bond_<next> is spent by Challenge_<next>. Answered, the respond loop moves `next` on and the refund
    // follows from there; unanswered for Δ, the client can take it.
    const st = await tool.run("bond-status", b.path);
    const s = st.states[b.next];
    if (s && s.challenge !== null && s.respond === null && s.challenge >= 144 + NET.confs) {
      b.settled = "forfeitable";
      log({ event: "bond-gone", sha: sha.slice(0, 12), i: b.next, why: "challenge unanswered for Δ" });
    } else if (b.waiting !== m) { b.waiting = m; log({ event: "refund-waiting", sha: sha.slice(0, 12), i: b.next, why: "a challenge holds the bond; answering it first" }); }
  }
}

/** Whether bsb-bond bond-respond has anything to do for the next sentinel, asked over this process's own
 *  RPC connection rather than by spawning bsb-bond: an idle bond-respond costs a process, a TCP
 *  connection to bitcoind and three calls, and the agent used to ask every tick. bond-respond acts only when
 *  Respond_i is known (to report its depth) or Challenge_i is confirmed (to answer it), so nothing else
 *  needs it. A confirmed challenge whose output is spent by something other than our answer was
 *  forfeited: the bond is over. */
async function respondWork(sha: string, b: Bond): Promise<boolean> {
  if (!b.ids) b.ids = ((await tool.run("bond-status", b.path)).states as any[]).map((s) => ({ challenge: s.challenge_txid, respond: s.respond_txid }));
  const id = b.ids[b.next];
  if ((await txConfirmations(id.respond, RPC)) !== null) return true;
  if (!(await txConfirmations(id.challenge, RPC))) return false;
  if ((await rpc("gettxout", [id.challenge, 0, true], RPC)) !== null) return true;
  if ((await txConfirmations(id.respond, RPC)) !== null) return true;   // our answer arrived between the calls
  b.settled = "forfeited";
  log({ event: "bond-gone", sha: sha.slice(0, 12), i: b.next, why: "the challenge output was spent without our answer (forfeited)" });
  return false;
}

// The on-chain agent: for each sealed bond, try the next sentinel. bsb-bond answers only once the
// challenge is confirmed, and reads r from it. Answering goes on while a refund is pending. Each tick asks
// only the tip. Once per new tip it looks at each bond over this process's kept-alive connection, and runs
// bsb-bond only if there is work.
let stopping = false;
(async () => {
  let lastHeight = -1, tip = "", height = -1;
  while (!stopping) {
    try {
      const t: string = await rpc("getbestblockhash", [], RPC);
      if (t !== tip) { height = await rpc("getblockcount", [], RPC); tip = t; }
    } catch (e) { log({ event: "watch-error", error: (e as Error).message }); }
    for (const [sha, b] of bonds) {
      if (b.settled || !b.sealed) continue;
      if (b.next < b.k && tip && b.checkedAt !== tip) {
        b.checkedAt = tip;
        try {
          if (!(await respondWork(sha, b))) continue;
          const r = await tool.run("bond-respond", b.path, String(b.next));
          if (r.status === "responded" || r.status === "already") {
            // On regtest the orchestrator mines at once, so an answer counts when sent. Elsewhere it counts
            // at the network's depth; until then each pass asks again, which resends one a reorg dropped.
            const deep = NET.canMine || (r.status === "already" && r.confirmations >= NET.confs);
            const key = `${b.next}:${r.status}`;
            if (deep || r.status === "responded" || b.last !== key) log({ event: "bond-respond", sha: sha.slice(0, 12), i: b.next, ...r });
            b.last = key;
            if (deep) b.next++;
          } else if (r.status !== "idle") {
            const key = `${b.next}:${r.status}:${r.error ?? ""}`;
            if (b.last !== key) log({ event: "bond-respond", sha: sha.slice(0, 12), i: b.next, ...r });
            b.last = key;
          }
        } catch (e) { b.checkedAt = undefined; log({ event: "watch-error", error: (e as Error).message }); }   // look again next tick
      }
    }
    if (height >= 0 && height !== lastHeight && (AUTO_REFUND || [...bonds.values()].some((b) => b.refundTx && !b.settled))) {
      lastHeight = height;
      for (const [sha, b] of bonds) await settle(sha, b, height).catch((e) => log({ event: "watch-error", error: (e as Error).message }));
    }
    await sleep(NET.pollMs);
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
      else if (body.kind === "withhold") provider.withhold(body.sha);
      else throw new Error("kind must be delete, outsource or withhold");
      log({ event: "misbehave", kind: body.kind });
      return json(res, 200, { ok: true });
    }
    if (u.pathname === "/admin/sweep") {
      // The receipts naming this provider, from the relays; the wallet's own rescan is the check that
      // each output exists.
      if (!chainPayee) throw new Error("not paid on chain");
      const evs = await rc.query({ kinds: [KIND_PAYMENT_RECEIPT], "#p": [nostrKey.x] });
      const receipts = evs.map((e) => JSON.parse(e.content) as PaymentReceipt);
      // Named after this provider's pay key, so two runs (or two providers called alike) on one long-lived
      // node never share a sweep wallet. Regtest keeps the earlier name.
      const wallet = NET.canMine ? `bsb-${NAME}-paid` : `bsb-paid-${chainPayee.payKey.x.slice(0, 16)}`;
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
      return json(res, 200, await refund(String(body.sha), b));
    }
    if (u.pathname === "/admin/state") {
      return json(res, 200, { bonds: [...bonds].map(([sha, b]) => ({ sha, sealed: b.sealed, answered: b.next, k: b.k, t_end: b.tEnd, refund: b.refundTx ?? null, settled: b.settled ?? null })), channels: [...(chanPayee?.channels ?? [])].map(([c, ch]) => ({ client: c, paid: ch.paid })) });
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
// A provider started by hand (its parent a shell that stays) is unaffected.
setInterval(() => { try { process.kill(process.ppid, 0); } catch { void shutdown(); } }, 1000).unref();
log({ ready: true, network: NET.name, url: provider.url, ln: lnNode?.uri, admin: `http://127.0.0.1:${adminAddr.port}`, nostr: nostrKey.x, bond_x: me.x, fee_address: me.fee_address, offer: offer.id, relays: rc.connected(), pid: process.pid });
