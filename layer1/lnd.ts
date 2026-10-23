// Real Lightning for pay per proof: LND nodes on the regtest bitcoind, behind the same Payee/Payer
// interfaces as the stub and the one-way channel. Each party runs its own lnd process with its own
// wallet, TLS certificate and admin macaroon, and talks to it over LND's REST API on 127.0.0.1. Nothing
// else changes: the provider's invoice is a BOLT 11 string signed by its node key, the client decodes
// it itself (layer1/bolt11.ts) and checks the amount and the payee before paying, and the preimage LND
// returns is checked against the payment hash.
//
// LND polls bitcoind over RPC (bitcoind.rpcpolling), so the node from scripts/regtest-node.sh needs no
// ZMQ. Tested with lnd v0.21.4-beta (lnd-windows-amd64); point BSB_LND at the lnd binary. On signet
// (LndConfig.network, from net.ts) it runs with --bitcoin.signet, takes bitcoind's login from the same
// environment as everything else (net.ts rpcAuth), polls every 5 s, and can listen on a public address
// so that peers on other machines reach it. Its wallet is a fresh random one per node, as on regtest.
// On a private signet (layer1/private-signet.ts) set BSB_SIGNET_CHALLENGE to its challenge in hex.
// Testnet4 Lightning is refused until compatibility with this lnd version is verified; use --pay onchain.
//
// Load on bitcoind: lnd opens a new TCP connection for every RPC, and fetches every block (a new wallet
// also rescans the chain, since every regtest block looks recent). Each connection then sits in
// TIME_WAIT. On Windows, five nodes following a block every 150 ms run out of ephemeral ports within
// minutes, so the market stops its nodes once payments are settled (layer1/market.ts).

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, openSync, readdirSync, readFileSync, closeSync } from "node:fs";
import { request } from "node:https";
import { createServer } from "node:net";
import { join } from "node:path";
import { decodeBolt11, type Bolt11 } from "./bolt11.ts";
import { defaultRpcUrl, rpcAuth, type NetName } from "./net.ts";
import { preimageMatches, type Invoice, type Payee, type Payer } from "./lightning.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The lnd binary: BSB_LND, else the user-scope install under %LOCALAPPDATA%\Programs\lnd, else "lnd". */
export function lndExe(): string {
  if (process.env.BSB_LND) return process.env.BSB_LND;
  const base = process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "Programs", "lnd");
  if (base && existsSync(base)) {
    const hit = readdirSync(base).filter((d) => d.startsWith("lnd-")).sort().reverse().map((d) => join(base, d, "lnd.exe")).find((p) => existsSync(p));
    if (hit) return hit;
  }
  return "lnd";
}

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const a = s.address();
  await new Promise<void>((r) => s.close(() => r()));
  if (!a || typeof a === "string") throw new Error("no free port");
  return a.port;
}

export interface LndConfig {
  bin?: string;
  dir: string;
  alias: string;
  /** bitcoind RPC; defaults to BSB_RPC and the login net.ts rpcAuth() finds (on regtest,
   *  scripts/regtest-node.sh's test credentials). */
  bitcoind?: { host: string; user: string; pass: string };
  network?: NetName;
  /** host:port for peer connections, e.g. 0.0.0.0:9735 on a pilot machine; default a free localhost port. */
  listen?: string;
  /** The address other machines dial (lnd --externalip), when it differs from listen. */
  externalHost?: string;
  /** Channel confirmations lnd asks for (--bitcoin.defaultchanconfs); default 1. */
  chanConfs?: number;
  blockPollMs?: number;
  txPollMs?: number;
}

/** Check before setup or funding: this checkout has not verified lnd's testnet4 support. */
export function assertLndNetwork(network: string): asserts network is "regtest" | "signet" {
  if (network === "testnet4") throw new Error("Lightning on testnet4 is not enabled: lnd v0.21 testnet4 support is unverified; use --pay onchain (full-stack/provider) or --pay channel (market)");
  if (network !== "regtest" && network !== "signet") throw new Error(`network ${network}: only regtest and signet support Lightning, never mainnet`);
}

const b64hex = (b: string) => Buffer.from(b, "base64").toString("hex");
/** LND's REST API gives txids as raw bytes (little-endian) in base64. */
const txidFromBytes = (b: string) => Buffer.from(b, "base64").reverse().toString("hex");

export class LndNode {
  readonly dir: string;
  readonly child: ChildProcess;
  readonly restPort: number;
  readonly p2pPort: number;
  pubkey = "";
  private cert?: Buffer;
  private macaroon?: string;

  private constructor(dir: string, child: ChildProcess, restPort: number, p2pPort: number) {
    this.dir = dir; this.child = child; this.restPort = restPort; this.p2pPort = p2pPort;
  }

  /** Start lnd with a fresh wallet (noseedbackup: a test wallet, unlocked at start) and wait for its API. */
  static async start(cfg: LndConfig): Promise<LndNode> {
    const net = cfg.network ?? (process.env.BSB_NETWORK || "regtest");
    assertLndNetwork(net);
    mkdirSync(cfg.dir, { recursive: true });
    const [p2p, rpcPort, rest] = [cfg.listen ? Number(cfg.listen.split(":").pop()) : await freePort(), await freePort(), await freePort()];
    const btc = cfg.bitcoind ?? (() => {
      const [user, ...pass] = rpcAuth().split(":");
      return { host: new URL(process.env.BSB_RPC ?? defaultRpcUrl(net)).host, user, pass: pass.join(":") };
    })();
    const slow = net !== "regtest";
    // BSB_LND_NEUTRINO=<host:port> makes lnd follow that node over P2P with compact filters instead of
    // bitcoind RPC: needed on a private signet (layer1/private-signet.ts --local-p2p), where lnd v0.21
    // refuses a bitcoind backend whose chain name ("signet") does not match a custom challenge's magic.
    const neutrino = net === "signet" ? process.env.BSB_LND_NEUTRINO : undefined;
    const backend = neutrino
      ? ["--bitcoin.node=neutrino", `--neutrino.connect=${neutrino}`]
      : [
        "--bitcoin.node=bitcoind", `--bitcoind.rpchost=${btc.host}`, `--bitcoind.rpcuser=${btc.user}`, `--bitcoind.rpcpass=${btc.pass}`,
        "--bitcoind.rpcpolling", `--bitcoind.blockpollinginterval=${cfg.blockPollMs ?? (slow ? 5000 : 500)}ms`, `--bitcoind.txpollinginterval=${cfg.txPollMs ?? (slow ? 10000 : 2000)}ms`,
      ];
    const args = [
      `--lnddir=${cfg.dir}`, `--alias=${cfg.alias}`, `--bitcoin.${net}`, ...backend,
      "--noseedbackup", "--nobootstrap", `--bitcoin.defaultchanconfs=${cfg.chanConfs ?? 1}`, "--trickledelay=50",
      `--listen=${cfg.listen ?? `127.0.0.1:${p2p}`}`, `--rpclisten=127.0.0.1:${rpcPort}`, `--restlisten=127.0.0.1:${rest}`,
      "--tlsextraip=127.0.0.1", "--debuglevel=info", ...(cfg.externalHost ? [`--externalip=${cfg.externalHost}`] : []),
      ...(net === "signet" && process.env.BSB_SIGNET_CHALLENGE ? [`--bitcoin.signetchallenge=${process.env.BSB_SIGNET_CHALLENGE}`] : []),
    ];
    const out = openSync(join(cfg.dir, "lnd.out"), "a");
    const child = spawn(cfg.bin ?? lndExe(), args, { stdio: ["ignore", out, out] });
    closeSync(out);
    const node = new LndNode(cfg.dir, child, rest, p2p);
    node.host = cfg.externalHost ?? (cfg.listen && !cfg.listen.startsWith("0.0.0.0") ? cfg.listen : `127.0.0.1:${p2p}`);
    let exited: number | string | null = null;
    child.on("exit", (c) => { exited = c ?? -1; });
    child.on("error", (e) => { exited = `${e.message} (set BSB_LND or --lnd to the lnd binary)`; });
    const mac = join(cfg.dir, "data", "chain", "bitcoin", net, "admin.macaroon");
    const t0 = Date.now();
    for (;;) {
      if (exited !== null) throw new Error(`lnd exited ${exited}; see ${join(cfg.dir, "lnd.out")}`);
      if (Date.now() - t0 > 90_000) { child.kill(); throw new Error(`lnd did not start; see ${join(cfg.dir, "lnd.out")}`); }
      if (existsSync(mac) && existsSync(join(cfg.dir, "tls.cert"))) {
        node.cert = readFileSync(join(cfg.dir, "tls.cert"));
        node.macaroon = readFileSync(mac).toString("hex");
        try { node.pubkey = (await node.rest("GET", "/v1/getinfo")).identity_pubkey; break; } catch { /* not up yet */ }
      }
      await sleep(250);
    }
    return node;
  }

  /** host:port peers dial. */
  host = "";
  get uri(): string { return `${this.pubkey}@${this.host}`; }

  /** One REST call. For a streaming endpoint, `until` sees each message and ends the call when true. */
  rest(method: string, path: string, body?: unknown, until?: (msg: any) => boolean, timeoutMs = 60_000): Promise<any> {
    return new Promise((ok, bad) => {
      const req = request({
        host: "127.0.0.1", port: this.restPort, path, method, ca: this.cert, timeout: timeoutMs,
        headers: { "Grpc-Metadata-macaroon": this.macaroon ?? "", "Content-Type": "application/json" },
      }, (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          buf += chunk;
          if (!until) return;
          let nl;
          while ((nl = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
            if (!line) continue;
            let msg: any;
            try { msg = JSON.parse(line); } catch { continue; }
            if (msg.error) { req.destroy(); return bad(new Error(`${path}: ${msg.error.message ?? JSON.stringify(msg.error)}`)); }
            if (until(msg.result ?? msg)) { req.destroy(); return ok(msg.result ?? msg); }
          }
        });
        res.on("end", () => {
          if (until) return bad(new Error(`${path}: stream ended ${buf.slice(0, 200)}`));
          let v: any;
          try { v = buf ? JSON.parse(buf) : {}; } catch { return bad(new Error(`${path}: ${res.statusCode} ${buf.slice(0, 200)}`)); }
          if (res.statusCode !== 200) return bad(new Error(`${path}: ${res.statusCode} ${v.message ?? buf.slice(0, 200)}`));
          ok(v);
        });
      });
      req.on("timeout", () => req.destroy(new Error(`${path}: timed out`)));
      req.on("error", bad);
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
  }

  /** Wait until lnd has processed the chain up to `height` and reports itself synced. */
  async waitSynced(height: number, timeoutMs = 60_000): Promise<void> {
    if (process.env.BSB_NETWORK === "signet" || process.env.BSB_NETWORK === "testnet4") timeoutMs = Math.max(timeoutMs, 3_600_000);
    const t0 = Date.now();
    for (;;) {
      const i = await this.rest("GET", "/v1/getinfo");
      if (i.synced_to_chain && i.block_height >= height) return;
      if (Date.now() - t0 > timeoutMs) throw new Error(`${this.pubkey.slice(0, 12)}: not synced to ${height} (at ${i.block_height})`);
      await sleep(200);
    }
  }

  async newAddress(): Promise<string> { return (await this.rest("GET", "/v1/newaddress?type=WITNESS_PUBKEY_HASH")).address; }

  async connect(uri: string): Promise<void> {
    const [pubkey, host] = uri.split("@");
    try { await this.rest("POST", "/v1/peers", { addr: { pubkey, host }, perm: false, timeout: "10" }); }
    catch (e) { if (!/already connected/.test((e as Error).message)) throw e; }
  }

  /** Open a private channel funded by this node; resolves with the channel point "txid:vout". */
  async openChannel(pubkey: string, sats: number, satPerVbyte = 2): Promise<string> {
    const cp = await this.rest("POST", "/v1/channels", {
      node_pubkey: Buffer.from(pubkey, "hex").toString("base64"), local_funding_amount: String(sats),
      private: true, sat_per_vbyte: String(satPerVbyte), spend_unconfirmed: false,
    });
    return `${txidFromBytes(cp.funding_txid_bytes)}:${cp.output_index ?? 0}`;
  }

  async channel(point: string): Promise<any | undefined> {
    return ((await this.rest("GET", "/v1/channels")).channels ?? []).find((c: any) => c.channel_point === point);
  }
  async channelsWith(pubkey: string): Promise<any[]> {
    return ((await this.rest("GET", "/v1/channels")).channels ?? []).filter((c: any) => c.remote_pubkey === pubkey);
  }

  async waitActive(point: string, timeoutMs = 60_000): Promise<void> {
    const t0 = Date.now();
    while (!(await this.channel(point))?.active) {
      if (Date.now() - t0 > timeoutMs) throw new Error(`channel ${point} not active`);
      await sleep(200);
    }
  }

  /** Cooperative close. Resolves with the closing txid once lnd has broadcast it. A payment that has
   *  just settled can leave its HTLC on the commitment for a moment, so that refusal is retried. */
  async closeChannel(point: string, satPerVbyte = 2): Promise<string> {
    const [txid, vout] = point.split(":");
    for (let i = 0; ; i++) {
      try {
        const upd = await this.rest("DELETE", `/v1/channels/${txid}/${vout}?sat_per_vbyte=${satPerVbyte}`, undefined, (m) => !!m.close_pending);
        return txidFromBytes(upd.close_pending.txid);
      } catch (e) {
        if (i >= 40 || !/active htlcs/.test((e as Error).message)) throw e;
        await sleep(250);
      }
    }
  }

  async stop(): Promise<void> {
    try { await this.rest("POST", "/v1/stop", {}, undefined, 5_000); } catch { /* already gone */ }
    for (let i = 0; i < 40 && this.child.exitCode === null; i++) await sleep(250);
    if (this.child.exitCode === null) this.child.kill();
  }
}

/** The provider's side: BOLT 11 invoices from its own node. */
export class LndPayee implements Payee {
  readonly nodeId: string;
  readonly node: LndNode;
  /** Put route hints for private channels into invoices (lnd "private"), so a payer whose route
   *  reaches this node only through a private channel can find it. Off on regtest, where the client's
   *  channel is direct. */
  readonly routeHints: boolean;
  constructor(node: LndNode, routeHints = false) { this.node = node; this.nodeId = node.pubkey; this.routeHints = routeHints; }

  async createInvoice(amountMsat: number, memo: string, ttlSec = 600): Promise<Invoice> {
    if (!Number.isSafeInteger(amountMsat) || amountMsat <= 0) throw new Error("amount must be a positive integer msat");
    const r = await this.node.rest("POST", "/v1/invoices", { value_msat: String(amountMsat), memo, expiry: String(ttlSec), ...(this.routeHints ? { private: true } : {}) });
    const inv = decodeBolt11(r.payment_request);
    // Check lnd's invoice says what was asked, before handing it to a client.
    if (inv.paymentHash !== b64hex(r.r_hash) || inv.payee !== this.nodeId || inv.amountMsat !== amountMsat) throw new Error("lnd returned an invoice that differs from the request");
    return inv;
  }

  /** Check a channel a client says it opened: it exists on this node, the client funded it, and it is
   *  active here. Waits for it to become active. */
  async accept(point: string, clientPubkey: string, timeoutMs = 60_000): Promise<{ channel_point: string; capacity_sats: number }> {
    const t0 = Date.now();
    for (;;) {
      const ch = await this.node.channel(point);
      if (ch && ch.remote_pubkey !== clientPubkey) throw new Error("channel is with another node");
      if (ch && ch.initiator) throw new Error("this node funded the channel, not the client");
      if (ch?.active) return { channel_point: point, capacity_sats: Number(ch.capacity) };
      if (Date.now() - t0 > timeoutMs) throw new Error(`channel ${point} is not active on this node`);
      await sleep(200);
    }
  }

  /** Close the channel with this peer cooperatively, from this provider's own node. */
  async close(peer: string): Promise<{ txid: string; channel_point: string }> {
    const [ch] = await this.node.channelsWith(peer);
    if (!ch) throw new Error("no channel with this peer");
    return { txid: await this.node.closeChannel(ch.channel_point), channel_point: ch.channel_point };
  }
}

/** The client's side: decodes and checks BOLT 11 itself, then pays through its own node. */
export class LndPayer implements Payer {
  readonly nodeId: string;
  readonly node: LndNode;
  readonly network: string;
  private readonly paid = new Map<string, number>();
  constructor(node: LndNode, network = "bcrt") { this.node = node; this.nodeId = node.pubkey; this.network = network; }

  decode(pr: string): Bolt11 {
    const inv = decodeBolt11(pr);
    if (inv.network !== this.network) throw new Error(`invoice is for ${inv.network}, not ${this.network}`);
    if (inv.amountMsat === 0) throw new Error("invoice has no amount");
    return inv;
  }

  /** msat paid to this payee so far through this payer. */
  paidMsatTo(payee: string): number { return this.paid.get(payee) ?? 0; }

  async pay(pr: string, maxMsat: number): Promise<{ preimage: string }> {
    const inv = this.decode(pr);
    if (inv.amountMsat > maxMsat) throw new Error("invoice amount over max");
    if (inv.expiresAt < Date.now() / 1000) throw new Error("invoice expired");
    // A channel lnd has just marked active can still show zero outbound balance to the router for a
    // moment, and the attempt fails as INSUFFICIENT_BALANCE before any HTLC leaves. lnd lets a failed
    // payment hash be sent again, so that one reason is retried for a few seconds; nothing else is.
    let res: any;
    for (let i = 0; ; i++) {
      res = await this.node.rest("POST", "/v2/router/send", {
        payment_request: pr, timeout_seconds: 30, fee_limit_msat: String(maxMsat - inv.amountMsat), no_inflight_updates: true,
      }, (m) => m.status === "SUCCEEDED" || m.status === "FAILED");
      if (res.status === "SUCCEEDED" || res.failure_reason !== "FAILURE_REASON_INSUFFICIENT_BALANCE" || i >= 20) break;
      await sleep(250);
    }
    if (res.status !== "SUCCEEDED") throw new Error(`payment failed: ${res.failure_reason}`);
    if (!preimageMatches(inv.paymentHash, res.payment_preimage)) throw new Error("lnd returned a preimage that does not open the hash");
    this.paid.set(inv.payee, this.paidMsatTo(inv.payee) + inv.amountMsat);
    return { preimage: res.payment_preimage };
  }
}
