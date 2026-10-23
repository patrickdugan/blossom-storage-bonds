// The chain a party runs on (--network regtest|signet, or BSB_NETWORK), and what differs between
// regtest and a pilot network:
//
//                   regtest (the default)                   signet
//   RPC             127.0.0.1:18543, fixed test login       127.0.0.1:38332, BSB_RPC_COOKIE or BSB_RPC_USER/_PASS
//   addresses       bcrt1…                                  tb1…
//   BOLT 11         lnbcrt…                                 lntbs…
//   confirmations   1                                       3 (--confs or BSB_CONFS)
//   blocks          mined by the orchestrator               waited for; nothing here ever mines
//   fees            fixed, as measured in phases 1 to 6     estimatesmartfee (BSB_FEE_RATE pins one)
//   party keys      fixed labels, so runs reproduce         32 fresh random bytes per party and run, kept in
//                                                           that party's directory; fixed labels refused
//
// bsb-bond (regtest/src/bin/bond.rs, common.rs NetCfg) reads the same environment variables, so a process
// calls useNetwork() once and every bsb-bond and child process it starts agrees with it. Mainnet is
// refused here and there. Regtest behaviour is unchanged: same keys, fees, depths and RPC defaults.

import { randomBytes, createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type NetName = "regtest" | "signet";

export interface Net {
  readonly name: NetName;
  /** Confirmations before a party relies on an output the other side created. */
  readonly confs: number;
  /** Only regtest mines; everywhere else the code waits for blocks. */
  readonly canMine: boolean;
  /** bech32 address prefix. */
  readonly hrp: string;
  /** BOLT 11 currency prefix. */
  readonly lnHrp: string;
  /** How often to look for a new block or a change on chain. */
  readonly pollMs: number;
}

const PROFILE: Record<NetName, Omit<Net, "confs">> = {
  regtest: { name: "regtest", canMine: true, hrp: "bcrt", lnHrp: "bcrt", pollMs: 150 },
  signet: { name: "signet", canMine: false, hrp: "tb", lnHrp: "tbs", pollMs: 5_000 },
};

export const defaultRpcUrl = (name: NetName): string => (name === "regtest" ? "http://127.0.0.1:18543" : "http://127.0.0.1:38332");

function parseName(v: string): NetName {
  if (v === "regtest" || v === "signet") return v;
  throw new Error(`network ${v}: only regtest and signet are supported, never mainnet`);
}

/** The network profile from the environment alone (for modules that are not entry points). */
export function currentNet(env: NodeJS.ProcessEnv = process.env): Net {
  const name = parseName(env.BSB_NETWORK || "regtest");
  const confs = Number(env.BSB_CONFS || (name === "regtest" ? 1 : 3));
  if (!Number.isSafeInteger(confs) || confs < 1) throw new Error("BSB_CONFS must be a whole number of at least 1");
  return { ...PROFILE[name], confs };
}

/** For an entry point: read --network, --confs and --rpc, write them into the environment so that every
 *  bsb-bond and child process inherits them, and check the RPC login is usable on this network. */
export function useNetwork(argv: string[] = process.argv, env: NodeJS.ProcessEnv = process.env): Net {
  const flag = (n: string) => { const i = argv.indexOf(`--${n}`); return i > 0 ? argv[i + 1] : undefined; };
  env.BSB_NETWORK = parseName(flag("network") || env.BSB_NETWORK || "regtest");
  if (flag("confs")) env.BSB_CONFS = flag("confs");
  if (flag("rpc")) env.BSB_RPC = flag("rpc");
  const net = currentNet(env);
  env.BSB_RPC ||= defaultRpcUrl(net.name);
  rpcAuth(env);
  return net;
}

/** "user:password" for bitcoind: the cookie file, an explicit login, or on regtest only, the fixed test
 *  login of scripts/regtest-node.sh. Off regtest the regtest password is refused. */
export function rpcAuth(env: NodeJS.ProcessEnv = process.env): string {
  const name = parseName(env.BSB_NETWORK || "regtest");
  let auth: string;
  if (env.BSB_RPC_COOKIE) auth = readFileSync(env.BSB_RPC_COOKIE, "utf8").trim();
  else if (env.BSB_RPC_USER && env.BSB_RPC_PASS) auth = `${env.BSB_RPC_USER}:${env.BSB_RPC_PASS}`;
  else if (name === "regtest") auth = "bsb:bsb-regtest-only";
  else throw new Error("off regtest, set BSB_RPC_COOKIE or BSB_RPC_USER and BSB_RPC_PASS");
  if (name !== "regtest" && auth.endsWith(":bsb-regtest-only")) throw new Error("refusing the fixed regtest RPC password off regtest");
  return auth;
}

/** Bitcoin Core JSON-RPC. The URL defaults to BSB_RPC, then to the network's default port. */
export async function rpc(method: string, params: unknown[] = [], url?: string): Promise<any> {
  const env = process.env;
  const r = await fetch(url ?? env.BSB_RPC ?? defaultRpcUrl(parseName(env.BSB_NETWORK || "regtest")), {
    method: "POST", headers: { Authorization: "Basic " + Buffer.from(rpcAuth()).toString("base64") },
    body: JSON.stringify({ jsonrpc: "1.0", id: "bsb", method, params }),
  });
  const text = await r.text();
  let v: { result: unknown; error: { message: string } | null };
  try { v = JSON.parse(text); } catch { throw new Error(`${method}: HTTP ${r.status} ${text.slice(0, 120)}`); }
  if (v.error) throw new Error(`${method}: ${v.error.message}`);
  return v.result;
}

/** Confirmations of a transaction: null if the node has never seen it, 0 in the mempool. It goes over
 *  this process's own kept-alive connection, so a watcher can poll it every tick; spawning bsb-bond for
 *  the same question costs a process and a TCP connection, which ends in TIME_WAIT. Needs txindex on
 *  confirmed transactions (scripts/regtest-node.sh sets it; bsb-bond requires it off regtest). */
export async function txConfirmations(txid: string, url?: string): Promise<number | null> {
  try { return ((await rpc("getrawtransaction", [txid, true], url)) as { confirmations?: number }).confirmations ?? 0; }
  catch (e) { if (/No such mempool or blockchain transaction/.test((e as Error).message)) return null; throw e; }
}

// ───────────────────────────── blocks ─────────────────────────────

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The chain height; off regtest a failed call (a node restarting, a dropped connection) is retried
 *  rather than ending a run that may be days long. */
async function heightNow(net: Net): Promise<number> {
  for (let fails = 0; ; fails++) {
    try { return await rpc("getblockcount"); }
    catch (e) { if (net.canMine || fails >= 720) throw e; await sleep(Math.max(net.pollMs, 5_000)); }
  }
}

/** Regtest mines `n` blocks to `addr`. Elsewhere this waits until the chain has grown by `n`. */
export async function advance(net: Net, n: number, addr: string, onWait?: (h: number, want: number) => void): Promise<void> {
  if (n <= 0) return;
  if (net.canMine) { await rpc("generatetoaddress", [n, addr]); return; }
  const want = (await heightNow(net)) + n;
  await waitHeight(net, want, onWait);
}

/** Regtest mines up to `h`; elsewhere this waits for it. Returns the height reached. */
export async function untilHeight(net: Net, h: number, addr: string, onWait?: (h: number, want: number) => void): Promise<number> {
  const now = await heightNow(net);
  if (now >= h) return now;
  if (net.canMine) { await rpc("generatetoaddress", [h - now, addr]); return h; }
  return waitHeight(net, h, onWait);
}

export async function waitHeight(net: Net, h: number, onWait?: (h: number, want: number) => void): Promise<number> {
  let last = -1;
  for (;;) {
    const now = await heightNow(net);
    if (now >= h) return now;
    if (now !== last) { onWait?.(now, h); last = now; }
    await sleep(net.pollMs);
  }
}

/** Until `txid` has the network's confirmation depth. On regtest that is `confs` mined blocks: one by
 *  default, exactly as every earlier run did after a funding transaction. */
export async function confirm(net: Net, txid: string, addr: string, onWait?: (conf: number, want: number) => void): Promise<void> {
  if (net.canMine) { await rpc("generatetoaddress", [net.confs, addr]); return; }
  let last = -1;
  for (;;) {
    const t = await rpc("getrawtransaction", [txid, true]).catch(() => undefined);
    const c = t?.confirmations ?? 0;
    if (c >= net.confs) return;
    if (c !== last) { onWait?.(c, net.confs); last = c; }
    await sleep(net.pollMs);
  }
}

// ───────────────────────────── fees ─────────────────────────────

/** sat/vB: `fixed` on regtest (or when BSB_FEE_RATE pins one); elsewhere Core's estimate for
 *  BSB_FEE_TARGET blocks (default 6), clamped to 1..BSB_MAX_FEE_RATE (default 10), and BSB_FEE_FALLBACK
 *  (default 2) when the node has no estimate. The same rules as bsb-bond's. */
export async function feeRate(net: Net, fixed: number, env: NodeJS.ProcessEnv = process.env): Promise<number> {
  if (env.BSB_FEE_RATE) return Math.max(1, Number(env.BSB_FEE_RATE));
  if (net.canMine) return fixed;
  const target = Number(env.BSB_FEE_TARGET || 6), fallback = Math.max(1, Number(env.BSB_FEE_FALLBACK || 2)), max = Math.max(1, Number(env.BSB_MAX_FEE_RATE || 10));
  const est = await rpc("estimatesmartfee", [target, "conservative"]).catch(() => undefined);
  const r = typeof est?.feerate === "number" ? Math.ceil(est.feerate * 1e5) : fallback;
  return Math.min(max, Math.max(1, r));
}

// ───────────────────────────── keys ─────────────────────────────

/** Off regtest a seed must be 32 fresh random bytes in hex. Every fixed seed in this repository is a
 *  readable label, so the format refuses them all; a constant byte string is refused too. */
export function assertFreshSeed(net: Net, seed: string): void {
  if (net.canMine) return;
  if (!/^[0-9a-fA-F]{64}$/.test(seed)) throw new Error("off regtest a seed must be 32 fresh random bytes in hex, not a fixed test value");
  if (/^(..)\1{31}$/.test(seed.toLowerCase())) throw new Error("seed is a constant byte string");
}

/** A party's seed. On regtest, the fixed `label` (so a run reproduces phase 1 to 6 keys). Elsewhere a
 *  fresh random seed made on first use and kept in `<dir>/party.seed`, so a restarted process keeps its
 *  bond and wallet keys; a new run gets a new directory and so new keys. `given` (a --seed flag) must
 *  pass assertFreshSeed off regtest. */
export function partySeed(net: Net, dir: string, label: string, given?: string): string {
  if (net.canMine) return given ?? label;
  if (given) { assertFreshSeed(net, given); return given; }
  const file = join(dir, "party.seed");
  if (existsSync(file)) {
    const s = readFileSync(file, "utf8").trim();
    assertFreshSeed(net, s);
    return s;
  }
  mkdirSync(dir, { recursive: true });
  const s = randomBytes(32).toString("hex");
  writeFileSync(file, s + "\n", { mode: 0o600, flag: "wx" });
  return s;
}

/** The client's long-term storage secret: SHA-256 of a fixed label on regtest, else derived from the
 *  party's fresh seed. */
export function storageSecret(net: Net, seed: string, label: string): Buffer {
  return createHash("sha256").update(net.canMine ? label : `bsb/storage-secret|${seed}`).digest();
}
