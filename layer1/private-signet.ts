// A private signet for rehearsals: Bitcoin Core with a challenge of its own (OP_TRUE by default), no
// P2P at all, and blocks that this process makes at a fixed interval. The stack runs against it exactly
// as against the public signet (--network signet: cookie login, tb/tbs prefixes, --confs depth, fees
// from estimatesmartfee, waiting for blocks), but nothing leaves this machine and nobody else mines.
//
//   node layer1/private-signet.ts --datadir <dir> [--bitcoind <path>] [--block-secs 5] [--challenge 51]
//                                 [--rpc-port 38332] [--premine 110] [--fund-from <log file>] [--local-p2p]
//
// --local-p2p lets peers on 127.0.0.1 connect (port rpc-port + 2) and serves compact block filters, for
// lnd's neutrino backend: lnd v0.21 cannot use a bitcoind backend on a signet with a custom challenge
// (it maps getblockchaininfo's "signet" to the public signet's network magic and refuses the mismatch).
// The node still makes no outbound connections and accepts none from other machines.
//
// The protocol code never mines off regtest (net.ts). This process stands in for signet's block
// signers, and with --fund-from for a faucet: it follows a full-stack.ts log and pays each "send at
// least N sats (signet) to <address>" line once, from its own wallet, with a little to spare. It refuses
// the public signet's challenge, and its node makes no peer connections. It prints one JSON line per
// event; {"ready": true, ...} carries the RPC URL and cookie path the parties need.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { constants as osConstants, setPriority } from "node:os";
import { join } from "node:path";

const opt = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const DATADIR = opt("datadir", "");
if (!DATADIR) throw new Error("--datadir is required");
const BITCOIND = opt("bitcoind", "bitcoind");
const BLOCK_SECS = Number(opt("block-secs", "5"));
const CHALLENGE = opt("challenge", "51").toLowerCase();
const RPC_PORT = Number(opt("rpc-port", "38332"));
const PREMINE = Number(opt("premine", "110"));
const FUND_FROM = opt("fund-from", "");
const LOCAL_P2P = process.argv.includes("--local-p2p");
// The public signet's challenge (Core chainparams): a 1-of-2 multisig of its block signers.
const PUBLIC_CHALLENGE = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
if (CHALLENGE === PUBLIC_CHALLENGE || !/^[0-9a-f]+$/.test(CHALLENGE)) throw new Error("--challenge must be a private signet challenge in hex, not the public signet's");

const log = (ev: Record<string, unknown>) => process.stdout.write(JSON.stringify({ t: Date.now(), signet: true, ...ev }) + "\n");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

mkdirSync(DATADIR, { recursive: true });
writeFileSync(join(DATADIR, "bitcoin.conf"), [
  "signet=1", "server=1", "txindex=1", "[signet]",
  `signetchallenge=${CHALLENGE}`, `rpcport=${RPC_PORT}`, "rpcbind=127.0.0.1", "rpcallowip=127.0.0.1",
  // No peers out, and in only from this machine with --local-p2p: a private chain.
  ...(LOCAL_P2P
    ? [`bind=127.0.0.1:${RPC_PORT + 2}`, "listen=1", "blockfilterindex=1", "peerblockfilters=1"]
    : [`port=${RPC_PORT + 2}`, "listen=0"]),
  "connect=0", "dnsseed=0", "fixedseeds=0",
  // The faucet wallet's sends need a fee when estimatesmartfee has no data, which on a new chain it never has.
  "fallbackfee=0.00002",
].join("\n") + "\n");
const node = spawn(BITCOIND, [`-datadir=${DATADIR}`], { stdio: ["ignore", "ignore", "inherit"] });
// Mining at signet's minimum difficulty keeps a core busy (about 4 s of proof of work per block on a
// laptop); below-normal priority keeps the rest of the machine responsive. Pick --block-secs well above
// that so the core idles between blocks.
try { setPriority(node.pid!, osConstants.priority.PRIORITY_BELOW_NORMAL); } catch { /* not permitted: leave it */ }
let nodeExited = false;
node.on("exit", (c) => { nodeExited = true; log({ event: "node-exit", code: c }); });

const URL_ = `http://127.0.0.1:${RPC_PORT}`;
const COOKIE = join(DATADIR, "signet", ".cookie");
async function rpc(method: string, params: unknown[] = [], wallet?: string): Promise<any> {
  const auth = readFileSync(COOKIE, "utf8").trim();
  const r = await fetch(wallet ? `${URL_}/wallet/${wallet}` : URL_, {
    method: "POST", headers: { Authorization: "Basic " + Buffer.from(auth).toString("base64") },
    body: JSON.stringify({ jsonrpc: "1.0", id: "signet", method, params }),
  });
  const v = JSON.parse(await r.text());
  if (v.error) throw new Error(`${method}: ${v.error.message}`);
  return v.result;
}

for (let i = 0; ; i++) {
  if (nodeExited) throw new Error("bitcoind exited during startup");
  if (existsSync(COOKIE)) { try { await rpc("getblockcount"); break; } catch { /* warming up */ } }
  if (i > 240) throw new Error("bitcoind did not answer");
  await sleep(500);
}
const info = await rpc("getblockchaininfo");
if (info.chain !== "signet" || String(info.signet_challenge ?? "").toLowerCase() !== CHALLENGE) {
  await rpc("stop").catch(() => undefined);
  throw new Error(`node is on ${info.chain} with challenge ${info.signet_challenge}, not this private signet`);
}
const net = await rpc("getnetworkinfo");
const remote = (net.localaddresses ?? []).filter((a: { address: string }) => a.address !== "127.0.0.1");
if (net.connections !== 0 || remote.length) log({ event: "warning", why: "node reports peers or non-local addresses", connections: net.connections, remote });

// A restart on the same datadir reuses the wallet, and the chain it already has.
try { await rpc("createwallet", ["miner"]); }
catch (e) { if (!/already exists/.test((e as Error).message)) throw e; await rpc("loadwallet", ["miner"]).catch(() => undefined); }
const miner: string = await rpc("getnewaddress", ["", "bech32m"], "miner");
// generatetoaddress gives up after maxtries hashes, 1,000,000 by default; a block at signet's minimum
// difficulty needs about 4.8 million on average, so the default finds one only about one call in five.
const mine = (n: number) => rpc("generatetoaddress", [n, miner, 1_000_000_000]);
const t0 = Date.now();
for (let h = await rpc("getblockcount"); h < PREMINE; h = await rpc("getblockcount")) await mine(Math.min(10, PREMINE - h));
log({ ready: true, rpc: URL_, cookie: COOKIE, challenge: CHALLENGE, height: await rpc("getblockcount"), premine_s: Math.round((Date.now() - t0) / 1000), block_secs: BLOCK_SECS, miner, ...(LOCAL_P2P ? { p2p: `127.0.0.1:${RPC_PORT + 2}` } : {}) });

// The faucet: each funding line of a full-stack.ts log, paid once.
const funded = new Set<string>();
async function faucet() {
  if (!FUND_FROM || !existsSync(FUND_FROM)) return;
  const text = readFileSync(FUND_FROM, "utf8");
  for (const m of text.matchAll(/send at least (\d+) sats \(signet\) to (\S+?);/g)) {
    const [, sats, addr] = m;
    if (funded.has(addr)) continue;
    funded.add(addr);
    try {
      const txid = await rpc("sendtoaddress", [addr, (Number(sats) + 10_000) / 1e8], "miner");
      log({ event: "funded", address: addr, sats: Number(sats) + 10_000, txid });
    } catch (e) { funded.delete(addr); log({ event: "fund-error", address: addr, error: (e as Error).message }); }
  }
}

let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await rpc("stop").catch(() => undefined);
  for (let i = 0; i < 60 && !nodeExited; i++) await sleep(250);
  process.exit(0);
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);

let fails = 0, logged = -1;
for (let next = Date.now(); !stopping;) {
  try {
    await faucet();
    if (Date.now() >= next) {
      await mine(1);
      next = Math.max(next + BLOCK_SECS * 1000, Date.now());
      const h: number = await rpc("getblockcount");
      if (h % 10 === 0 && h !== logged) { log({ event: "block", height: h }); logged = h; }
    }
    fails = 0;
  } catch (e) {
    if (nodeExited || ++fails > 20) { log({ event: "stopped", why: (e as Error).message }); process.exit(nodeExited ? 0 : 1); }
  }
  await sleep(250);
}
