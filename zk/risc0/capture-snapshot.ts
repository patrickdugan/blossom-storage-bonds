// Prepare fresh, synthetic storage-proof inputs on a disposable local Core regtest node.
// node zk/risc0/capture-snapshot.ts --bitcoind <binary> --dir <new-node-dir> --out <new-snapshot>
// The snapshot contains public test inputs, never wallet files or signing keys.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { HeaderChain, REGTEST } from "../../layer1/headerchain.ts";
import { dealsDigest, journalBytes, risc0Witness, syntheticDeal } from "../../model/zk_pdp.ts";
import { termJournal, termPreimage } from "../../model/bitvm_term.ts";

const option = (name: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i < 0 ? undefined : process.argv[i + 1];
};
const required = (name: string) => {
  const value = option(name);
  assert.ok(value, `--${name} is required`);
  return value;
};
const bitcoind = required("bitcoind"), dir = resolve(required("dir")), out = resolve(required("out"));
assert.ok(!existsSync(dir) && !existsSync(out), "node and snapshot directories must be new");
const first = 170, step = 10, epochs = 3, depth = 6, tip = 200, q = 16;
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const old = JSON.parse(readFileSync(join(repo, "results/bitvm2-spike.json"), "utf8"));
const ids = old.image_ids;
const held = Array.from({ length: 3 }, (_, d) => syntheticDeal("sha", `deal-${d}-of-256`, 256));
const refs = held.map(d => ({ root: d.tree.root, n: d.tree.n }));
const files: Record<string, string> = {};
const write = (name: string, data: Uint8Array | string) => {
  const path = join(out, name);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, data, { flag: "wx" });
  files[name] = createHash("sha256").update(data).digest("hex");
};
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const portServer = createServer();
await new Promise<void>((ok, fail) => { portServer.once("error", fail); portServer.listen(0, "127.0.0.1", ok); });
const port = (portServer.address() as { port: number }).port;
await new Promise<void>(ok => portServer.close(() => ok()));
mkdirSync(dir);
mkdirSync(out);
const core = spawn(bitcoind, [
  "-regtest=1", `-datadir=${dir}`, "-server=1", "-listen=0", "-connect=0", "-dnsseed=0", "-discover=0",
  "-persistmempool=0", `-rpcport=${port}`, "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
  "-rpcuser=bsb", "-rpcpassword=bsb-regtest-only", "-fallbackfee=0.00002",
], { windowsHide: true, stdio: "ignore" });
let spawnError: Error | undefined;
core.once("error", error => { spawnError = error; });
async function rpc(method: string, params: unknown[] = [], wallet = false): Promise<any> {
  const response = await fetch(`http://127.0.0.1:${port}${wallet ? "/wallet/snapshot" : ""}`, {
    method: "POST", headers: { Authorization: "Basic " + Buffer.from("bsb:bsb-regtest-only").toString("base64") },
    body: JSON.stringify({ jsonrpc: "2.0", id: "snapshot", method, params }), signal: AbortSignal.timeout(30_000),
  });
  const value = await response.json() as { result: any; error: any };
  if (value.error) throw Error(`${method}: ${JSON.stringify(value.error)}`);
  return value.result;
}
let manifest: any;
try {
  for (const started = Date.now();;) {
    if (spawnError) throw spawnError;
    if (core.exitCode !== null) throw Error(`Core exited ${core.exitCode}`);
    try { if ((await rpc("getblockchaininfo")).chain === "regtest") break; } catch {}
    assert.ok(Date.now() - started < 60_000, "Core startup timed out");
    await sleep(200);
  }
  assert.equal((await rpc("getblockchaininfo")).chain, "regtest");
  const version = (await rpc("getnetworkinfo")).subversion;
  await rpc("createwallet", ["snapshot"]);
  const address = await rpc("getnewaddress", [], true);
  await rpc("generatetoaddress", [tip, address]);
  const headers: Buffer[] = [], hashes: string[] = [];
  for (let height = 0; height <= tip; height++) {
    const hash = await rpc("getblockhash", [height]);
    headers.push(Buffer.from(await rpc("getblockheader", [hash, false]), "hex"));
    hashes.push(hash);
  }
  const raw = Buffer.concat(headers), checked = new HeaderChain(REGTEST);
  checked.ingest(0, raw);
  assert.equal(checked.height, tip);
  assert.equal(checked.tip, hashes[tip]);
  const chainInfo = await rpc("getblockchaininfo");
  assert.equal(checked.totalWork, BigInt("0x" + chainInfo.chainwork));
  assert.notEqual(hashes[tip], old.m2.header_chain.tip_hash, "fresh snapshot must not reuse the phase-6 chain");
  write("chain/headers.bin", raw);
  write("chain/hashes.json", JSON.stringify({ chain: "regtest", hashes }, null, 2) + "\n");
  write("vk.json", readFileSync(join(repo, "results/bitvm2-spike-groth16/vk.json")));
  for (let i = 0; i < epochs; i++) {
    const height = first + i * step, seed = Buffer.from(hashes[height], "hex");
    const statement = {
      hash: "sha", mode: 1, seed: seed.toString("hex"), q,
      deals: refs.map(d => ({ root: d.root.toString("hex"), n: d.n })),
      journal: journalBytes(seed, q, refs).toString("hex"),
    };
    write(`hold-${height}/witness.bin`, risc0Witness(seed, q, held));
    write(`hold-${height}/statement.json`, JSON.stringify(statement, null, 2) + "\n");
  }
  const setup = {
    holdId: Buffer.from(ids.hold, "hex"), headerChainId: Buffer.from(ids.header_chain, "hex"),
    q, dealCount: refs.length, dealsDigest: dealsDigest("sha", refs), firstHeight: first, step, epochs, depth,
  };
  const claim = { tipHeight: tip, tipHash: Buffer.from(hashes[tip], "hex").reverse(), totalWork: checked.totalWork };
  manifest = {
    format: "bsb/fresh-proof-snapshot/v1", generated: new Date().toISOString(), network: "regtest", core: version,
    scope: "fresh synthetic holdings and chain inputs; no proofs generated and no storage graph funded",
    image_ids: ids, chain: { tip_height: tip, tip_hash: hashes[tip], total_work: checked.totalWork.toString() },
    term: { first, step, epochs, depth, q, deal_count: refs.length, deals_digest: setup.dealsDigest.toString("hex") },
    expected_preimage: termPreimage(setup, claim).toString("hex"), expected_journal: termJournal(setup, claim).toString("hex"),
    sha256: files,
  };
} finally {
  if (core.exitCode === null && !spawnError) {
    await rpc("stop").catch(() => undefined);
    for (let i = 0; i < 100 && core.exitCode === null; i++) await sleep(100);
    if (core.exitCode === null) core.kill();
    assert.notEqual(core.exitCode, null, "Core did not stop cleanly");
  }
}
const log = readFileSync(join(dir, "regtest/debug.log"), "utf8");
assert.match(log, /Shutdown done/, "test node must finish shutting down before snapshot delivery");
writeFileSync(join(out, "snapshot.json"), JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
console.log(JSON.stringify({ snapshot: out, headers: tip + 1, epochs, q, proof_generated: false, node_stopped: true, journal: manifest.expected_journal }));
