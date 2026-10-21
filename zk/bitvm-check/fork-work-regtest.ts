// Two isolated Core nodes demonstrate why outweighing an old claim is insufficient.
// This is protocol research, not a Bitcoin-enforced cumulative-work dispute.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join, resolve } from "node:path";
import { HeaderChain, REGTEST } from "../../layer1/headerchain.ts";

const opt = (name: string) => { const i = process.argv.indexOf(`--${name}`); return i < 0 ? undefined : process.argv[i + 1]; };
const req = (name: string) => { const v = opt(name); assert.ok(v, `--${name} is required`); return v; };
const root = resolve(req("dir")), output = resolve(req("out")), bitcoind = req("bitcoind");
assert.ok(!existsSync(root) && !existsSync(output), "new data and output paths required");
mkdirSync(root, { recursive: true });
const pause = (ms: number) => new Promise(r => setTimeout(r, ms));
async function node(name: string) {
  const dir = join(root, name); mkdirSync(dir);
  const server = createServer();
  await new Promise<void>((ok, bad) => { server.once("error", bad); server.listen(0, "127.0.0.1", ok); });
  const port = (server.address() as { port: number }).port;
  await new Promise<void>(ok => server.close(() => ok()));
  const proc = spawn(bitcoind, ["-regtest=1", `-datadir=${dir}`, "-server=1", "-listen=0", "-connect=0", "-dnsseed=0", "-discover=0", "-persistmempool=0", `-rpcport=${port}`, "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcuser=bsb", "-rpcpassword=bsb-regtest-only"], { windowsHide: true, stdio: "ignore" });
  let failure: Error | undefined;
  proc.once("error", error => { failure = error; });
  const exited = new Promise<void>(ok => proc.once("close", () => ok()));
  async function rpc(method: string, params: unknown[] = [], wallet = false): Promise<any> {
    const response = await fetch(`http://127.0.0.1:${port}${wallet ? "/wallet/research" : ""}`, {
      method: "POST", headers: { Authorization: "Basic " + Buffer.from("bsb:bsb-regtest-only").toString("base64") },
      body: JSON.stringify({ jsonrpc: "2.0", id: "fork-research", method, params }), signal: AbortSignal.timeout(30_000),
    });
    const result = await response.json() as any;
    if (result.error) throw Error(`${name} ${method}: ${JSON.stringify(result.error)}`);
    return result.result;
  }
  return { proc, rpc, exited, failure: () => failure };
}
type Node = Awaited<ReturnType<typeof node>>;
const nodes: Node[] = [];
let report: any;
try {
  for (const name of ["honest", "alternative"]) {
    const n = await node(name); nodes.push(n);
    for (const start = Date.now();;) {
      if (n.failure()) throw n.failure();
      assert.equal(n.proc.exitCode, null, `${name} exited at startup`);
      try { assert.equal((await n.rpc("getblockchaininfo")).chain, "regtest"); break; } catch {}
      assert.ok(Date.now() - start < 60_000, "Core startup timeout"); await pause(200);
    }
  }
  const [a, b] = nodes;
  const addresses: string[] = [];
  for (const n of nodes) {
    assert.equal(await n.rpc("getconnectioncount"), 0);
    await n.rpc("createwallet", ["research"]);
    addresses.push(await n.rpc("getnewaddress", [], true));
  }
  async function transfer(source: Node, destination: Node, first: number, last: number) {
    for (let height = first; height <= last; height++) {
      const hash = await source.rpc("getblockhash", [height]);
      const result = await destination.rpc("submitblock", [await source.rpc("getblock", [hash, 0])]);
      assert.ok(result === null || result === "inconclusive", `submitblock: ${result}`);
      assert.equal((await destination.rpc("getblockheader", [hash])).hash, hash);
    }
  }
  async function headers(n: Node) {
    const tip = await n.rpc("getblockcount"), raw: string[] = [];
    for (let h = 0; h <= tip; h++) raw.push(await n.rpc("getblockheader", [await n.rpc("getblockhash", [h]), false]));
    const chain = new HeaderChain(REGTEST);
    chain.ingest(0, Buffer.from(raw.join(""), "hex"), Math.floor(Date.now() / 1000));
    const core = await n.rpc("getblockchaininfo");
    assert.equal(chain.tip, core.bestblockhash);
    assert.equal(chain.totalWork, BigInt("0x" + core.chainwork));
    return { chain, raw };
  }
  const summary = (c: HeaderChain) => ({ height: c.height, hash: c.tip, work: c.totalWork.toString(), hashAtClaimHeight: c.hashAt(220), firstSeedHash: c.hashAt(170) });
  await a.rpc("generatetoaddress", [220, addresses[0]]);
  const claim = await headers(a);
  assert.equal(claim.chain.totalWork, 442n);
  await transfer(a, b, 1, 169);
  await a.rpc("generatetoaddress", [12, addresses[0]]);
  const honest = await headers(a);
  const honestSummary = summary(honest.chain);
  await b.rpc("generatetoaddress", [52, addresses[1]]);
  const weaker = await headers(b);
  assert.notEqual(weaker.chain.hashAt(220), claim.chain.tip);
  assert.notEqual(weaker.chain.hashAt(170), claim.chain.hashAt(170));
  assert.ok(weaker.chain.totalWork > claim.chain.totalWork);
  assert.ok(weaker.chain.totalWork < honest.chain.totalWork);
  await transfer(b, a, 170, 221);
  assert.equal(await a.rpc("getbestblockhash"), honest.chain.tip);
  assert.deepEqual(honest.chain.ingest(170, Buffer.from(weaker.raw.slice(170).join(""), "hex")), { added: 0 });
  await b.rpc("generatetoaddress", [11, addresses[1]]);
  const equal = await headers(b);
  assert.equal(equal.chain.totalWork, honest.chain.totalWork);
  await transfer(b, a, 222, 232);
  assert.equal(await a.rpc("getbestblockhash"), honest.chain.tip);
  assert.deepEqual(honest.chain.ingest(170, Buffer.from(equal.raw.slice(170).join(""), "hex")), { added: 0 });
  await b.rpc("generatetoaddress", [1, addresses[1]]);
  const heavier = await headers(b);
  assert.ok(heavier.chain.totalWork > honest.chain.totalWork);
  await transfer(b, a, 233, 233);
  assert.equal(await a.rpc("getbestblockhash"), heavier.chain.tip);
  assert.deepEqual(honest.chain.ingest(170, Buffer.from(heavier.raw.slice(170).join(""), "hex")), { added: 64, reorgFrom: 170 });
  assert.equal(honest.chain.tip, heavier.chain.tip);
  assert.equal(await a.rpc("getblockhash", [220]), heavier.chain.hashAt(220));
  for (const n of nodes) assert.equal(await n.rpc("getconnectioncount"), 0);
  report = {
    format: "bsb/cumulative-work-fork-research/v1", network: "regtest", core: (await a.rpc("getnetworkinfo")).subversion,
    commonAncestorHeight: 169, firstSeedHeight: 170, claim: summary(claim.chain), honestExtension: honestSummary,
    cases: [
      { name: "outweighs-old-claim-but-loses-to-honest-extension", alternative: summary(weaker.chain), coreReorganized: false, independentVerifierReorganized: false, oldClaimComparisonWouldAccept: true },
      { name: "equal-work-conflicting-extension", alternative: summary(equal.chain), coreReorganized: false, independentVerifierReorganized: false },
      { name: "outweighs-honest-extension", alternative: summary(heavier.chain), coreReorganized: true, independentVerifierReorganized: true },
    ],
    headers: { honest: honest.raw, alternative: heavier.raw },
    checks: { nodesIsolated: true, bothBranchesValidatedFromGenesis: true, nativeCoreWorkMatchesIndependentVerifier: true },
    scope: "Local protocol research with free regtest work. No zk proof, Bitcoin-enforced fork challenge, canonical-chain oracle, or mainnet security claim. A valid fork outweighing an old claim need not outweigh its honest extension.",
  };
} finally {
  for (const n of nodes) {
    if (n.proc.exitCode === null) {
      await n.rpc("stop").catch(() => undefined);
      const stopped = await Promise.race([n.exited.then(() => true), pause(10_000).then(() => false)]);
      if (!stopped) { n.proc.kill(); await n.exited; }
    }
    assert.equal(n.proc.exitCode, 0, "Core must exit cleanly");
  }
}
report.checks.nodesStopped = true;
writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { flag: "wx" });
console.log(JSON.stringify({ ...report, headers: "Raw headers saved in output report", output }));
