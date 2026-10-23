// Offline coverage: no Bitcoin Core or lnd process is started, and RPC is stubbed.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { HeaderChain, REGTEST, TESTNET4, compactToTarget, parseHeader, paramsFor, sha256d, targetToCompact, toDisplay } from "./headerchain.ts";
import { LndNode } from "./lnd.ts";
import { advance, assertFreshSeed, confirm, currentNet, defaultRpcUrl, feeRate, partySeed, rpcAuth, untilHeight, useNetwork } from "./net.ts";
import { HRP, taprootAddress } from "./onchain.ts";

const net = currentNet({ BSB_NETWORK: "testnet4" });

test("testnet4 parses from the environment and CLI with public-network defaults", () => {
  assert.deepEqual(net, { name: "testnet4", confs: 3, canMine: false, hrp: "tb", lnHrp: "tb", pollMs: 5_000 });
  assert.equal(defaultRpcUrl("testnet4"), "http://127.0.0.1:48332");
  const env: NodeJS.ProcessEnv = { BSB_RPC_USER: "u", BSB_RPC_PASS: "test-password" };
  assert.deepEqual(useNetwork(["node", "x", "--network", "testnet4"], env), net);
  assert.equal(env.BSB_NETWORK, "testnet4");
  assert.equal(env.BSB_RPC, "http://127.0.0.1:48332");
  assert.equal(useNetwork(["node", "x", "--confs", "6", "--rpc", "http://localhost:48332"], env).confs, 6);
  assert.equal(env.BSB_CONFS, "6");
  assert.equal(env.BSB_RPC, "http://localhost:48332");
  for (const confs of ["0", "-1", "1.5"]) assert.throws(() => currentNet({ BSB_NETWORK: "testnet4", BSB_CONFS: confs }), /at least 1/);
  for (const bad of ["mainnet", "main", "bitcoin", "testnet"]) {
    assert.throws(() => currentNet({ BSB_NETWORK: bad }), /never mainnet/);
    assert.throws(() => useNetwork(["node", "x", "--network", bad], {}), /never mainnet/);
    assert.throws(() => rpcAuth({ BSB_NETWORK: bad }), /never mainnet/);
  }
});

test("testnet4 requires RPC credentials and refuses the regtest password, including in cookies", () => {
  assert.throws(() => rpcAuth({ BSB_NETWORK: "testnet4" }), /BSB_RPC_COOKIE/);
  assert.throws(() => useNetwork(["node", "x", "--network", "testnet4"], {}), /BSB_RPC_COOKIE/);
  assert.throws(() => rpcAuth({ BSB_NETWORK: "testnet4", BSB_RPC_USER: "u", BSB_RPC_PASS: "bsb-regtest-only" }), /fixed regtest RPC password/);
  const dir = mkdtempSync(join(tmpdir(), "bsb-testnet4-cookie-")), cookie = join(dir, ".cookie");
  try {
    writeFileSync(cookie, "__cookie__:test-password\n");
    assert.equal(rpcAuth({ BSB_NETWORK: "testnet4", BSB_RPC_COOKIE: cookie }), "__cookie__:test-password");
    writeFileSync(cookie, "__cookie__:bsb-regtest-only\n");
    assert.throws(() => rpcAuth({ BSB_NETWORK: "testnet4", BSB_RPC_COOKIE: cookie }), /fixed regtest RPC password/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("testnet4 uses fresh party keys, keeps them for restarts, and refuses fixed labels", () => {
  const dir = mkdtempSync(join(tmpdir(), "bsb-testnet4-seed-"));
  try {
    const seed = partySeed(net, join(dir, "a"), "bsb/provider/honest");
    assert.match(seed, /^[0-9a-f]{64}$/);
    assert.equal(partySeed(net, join(dir, "a"), "ignored"), seed);
    assert.notEqual(partySeed(net, join(dir, "b"), "bsb/provider/honest"), seed);
    for (const fixed of ["bsb/provider/honest", "bsb/client/full-stack", "bsb/fee-wallet", "00".repeat(32), "01".repeat(32)]) {
      assert.throws(() => assertFreshSeed(net, fixed));
      assert.throws(() => partySeed(net, join(dir, "c"), "ignored", fixed));
    }
    writeFileSync(join(dir, "a", "party.seed"), "bsb/provider/honest\n");
    assert.throws(() => partySeed(net, join(dir, "a"), "ignored"), /fresh random/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("testnet4 waits without mining and estimates fees through its default RPC port", async () => {
  const saved = { ...process.env }, realFetch = globalThis.fetch;
  const calls: string[] = [];
  let height = 10, confirmations = 0;
  try {
    for (const key of ["BSB_RPC", "BSB_RPC_COOKIE", "BSB_FEE_RATE", "BSB_FEE_TARGET", "BSB_FEE_FALLBACK", "BSB_MAX_FEE_RATE"]) delete process.env[key];
    Object.assign(process.env, { BSB_NETWORK: "testnet4", BSB_RPC_USER: "u", BSB_RPC_PASS: "test-password" });
    globalThis.fetch = (async (url: unknown, init?: { body?: string }) => {
      assert.equal(url, "http://127.0.0.1:48332");
      const { method } = JSON.parse(String(init?.body));
      calls.push(method);
      let result: unknown;
      if (method === "getblockcount") result = height++;
      else if (method === "getrawtransaction") result = { confirmations: confirmations++ };
      else if (method === "estimatesmartfee") result = { feerate: 0.00003 };
      else assert.fail(`unexpected RPC method ${method}`);
      return new Response(JSON.stringify({ result, error: null }));
    }) as typeof fetch;
    const fast = { ...net, pollMs: 1 };
    await advance(fast, 2, "unused");
    assert.equal(await untilHeight(fast, 15, "unused"), 15);
    await confirm(fast, "test-txid", "unused");
    assert.equal(confirmations, 4, "waits for three confirmations");
    assert.equal(await feeRate(net, 9), 3);
    assert.ok(!calls.some((m) => m === "generatetoaddress" || m === "generateblock"));
  } finally { globalThis.fetch = realFetch; process.env = saved; }
});

test("testnet4 has its own genesis, proof of work and tb1 addresses", () => {
  // BIP94's published genesis header, not fetched from a node.
  const raw = Buffer.from("01000000" + "00".repeat(32) + "4e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a" + "046f3566ffff001dbb0c7817", "hex");
  const header = parseHeader(raw);
  assert.equal(header.hash, TESTNET4.genesis);
  assert.ok(BigInt("0x" + header.hash) <= compactToTarget(header.bits)!);
  assert.equal(paramsFor("testnet4"), TESTNET4);
  const chain = new HeaderChain(TESTNET4);
  assert.deepEqual(chain.ingest(0, raw), { added: 1 });
  assert.equal(chain.hashAt(0), TESTNET4.genesis);
  assert.throws(() => new HeaderChain(REGTEST).ingest(0, raw), /genesis/);
  assert.equal(HRP.testnet4, "tb");
  assert.equal(taprootAddress("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", "testnet4"), "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c");
});

test("testnet4 Lightning is refused before creating a directory or starting lnd; mainnet stays refused", async () => {
  const root = mkdtempSync(join(tmpdir(), "bsb-testnet4-ln-")), dir = join(root, "lnd");
  const saved = process.env.BSB_NETWORK;
  try {
    await assert.rejects(LndNode.start({ network: "testnet4", dir, alias: "test" }), /Lightning on testnet4.*use --pay onchain/);
    process.env.BSB_NETWORK = "testnet4";
    await assert.rejects(LndNode.start({ dir, alias: "test" }), /Lightning on testnet4/);
    for (const network of ["mainnet", "main", "bitcoin"]) {
      process.env.BSB_NETWORK = network;
      await assert.rejects(LndNode.start({ dir, alias: "test" }), /never mainnet/);
    }
    assert.equal(existsSync(dir), false);
  } finally {
    if (saved === undefined) delete process.env.BSB_NETWORK; else process.env.BSB_NETWORK = saved;
    rmSync(root, { recursive: true, force: true });
  }
});

test("BIP94 validates minimum-difficulty recovery, retarget base and the time-warp boundary", () => {
  // Exercise real header ingestion with cheap synthetic proof of work, never a live chain.
  const genesis = Buffer.from("01000000" + "00".repeat(32) + "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" + "dae5494dffff7f2002000000", "hex");
  const chain = new HeaderChain({ ...TESTNET4, genesis: REGTEST.genesis, powLimit: REGTEST.powLimit });
  chain.ingest(0, genesis);
  const min = 0x207fffff, harder = 0x201fffff;
  let prev = genesis, time = parseHeader(genesis).time;
  const mine = (bits: number, nextTime: number) => {
    const raw = Buffer.alloc(80);
    raw.writeInt32LE(4, 0); sha256d(prev).copy(raw, 4);
    raw.writeUInt32LE(nextTime, 68); raw.writeUInt32LE(bits, 72);
    for (let nonce = 0; ; nonce++) {
      raw.writeUInt32LE(nonce, 76);
      if (BigInt("0x" + toDisplay(sha256d(raw))) <= compactToTarget(bits)!) return raw;
    }
  };
  const append = (bits: number, delta: number) => {
    const raw = mine(bits, time + delta);
    chain.ingest(chain.height + 1, raw);
    prev = raw; time += delta;
  };
  for (let h = 1; h < 2016; h++) append(min, 1);
  assert.throws(() => chain.ingest(2016, mine(min, time + 1201)), /bits/);
  append(harder, 1);
  const firstTime = time;
  assert.throws(() => chain.ingest(2017, mine(min, time + 1200)), /bits/);
  append(harder, 1200);
  append(min, 1201);
  assert.throws(() => chain.ingest(2019, mine(min, time + 1)), /bits/);
  append(harder, 1);
  for (let h = 2020; h < 4031; h++) append(harder, 600);
  append(min, 1201);
  const nextBits = targetToCompact(compactToTarget(harder)! * BigInt(time - firstTime) / BigInt(14 * 24 * 60 * 60));
  assert.notEqual(nextBits, min, "retarget uses the period's first block, not its minimum-difficulty last block");
  assert.throws(() => chain.ingest(4032, mine(min, time + 1201)), /bits/);
  assert.throws(() => chain.ingest(4032, mine(nextBits, time - 601)), /BIP94 time warp/);
  append(nextBits, -600);
  assert.equal(chain.height, 4032);
});
