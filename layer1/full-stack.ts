// Phase 4: the whole stack in one regtest run, with every party in its own process.
//
//   scripts/regtest-node.sh <datadir> <bitcoind>      (another shell; RPC on 127.0.0.1:18543)
//   node layer1/full-stack.ts [--epochs 3] [--from-epoch 2] [--q 16] [--out results/full-stack.json]
//                             [--pay ln|onchain] [--pay-every 1] [--fee-rate 5]
//
// This process is the client (and the miner). Three provider processes run with their own keys, fee
// wallets and lnd (layer1/provider.ts --pay ln --zk), and one watchtower process watches them.
//
//   1. Deals and bonds. The client uploads three blobs (1 MiB, 512 KiB, 256 KiB), encrypted per
//      provider, to each provider's Blossom server and registers all three as deals for public proofs.
//      On the 1 MiB deal it runs cut and choose (64 sentinels of 16 windows, 4 kept). The provider then
//      funds a 1 BTC sentinel bond from its own wallet, and both sides check the other's presignatures.
//   2. Lightning. The client's lnd opens a private 50,000-sat channel to each provider's lnd.
//   3. Public epoch proofs. Every 10 blocks each provider proves its holdings unprompted: the seed is
//      the boundary block's hash, and q challenges are drawn across all three deals. It stores the STARK
//      on its own Blossom server and announces it on Nostr.
//   4. Payment. The client checks that its deals are in the announced list, verifies the proof against
//      its own node's block hash, and pays that epoch's BOLT 11 invoice over Lightning. It pays nothing
//      without a valid proof.
//   5. Attestation. The watchtower verifies every proof on its own and attests valid, invalid or
//      missing. From --from-epoch on, one provider zeroes 10% of every replica, and one reads the honest
//      provider's copies instead of its own.
//   6. Enforcement. A missing or invalid attestation puts that provider on the client's list. Once
//      Lightning is settled, the client challenges each listed provider's bond on chain, revealing its
//      sentinels. The provider's own process reads the revealed secret from the chain and answers from
//      its own bytes. If Core rejects every answer, or none comes within 144 blocks, the client forfeits
//      the bond. A provider with no adverse attestation is not challenged, and refunds its bond at the
//      term's end.
//
// Every outcome is read back from the chain into results/full-stack.json: bond funding, each challenge,
// response, forfeit and refund, each Lightning channel's funding and close, and the attestations.
//
// With --pay onchain (layer1/onchain.ts) there is no lnd. Step 2 is a Core wallet for the client, and
// step 4 pays on chain: every --pay-every epochs the client pays all it owes in one transaction, one
// taproot output per provider committing to the payment hashes of the invoices it settles, then
// publishes a receipt (kind 4247): the txid, the invoices, and the transaction's Merkle inclusion proof.
// The watchtower then runs without a node. It follows an untrusted header mirror served by this process
// and checks every header from genesis (layer1/headerchain.ts, the stand-in for a ZeroSync-style STARK
// of the header chain), takes each epoch's seed from that chain, and attests both sides of every epoch
// from public data alone: "stored" from the STARK, "paid" from the receipt. At the end each provider
// sweeps what it was paid with its own key, and the results go to results/full-stack-onchain.json.

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { keyFromSeed } from "../model/schnorr.ts";
import { CHUNK, encryptReplica, replicaKey, sentinelSurvival } from "../model/storage_bonds.ts";
import { BondTool, rpc } from "./bondtool.ts";
import { StorageClient, type BondSentinel, type Offer, type Replica } from "./client.ts";
import { HeaderChain, REGTEST, serveHeaders, syncFrom } from "./headerchain.ts";
import { LndNode, LndPayer, lndExe } from "./lnd.ts";
import { now, signEvent, type NostrEvent } from "./nostr.ts";
import { KIND_PAYMENT_RECEIPT, OnchainPayer, batchVsize, buildReceipt, receiptTags, verifyReceipt, type BatchPayment, type OnchainInvoice, type PaymentReceipt } from "./onchain.ts";
import { RelayClient, startRelay } from "./relay.ts";
import { defaultZk, statementFor, verifyProof, zkTree } from "./zk.ts";
import { KIND_ATTESTATION, KIND_EPOCH_PROOF } from "./zk-provider.ts";

const here = dirname(fileURLToPath(import.meta.url));
const arg = (name: string, dflt: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const EPOCHS = Number(arg("epochs", "3")), FROM_EPOCH = Number(arg("from-epoch", "2")), Q = Number(arg("q", "16"));
const EPOCH = 10, DEADLINE = 6, DELTA = 144;
const M = 64, K = 4, W = 16;
const PAY = arg("pay", "ln");
if (PAY !== "ln" && PAY !== "onchain") throw new Error("--pay must be ln or onchain");
const ONCHAIN = PAY === "onchain";
const PAY_EVERY = Number(arg("pay-every", "1")), FEE_RATE = Number(arg("fee-rate", "5"));
const LND = arg("lnd", lndExe());
const OUT = arg("out", join(here, "..", "results", ONCHAIN ? "full-stack-onchain.json" : "full-stack.json"));
const RPC = process.env.BSB_RPC ?? "http://127.0.0.1:18543";
const WALLET = "bsb-full-stack-client";
const wallet = (m: string, p: unknown[] = []) => rpc(m, p, `${RPC}/wallet/${WALLET}`);
const PRICE_MSAT = 512_000;       // per verified epoch, per provider
const CAPACITY = 50_000;
const SIZES = [256, 128, 64];     // chunks: the bonded 1 MiB deal, then 512 KiB and 256 KiB
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function blobOf(label: string, chunks: number): Buffer {
  const out = Buffer.alloc(chunks * CHUNK);
  for (let o = 0, i = 0; o < out.length; o += 32, i++) createHash("sha256").update(`${label} ${i}`).digest().copy(out, o);
  return out;
}
function pick(n: number, f: number, seed: string): number[] {
  const order = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = createHash("sha256").update(`${seed}|${i}`).digest().readUInt32LE(0) % (i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order.slice(0, Math.ceil(f * n));
}

interface Role { name: string; slug: string; kept: number }
const ROLES: Role[] = [{ name: "honest", slug: "honest", kept: 1 }, { name: "deletes 10%", slug: "deletes10", kept: 0.9 }, { name: "outsources", slug: "outsources", kept: 0 }];

interface Proc { child: ChildProcess; url: string; admin: string; nostr: string; bond_x: string; fee_address: string; ln?: string; pid: number; log: any[]; waiters: ((ev: any) => void)[] }

function spawnLogged(name: string, args: string[], show: (ev: any) => void = () => {}): Promise<Proc> {
  const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "inherit"] });
  const p = { child, pid: child.pid!, log: [] as any[], waiters: [] as ((ev: any) => void)[] } as Proc;
  return new Promise((ok, bad) => {
    const t = setTimeout(() => bad(new Error(`${name} did not start`)), 60_000);
    createInterface({ input: child.stdout! }).on("line", (line) => {
      let ev: any; try { ev = JSON.parse(line); } catch { return; }
      p.log.push(ev);
      for (const w of [...p.waiters]) w(ev);
      if (ev.ready) { clearTimeout(t); Object.assign(p, ev); ok(p); } else show(ev);
    });
    child.on("exit", (c) => { clearTimeout(t); if (c) bad(new Error(`${name} exited ${c}`)); });
  });
}
const waitLog = (p: Proc, pred: (ev: any) => boolean, ms: number) => new Promise<any>((ok, bad) => {
  const hit = p.log.find(pred);
  if (hit) return ok(hit);
  const f = (ev: any) => { if (pred(ev)) { clearTimeout(t); p.waiters = p.waiters.filter((w) => w !== f); ok(ev); } };
  const t = setTimeout(() => { p.waiters = p.waiters.filter((w) => w !== f); bad(new Error("timed out waiting for a log line")); }, ms);
  p.waiters.push(f);
});
const post = async (url: string, body: unknown, headers: Record<string, string> = {}) => {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  if (r.status !== 200) throw new Error(`${url}: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
  return r.json() as Promise<any>;
};
const mine = (n: number, addr: string) => (n > 0 ? rpc("generatetoaddress", [n, addr]) : Promise.resolve());
const tx = (txid: string) => rpc("getrawtransaction", [txid, true]);

let height0: number;
try { height0 = (await rpc("getblockchaininfo")).blocks; } catch (e) {
  console.error(`No regtest node (${(e as Error).message}). Start one with scripts/regtest-node.sh <datadir> <bitcoind>.`);
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), "bsb-full-stack-"));
const token = randomBytes(16).toString("hex");
const relay = await startRelay();
const procs: Proc[] = [];
let tower: Proc | undefined;
let clientLn: LndNode | undefined;
let finished = false;
// The header mirror: anyone's node will do, since the watchtower checks every header it is served.
const mirrorHandler = serveHeaders((m, p) => rpc(m, p));
const mirror = createServer((req, res) => { const u = new URL(req.url ?? "/", "http://x"); if (u.pathname === "/headers") void mirrorHandler(req, res, u); else res.writeHead(404).end(); });
await new Promise<void>((r) => mirror.listen(0, "127.0.0.1", r));
const MIRROR = `http://127.0.0.1:${(mirror.address() as { port: number }).port}/headers`;
try {
  const SEED = "bsb/client/full-stack";
  const tool = new BondTool(SEED);
  const me = await tool.run("info");
  const nostrKey = keyFromSeed(`nostr|${SEED}`);
  const secret = createHash("sha256").update("full-stack client storage secret").digest();
  await mine(1, me.fee_address);             // lnd waits until Core has a recent block
  let payAddr = "";
  if (ONCHAIN) { await rpc("createwallet", [WALLET]); payAddr = await wallet("getnewaddress", ["", "bech32m"]); }
  // Setup mines about 125 blocks; public proofs start at the first boundary well after that.
  const FIRST = Math.ceil((height0 + 170) / EPOCH) * EPOCH;

  // ── parties ──
  const show = (slug: string) => (ev: any) => {
    if (ev.event === "zk-epoch") console.log(`    [${slug}] block ${ev.height}: ${ev.proved ? `proved (${(ev.bytes / 1e6).toFixed(1)} MB, ${ev.seconds.toFixed(0)} s)` : "could not prove"}`);
    else if (ev.event === "bond-respond" && ev.status !== "idle") console.log(`    [${slug}] saw sentinel ${ev.i} revealed on chain: ${ev.status}${ev.error ? ` (${String(ev.error).replace(/^transaction failed: /, "").slice(0, 80)})` : ""}`);
  };
  const started = await Promise.all([
    ONCHAIN ? Promise.resolve(undefined) : LndNode.start({ bin: LND, dir: join(dir, "client-lnd"), alias: "bsb-client" }),
    ...ROLES.map((r) => spawnLogged(r.slug, [join(here, "provider.ts"), "--name", r.slug, "--seed", `bsb/provider/${r.slug}`, "--dir", join(dir, r.slug),
      "--relay", relay.url, "--admin-token", token, ...(ONCHAIN ? ["--pay", "onchain", "--network", "regtest"] : ["--pay", "ln", "--lnd", LND]),
      "--zk", "--epoch-blocks", String(EPOCH), "--zk-q", String(Q), "--zk-from", String(FIRST), "--zk-price", String(PRICE_MSAT)], show(r.slug))),
  ]);
  clientLn = started[0] as LndNode | undefined;
  procs.push(...(started.slice(1) as Proc[]));
  // On chain, the watchtower has no node: a work floor (here the chain's work now; on mainnet a recent
  // nMinimumChainWork) and the mirror are all it gets.
  const minWork: string = (await rpc("getblockchaininfo")).chainwork;
  const RECEIPT_DEADLINE = DEADLINE + EPOCH * PAY_EVERY + 2;
  tower = await spawnLogged("watchtower", [join(here, "watchtower.ts"), "--relay", relay.url, "--providers", procs.map((p) => p.nostr).join(","),
    "--epoch-blocks", String(EPOCH), "--from", String(FIRST), "--deadline", String(DEADLINE), "--min-q", String(Q), "--dir", join(dir, "watchtower"),
    ...(ONCHAIN ? ["--headers", MIRROR, "--network", "regtest", "--min-work", minWork, "--receipt-deadline", String(RECEIPT_DEADLINE)] : [])]);
  console.log(`regtest height ${height0}; public proofs every ${EPOCH} blocks from ${FIRST}, q = ${Q}; relay ${relay.url}; payment ${ONCHAIN ? `on chain, every ${PAY_EVERY} epoch(s), ${FEE_RATE} sat/vB` : "Lightning"}`);
  console.log(`client (pid ${process.pid}): bond key ${me.x.slice(0, 16)}…  ${clientLn ? `lnd ${clientLn.pubkey.slice(0, 16)}…` : `wallet ${WALLET} (${payAddr.slice(0, 16)}…)`}`);
  for (const [i, p] of procs.entries()) console.log(`provider ${ROLES[i].name.padEnd(12)} pid ${String(p.pid).padEnd(6)} ${p.url}  bond key ${p.bond_x.slice(0, 16)}…  ${p.ln ? `lnd ${p.ln.slice(0, 16)}…` : `nostr ${p.nostr.slice(0, 16)}…`}`);
  console.log(`watchtower           pid ${String(tower.pid).padEnd(6)} nostr ${tower.nostr.slice(0, 16)}…  (verifies every proof itself; no stake in any deal${ONCHAIN ? `; no node: headers from ${MIRROR}` : ""})`);

  for (const p of procs) await mine(2, p.fee_address);
  await mine(3, me.fee_address);
  await mine(ROLES.length, ONCHAIN ? payAddr : await clientLn!.newAddress());
  await mine(100, me.fee_address);
  await clientLn?.waitSynced(await rpc("getblockcount"));

  const rc = await RelayClient.connect(relay.url);
  const payer = ONCHAIN ? new OnchainPayer(wallet, "regtest", FEE_RATE, WALLET) : new LndPayer(clientLn!);
  const client = new StorageClient({ key: nostrKey, secret, payer });

  // ── deals, bonds, channels ──
  console.log(`\nsetup: 3 deals per provider (${SIZES.join(" + ")} chunks); a 1 BTC sentinel bond on the first (M = ${M}, k = ${K}, ${W} windows); ${ONCHAIN ? "payment on chain" : `${CAPACITY}-sat Lightning channels`}`);
  const blobs = SIZES.map((n, k) => blobOf(`full-stack blob ${k}`, n));
  const reps: Replica[][] = [], roots: { root: string; n: number }[][] = [], kept: BondSentinel[][] = [];
  const deals: string[] = [], fundTx: string[] = [], chans: string[] = [], payees: string[] = [], payKeys: string[] = [];
  const tEnd = (await rpc("getblockcount")) + 1500;
  for (const [i, p] of procs.entries()) {
    const info = (await (await fetch(`${p.url}/`)).json()) as { pubkey: string; bond_x: string; channel_payee: string; ln_uri?: string; onchain_key?: string };
    const offer: Offer = { url: p.url, pubkey: info.pubkey, lightningNodeId: info.channel_payee, priceMsatPerChunkEpoch: 1000 };
    const rs: Replica[] = [], rr: { root: string; n: number }[] = [];
    for (const [k, blob] of blobs.entries()) {
      const rep = await client.store(blob, offer, 8, "application/octet-stream", k === 0 ? M : 0, W);
      const ours = zkTree(encryptReplica(blob, replicaKey(secret, rep.blobId, offer.pubkey)));
      const reg = await post(`${p.url}/zk/register`, { sha256: rep.sha256 });
      if (reg.zk_root !== ours.root.toString("hex") || reg.n !== ours.n) throw new Error(`${ROLES[i].slug}: zk root differs from ours`);
      rs.push(rep); rr.push({ root: reg.zk_root, n: reg.n });
    }
    // The sentinel bond on the first deal.
    const ks = await client.bond(rs[0], K);
    const f = await post(`${p.url}/bond/${rs[0].sha256}/fund`, { client_x: me.x, t_end: tEnd });
    if (JSON.stringify(f.deal.sentinels) !== JSON.stringify(ks.map((s) => ({ s: s.s, h: s.h, hs: s.hs }))) || f.deal.client_x !== me.x || f.deal.provider_x !== info.bond_x) {
      throw new Error(`${ROLES[i].slug}: the provider's deal differs from ours`);
    }
    const dealPath = join(dir, `client-deal-${ROLES[i].slug}.json`);
    writeFileSync(dealPath, JSON.stringify(f.deal, null, 2));
    writeFileSync(dealPath.replace(".json", ".p.json"), JSON.stringify({ fund_txid: f.fund_txid, sig_p_challenge: f.sig_p_challenge }));
    await mine(1, me.fee_address);
    const c = await tool.run("bond-presign", dealPath);
    await post(`${p.url}/bond/${rs[0].sha256}/presigs`, { sig_c_respond: c.sig_c_respond });
    if (ONCHAIN) {
      if (!info.onchain_key || info.channel_payee !== p.nostr) throw new Error(`${ROLES[i].slug}: no on-chain pay key in its info`);
      reps.push(rs); roots.push(rr); kept.push(ks); deals.push(dealPath); fundTx.push(f.fund_txid); payees.push(info.channel_payee); payKeys.push(info.onchain_key);
      console.log(`  ${ROLES[i].name.padEnd(12)} zk roots match; bond ${f.fund_txid.slice(0, 12)}… (${c.checked.provider_signatures} signatures checked); pay key ${info.onchain_key.slice(0, 12)}…`);
      continue;
    }
    // The Lightning channel.
    if (!info.ln_uri?.startsWith(info.channel_payee + "@")) throw new Error(`${ROLES[i].slug}: no Lightning node in its info`);
    const ln = clientLn!;
    await ln.connect(info.ln_uri);
    await ln.waitSynced(await rpc("getblockcount"));
    await post(`${p.url}/channel/prepare`, {});
    let point = "";
    for (let tries = 0; !point; tries++) {
      try { point = await ln.openChannel(info.channel_payee, CAPACITY); }
      catch (e) { if (tries > 40 || !/sync/i.test((e as Error).message)) throw e; await sleep(250); }
    }
    await mine(1, me.fee_address);
    await ln.waitActive(point);
    await post(`${p.url}/channel/open`, { channel_point: point, client_pubkey: ln.pubkey });
    reps.push(rs); roots.push(rr); kept.push(ks); deals.push(dealPath); fundTx.push(f.fund_txid); chans.push(point); payees.push(info.channel_payee);
    console.log(`  ${ROLES[i].name.padEnd(12)} zk roots match; bond ${f.fund_txid.slice(0, 12)}… (${c.checked.provider_signatures} signatures checked); ln channel ${point.slice(0, 12)}…`);
  }
  if ((await rpc("getblockcount")) >= FIRST) throw new Error(`setup ran past the first boundary ${FIRST}`);

  // ── the client: verify each announced proof, then pay it (over Lightning at once; on chain, in the
  //    next batch) ──
  type Row = { proof?: string; client?: string; paidSats?: number; payment?: { hash: string; preimage: string }; tower?: string; towerEvent?: string; providerSays?: string;
    payTx?: string; towerPaid?: string; towerPaidEvent?: string; towerPaidWhy?: string; paidCheck?: Record<string, unknown> };
  const table = new Map<string, Row>();
  const row = (i: number, h: number) => { const k = `${i}|${h}`; if (!table.has(k)) table.set(k, {}); return table.get(k)!; };
  const byNostr = new Map(procs.map((p, i) => [p.nostr, i]));
  const adverse = new Map<number, { height: number; result: string; event: string; why?: string }>();
  let pending = Promise.resolve();
  let paying = true;
  let owed: { i: number; height: number; pr: string }[] = [];
  const batches: (BatchPayment & { epochs: number[]; receipt: PaymentReceipt; receiptEvent: string })[] = [];
  rc.subscribe([{ kinds: [KIND_EPOCH_PROOF], authors: procs.map((p) => p.nostr) }], (e: NostrEvent) => {
    if (!paying) return;
    pending = pending.then(async () => {
      const i = byNostr.get(e.pubkey)!;
      const c = JSON.parse(e.content);
      const r = row(i, c.height);
      r.proof = c.proof.sha256;
      if (!roots[i].every((m) => c.deals.some((d: any) => d.root === m.root && d.n === m.n))) { r.client = "rejected: deals not covered"; return; }
      const seed = Buffer.from(await rpc("getblockhash", [c.height]), "hex");
      const proof = Buffer.from(await (await fetch(c.proof.url)).arrayBuffer());
      if (createHash("sha256").update(proof).digest("hex") !== c.proof.sha256) { r.client = "rejected: proof bytes differ"; return; }
      const v = await verifyProof(defaultZk(), join(dir, "client-verify"), proof, statementFor(seed, Number(c.q), c.deals));
      if (!v.ok) { r.client = `rejected: ${v.why.slice(0, 50)}`; return; }
      r.client = "verified";
      const inv = (await (await fetch(`${procs[i].url}/zk/invoice/${c.height}?client=${me.x}`)).json()) as { paymentRequest: string };
      const d = payer.decode(inv.paymentRequest);
      if (d.payee !== payees[i] || d.amountMsat !== PRICE_MSAT) { r.client = "verified; invoice refused"; return; }
      if (ONCHAIN) {
        if ((d as OnchainInvoice).payKey !== payKeys[i]) { r.client = "verified; invoice refused"; return; }
        owed.push({ i, height: c.height, pr: inv.paymentRequest });
        return;
      }
      const { preimage } = await payer.pay(inv.paymentRequest, PRICE_MSAT);
      r.paidSats = PRICE_MSAT / 1000;
      r.payment = { hash: d.paymentHash, preimage };
    }).catch((err) => { console.log(`  client: ${(err as Error).message}`); });
  });
  rc.subscribe([{ kinds: [KIND_ATTESTATION], authors: [tower.nostr] }], (e: NostrEvent) => {
    const c = JSON.parse(e.content);
    const i = byNostr.get(c.provider);
    if (i === undefined) return;
    const r = row(i, c.height);
    if (c.side === "paid") {
      r.towerPaid = c.result; r.towerPaidEvent = e.id; r.towerPaidWhy = c.why;
      if (c.result === "paid") r.paidCheck = { txid: c.txid, vout: c.vout, block: c.block, confirmations: c.confirmations, receipt_bytes: c.receipt_bytes, verify_ms: c.verify_ms, chain: c.chain };
      return;
    }
    r.tower = c.result; r.towerEvent = e.id;
    if ((c.result === "missing" || c.result === "invalid") && !adverse.has(i)) adverse.set(i, { height: c.height, result: c.result, event: e.id, why: c.why });
  });

  /** Pay everything owed in one transaction, mine it, publish the receipt, and wait for the
   *  watchtower to check it from its own header chain. */
  async function settleOnChain(epoch: number) {
    const due = owed;
    owed = [];
    if (due.length === 0) return;
    const b = await (payer as OnchainPayer).payBatch(due.map((o) => ({ paymentRequest: o.pr, maxMsat: PRICE_MSAT })));
    await mine(1, me.fee_address);
    const receipt = await buildReceipt((m, p) => rpc(m, p), "regtest", b.txid, b.outputs.map((o) => ({ vout: o.vout, invoices: o.invoices })), { kind: "headers-standin", mirror: MIRROR });
    const ev = signEvent(nostrKey, { created_at: now(), kind: KIND_PAYMENT_RECEIPT, tags: receiptTags(receipt), content: JSON.stringify(receipt) });
    await rc.publish(ev);
    const epochs = [...new Set(due.map((o) => o.height))];
    batches.push({ ...b, epochs, receipt, receiptEvent: ev.id });
    for (const o of due) { const r = row(o.i, o.height); r.paidSats = PRICE_MSAT / 1000; r.payTx = b.txid; }
    console.log(`  paid on chain after epoch ${epoch}: ${due.length} invoice(s) for ${epochs.length} epoch(s) in ${b.txid.slice(0, 16)}…, ${b.outputs.length} provider output(s), ${b.vsize} vB, fee ${b.feeSats} sats; receipt ${ev.id.slice(0, 12)}… (${Buffer.byteLength(ev.content)} B)`);
    for (let k = 0; k < 240 && due.some((o) => !row(o.i, o.height).towerPaid); k++) await sleep(250);
  }

  // ── epochs ──
  console.log(`\nepochs: providers prove on their own at each boundary; the client verifies and pays ${ONCHAIN ? `on chain every ${PAY_EVERY} epoch(s)` : "over Lightning"}`);
  for (let e = 1; e <= EPOCHS; e++) {
    const b = FIRST + (e - 1) * EPOCH;
    if (e === FROM_EPOCH) {
      for (const k of SIZES.keys()) {
        await post(`${procs[1].admin}/admin/misbehave`, { kind: "delete", sha: reps[1][k].sha256, indices: pick(reps[1][k].n, 0.1, `lazy ${k}`) }, { "x-admin-token": token });
        await post(`${procs[2].admin}/admin/misbehave`, { kind: "outsource", sha: reps[2][k].sha256, from: { url: procs[0].url, sha256: reps[0][k].sha256 } }, { "x-admin-token": token });
      }
      console.log(`  from epoch ${e}: "deletes 10%" zeroes a tenth of each replica; "outsources" reads the honest provider's copies`);
    }
    await mine(b - (await rpc("getblockcount")), me.fee_address);
    console.log(`  epoch ${e}: boundary block ${b}, seed ${String(await rpc("getblockhash", [b])).slice(0, 16)}…`);
    const said = await Promise.all(procs.map((p) => waitLog(p, (ev) => ev.event === "zk-epoch" && ev.height === b, 900_000)));
    said.forEach((ev, i) => { row(i, b).providerSays = ev.proved ? "proved" : "could not prove"; });
    await mine(DEADLINE, me.fee_address);
    await pending;
    for (let k = 0; k < 600 && procs.some((_, i) => !row(i, b).tower); k++) await sleep(250);
    await pending;
    if (ONCHAIN && (e % PAY_EVERY === 0 || e === EPOCHS)) await settleOnChain(e);
  }
  // The epoch phase is over: no more proofs, payments or attestations while the bond phase mines.
  paying = false;
  for (const p of procs) await post(`${p.admin}/admin/zk-stop`, {}, { "x-admin-token": token });
  await pending;
  if (ONCHAIN) await settleOnChain(EPOCHS);
  const attestations = tower.log.filter((ev) => ev.event === "attest");
  tower.child.kill("SIGTERM");

  const via = ONCHAIN ? "paid (chain)" : "paid (LN)";
  console.log(`\n${"provider".padEnd(12)} ${"epoch".padEnd(6)} ${"provider".padEnd(16)} ${"client".padEnd(12)} ${via.padEnd(13)} watchtower${ONCHAIN ? ": stored / paid" : ""}`);
  for (const [i, r] of ROLES.entries()) for (let e = 1; e <= EPOCHS; e++) {
    const x = row(i, FIRST + (e - 1) * EPOCH);
    console.log(`${r.name.padEnd(12)} ${String(e).padEnd(6)} ${(x.providerSays ?? "—").padEnd(16)} ${(x.client ?? "nothing").slice(0, 12).padEnd(12)} ${String(x.paidSats ?? 0).padEnd(13)} ${x.tower ?? "—"}${ONCHAIN ? ` / ${x.towerPaid ?? "—"}` : ""}`);
  }

  // ── Lightning settlement, before the long mining of the bond phase (lnd's per-block RPC would
  //    exhaust Windows' ephemeral ports at a block every 150 ms) ──
  const lnCloses: string[] = [];
  const sweeps: ({ txid: string; outputs: { txid: string; vout: number; sats: number }[]; sats: number; feeRate: number; uneconomicAt?: number } | null)[] = [];
  if (ONCHAIN) {
    console.log("\non-chain settlement: each provider spends what the receipts paid it, with its own pay key plus each output's tweak");
    for (const [i, p] of procs.entries()) {
      if (payer.paidMsatTo(payees[i]) === 0) { sweeps.push(null); console.log(`  ${ROLES[i].name.padEnd(12)} paid nothing; nothing to sweep`); continue; }
      const s = await post(`${p.admin}/admin/sweep`, { fee_rate: FEE_RATE }, { "x-admin-token": token });
      await mine(1, me.fee_address);
      sweeps.push(s);
      console.log(`  ${ROLES[i].name.padEnd(12)} sweep ${s.txid.slice(0, 16)}… spends ${s.outputs.length} payment output(s), ${s.sats} sats, to its fee address at ${s.feeRate} sat/vB${s.uneconomicAt ? ` (worth less than its spend at ${s.uneconomicAt} sat/vB)` : ""}`);
    }
  } else console.log("\nLightning settlement: each provider closes its channel cooperatively from its own node");
  for (const [i, p] of ONCHAIN ? [] : procs.entries()) {
    const close = await post(`${p.admin}/admin/close-channel`, { peer: clientLn!.pubkey }, { "x-admin-token": token });
    await mine(1, me.fee_address);
    lnCloses.push(close.txid);
    console.log(`  ${ROLES[i].name.padEnd(12)} close ${close.txid.slice(0, 16)}…  (${payer.paidMsatTo(payees[i]) / 1000} sats paid over Lightning)`);
  }
  if (!ONCHAIN) for (const p of procs) await post(`${p.admin}/admin/ln-stop`, {}, { "x-admin-token": token });
  await clientLn?.stop();

  // ── enforcement: driven by the watchtower's attestations ──
  console.log(`\nenforcement: a missing or invalid attestation sends the client to that provider's bond`);
  const enforcement = [];
  for (const [i, role] of ROLES.entries()) {
    const cause = adverse.get(i);
    if (!cause) { console.log(`  ${role.name.padEnd(12)} no adverse attestation: not challenged`); enforcement.push({ role: role.name, cause: null, steps: [], forfeit: null }); continue; }
    console.log(`  ${role.name.padEnd(12)} attested ${cause.result} at block ${cause.height} (event ${cause.event.slice(0, 12)}…): challenging its bond`);
    const steps = [];
    let forfeit: string | null = null;
    for (let j = 0; j < K && !forfeit; j++) {
      const c = await tool.run("bond-challenge", deals[i], String(j), kept[i][j].r);
      await mine(1, me.fee_address);
      let answeredAt = -1;
      for (let b = 1; b < DELTA; b++) {
        await sleep(150);
        const st = await tool.run("bond-status", deals[i]);
        if ((st.states[j].respond ?? 0) >= 1) { answeredAt = b; break; }
        await mine(1, me.fee_address);
      }
      if (answeredAt < 0) {
        try { forfeit = (await tool.run("bond-forfeit", deals[i], String(j))).txid; } catch (e) { console.log(`    forfeit refused: ${(e as Error).message}`); }
        await mine(1, me.fee_address);
        if (forfeit) console.log(`    sentinel ${j}: no valid answer in ${DELTA} blocks → forfeit ${forfeit.slice(0, 16)}…`);
      } else console.log(`    sentinel ${j}: answered on chain after ${answeredAt} block(s)`);
      steps.push({ sentinel: j, challenge_txid: c.txid, answered_after_blocks: answeredAt < 0 ? null : answeredAt, forfeit_txid: forfeit });
    }
    enforcement.push({ role: role.name, cause, steps, forfeit });
  }

  // ── bond refunds at the term's end ──
  const refunds: (string | null)[] = [];
  for (const [i, p] of procs.entries()) {
    if (enforcement[i].forfeit) { refunds.push(null); continue; }
    const h = await rpc("getblockcount");
    if (h < tEnd) await mine(tEnd - h, me.fee_address);
    refunds.push((await post(`${p.admin}/admin/refund`, { sha: reps[i][0].sha256 }, { "x-admin-token": token })).txid);
    await mine(1, me.fee_address);
  }

  // ── read every outcome back from the chain ──
  // A third party's re-check at the end: a fresh header chain from the mirror, every receipt against it.
  const finalChain = new HeaderChain(REGTEST);
  if (ONCHAIN) await syncFrom(finalChain, MIRROR);
  const finalChecks = batches.map((b) => {
    const t = process.hrtime.bigint();
    const v = verifyReceipt(b.receipt, finalChain, { network: "regtest", minConf: 1 });
    return { txid: b.txid, ok: v.ok, ...(v.ok ? { confirmations: v.confirmations, payments: v.payments.length } : { why: v.why }), verify_ms: Number(process.hrtime.bigint() - t) / 1e6 };
  });

  console.log("\nfrom the chain:");
  const summary = [];
  for (const [i, role] of ROLES.entries()) {
    const fund = await tx(fundTx[i]);
    const bondOut = fund.vout[0];
    const paid = payer.paidMsatTo(payees[i]) / 1000;
    let lightning: Record<string, unknown> | undefined, onchain: Record<string, unknown> | undefined, payNote: string;
    if (ONCHAIN) {
      // Each payment output: confirmed, worth what was paid, and spent by the provider's sweep.
      const ours = batches.flatMap((b) => b.outputs.filter((o) => o.payee === payees[i]).map((o) => ({ b, o })));
      const sweep = sweeps[i];
      const st = sweep ? await tx(sweep.txid) : undefined;
      const payments = [];
      for (const { b, o } of ours) {
        const t = await tx(b.txid);
        if (t.confirmations < 1 || Math.round(t.vout[o.vout].value * 1e8) !== o.sats) throw new Error(`${role.slug}: payment output ${b.txid}:${o.vout} not as paid`);
        if (!st?.vin.some((x: any) => x.txid === b.txid && x.vout === o.vout)) throw new Error(`${role.slug}: sweep does not spend ${b.txid}:${o.vout}`);
        payments.push({ txid: b.txid, vout: o.vout, sats: o.sats, epochs: o.invoices.length, confirmations: t.confirmations, script: t.vout[o.vout].scriptPubKey.hex });
      }
      onchain = { payments, paid_sats: paid, sweep: sweep && { txid: sweep.txid, confirmations: st.confirmations, inputs: st.vin.length, vsize: st.vsize, fee_rate: sweep.feeRate, ...(sweep.uneconomicAt ? { uneconomic_at_fee_rate: sweep.uneconomicAt } : {}), output_sats: Math.round(st.vout[0].value * 1e8), to: st.vout[0].scriptPubKey.address } };
      payNote = `${payments.length} payment output(s) for ${paid} sats${sweep ? `, swept by ${sweep.txid.slice(0, 12)}…` : ""}`;
    } else {
      const close = await tx(lnCloses[i]);
      const [ftxid, fvout] = chans[i].split(":");
      if (close.confirmations < 1 || close.vin.length !== 1 || close.vin[0].txid !== ftxid || close.vin[0].vout !== Number(fvout)) throw new Error(`${role.slug}: close does not spend its channel`);
      const outs = close.vout.map((o: any) => Math.round(o.value * 1e8));
      if (paid > 0 && !outs.includes(paid)) throw new Error(`${role.slug}: close has no ${paid}-sat output (${outs.join(", ")})`);
      lightning = { channel_point: chans[i], close_txid: lnCloses[i], close_confirmations: close.confirmations, close_outputs_sats: outs, paid_sats: paid };
      payNote = `ln close ${lnCloses[i].slice(0, 12)}… pays ${paid} sats`;
    }
    const settleTxid = enforcement[i].forfeit ?? refunds[i]!;
    const settle = await tx(settleTxid);
    if (settle.confirmations < 1) throw new Error(`${role.slug}: bond settlement unconfirmed`);
    const leaf = settle.vin[0].sequence === DELTA ? "forfeit leaf (CSV 144), to the client" : "refund leaf (CLTV t_end), to the provider";
    const challenges = [];
    for (const s of enforcement[i].steps as any[]) {
      const ct = await tx(s.challenge_txid);
      challenges.push({ ...s, challenge_confirmations: ct.confirmations, revealed_r: ct.vin[0].txinwitness[0] });
    }
    console.log(`  ${role.name.padEnd(12)} bond ${fundTx[i].slice(0, 12)}… ${Math.round(bondOut.value * 1e8)} sats → ${settleTxid.slice(0, 12)}… via ${leaf}; ${payNote}`);
    const epochs = Array.from({ length: EPOCHS }, (_, e) => ({ epoch: e + 1, height: FIRST + e * EPOCH, ...row(i, FIRST + e * EPOCH) }));
    summary.push({
      role: role.name, pid: procs[i].pid,
      epochs,
      ...(lightning ? { lightning } : { onchain }),
      bond: { fund_txid: fundTx[i], value_sats: Math.round(bondOut.value * 1e8), settled_by: settleTxid, settle_confirmations: settle.confirmations, leaf, to: enforcement[i].forfeit ? "client" : "provider" },
      enforcement: { cause: enforcement[i].cause, challenges },
      p_detect_10pct_per_epoch: role.kept === 1 ? 0 : 1 - Math.pow(role.kept, Q),
      p_forfeit_given_challenge: role.kept === 1 ? 0 : 1 - sentinelSurvival(role.kept, W, K),
      providerLog: procs[i].log.filter((ev) => ["zk-epoch", "bond-respond", "ln-channel", "onchain-sweep"].includes(ev.event)),
    });
  }
  rc.close();

  console.log(`\n${"provider".padEnd(12)} ${"proofs ok".padEnd(10)} ${via.padEnd(13)} ${"attested".padEnd(22)} bond (1 BTC)`);
  for (const s of summary) {
    const ok = s.epochs.filter((e) => e.client === "verified").length;
    const att = s.enforcement.cause ? `${s.enforcement.cause.result} @ ${s.enforcement.cause.height}` : "valid throughout";
    const paidSats = ((s as any).lightning ?? (s as any).onchain).paid_sats;
    console.log(`${s.role.padEnd(12)} ${`${ok}/${EPOCHS}`.padEnd(10)} ${String(paidSats).padEnd(13)} ${att.padEnd(22)} ${s.bond.to === "client" ? "forfeited to the client" : "refunded to the provider"}`);
  }
  if (ONCHAIN) {
    console.log(`\non-chain payments (${FEE_RATE} sat/vB):`);
    for (const b of batches) console.log(`  ${b.txid.slice(0, 16)}… epochs ${b.epochs.join(", ")}: ${b.outputs.length} output(s), ${b.outputs.reduce((a, o) => a + o.invoices.length, 0)} invoice(s), ${b.vsize} vB (model ${batchVsize(b.outputs.length)}), fee ${b.feeSats} sats`);
    console.log(`  a third party's re-check from ${finalChain.height + 1} mirrored headers: ${finalChecks.filter((c) => c.ok).length}/${finalChecks.length} receipts verify`);
  }

  const height1 = await rpc("getblockcount");
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({
    generated: new Date().toISOString(),
    note: ONCHAIN
      ? "One regtest run: every party a separate process with its own keys and wallet. Public STARK epoch proofs seeded by block hashes; verified epochs paid on chain to taproot outputs committing to the invoices' payment hashes, batched; a receipt (txid + Merkle inclusion proof) per payment, checked by a watchtower with no node against a header chain it validated from genesis (the stand-in for a ZeroSync-style STARK of that chain); a missing or invalid attestation triggers on-chain sentinel challenges; every txid here was read back from bitcoind."
      : "One regtest run: every party a separate process with its own keys, wallet and lnd. Public STARK epoch proofs seeded by block hashes; each verified epoch paid by BOLT 11 over Lightning; a missing or invalid watchtower attestation triggers on-chain sentinel challenges; every txid here was read back from bitcoind.",
    params: { epochs: EPOCHS, misbehaviourFromEpoch: FROM_EPOCH, q: Q, epochBlocks: EPOCH, deadline: DEADLINE, firstBoundary: FIRST, deals: SIZES, bondSats: 100_000_000, sentinels: { M, k: K, windows: W }, delta: DELTA, priceSatsPerEpoch: PRICE_MSAT / 1000,
      ...(ONCHAIN ? { pay: "onchain", payEvery: PAY_EVERY, feeRateSatPerVb: FEE_RATE, receiptDeadline: DEADLINE + EPOCH * PAY_EVERY + 2, watchtowerNode: "none: header mirror + work floor" } : { pay: "ln", channelSats: CAPACITY }) },
    regtest: { heightBefore: height0, heightAfter: height1 },
    summary,
    ...(ONCHAIN ? {
      payments: batches.map((b) => ({ txid: b.txid, epochs: b.epochs, vsize: b.vsize, vsize_model: batchVsize(b.outputs.length), fee_sats: b.feeSats, fee_rate: b.feeRate,
        outputs: b.outputs.map((o) => ({ vout: o.vout, payee: o.payee, invoices: o.invoices.length, sats: o.sats })), receipt_event: b.receiptEvent, receipt_bytes: Buffer.byteLength(JSON.stringify(b.receipt)), receipt: b.receipt })),
      final_check: { headers: finalChain.height + 1, total_work: "0x" + finalChain.totalWork.toString(16), receipts: finalChecks },
    } : {}),
    watchtower: attestations,
  }, null, 2) + "\n");
  console.log(`\nregtest height ${height0} → ${height1}; wrote ${OUT}`);
  finished = true;
} finally {
  await Promise.all(procs.map((p) => fetch(`${p.admin}/admin/stop`, { method: "POST", headers: { "x-admin-token": token } }).catch(() => undefined)));
  await clientLn?.stop().catch(() => undefined);
  for (let i = 0; i < 40 && procs.some((p) => p.child.exitCode === null); i++) await sleep(250);
  for (const p of procs) p.child.kill("SIGTERM");
  tower?.child.kill("SIGTERM");
  await sleep(300);
  await relay.close();
  mirror.close();
  if (finished) rmSync(dir, { recursive: true, force: true });
  else console.error(`run failed; kept ${dir}`);
}
