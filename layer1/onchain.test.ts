import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { G, keyFromSeed, mul, be32 } from "../model/schnorr.ts";
import { HeaderChain, MAINNET, REGTEST, compactToTarget, fromDisplay, parseHeader, sha256d, targetToCompact, toDisplay } from "./headerchain.ts";
import {
  OnchainPayee, OnchainPayer, buildReceipt, decodeOnchainInvoice, merkleBranch, merkleRoot, p2trScript, parseTx, payToContract,
  payToContractSecret, rootFromBranch, taprootAddress, tweakKey, verifyReceipt, wif, type PaymentReceipt,
} from "./onchain.ts";

const here = dirname(fileURLToPath(import.meta.url));

// ── helpers: serialise transactions and mine regtest headers ──

const vi = (n: number) => (n < 0xfd ? Buffer.from([n]) : Buffer.from([0xfd, n & 0xff, n >> 8]));
const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64 = (n: bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
interface In { txid: string; vout: number; script?: Buffer; witness?: Buffer[] }
function serTx(ins: In[], outs: { value: bigint; script: Buffer }[], segwit = ins.some((i) => i.witness)): Buffer {
  const parts = [u32(2)];
  if (segwit) parts.push(Buffer.from([0, 1]));
  parts.push(vi(ins.length));
  for (const i of ins) parts.push(fromDisplay(i.txid), u32(i.vout), vi(i.script?.length ?? 0), i.script ?? Buffer.alloc(0), u32(0xfffffffd));
  parts.push(vi(outs.length));
  for (const o of outs) parts.push(u64(o.value), vi(o.script.length), o.script);
  if (segwit) for (const i of ins) { const w = i.witness ?? []; parts.push(vi(w.length)); for (const x of w) parts.push(vi(x.length), x); }
  parts.push(u32(0));
  return Buffer.concat(parts);
}
const coinbase = (height: number) => serTx([{ txid: "0".repeat(64), vout: 0xffffffff, script: Buffer.from([3, height & 0xff, height >> 8, 0, 0x51]) }],
  [{ value: 5_000_000_000n, script: Buffer.from("51", "hex") }], false);

const GENESIS_RT = Buffer.concat([u32(1), Buffer.alloc(32), fromDisplay("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"), u32(1296688602), u32(0x207fffff), u32(2)]);

function mineHeader(prev: Buffer, merkle: Buffer, time: number, bits = 0x207fffff): Buffer {
  const target = compactToTarget(bits)!;
  for (let nonce = 0; ; nonce++) {
    const h = Buffer.concat([u32(0x20000000), sha256d(prev), merkle, u32(time), u32(bits), u32(nonce)]);
    if (BigInt("0x" + toDisplay(sha256d(h))) <= target) return h;
  }
}
/** A regtest chain: genesis plus n blocks, with optional block bodies (txids) at some heights. */
function regtestChain(n: number, bodies: Map<number, Buffer[]> = new Map(), t0 = 1_700_000_000): Buffer[] {
  const hs = [GENESIS_RT];
  for (let h = 1; h <= n; h++) {
    const txids = bodies.get(h) ?? [sha256d(coinbase(h))];
    hs.push(mineHeader(hs[h - 1], merkleRoot(txids), t0 + h * 600));
  }
  return hs;
}

// ── header chain ──

test("regtest genesis hashes to Core's, and a mined regtest chain validates", () => {
  assert.equal(parseHeader(GENESIS_RT).hash, REGTEST.genesis);
  const c = new HeaderChain(REGTEST);
  const hs = regtestChain(30);
  assert.deepEqual(c.ingest(0, Buffer.concat(hs)), { added: 31 });
  assert.equal(c.height, 30);
  assert.equal(c.totalWork, 31n * 2n);          // regtest: two expected hashes per block
  assert.equal(c.hashAt(30), parseHeader(hs[30]).hash);
});

test("each header rule rejects", () => {
  const hs = regtestChain(12);
  const bad = (h: number, edit: (b: Buffer) => void, re: RegExp) => {
    const c = new HeaderChain(REGTEST);
    const copy = hs.map((x) => Buffer.from(x));
    edit(copy[h]);
    assert.throws(() => c.ingest(0, Buffer.concat(copy)), re);
  };
  bad(0, (b) => b.writeUInt32LE(3, 76), /genesis/);
  bad(5, (b) => b.writeUInt32LE(0, 4), /does not link/);
  bad(5, (b) => b.writeInt32LE(1, 0), /bad-version|hash above/);
  bad(12, (b) => b.writeUInt32LE(1_700_000_000, 68), /median/);
  bad(12, (b) => b.writeUInt32LE(0x207ffffe, 72), /bits/);
  // A header that misses the target: try nonces until one hashes above it.
  bad(12, (b) => { for (let n = 0; ; n++) { b.writeUInt32LE(n, 76); if (BigInt("0x" + toDisplay(sha256d(b))) > compactToTarget(0x207fffff)!) return; } }, /above target/);
  const c = new HeaderChain(REGTEST);
  assert.throws(() => c.ingest(0, Buffer.concat(hs.slice(0, 3)), 1_699_990_000), /future/);
});

test("a fork replaces the chain only with more work", () => {
  const a = regtestChain(8);
  const b = regtestChain(10, new Map(), 1_700_000_001);   // a different chain from genesis on
  const c = new HeaderChain(REGTEST);
  c.ingest(0, Buffer.concat(a));
  assert.deepEqual(c.ingest(0, Buffer.concat(b.slice(0, 6))), { added: 0 });   // less work: ignored
  assert.equal(c.hashAt(8), parseHeader(a[8]).hash);
  assert.deepEqual(c.ingest(0, Buffer.concat(b)), { added: 10, reorgFrom: 1 });
  assert.equal(c.height, 10);
  assert.equal(c.hashAt(10), parseHeader(b[10]).hash);
});

test("compact targets round-trip as Core encodes them", () => {
  for (const bits of [0x1d00ffff, 0x207fffff, 0x1b0404cb, 0x170331db]) assert.equal(targetToCompact(compactToTarget(bits)!), bits);
  assert.equal(compactToTarget(0x04923456), null);   // negative
  assert.equal(compactToTarget(0x00000000), null);
});

// The rust-bitcoin zk-client fixture: mainnet headers 0..2100 from mempool.space, which cross the first
// retarget at 2016.
const mainnetHeaders = [
  process.env.BSB_MAINNET_HEADERS,
  join(here, "..", "..", "rust-bitcoin", "zk", "sync", "tests", "data", "headers_0_2100.bin"),
  join(here, "..", "..", "..", "..", "..", "rust-bitcoin", "zk", "sync", "tests", "data", "headers_0_2100.bin"),
].find((p): p is string => !!p && existsSync(p));
test("mainnet headers 0..2100 validate, including the 2016 retarget", { skip: !mainnetHeaders && "no headers_0_2100.bin" }, () => {
  const raw = readFileSync(mainnetHeaders!);
  const c = new HeaderChain(MAINNET);
  c.ingest(0, raw);
  assert.equal(c.height, 2100);
  assert.equal(c.hashAt(170), "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee");
  const t = Buffer.from(raw);
  t.writeUInt32LE(t.readUInt32LE(2016 * 80 + 72) + 1, 2016 * 80 + 72);   // other bits at the retarget
  assert.throws(() => new HeaderChain(MAINNET).ingest(0, t), /header 2016: bits/);
});

// ── encodings ──

test("BIP341 key tweak, BIP350 address and a WIF match their published vectors", () => {
  const v = tweakKey("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
  assert.equal(v.tweak.toString(16), "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70");
  assert.equal(v.outputKey, "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
  assert.equal(taprootAddress(v.outputKey, "mainnet"), "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5");
  assert.equal(taprootAddress("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "mainnet"), "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
  assert.equal(wif(1n, "mainnet"), "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
});

test("a pay-to-contract output is spendable with the pay key plus the tweak, and commits to the hash list", () => {
  const k = keyFromSeed("onchain|test");
  const hs = ["11".repeat(32), "22".repeat(32)];
  const q = payToContract(k.x, hs).outputKey;
  assert.equal(be32(mul(payToContractSecret(k, hs), G)!.x).toString("hex"), q);
  assert.notEqual(payToContract(k.x, [hs[1], hs[0]]).outputKey, q);   // order matters
  assert.notEqual(payToContract(k.x, hs.slice(0, 1)).outputKey, q);
});

test("parseTx strips the witness for the txid and rejects junk", () => {
  const ins = [{ txid: "ab".repeat(32), vout: 1, witness: [Buffer.alloc(64, 7)] }];
  const outs = [{ value: 1234n, script: p2trScript("cd".repeat(32)) }];
  const sw = parseTx(serTx(ins, outs));
  const legacy = parseTx(serTx(ins.map(({ txid, vout }) => ({ txid, vout })), outs, false));
  assert.equal(sw.txid, legacy.txid);
  assert.equal(sw.outputs[0].value, 1234n);
  assert.throws(() => parseTx(Buffer.concat([serTx(ins, outs), Buffer.from([0])])), /trailing/);
  assert.throws(() => parseTx(serTx(ins, outs).subarray(0, 30)), /truncated/);
});

test("Merkle branches reach Core's root at every index", () => {
  for (const n of [1, 2, 3, 5, 8, 13]) {
    const leaves = Array.from({ length: n }, (_, i) => sha256d(Buffer.from([i])));
    const root = merkleRoot(leaves);
    for (let i = 0; i < n; i++) assert.ok(rootFromBranch(leaves[i], i, merkleBranch(leaves, i)).equals(root));
  }
});

// ── invoices and receipts ──

const providerNostr = keyFromSeed("nostr|bsb/provider/test");
const providerPay = keyFromSeed("onchain|bsb/provider/test");

test("invoices are signed by the payee; any edit breaks the signature", async () => {
  const payee = new OnchainPayee(providerNostr, providerPay, "regtest");
  const inv = await payee.createInvoice(512_000, "bsb zk epoch 200");
  const d = decodeOnchainInvoice(inv.paymentRequest);
  assert.equal(d.payee, providerNostr.x);
  assert.equal(d.payKey, providerPay.x);
  const body = JSON.parse(Buffer.from(inv.paymentRequest.slice(11), "base64url").toString());
  const forge = (b: object) => "bsbonchain1" + Buffer.from(JSON.stringify(b)).toString("base64url");
  assert.throws(() => decodeOnchainInvoice(forge({ ...body, a: 1_000_000 })), /signature/);
  assert.throws(() => decodeOnchainInvoice(forge({ ...body, k: keyFromSeed("thief").x })), /signature/);
  await assert.rejects(payee.createInvoice(512_001, "x"), /whole number of sats/);
});

test("the payer refuses expired, over-max and repeated invoices before touching its wallet", async () => {
  const payee = new OnchainPayee(providerNostr, providerPay, "regtest");
  const payer = new OnchainPayer(async () => { throw new Error("wallet must not be called"); }, "regtest");
  const inv = await payee.createInvoice(512_000, "e");
  await assert.rejects(payer.payBatch([{ paymentRequest: (await payee.createInvoice(512_000, "e", -10)).paymentRequest, maxMsat: 1e9 }]), /expired/);
  await assert.rejects(payer.payBatch([{ paymentRequest: inv.paymentRequest, maxMsat: 511_000 }]), /over max/);
  await assert.rejects(payer.payBatch([{ paymentRequest: inv.paymentRequest, maxMsat: 1e9 }, { paymentRequest: inv.paymentRequest, maxMsat: 1e9 }]), /already paid/);
  await assert.rejects(payer.payBatch([{ paymentRequest: (await new OnchainPayee(providerNostr, providerPay, "mainnet").createInvoice(512_000, "e")).paymentRequest, maxMsat: 1e9 }]), /for mainnet/);
});

/** A regtest chain with a payment for two invoices of one payee and one of another, in block 5, and
 *  the receipt for it built by buildReceipt from a fake node. */
async function scenario(extra = 3) {
  const a = new OnchainPayee(providerNostr, providerPay, "regtest");
  const b = new OnchainPayee(keyFromSeed("nostr|b"), keyFromSeed("onchain|b"), "regtest");
  const ia = [await a.createInvoice(512_000, "bsb zk epoch 200"), await a.createInvoice(512_000, "bsb zk epoch 210")];
  const ib = [await b.createInvoice(700_000, "bsb zk epoch 200")];
  const qa = payToContract(providerPay.x, ia.map((i) => i.paymentHash)).outputKey;
  const qb = payToContract(b.payKey.x, ib.map((i) => i.paymentHash)).outputKey;
  const pay = serTx([{ txid: "aa".repeat(32), vout: 0, witness: [Buffer.alloc(64, 1)] }],
    [{ value: 900_000n, script: p2trScript("ee".repeat(32)) }, { value: 1024n, script: p2trScript(qa) }, { value: 700n, script: p2trScript(qb) }]);
  const others = [1, 2, 3].map((i) => serTx([{ txid: "bb".repeat(32), vout: i }], [{ value: 5000n, script: Buffer.from("51", "hex") }], false));
  const txs = [coinbase(5), others[0], pay, others[1], others[2]];
  const txids = txs.map((t) => toDisplay(sha256d(parseTx(t).stripped)));
  const hs = regtestChain(5 + extra, new Map([[5, txids.map(fromDisplay)]]));
  const blockHash = parseHeader(hs[5]).hash;
  const node = async (m: string, p: any[] = []) => {
    if (m === "getrawtransaction" && p[1] === 1) return { hex: pay.toString("hex"), blockhash: blockHash };
    if (m === "getrawtransaction") return txs[txids.indexOf(p[0])].toString("hex");
    if (m === "getblock") return { height: 5, time: parseHeader(hs[5]).time, tx: txids };
    if (m === "getblockheader") return hs[5].toString("hex");
    throw new Error(m);
  };
  const r = await buildReceipt(node, "regtest", txids[2], [{ vout: 1, invoices: ia.map((i) => i.paymentRequest) }, { vout: 2, invoices: ib.map((i) => i.paymentRequest) }], { kind: "headers-standin" });
  const chain = new HeaderChain(REGTEST);
  chain.ingest(0, Buffer.concat(hs));
  return { r, chain, ia, ib, hs };
}

test("a receipt verifies from the header chain alone, and says what it paid", async () => {
  const { r, chain, ia, ib } = await scenario();
  const v = verifyReceipt(r, chain, { network: "regtest", minConf: 4 });
  assert.ok(v.ok, !v.ok ? v.why : "");
  if (!v.ok) return;
  assert.equal(v.height, 5);
  assert.equal(v.confirmations, 4);
  assert.deepEqual(v.payments.map((p) => [p.vout, p.paymentHash, p.amountMsat]),
    [[1, ia[0].paymentHash, 512_000], [1, ia[1].paymentHash, 512_000], [2, ib[0].paymentHash, 700_000]]);
  assert.equal(verifyReceipt(r, chain, { network: "regtest", minConf: 5 }).ok, false);
});

test("every tampered receipt is rejected by the intended check", async () => {
  const { r, chain, ia, hs } = await scenario();
  const edit = (f: (x: PaymentReceipt) => void) => { const x = structuredClone(r); f(x); return verifyReceipt(x, chain, { network: "regtest" }); };
  const why = (f: (x: PaymentReceipt) => void) => { const v = edit(f); assert.equal(v.ok, false); return v.ok ? "" : v.why; };
  const flipOutput = (hex: string) => { const t = Buffer.from(hex, "hex"); const i = t.indexOf(Buffer.from([0x00, 0x04, 0, 0, 0, 0, 0, 0])); t[i] = 0x05; return t.toString("hex"); };
  assert.match(why((x) => { x.tx = flipOutput(x.tx); }), /does not hash to the txid/);
  assert.match(why((x) => { x.tx = flipOutput(x.tx); x.txid = parseTx(Buffer.from(x.tx, "hex")).txid; }), /Merkle branch/);
  assert.match(why((x) => { x.block.index = 3; }), /Merkle branch/);
  assert.match(why((x) => { x.block.index = 8; }), /index out of range/);
  assert.match(why((x) => { x.block.coinbaseBranch = x.block.coinbaseBranch.slice(1); }), /depth/);
  assert.match(why((x) => { x.block.height = 6; }), /not this header/);
  assert.match(why((x) => { x.block.header = hs[5].toString("hex").replace(/..$/, "ff"); }), /not this header/);
  assert.match(why((x) => { x.outputs[0].invoices.reverse(); }), /does not commit/);
  assert.match(why((x) => { x.outputs[0].invoices.pop(); }), /does not commit/);
  assert.match(why((x) => { x.outputs[0].vout = 2; }), /mixes payees|commit/);
  assert.match(why((x) => { x.outputs[1].vout = 1; }), /listed twice/);
  assert.match(why((x) => { x.outputs[1].invoices = [x.outputs[0].invoices[0]]; }), /does not commit|twice/);
  assert.match(why((x) => { x.network = "mainnet"; }), /network/);
  // An honest-looking output holding less than the invoices ask.
  const body = JSON.parse(Buffer.from(ia[0].paymentRequest.slice(11), "base64url").toString());
  assert.match(why((x) => { x.outputs[0].invoices[0] = "bsbonchain1" + Buffer.from(JSON.stringify({ ...body, a: 600_000 })).toString("base64url"); }), /signature/);
  // A forked chain without the block: the receipt does not verify against it.
  const other = new HeaderChain(REGTEST);
  other.ingest(0, Buffer.concat(regtestChain(9, new Map(), 1_700_000_001)));
  assert.equal(verifyReceipt(r, other, { network: "regtest" }).ok, false);
});

test("an output short of what its invoices ask is refused", async () => {
  const payee = new OnchainPayee(providerNostr, providerPay, "regtest");
  const inv = await payee.createInvoice(512_000, "e");
  const q = payToContract(providerPay.x, [inv.paymentHash]).outputKey;
  const pay = serTx([{ txid: "aa".repeat(32), vout: 0, witness: [Buffer.alloc(64)] }], [{ value: 511n, script: p2trScript(q) }]);
  const txs = [coinbase(1), pay];
  const txids = txs.map((t) => sha256d(parseTx(t).stripped));
  const hs = regtestChain(1, new Map([[1, txids]]));
  const chain = new HeaderChain(REGTEST);
  chain.ingest(0, Buffer.concat(hs));
  const r: PaymentReceipt = {
    v: 1, network: "regtest", txid: toDisplay(txids[1]), tx: pay.toString("hex"),
    block: { height: 1, header: hs[1].toString("hex"), time: parseHeader(hs[1]).time, index: 1, branch: merkleBranch(txids, 1).map((b) => b.toString("hex")), coinbase: txs[0].toString("hex"), coinbaseBranch: merkleBranch(txids, 0).map((b) => b.toString("hex")) },
    outputs: [{ vout: 0, invoices: [inv.paymentRequest] }], chain: { kind: "headers-standin" },
  };
  const v = verifyReceipt(r, chain, { network: "regtest" });
  assert.equal(v.ok, false);
  assert.match(v.ok ? "" : v.why, /holds 511 sats/);
});
