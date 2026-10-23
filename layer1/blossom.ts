// A minimal Blossom server (BUD-01 GET/HEAD /<sha256>, BUD-02 PUT /upload with BUD-11 kind-24242 auth)
// plus the pay-per-proof sidecar, GET /pdp/<sha256>?nonce=&q=&epoch=. The sidecar answers from the stored
// bytes with the chunks the nonce selects and their Merkle paths, and attaches a Lightning invoice for the
// epoch. The client pays only if the answer checks against the root it computed itself.
//
// Storage, per blob: <sha>.blob (the bytes as uploaded), <sha>.leaves (32 bytes per 4 KiB chunk, computed
// at upload) and <sha>.json (descriptor plus root). Keeping the leaves lets a provider answer with paths
// even for chunks it no longer has, so the only thing a deleter loses is the chunk bytes themselves.
//
// Layer 2 support: GET /sentinel/<sha256>?r= answers a revealed sentinel with r ‖ window from the stored
// bytes, and POST /bond/<sha256>/commit and /reveal run cut and choose before a bond is funded.
//
// Not implemented: BUD-04 mirror, BUD-06 HEAD /upload, BUD-12 list/delete, quotas, rate limits. Two
// misbehaviours exist for the demo and tests, set through methods on the returned object, never over HTTP.

import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, renameSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Key } from "../model/schnorr.ts";
import {
  CHUNK, SALT, WINDOWS_PER_CHUNK, epochIndices, leafHash, merkleProof, sentinelIndex, treeFromLeaves, windowOf, type Tree,
} from "../model/storage_bonds.ts";
import { be32, sha256 } from "../model/schnorr.ts";
import { zkTree as zkTreeOf, zkTreeFromLeaves } from "./zk.ts";
import { commitmentsRoot } from "./deals.ts";
import type { Tree as ZkTree } from "../model/zk_pdp.ts";
import { checkBlossomAuth, newKey } from "./nostr.ts";
import { StubNetwork, type Payee } from "./lightning.ts";

export const MAX_Q = 256;
export const MAX_WINDOWS = 64;   // windows per sentinel; 64 makes a ~2.3 kB leaf and a ~1.4k-vB answer

export interface ProviderConfig {
  dir: string;
  key: Key;                      // the provider's Nostr identity; replica keys and receipts name it
  payee: Payee;
  priceMsatPerChunkEpoch: number;
  port?: number;
  host?: string;
  /** The URL clients reach this server at (a public address or a reverse proxy). It goes into blob
   *  descriptors, proof URLs and offers. Default: http://<host>:<port>. */
  publicUrl?: string;
  maxUploadBytes?: number;
  uploaders?: string[];          // pubkeys allowed to upload; omitted means anyone with a valid token
  /** Extra routes tried before the built-in ones (the provider process adds bond and channel endpoints).
   *  Return true if the request was handled. */
  routes?: (req: IncomingMessage, res: ServerResponse, url: URL) => Promise<boolean>;
  /** Extra fields for GET / (for example the provider's on-chain key). */
  info?: Record<string, unknown>;
}

export interface Descriptor {
  url: string; sha256: string; size: number; type: string; uploaded: number;
  /** Extension field: the chunk-tree commitment the provider recomputed from the bytes it received,
   *  and the Blake2s tree root that public epoch proofs (layer1/zk.ts) are made against. */
  bsb: { root: string; n: number; chunk: number; zk_root?: string };
}

export interface PdpAnswer {
  sha256: string; n: number; root: string; nonce: string; q: number; epoch: number;
  indices: number[]; chunks: string[]; paths: string[][];
  invoice: string;
}

export interface Provider {
  readonly url: string;
  /** The same server on its loopback address: what the provider's own agent calls. */
  readonly localUrl: string;
  readonly pubkey: string;
  readonly config: ProviderConfig;
  /** Overwrite these chunks with zeros on disk. The provider keeps its leaves, so it still sends paths. */
  deleteChunks(sha: string, indices: number[]): void;
  /** Delete the replica's bytes and answer PDP by fetching the same chunk indices from another server's
   *  blob (outsourcing, design finding 3). The leaves of the provider's own replica are kept. */
  outsource(sha: string, from: { url: string; sha256: string }): void;
  /** Phase 7C: keep the bytes and answer every proof, but refuse BUD-01 downloads (GET, HEAD, Range).
   *  The bond only enforces possession, so a withholder keeps it; only a retrieval probe can tell. */
  withhold(sha: string, selective?: boolean): void;
  /** The PDP answer for a nonce, from whatever the provider holds: what the sidecar serves over HTTP and
   *  the provider process sends over NIP-44. */
  pdpAnswer(sha: string, nonce: string, q: number, epoch: number): Promise<PdpAnswer | { error: string }>;
  /** The commitments left unopened by the last completed cut and choose for a blob, if any. */
  bondTerms(sha: string): { s: string; h: string; hs?: string[] }[] | undefined;
  /** That cut and choose: the root of all M commitments (deals.ts commitmentsRoot), M and k. */
  bondCommitment(sha: string): { root: string; m: number; k: number } | undefined;
  /** The Nostr key whose BUD-11 token uploaded the blob. */
  uploader(sha: string): string | undefined;
  /** Read chunk i as this provider would send it (zeros if deleted, someone else's bytes if
   *  outsourced): what goes into its witness. */
  readChunk(sha: string, i: number): Promise<Buffer>;
  /** The Blake2s chunk tree of a blob, from the leaves recorded at upload (a deleter keeps them). */
  zkTree(sha: string): ZkTree | undefined;
  /** Store bytes as a blob of this server (BUD-01 GET serves it): how proofs are published. */
  putBlob(body: Buffer, type: string): Descriptor;
  /** Hold a body for one GET at an unguessable /pdp-answer/<id> URL: how an answer too large for one
   *  NIP-44 message (65,535 bytes) is delivered. The Nostr message then carries the URL and its hash. */
  stash(body: string): string;
  close(): Promise<void>;
}

const SHA_PATH = /^\/([0-9a-f]{64})(\.[A-Za-z0-9]{1,10})?$/;
const extFor = (type: string): string =>
  ({ "application/octet-stream": ".bin", "text/plain": ".txt", "image/png": ".png", "image/jpeg": ".jpg", "application/pdf": ".pdf" } as Record<string, string>)[type] ?? ".bin";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Authorization, *",
  "Access-Control-Allow-Methods": "GET, HEAD, PUT, POST, DELETE",
  "Access-Control-Max-Age": "86400",
};

export function fail(res: ServerResponse, status: number, reason: string) {
  res.writeHead(status, { ...CORS, "X-Reason": reason, "Content-Type": "text/plain" });
  res.end(reason + "\n");
}
export function json(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { ...CORS, "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

export function readBody(req: IncomingMessage, max: number): Promise<Buffer | null> {
  return new Promise((ok, bad) => {
    const parts: Buffer[] = [];
    let n = 0;
    req.on("data", (d: Buffer) => { n += d.length; if (n > max) { req.destroy(); ok(null); } else parts.push(d); });
    req.on("end", () => ok(Buffer.concat(parts)));
    req.on("error", bad);
  });
}

/** Leaf hashes of the chunk tree, computed the same way as model chunk() + buildTree(). */
export function leavesOf(data: Buffer): Buffer[] {
  const n = Math.max(1, Math.ceil(data.length / CHUNK));
  const out: Buffer[] = [];
  for (let i = 0; i < n; i++) {
    const c = Buffer.alloc(CHUNK);
    data.copy(c, 0, i * CHUNK, Math.min((i + 1) * CHUNK, data.length));
    out.push(leafHash(c));
  }
  return out;
}

export async function startProvider(cfg: ProviderConfig): Promise<Provider> {
  mkdirSync(cfg.dir, { recursive: true });
  const host = cfg.host ?? "127.0.0.1";
  const maxUpload = cfg.maxUploadBytes ?? 64 << 20;
  const trees = new Map<string, Tree>();
  const zkTrees = new Map<string, ZkTree>();
  const outsourced = new Map<string, { url: string; sha256: string }>();
  /** Withheld blobs: null refuses every download; a set serves only those chunk indices (the
   *  "serve only what was just challenged" withholder of the phase 7C review). */
  const withheld = new Map<string, Set<number> | null>();
  let base = "";

  const metaPath = (sha: string) => join(cfg.dir, `${sha}.json`);
  const blobPath = (sha: string) => join(cfg.dir, `${sha}.blob`);
  const leavesPath = (sha: string) => join(cfg.dir, `${sha}.leaves`);
  const zkLeavesPath = (sha: string) => join(cfg.dir, `${sha}.zkleaves`);
  const meta = (sha: string): Omit<Descriptor, "url"> | null =>
    existsSync(metaPath(sha)) ? JSON.parse(readFileSync(metaPath(sha), "utf8")) : null;
  const descriptor = (m: Omit<Descriptor, "url">): Descriptor => ({ url: `${base}/${m.sha256}${extFor(m.type)}`, ...m });

  function tree(sha: string): Tree {
    let t = trees.get(sha);
    if (!t) {
      const raw = readFileSync(leavesPath(sha));
      const leaves: Buffer[] = [];
      for (let o = 0; o < raw.length; o += 32) leaves.push(raw.subarray(o, o + 32));
      t = treeFromLeaves(leaves);
      trees.set(sha, t);
    }
    return t;
  }

  /** One chunk, zero-padded to CHUNK, from whatever this provider still has; empty if it has nothing. */
  async function readChunk(sha: string, size: number, i: number): Promise<Buffer> {
    const src = outsourced.get(sha);
    const start = i * CHUNK, end = Math.min(start + CHUNK, size);
    if (src) {
      const r = await fetch(`${src.url}/${src.sha256}`, { headers: { Range: `bytes=${start}-${end - 1}` } });
      if (r.status !== 206 && r.status !== 200) return Buffer.alloc(0);
      const got = Buffer.from(await r.arrayBuffer());
      const body = r.status === 200 ? got.subarray(start, end) : got;
      const c = Buffer.alloc(CHUNK); body.copy(c); return c;
    }
    if (!existsSync(blobPath(sha))) return Buffer.alloc(0);
    const c = Buffer.alloc(CHUNK);
    if (end > start) {
      const fd = openSync(blobPath(sha), "r");
      try { readSync(fd, c, 0, end - start, start); } finally { closeSync(fd); }
    }
    return c;
  }

  async function onUpload(req: IncomingMessage, res: ServerResponse) {
    const want = String(req.headers["x-sha-256"] ?? "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(want)) return fail(res, 400, "X-SHA-256 header required (BUD-11 x tag source)");
    const auth = checkBlossomAuth(req.headers.authorization, { verb: "upload", x: want, xRequired: true, domain: hostname(req) });
    if (!auth.ok) return fail(res, 401, auth.why);
    if (cfg.uploaders && !cfg.uploaders.includes(auth.event.pubkey)) return fail(res, 403, "pubkey not allowed to upload");
    const len = req.headers["content-length"];
    if (len === undefined) return fail(res, 411, "Content-Length required");
    if (Number(len) > maxUpload) return fail(res, 413, `blob over ${maxUpload} bytes`);
    const body = await readBody(req, maxUpload);
    if (!body) return fail(res, 413, `blob over ${maxUpload} bytes`);
    const sha = createHash("sha256").update(body).digest("hex");
    if (sha !== want) return fail(res, 409, "X-SHA-256 does not match the body");
    const have = meta(sha);
    if (have) return json(res, 200, descriptor(have));
    json(res, 201, store(body, String(req.headers["content-type"] ?? "application/octet-stream").split(";")[0], auth.event.pubkey));
  }

  /** Write a blob and its two trees; returns its descriptor. */
  function store(body: Buffer, type: string, uploader?: string): Descriptor {
    const sha = createHash("sha256").update(body).digest("hex");
    const have = meta(sha);
    if (have) return descriptor(have);
    const leaves = leavesOf(body);
    const t = treeFromLeaves(leaves);
    const z = zkTreeOf(body);
    const m = {
      sha256: sha, size: body.length, type,
      uploaded: Math.floor(Date.now() / 1000), bsb: { root: t.root.toString("hex"), n: t.n, chunk: CHUNK, zk_root: z.root.toString("hex") },
      ...(uploader ? { uploader } : {}),
    };
    writeFileSync(blobPath(sha) + ".tmp", body); renameSync(blobPath(sha) + ".tmp", blobPath(sha));
    writeFileSync(leavesPath(sha), Buffer.concat(leaves));
    writeFileSync(zkLeavesPath(sha), Buffer.concat(z.levels[0]));
    writeFileSync(metaPath(sha), JSON.stringify(m));
    trees.set(sha, t);
    zkTrees.set(sha, z);
    return descriptor(m);
  }

  function onGet(req: IncomingMessage, res: ServerResponse, sha: string) {
    const m = meta(sha);
    if (!m || !existsSync(blobPath(sha))) return fail(res, 404, "blob not found");
    if (withheld.has(sha)) {
      const allow = withheld.get(sha);
      const rg = /^bytes=(\d+)-(\d+)$/.exec(String(req.headers.range ?? ""));
      const i = rg ? Math.floor(Number(rg[1]) / CHUNK) : -1;
      if (!allow || !rg || Number(rg[2]) >= (i + 1) * CHUNK || !allow.has(i)) return fail(res, 404, "blob not found");
    }
    const head = req.method === "HEAD";
    const headers = { ...CORS, "Content-Type": m.type, "Accept-Ranges": "bytes" };
    const range = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.range ?? ""));
    if (range && (range[1] !== "" || range[2] !== "")) {
      let a = range[1] === "" ? Math.max(0, m.size - Number(range[2])) : Number(range[1]);
      let b = range[1] === "" || range[2] === "" ? m.size - 1 : Math.min(Number(range[2]), m.size - 1);
      if (a > b || a >= m.size) {
        res.writeHead(416, { ...headers, "Content-Range": `bytes */${m.size}` }); return res.end();
      }
      const out = Buffer.alloc(b - a + 1);
      const fd = openSync(blobPath(sha), "r");
      try { readSync(fd, out, 0, out.length, a); } finally { closeSync(fd); }
      res.writeHead(206, { ...headers, "Content-Length": out.length, "Content-Range": `bytes ${a}-${b}/${m.size}` });
      return res.end(head ? undefined : out);
    }
    res.writeHead(200, { ...headers, "Content-Length": m.size });
    res.end(head ? undefined : readFileSync(blobPath(sha)));
  }

  async function onPdp(res: ServerResponse, sha: string, params: URLSearchParams) {
    const a = await pdpAnswer(sha, params.get("nonce") ?? "", Number(params.get("q")), Number(params.get("epoch") ?? 0));
    if ("error" in a) return fail(res, a.error === "blob not found" ? 404 : 400, a.error);
    json(res, 200, a);
  }

  async function pdpAnswer(sha: string, nonce: string, q: number, epoch: number): Promise<PdpAnswer | { error: string }> {
    const m = meta(sha);
    if (!m) return { error: "blob not found" };
    if (!/^[0-9a-f]{64}$/.test(nonce)) return { error: "nonce must be 32 bytes of lowercase hex" };
    if (!Number.isSafeInteger(q) || q < 1 || q > MAX_Q) return { error: `q must be an integer in 1..${MAX_Q}` };
    if (!Number.isSafeInteger(epoch) || epoch < 0) return { error: "epoch must be a non-negative integer" };
    const t = tree(sha);
    const indices = epochIndices(Buffer.from(nonce, "hex"), t.n, q);
    if (withheld.get(sha)) withheld.set(sha, new Set(indices));
    const chunks = await Promise.all(indices.map((i) => readChunk(sha, m.size, i)));
    const invoice = await cfg.payee.createInvoice(cfg.priceMsatPerChunkEpoch * t.n, `bsb epoch ${epoch} ${sha}`);
    const answer: PdpAnswer = {
      sha256: sha, n: t.n, root: t.root.toString("hex"), nonce, q, epoch, indices,
      chunks: chunks.map((c) => c.toString("base64")),
      paths: indices.map((i) => merkleProof(t, i).map((p) => p.toString("hex"))),
      invoice: invoice.paymentRequest,
    };
    return answer;
  }

  // ── layer 2 support: sentinel answers and cut and choose ──

  /** r ‖ window[idx(r)] from whatever this provider still has (its own bytes, or an outsourced copy), or
   *  null if it has nothing for that chunk. The bond tool puts this on chain as is; Core is the judge. */
  async function sentinelItem(sha: string, r: Buffer, j = 0): Promise<Buffer | null> {
    const m = meta(sha);
    if (!m) return null;
    const idx = sentinelIndex(r, tree(sha).n, j);
    const c = await readChunk(sha, m.size, Math.floor(idx / WINDOWS_PER_CHUNK));
    return c.length === 0 ? null : Buffer.concat([r, windowOf(c, idx)]);
  }

  async function onSentinel(res: ServerResponse, sha: string, params: URLSearchParams) {
    const r = params.get("r") ?? "";
    if (!new RegExp(`^[0-9a-f]{${2 * SALT}}$`).test(r)) return fail(res, 400, `r must be ${SALT} bytes of lowercase hex`);
    const m = Number(params.get("m") ?? 1);
    if (!Number.isSafeInteger(m) || m < 1 || m > MAX_WINDOWS) return fail(res, 400, `m must be an integer in 1..${MAX_WINDOWS}`);
    if (!meta(sha)) return fail(res, 404, "blob not found");
    const items: Buffer[] = [];
    for (let j = 0; j < m; j++) {
      const item = await sentinelItem(sha, Buffer.from(r, "hex"), j);
      if (!item) return fail(res, 404, `chunk for window ${j} not held`);
      items.push(item);
    }
    json(res, 200, { item: items[0].toString("hex"), items: items.map((x) => x.toString("hex")) });
  }

  /** Cut and choose (design §2.3). The client commits to M pairs (s_j, h_j); the provider picks M − k to
   *  open, from its secret key and the commitments, so the client cannot predict or grind the choice. */
  type Commitment = { s: string; h: string; hs?: string[] };
  const pending = new Map<string, { commitments: Commitment[]; open: number[]; k: number }>();
  const terms = new Map<string, Commitment[]>();
  const commits = new Map<string, { root: string; m: number; k: number }>();
  const loadBond = (sha: string) => {
    const f = join(cfg.dir, `${sha}.bond.json`);
    if (terms.has(sha) || !/^[0-9a-f]{64}$/.test(sha) || !existsSync(f)) return;
    const v = JSON.parse(readFileSync(f, "utf8"));
    terms.set(sha, v.kept); commits.set(sha, v.commit);
  };
  const stashed = new Map<string, string>();

  async function onCommit(req: IncomingMessage, res: ServerResponse, sha: string) {
    if (!meta(sha)) return fail(res, 404, "blob not found");
    const body = await readBody(req, 1 << 20);
    let msg: { commitments?: Commitment[]; k?: number };
    try { msg = JSON.parse(String(body)); } catch { return fail(res, 400, "body must be JSON"); }
    const cs = msg.commitments, k = msg.k;
    const hex32 = (x: unknown) => typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
    const hsOk = (c: Commitment) => c.hs === undefined || (Array.isArray(c.hs) && c.hs.length >= 1 && c.hs.length <= MAX_WINDOWS && c.hs.every(hex32) && c.hs[0] === c.h);
    if (!Array.isArray(cs) || cs.length < 2 || cs.length > 4096 || !cs.every((c) => hex32(c?.s) && hex32(c?.h) && hsOk(c))) {
      return fail(res, 400, `commitments: 2..4096 entries of 32-byte hex s and h, and optional hs (1..${MAX_WINDOWS}, hs[0] = h)`);
    }
    if (!Number.isSafeInteger(k) || k! < 1 || k! >= cs.length) return fail(res, 400, "k must be in 1..M-1");
    const seed = sha256("bsb/cut-and-choose|", be32(cfg.key.d), sha, JSON.stringify(cs));
    const order = cs.map((_, j) => j);
    for (let i = order.length - 1; i > 0; i--) {
      const j = sha256(seed, String(i)).readUInt32LE(0) % (i + 1);
      [order[i], order[j]] = [order[j], order[i]];
    }
    const open = order.slice(0, cs.length - k!).sort((a, b) => a - b);
    pending.set(sha, { commitments: cs, open, k: k! });
    json(res, 200, { open });
  }

  async function onReveal(req: IncomingMessage, res: ServerResponse, sha: string) {
    const p = pending.get(sha);
    if (!p) return fail(res, 409, "no pending commitment for this blob");
    const body = await readBody(req, 1 << 20);
    let msg: { reveals?: { j: number; r: string }[] };
    try { msg = JSON.parse(String(body)); } catch { return fail(res, 400, "body must be JSON"); }
    const rv = new Map((msg.reveals ?? []).map((x) => [x.j, x.r]));
    const bad: number[] = [];
    for (const j of p.open) {
      const r = rv.get(j);
      if (typeof r !== "string" || !new RegExp(`^[0-9a-f]{${2 * SALT}}$`).test(r)) { bad.push(j); continue; }
      const rb = Buffer.from(r, "hex");
      const c = p.commitments[j];
      let good = sha256(rb).equals(Buffer.from(c.s, "hex"));
      for (const [w, h] of (c.hs ?? [c.h]).entries()) {
        if (!good) break;
        const item = await sentinelItem(sha, rb, w);
        good = !!item && sha256(item).equals(Buffer.from(h, "hex"));
      }
      if (!good) bad.push(j);
    }
    pending.delete(sha);
    if (bad.length) return json(res, 200, { ok: false, bad });
    const opened = new Set(p.open);
    const kept = p.commitments.map((_, j) => j).filter((j) => !opened.has(j));
    terms.set(sha, kept.map((j) => p.commitments[j]));
    commits.set(sha, { root: commitmentsRoot(p.commitments), m: p.commitments.length, k: p.k });
    // Kept on disk, so a provider restarted between cut and choose and the deal can still honour it.
    writeFileSync(join(cfg.dir, `${sha}.bond.json`), JSON.stringify({ kept: terms.get(sha), commit: commits.get(sha) }));
    json(res, 200, { ok: true, kept });
  }

  const hostname = (req: IncomingMessage) => String(req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();

  const server = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const run = async () => {
      if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }
      if (cfg.routes && (await cfg.routes(req, res, u))) return;
      if (req.method === "PUT" && u.pathname === "/upload") return onUpload(req, res);
      const st = /^\/pdp-answer\/([0-9a-f]{32})$/.exec(u.pathname);
      if (req.method === "GET" && st) {
        const body = stashed.get(st[1]);
        if (body === undefined) return fail(res, 404, "no such answer");
        stashed.delete(st[1]);
        res.writeHead(200, { ...CORS, "Content-Type": "application/json" });
        return res.end(body);
      }
      // Phase 7C: the Merkle path of any chunk, so a client can check a chunk it downloaded at an index
      // of its own choosing. The path is public data; serving it says nothing about holding the bytes.
      const pth = /^\/path\/([0-9a-f]{64})\/(\d+)$/.exec(u.pathname);
      if (req.method === "GET" && pth) {
        const m = meta(pth[1]);
        const i = Number(pth[2]);
        if (!m) return fail(res, 404, "blob not found");
        const t = tree(pth[1]);
        if (!Number.isSafeInteger(i) || i < 0 || i >= t.n) return fail(res, 400, "no such chunk");
        res.writeHead(200, { ...CORS, "Content-Type": "application/json" });
        return res.end(JSON.stringify({ n: t.n, i, path: merkleProof(t, i).map((x) => x.toString("hex")) }));
      }
      const pdp = /^\/pdp\/([0-9a-f]{64})$/.exec(u.pathname);
      if (req.method === "GET" && pdp) return onPdp(res, pdp[1], u.searchParams);
      const sen = /^\/sentinel\/([0-9a-f]{64})$/.exec(u.pathname);
      if (req.method === "GET" && sen) return onSentinel(res, sen[1], u.searchParams);
      const bond = /^\/bond\/([0-9a-f]{64})\/(commit|reveal)$/.exec(u.pathname);
      if (req.method === "POST" && bond) return bond[2] === "commit" ? onCommit(req, res, bond[1]) : onReveal(req, res, bond[1]);
      const g = SHA_PATH.exec(u.pathname);
      if ((req.method === "GET" || req.method === "HEAD") && g) return onGet(req, res, g[1]);
      if (req.method === "GET" && u.pathname === "/") {
        return json(res, 200, { software: "blossom-storage-bonds/layer1", pubkey: cfg.key.x, ...cfg.info, pdp: { chunk: CHUNK, maxQ: MAX_Q, priceMsatPerChunkEpoch: cfg.priceMsatPerChunkEpoch, lightning: cfg.payee.nodeId } });
      }
      fail(res, 404, "not found");
    };
    run().catch((e) => { if (!res.headersSent) fail(res, 500, String(e?.message ?? e)); else res.destroy(); });
  });

  await new Promise<void>((r) => server.listen(cfg.port ?? 0, host, r));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("server did not bind");
  base = cfg.publicUrl ? cfg.publicUrl.replace(/\/$/, "") : `http://${host}:${addr.port}`;

  return {
    url: base,
    localUrl: `http://${host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host}:${addr.port}`,
    pubkey: cfg.key.x,
    config: cfg,
    deleteChunks(sha, indices) {
      const m = meta(sha);
      if (!m) throw new Error("no such blob");
      const fd = openSync(blobPath(sha), "r+");
      try {
        for (const i of indices) {
          const start = i * CHUNK, end = Math.min(start + CHUNK, m.size);
          if (end > start) writeSync(fd, Buffer.alloc(end - start), 0, end - start, start);
        }
      } finally { closeSync(fd); }
    },
    withhold(sha, selective = false) {
      if (!meta(sha)) throw new Error("no such blob");
      withheld.set(sha, selective ? new Set() : null);
    },
    outsource(sha, from) {
      if (!meta(sha)) throw new Error("no such blob");
      rmSync(blobPath(sha), { force: true });
      outsourced.set(sha, from);
    },
    pdpAnswer,
    bondTerms: (sha) => { loadBond(sha); return terms.get(sha); },
    bondCommitment: (sha) => { loadBond(sha); return commits.get(sha); },
    uploader: (sha) => (meta(sha) as { uploader?: string } | null)?.uploader,
    readChunk: async (sha, i) => { const m = meta(sha); return m ? readChunk(sha, m.size, i) : Buffer.alloc(0); },
    zkTree: (sha) => {
      // After a restart, from the leaves recorded at upload (a deleter keeps them, as with the SHA tree).
      if (!zkTrees.has(sha) && existsSync(zkLeavesPath(sha))) {
        const raw = readFileSync(zkLeavesPath(sha));
        const leaves: Buffer[] = [];
        for (let o = 0; o < raw.length; o += 32) leaves.push(raw.subarray(o, o + 32));
        zkTrees.set(sha, zkTreeFromLeaves(leaves));
      }
      return zkTrees.get(sha);
    },
    putBlob: (body, type) => store(body, type),
    stash(body) {
      const id = randomBytes(16).toString("hex");
      stashed.set(id, body);
      setTimeout(() => stashed.delete(id), 600_000).unref();
      return `${base}/pdp-answer/${id}`;
    },
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
}

// Standalone: node layer1/blossom.ts [port] [dir]. A Blossom-compatible server any client can upload to.
// Its invoices come from a private stub ledger, so nothing outside this process can pay them.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.argv[2] ?? 3000);
  const dir = process.argv[3] ?? join(process.cwd(), ".bsb-blobs");
  const key = newKey();
  const p = await startProvider({ dir, key, port, payee: new StubNetwork().node("standalone"), priceMsatPerChunkEpoch: 1 });
  console.log(`blossom + pdp on ${p.url}, data in ${dir}, provider pubkey ${p.pubkey}`);
}
