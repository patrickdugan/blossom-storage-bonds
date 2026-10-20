// The provider's side of public epoch proofs (phase 3b), run inside layer1/provider.ts with --zk.
//
// Every EPOCH_BLOCKS blocks the provider proves its holdings with no prompt from anyone. The seed is
// the hash of the boundary block, read from the provider's own bitcoind, so nobody chooses the
// challenges. The proof (~11 MB) goes onto the provider's own Blossom server as a blob. A Nostr event
// (kind 4245, placeholder) announces it with everything a verifier needs besides the chain: the
// boundary height, q, the deal list (Blake2s roots and chunk counts) and the proof's SHA-256 and URL.
// A provider that cannot prove publishes nothing, and the watchtower marks it missing.

import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import type { Key } from "../model/schnorr.ts";
import type { HeldDeal } from "../model/zk_pdp.ts";
import { fail, json, readBody, type Provider } from "./blossom.ts";
import { rpc } from "./bondtool.ts";
import type { Payee } from "./lightning.ts";
import { now, signEvent } from "./nostr.ts";
import type { RelayClient } from "./relay.ts";
import { challengesFor, defaultZk, proveEpoch, type DealEntry } from "./zk.ts";

/** Placeholder kinds, not registered in the NIPs. */
export const KIND_EPOCH_PROOF = 4245;
export const KIND_ATTESTATION = 4246;

export interface ZkOptions {
  epochBlocks: number;
  q: number;
  /** The first boundary to prove (so a provider does not prove the chain's history). */
  fromHeight: number;
  priceMsat: number;
  rpcUrl: string;
  workDir: string;
  log: (ev: Record<string, unknown>) => void;
}

export function startZkEpochs(p: Provider, relay: RelayClient, key: Key, payee: Payee, o: ZkOptions) {
  const deals: string[] = [];                       // blob sha256s registered as deals, in order
  const invoiced = new Set<string>();
  let last = -1;
  let stopping = false;

  async function epoch(height: number) {
    if (deals.length === 0) return;
    const seedHex: string = await rpc("getblockhash", [height], o.rpcUrl);
    const seed = Buffer.from(seedHex, "hex");
    const trees = deals.map((sha) => p.zkTree(sha)!);
    const list: DealEntry[] = trees.map((t) => ({ root: t.root.toString("hex"), n: t.n }));
    // Fetch exactly the challenged chunks, as this provider holds them, then prove synchronously.
    const cs = challengesFor(seed, o.q, list);
    const got = new Map<string, Buffer>();
    for (const c of cs) got.set(`${c.deal}:${c.idx}`, await p.readChunk(deals[c.deal], c.idx));
    const held: HeldDeal[] = trees.map((t, k) => ({ tree: t, chunk: (i: number) => got.get(`${k}:${i}`) }));
    o.log({ event: "zk-proving", height, deals: deals.length, q: o.q });
    const r = await proveEpoch(defaultZk(), join(o.workDir, `epoch-${height}`), seed, o.q, held);
    if (!r.ok) { o.log({ event: "zk-epoch", height, proved: false, why: r.why, seconds: r.seconds }); return; }
    const d = p.putBlob(r.proof, "application/json");
    const content = { height, seed: seedHex, q: o.q, hash: "blake", mode: 1, deals: list, proof: { sha256: d.sha256, url: d.url, size: d.size } };
    const ev = signEvent(key, {
      created_at: now(), kind: KIND_EPOCH_PROOF,
      tags: [["h", String(height)], ["x", d.sha256], ["url", d.url]], content: JSON.stringify(content),
    });
    const pub = await relay.publish(ev);
    o.log({ event: "zk-epoch", height, proved: true, proof: d.sha256, bytes: d.size, seconds: r.seconds, published: pub.accepted, id: ev.id });
  }

  (async () => {
    while (!stopping) {
      try {
        const h: number = await rpc("getblockcount", [], o.rpcUrl);
        const boundary = Math.floor(h / o.epochBlocks) * o.epochBlocks;
        if (boundary >= o.fromHeight && boundary > last) { last = boundary; await epoch(boundary); }
      } catch (e) { o.log({ event: "zk-error", error: (e as Error).message }); }
      await new Promise((r) => setTimeout(r, 400));
    }
  })();

  /** POST /zk/register {sha256}: add a stored blob to the deal list. GET /zk/invoice/<height>?client=X:
   *  one invoice per client per epoch, for a client that verified that epoch's proof. */
  async function route(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
    if (req.method === "POST" && url.pathname === "/zk/register") {
      let body: any;
      try { body = JSON.parse(String(await readBody(req, 1 << 12))); } catch { fail(res, 400, "body must be JSON"); return true; }
      const sha = String(body.sha256 ?? "");
      const t = p.zkTree(sha);
      if (!t) { fail(res, 404, "no such blob"); return true; }
      if (!deals.includes(sha)) deals.push(sha);
      json(res, 200, { ok: true, zk_root: t.root.toString("hex"), n: t.n, deals: deals.length });
      return true;
    }
    const m = /^\/zk\/invoice\/(\d+)$/.exec(url.pathname);
    if (req.method === "GET" && m) {
      const client = url.searchParams.get("client") ?? "";
      const k = `${m[1]}|${client}`;
      if (!/^[0-9a-f]{64}$/.test(client) || invoiced.has(k)) { fail(res, 409, "one invoice per client per epoch"); return true; }
      invoiced.add(k);
      json(res, 200, await payee.createInvoice(o.priceMsat, `bsb zk epoch ${m[1]}`));
      return true;
    }
    return false;
  }

  return { route, deals, stop: () => { stopping = true; } };
}

export const sha256hex = (b: Buffer) => createHash("sha256").update(b).digest("hex");
