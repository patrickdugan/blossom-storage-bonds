// The storage client. It encrypts a blob once per provider (model replicaKey/encryptReplica), uploads each
// replica over BUD-02, checks that the provider recomputed the same chunk-tree root, and then forgets the
// ciphertext: per replica it keeps the replica's sha256, its size, n and the 32-byte root.
//
// Each epoch it draws a fresh 32-byte nonce, asks the provider's sidecar for q chunks, checks them with
// the model's verifyEpoch against its own root (never the provider's), pays the epoch invoice only if
// they check, and publishes a signed receipt to a Nostr relay whatever the outcome.
//
// The nonce goes over HTTP to the sidecar here. The design sends it as a NIP-17/NIP-44 DM; that transport
// is not built (see README).

import { createHash, randomBytes } from "node:crypto";
import type { Key } from "../model/schnorr.ts";
import { buildTree, chunk, encryptReplica, makeSentinel, replicaKey, sentinelSecret, verifyEpoch } from "../model/storage_bonds.ts";
import { authHeader, blossomAuth, now, signEvent, tagValue, verifyEvent, type NostrEvent } from "./nostr.ts";
import { preimageMatches, type Payer } from "./lightning.ts";
import type { RelayClient } from "./relay.ts";
import type { Descriptor, PdpAnswer } from "./blossom.ts";

/** Placeholder kind for a per-epoch receipt. Unregistered: not in the NIPs kinds table as of 2026-10-20. */
export const KIND_EPOCH_RECEIPT = 8242;

/** What a third party can check in a receipt without trusting the client or the provider: the signature,
 *  the tags it needs, and for a paid receipt that the preimage opens the invoice's hash and the amount tag
 *  matches the invoice. It cannot check that the proof itself was valid; that needs the chunks. */
export function checkReceipt(ev: NostrEvent, decoder: Pick<Payer, "decode">): { ok: boolean; paid: boolean; why?: string } {
  if (!verifyEvent(ev) || ev.kind !== KIND_EPOCH_RECEIPT) return { ok: false, paid: false, why: "not a signed receipt" };
  for (const t of ["p", "x", "root", "epoch", "nonce", "result"]) if (!tagValue(ev, t)) return { ok: false, paid: false, why: `missing ${t} tag` };
  if (tagValue(ev, "result") !== "proved-paid") return { ok: true, paid: false };
  const invoice = tagValue(ev, "invoice"), preimage = tagValue(ev, "preimage");
  if (!invoice || !preimage) return { ok: false, paid: false, why: "paid receipt without invoice and preimage" };
  try {
    const inv = decoder.decode(invoice);
    if (!preimageMatches(inv.paymentHash, preimage)) return { ok: false, paid: false, why: "preimage does not open the hash" };
    if (String(inv.amountMsat) !== tagValue(ev, "amount")) return { ok: false, paid: false, why: "amount tag differs from invoice" };
  } catch (e) { return { ok: false, paid: false, why: `bad invoice: ${(e as Error).message}` }; }
  return { ok: true, paid: true };
}

/** What the client learns about a provider from its offer (design §6), out of band here. */
export interface Offer {
  url: string;
  pubkey: string;                 // Nostr identity: names the replica key and the receipt's p tag
  lightningNodeId: string;
  priceMsatPerChunkEpoch: number;
}

/** Everything the client keeps per replica after upload. */
export interface Replica {
  offer: Offer;
  blobId: string;                 // sha256 of the plaintext; with the secret and provider it gives the key
  sha256: string;                 // Blossom id of this provider's ciphertext
  size: number;
  n: number;
  root: string;
  q: number;
  /** Sentinel commitments (s_j, h_j), made at upload while the client still has the ciphertext. The
   *  secrets r_j are re-derived from the client secret when needed, so only these 64 bytes each are kept. */
  commitments?: { s: string; h: string; hs: string[] }[];
}

/** The sentinels a bond is built on: the k that cut and choose left unopened. */
export interface BondSentinel { j: number; r: string; s: string; h: string; hs: string[] }

export type Outcome = "proved-paid" | "proved-unpaid" | "failed" | "unreachable";

export interface EpochResult {
  epoch: number;
  provider: string;
  outcome: Outcome;
  detail: string;
  nonce: string;
  paidMsat: number;
  payment?: { invoice: string; preimage: string };
  receipt?: NostrEvent;
  published?: boolean;
}

const sha256hex = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

export interface ClientOptions {
  key: Key;
  secret: Buffer;                 // 32 bytes; the client's only long-term storage secret
  payer: Payer;
  relay?: RelayClient;
  /** Deterministic nonces for reproducible demos: nonce = SHA-256(seed ‖ sha256 ‖ epoch). Omit in use. */
  nonceSeed?: string;
  /** How the nonce reaches the provider and the answer comes back. Default: GET /pdp over HTTP.
   *  layer1/nostr-pdp.ts sends it as NIP-44 encrypted events instead. */
  transport?: (rep: Replica, epoch: number, nonce: string) => Promise<PdpAnswer>;
}

export class StorageClient {
  readonly opts: ClientOptions;
  constructor(opts: ClientOptions) { this.opts = opts; }

  /** Encrypt for this provider, upload, and check the provider's root against our own. */
  /** `sentinels` > 0 also commits to that many sentinels of `windows` windows each, for a bond. */
  async store(blob: Buffer, offer: Offer, q: number, type = "application/octet-stream", sentinels = 0, windows = 1): Promise<Replica> {
    const blobId = sha256hex(blob);
    const ct = encryptReplica(blob, replicaKey(this.opts.secret, blobId, offer.pubkey));
    const tree = buildTree(chunk(ct));
    const sha = sha256hex(ct);
    const auth = blossomAuth(this.opts.key, "upload", { x: [sha], server: new URL(offer.url).hostname, content: "Upload replica" });
    const r = await fetch(`${offer.url}/upload`, {
      method: "PUT",
      headers: { Authorization: authHeader(auth), "X-SHA-256": sha, "Content-Type": type },
      body: ct,
    });
    if (r.status !== 201 && r.status !== 200) throw new Error(`upload to ${offer.url}: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
    const d = (await r.json()) as Descriptor;
    if (d.sha256 !== sha || d.size !== ct.length) throw new Error("provider stored different bytes");
    if (d.bsb?.root !== tree.root.toString("hex") || d.bsb?.n !== tree.n) throw new Error("provider's chunk root differs from ours");
    const rep: Replica = { offer, blobId, sha256: sha, size: ct.length, n: tree.n, root: tree.root.toString("hex"), q };
    if (sentinels > 0) {
      const chunks = chunk(ct);
      rep.commitments = Array.from({ length: sentinels }, (_, j) => {
        const t = makeSentinel(this.sentinelSeed(sha), tree, chunks, j, windows);
        return { s: t.s.toString("hex"), h: t.h.toString("hex"), hs: t.hs.map((x) => x.toString("hex")) };
      });
    }
    return rep;
  }

  private sentinelSeed(sha: string): Buffer {
    return createHash("sha256").update("bsb/sentinel-seed|").update(this.opts.secret).update(sha).digest();
  }

  /** Cut and choose with the provider (design §2.3): commit to all M sentinels, reveal the M − k the
   *  provider opens, and keep the other k for the bond. Throws if the provider refuses. */
  async bond(rep: Replica, k: number): Promise<BondSentinel[]> {
    const cs = rep.commitments;
    if (!cs || cs.length <= k) throw new Error("store() the replica with more than k sentinels first");
    const post = async (what: string, body: unknown) => {
      const r = await fetch(`${rep.offer.url}/bond/${rep.sha256}/${what}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (r.status !== 200) throw new Error(`bond ${what}: ${r.status} ${r.headers.get("x-reason") ?? ""}`);
      return r.json() as Promise<Record<string, unknown>>;
    };
    const { open } = (await post("commit", { commitments: cs, k })) as { open: number[] };
    const opened = new Set(open);
    if (!Array.isArray(open) || opened.size !== cs.length - k || open.some((j) => !Number.isSafeInteger(j) || j < 0 || j >= cs.length)) {
      throw new Error("provider opened a malformed set");
    }
    const r = (j: number) => sentinelSecret(this.sentinelSeed(rep.sha256), Buffer.from(rep.root, "hex"), j).toString("hex");
    const res = (await post("reveal", { reveals: open.map((j) => ({ j, r: r(j) })) })) as { ok: boolean; kept?: number[]; bad?: number[] };
    if (!res.ok) throw new Error(`provider rejected opened sentinels ${JSON.stringify(res.bad)}`);
    const kept = cs.map((_, j) => j).filter((j) => !opened.has(j));
    if (JSON.stringify(res.kept) !== JSON.stringify(kept)) throw new Error("provider kept a different set");
    return kept.map((j) => ({ j, r: r(j), ...cs[j] }));
  }

  private nonceFor(rep: Replica, epoch: number): Buffer {
    if (this.opts.nonceSeed === undefined) return randomBytes(32);
    return createHash("sha256").update(`bsb/demo-nonce|${this.opts.nonceSeed}|${rep.sha256}|${epoch}`).digest();
  }

  async runEpoch(rep: Replica, epoch: number): Promise<EpochResult> {
    const nonce = this.nonceFor(rep, epoch);
    const res = await this.challenge(rep, epoch, nonce);
    res.receipt = this.receipt(rep, res);
    if (this.opts.relay) res.published = (await this.opts.relay.publish(res.receipt)).accepted;
    return res;
  }

  private async challenge(rep: Replica, epoch: number, nonce: Buffer): Promise<EpochResult> {
    const base = { epoch, provider: rep.offer.pubkey, nonce: nonce.toString("hex"), paidMsat: 0 };
    let a: PdpAnswer;
    try {
      if (this.opts.transport) {
        a = await this.opts.transport(rep, epoch, base.nonce);
      } else {
        const r = await fetch(`${rep.offer.url}/pdp/${rep.sha256}?nonce=${base.nonce}&q=${rep.q}&epoch=${epoch}`, { signal: AbortSignal.timeout(10_000) });
        if (r.status !== 200) return { ...base, outcome: "unreachable", detail: `HTTP ${r.status} ${r.headers.get("x-reason") ?? ""}`.trim() };
        a = (await r.json()) as PdpAnswer;
      }
    } catch (e) {
      return { ...base, outcome: "unreachable", detail: String((e as Error).message ?? e) };
    }
    // Check against our own root, n, nonce and q; the answer's copies of them are ignored.
    const ok = Array.isArray(a.chunks) && Array.isArray(a.paths) && a.chunks.length === rep.q && a.paths.length === rep.q &&
      a.paths.every((p) => Array.isArray(p) && p.every((h) => typeof h === "string" && /^[0-9a-f]{64}$/.test(h))) &&
      verifyEpoch(Buffer.from(rep.root, "hex"), rep.n, nonce, rep.q, {
        chunks: a.chunks.map((c) => Buffer.from(String(c), "base64")),
        paths: a.paths.map((p) => p.map((h) => Buffer.from(h, "hex"))),
      });
    if (!ok) return { ...base, outcome: "failed", detail: "a chunk did not open against the root" };

    const want = rep.offer.priceMsatPerChunkEpoch * rep.n;
    try {
      const inv = this.opts.payer.decode(String(a.invoice));
      if (inv.payee !== rep.offer.lightningNodeId) return { ...base, outcome: "proved-unpaid", detail: "invoice names another node" };
      if (inv.amountMsat !== want) return { ...base, outcome: "proved-unpaid", detail: `invoice for ${inv.amountMsat} msat, deal says ${want}` };
      const { preimage } = await this.opts.payer.pay(inv.paymentRequest, want);
      if (!preimageMatches(inv.paymentHash, preimage)) return { ...base, outcome: "proved-unpaid", detail: "preimage does not match" };
      return { ...base, outcome: "proved-paid", detail: `paid ${want} msat, hash ${inv.paymentHash.slice(0, 16)}…`, paidMsat: want, payment: { invoice: inv.paymentRequest, preimage } };
    } catch (e) {
      return { ...base, outcome: "proved-unpaid", detail: `payment failed: ${(e as Error).message}` };
    }
  }

  /** The per-epoch receipt (design §6): signed by the client, names the provider and replica. A paid
   *  receipt carries the invoice and preimage, so anyone can check that the payment matches the hash. */
  receipt(rep: Replica, r: EpochResult): NostrEvent {
    const pay = r.payment;
    const tags = [
      ["p", rep.offer.pubkey], ["x", rep.sha256], ["root", rep.root], ["n", String(rep.n)],
      ["epoch", String(r.epoch)], ["nonce", r.nonce], ["q", String(rep.q)], ["result", r.outcome],
    ];
    if (pay) tags.push(["amount", String(r.paidMsat)], ["invoice", pay.invoice], ["preimage", pay.preimage]);
    return signEvent(this.opts.key, { created_at: now(), kind: KIND_EPOCH_RECEIPT, tags, content: `epoch ${r.epoch}: ${r.outcome}` });
  }

  /** BUD-01 download, then decrypt with the replica key and check the plaintext hash. */
  async retrieve(rep: Replica): Promise<Buffer> {
    const r = await fetch(`${rep.offer.url}/${rep.sha256}`);
    if (r.status !== 200) throw new Error(`GET ${rep.sha256}: ${r.status}`);
    const ct = Buffer.from(await r.arrayBuffer());
    if (sha256hex(ct) !== rep.sha256) throw new Error("server returned other bytes");
    const plain = encryptReplica(ct, replicaKey(this.opts.secret, rep.blobId, rep.offer.pubkey));
    if (sha256hex(plain) !== rep.blobId) throw new Error("decrypted blob does not match");
    return plain;
  }
}
