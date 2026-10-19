// Nostr events (NIP-01) and Blossom's kind-24242 authorization token (BUD-11), on the model's BIP340 code.
// model/schnorr.ts is plain bigint arithmetic and not constant time: fine for localhost, not for real keys.

import { randomBytes } from "node:crypto";
import { N, int, keyFrom, schnorrSign, schnorrVerify, sha256, type Key } from "../model/schnorr.ts";

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}
export type Unsigned = Omit<NostrEvent, "id" | "pubkey" | "sig">;

export const now = (): number => Math.floor(Date.now() / 1000);

export function newKey(): Key {
  for (;;) {
    const d = int(randomBytes(32));
    if (d > 0n && d < N) return keyFrom(d);
  }
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

/** NIP-01: the id is the SHA-256 of [0, pubkey, created_at, kind, tags, content] as compact JSON. */
export const eventId = (e: Omit<NostrEvent, "id" | "sig">): string =>
  sha256(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])).toString("hex");

export function signEvent(k: Key, u: Unsigned): NostrEvent {
  const body = { pubkey: k.x, created_at: u.created_at, kind: u.kind, tags: u.tags, content: u.content };
  const id = eventId(body);
  return { id, ...body, sig: schnorrSign(Buffer.from(id, "hex"), k.d, randomBytes(32)).toString("hex") };
}

/** Shape, id and signature. Anything that arrives over the network goes through this first. */
export function verifyEvent(e: unknown): e is NostrEvent {
  if (typeof e !== "object" || e === null) return false;
  const v = e as Record<string, unknown>;
  if (typeof v.id !== "string" || !HEX64.test(v.id)) return false;
  if (typeof v.pubkey !== "string" || !HEX64.test(v.pubkey)) return false;
  if (typeof v.sig !== "string" || !HEX128.test(v.sig)) return false;
  if (!Number.isSafeInteger(v.created_at) || !Number.isSafeInteger(v.kind)) return false;
  if (typeof v.content !== "string") return false;
  if (!Array.isArray(v.tags) || !v.tags.every((t) => Array.isArray(t) && t.every((s) => typeof s === "string"))) return false;
  const ev = v as unknown as NostrEvent;
  if (eventId(ev) !== ev.id) return false;
  return schnorrVerify(Buffer.from(ev.id, "hex"), Buffer.from(ev.pubkey, "hex"), Buffer.from(ev.sig, "hex"));
}

export const tagValues = (e: NostrEvent, name: string): string[] => e.tags.filter((t) => t[0] === name).map((t) => t[1]);
export const tagValue = (e: NostrEvent, name: string): string | undefined => tagValues(e, name)[0];

// ───────────────────────────── Blossom authorization (BUD-11) ─────────────────────────────

export const KIND_BLOSSOM_AUTH = 24242;
export type BlossomVerb = "get" | "upload" | "list" | "delete" | "media";

export function blossomAuth(k: Key, verb: BlossomVerb, opts: { x?: string[]; server?: string; ttl?: number; content?: string } = {}): NostrEvent {
  const t = now();
  const tags = [["t", verb], ["expiration", String(t + (opts.ttl ?? 300))]];
  for (const x of opts.x ?? []) tags.push(["x", x]);
  if (opts.server) tags.push(["server", opts.server]);
  // created_at one second back, so "MUST be in the past" holds on a server whose clock is a little behind.
  return signEvent(k, { created_at: t - 1, kind: KIND_BLOSSOM_AUTH, tags, content: opts.content ?? `${verb} blob` });
}

/** BUD-11 wants base64url without padding. */
export const authHeader = (e: NostrEvent): string => "Nostr " + Buffer.from(JSON.stringify(e)).toString("base64url");

export type AuthResult = { ok: true; event: NostrEvent } | { ok: false; why: string };

/** Every check BUD-11 makes a server do. `x` is the hash the endpoint implies; when `xRequired` is set at
 *  least one x tag must match it. Accepts standard base64 too, which older clients send. */
export function checkBlossomAuth(
  header: string | undefined,
  want: { verb: BlossomVerb; x?: string; xRequired?: boolean; domain?: string; at?: number },
): AuthResult {
  if (!header) return { ok: false, why: "missing Authorization header" };
  const m = /^Nostr ([A-Za-z0-9+/_=-]+)$/.exec(header.trim());
  if (!m) return { ok: false, why: "Authorization scheme must be Nostr" };
  let ev: unknown;
  try { ev = JSON.parse(Buffer.from(m[1], m[1].includes("+") || m[1].includes("/") ? "base64" : "base64url").toString("utf8")); }
  catch { return { ok: false, why: "token is not base64 JSON" }; }
  if (!verifyEvent(ev)) return { ok: false, why: "bad event id or signature" };
  const t = want.at ?? now();
  if (ev.kind !== KIND_BLOSSOM_AUTH) return { ok: false, why: "kind must be 24242" };
  if (ev.created_at > t) return { ok: false, why: "created_at is in the future" };
  const exp = Number(tagValue(ev, "expiration"));
  if (!Number.isFinite(exp)) return { ok: false, why: "missing expiration tag" };
  if (exp <= t) return { ok: false, why: "token expired" };
  if (!tagValues(ev, "t").includes(want.verb)) return { ok: false, why: `t tag must be ${want.verb}` };
  const servers = tagValues(ev, "server");
  if (servers.length > 0 && !(want.domain && servers.includes(want.domain.toLowerCase()))) {
    return { ok: false, why: "token is scoped to another server" };
  }
  const xs = tagValues(ev, "x");
  if ((want.xRequired || xs.length > 0) && !(want.x && xs.includes(want.x))) {
    return { ok: false, why: "no x tag matches the blob hash" };
  }
  return { ok: true, event: ev };
}
