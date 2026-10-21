// A minimal Nostr relay (NIP-01: EVENT, REQ, CLOSE; OK, EVENT, EOSE, CLOSED, NOTICE) on node:http with a
// hand-written RFC 6455 framer, plus a small client on Node's global WebSocket. Enough to publish receipts
// and query them back on localhost; it keeps events in memory and does no rate limiting or auth (NIP-42).
// It keeps only the newest replaceable (kinds 0, 3, 10000-19999) and addressable (30000-39999, per d tag)
// event, as NIP-01 asks, so a provider's offer behaves as it would on a public relay.
//
// RelayPool is what the parties use: any number of relay URLs as one (publish to all, subscribe on all,
// events de-duplicated by id, dropped connections reopened). The bundled relay is one URL among them; a
// pilot names public ones with --relays.

import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { Duplex } from "node:stream";
import { verifyEvent, type NostrEvent } from "./nostr.ts";

export interface Filter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  since?: number;
  until?: number;
  limit?: number;
  [tag: `#${string}`]: string[] | undefined;
}

export function matches(f: Filter, e: NostrEvent): boolean {
  if (f.ids && !f.ids.includes(e.id)) return false;
  if (f.authors && !f.authors.includes(e.pubkey)) return false;
  if (f.kinds && !f.kinds.includes(e.kind)) return false;
  if (f.since !== undefined && e.created_at < f.since) return false;
  if (f.until !== undefined && e.created_at > f.until) return false;
  for (const [k, want] of Object.entries(f)) {
    if (!k.startsWith("#") || !Array.isArray(want)) continue;
    const name = k.slice(1);
    if (!e.tags.some((t) => t[0] === name && want.includes(t[1]))) return false;
  }
  return true;
}

const isEphemeral = (kind: number) => kind >= 20000 && kind < 30000;
const isReplaceable = (kind: number) => kind === 0 || kind === 3 || (kind >= 10000 && kind < 20000);
const isAddressable = (kind: number) => kind >= 30000 && kind < 40000;
const dTag = (e: NostrEvent) => e.tags.find((t) => t[0] === "d")?.[1] ?? "";
/** The slot a replaceable or addressable event occupies, or undefined for a regular one. */
export const replaceKey = (e: NostrEvent): string | undefined =>
  isReplaceable(e.kind) ? `${e.kind}:${e.pubkey}` : isAddressable(e.kind) ? `${e.kind}:${e.pubkey}:${dTag(e)}` : undefined;
/** NIP-01: the newer created_at wins, and on a tie the lower id. */
export const newer = (a: NostrEvent, b: NostrEvent) => a.created_at > b.created_at || (a.created_at === b.created_at && a.id < b.id);
const MAX_FRAME = 1 << 20;

// ───────────────────────────── RFC 6455, server side ─────────────────────────────

class WsConn {
  private buf = Buffer.alloc(0);
  private frags: Buffer[] = [];
  closed = false;
  private readonly sock: Duplex;
  private readonly onText: (s: string) => void;
  private readonly onClose: () => void;
  constructor(sock: Duplex, onText: (s: string) => void, onClose: () => void) {
    this.sock = sock; this.onText = onText; this.onClose = onClose;
    sock.on("data", (d: Buffer) => this.feed(d));
    sock.on("close", () => this.finish());
    sock.on("error", () => this.finish());
  }
  private finish() { if (!this.closed) { this.closed = true; this.onClose(); } }
  private feed(d: Buffer) {
    this.buf = Buffer.concat([this.buf, d]);
    for (;;) {
      if (this.buf.length < 2) return;
      const fin = (this.buf[0] & 0x80) !== 0, op = this.buf[0] & 0x0f;
      const masked = (this.buf[1] & 0x80) !== 0;
      let len = this.buf[1] & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) {
        if (this.buf.length < 10) return;
        const big = this.buf.readBigUInt64BE(2);
        if (big > BigInt(MAX_FRAME)) return this.fail(1009);
        len = Number(big); off = 10;
      }
      if (!masked) return this.fail(1002);            // clients must mask (RFC 6455 §5.1)
      if (len > MAX_FRAME) return this.fail(1009);
      if (this.buf.length < off + 4 + len) return;
      const mask = this.buf.subarray(off, off + 4);
      const payload = Buffer.from(this.buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      this.buf = this.buf.subarray(off + 4 + len);
      if (op === 0x8) { this.send(0x8, payload.subarray(0, 2)); this.sock.end(); return this.finish(); }
      if (op === 0x9) { this.send(0xa, payload); continue; }
      if (op === 0xa) continue;
      if (op === 0x1 || op === 0x2 || op === 0x0) {
        this.frags.push(payload);
        if (this.frags.reduce((a, b) => a + b.length, 0) > MAX_FRAME) return this.fail(1009);
        if (fin) { const msg = Buffer.concat(this.frags).toString("utf8"); this.frags = []; this.onText(msg); }
        continue;
      }
      return this.fail(1002);
    }
  }
  private fail(code: number) {
    const c = Buffer.alloc(2); c.writeUInt16BE(code);
    this.send(0x8, c); this.sock.end(); this.finish();
  }
  send(op: number, payload: Buffer) {
    if (this.closed) return;
    const n = payload.length;
    const head = n < 126 ? Buffer.from([0x80 | op, n])
      : n < 65536 ? Buffer.from([0x80 | op, 126, n >> 8, n & 0xff])
      : (() => { const h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); return h; })();
    this.sock.write(Buffer.concat([head, payload]));
  }
  text(s: string) { this.send(0x1, Buffer.from(s, "utf8")); }
}

// ───────────────────────────── relay ─────────────────────────────

export interface Relay { readonly url: string; readonly events: NostrEvent[]; close(): Promise<void> }

export async function startRelay(port = 0, host = "127.0.0.1"): Promise<Relay> {
  const events: NostrEvent[] = [];
  const seen = new Set<string>();
  const subs = new Map<WsConn, Map<string, Filter[]>>();
  const server: Server = createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/nostr+json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify({ name: "bsb localhost relay", supported_nips: [1, 11], software: "blossom-storage-bonds/layer1" }));
  });
  const sockets = new Set<Duplex>();

  server.on("upgrade", (req, sock: Duplex) => {
    const key = req.headers["sec-websocket-key"];
    if (typeof key !== "string" || (req.headers.upgrade ?? "").toLowerCase() !== "websocket") { sock.destroy(); return; }
    const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    sockets.add(sock);
    const conn: WsConn = new WsConn(sock, (s) => onMessage(conn, s), () => { subs.delete(conn); sockets.delete(sock); });
    subs.set(conn, new Map());
  });

  function onMessage(conn: WsConn, raw: string) {
    let msg: unknown;
    try { msg = JSON.parse(raw); } catch { return conn.text(JSON.stringify(["NOTICE", "invalid: not JSON"])); }
    if (!Array.isArray(msg) || typeof msg[0] !== "string") return conn.text(JSON.stringify(["NOTICE", "invalid: not an array"]));
    if (msg[0] === "EVENT") {
      const ev = msg[1];
      const id = typeof ev?.id === "string" ? ev.id : "";
      if (!verifyEvent(ev)) return conn.text(JSON.stringify(["OK", id, false, "invalid: bad id or signature"]));
      if (seen.has(ev.id)) return conn.text(JSON.stringify(["OK", ev.id, true, "duplicate: already have this event"]));
      const slot = replaceKey(ev);
      if (slot) {
        const i = events.findIndex((x) => replaceKey(x) === slot);
        if (i >= 0 && !newer(ev, events[i])) return conn.text(JSON.stringify(["OK", ev.id, true, "duplicate: have a newer version"]));
        if (i >= 0) events.splice(i, 1);
      }
      if (!isEphemeral(ev.kind)) { seen.add(ev.id); events.push(ev); }
      conn.text(JSON.stringify(["OK", ev.id, true, ""]));
      for (const [c, m] of subs) for (const [sid, fs] of m) if (fs.some((f) => matches(f, ev))) c.text(JSON.stringify(["EVENT", sid, ev]));
      return;
    }
    if (msg[0] === "REQ") {
      const sid = msg[1];
      if (typeof sid !== "string" || sid.length === 0 || sid.length > 64) return conn.text(JSON.stringify(["CLOSED", String(sid), "invalid: subscription id"]));
      const fs = msg.slice(2).filter((f): f is Filter => typeof f === "object" && f !== null);
      subs.get(conn)?.set(sid, fs);
      const out = new Map<string, NostrEvent>();
      for (const f of fs) {
        const hit = events.filter((e) => matches(f, e)).sort((a, b) => b.created_at - a.created_at);
        for (const e of f.limit !== undefined ? hit.slice(0, f.limit) : hit) out.set(e.id, e);
      }
      for (const e of out.values()) conn.text(JSON.stringify(["EVENT", sid, e]));
      return conn.text(JSON.stringify(["EOSE", sid]));
    }
    if (msg[0] === "CLOSE") { subs.get(conn)?.delete(String(msg[1])); return; }
    conn.text(JSON.stringify(["NOTICE", `invalid: unknown message ${msg[0]}`]));
  }

  await new Promise<void>((r) => server.listen(port, host, r));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("relay did not bind");
  return {
    url: `ws://${host}:${addr.port}`,
    events,
    close: () => new Promise<void>((r) => { for (const s of sockets) s.destroy(); server.close(() => r()); }),
  };
}

// ───────────────────────────── client ─────────────────────────────

/** What a party needs from Nostr: one relay (RelayClient) or several (RelayPool). */
export interface Relays {
  publish(e: NostrEvent, timeoutMs?: number): Promise<{ accepted: boolean; message: string }>;
  subscribe(filters: Filter[], onEvent: (e: NostrEvent) => void): { close(): void };
  query(...filters: Filter[]): Promise<NostrEvent[]>;
  close(): void;
}

/** One connection to one relay. publish() resolves on the relay's OK; query() collects until EOSE. */
export class RelayClient implements Relays {
  private ws!: WebSocket;
  private waiters = new Map<string, (m: unknown[]) => void>();
  private found = new Map<string, NostrEvent[]>();
  private n = 0;
  readonly url: string;
  private constructor(url: string) { this.url = url; }

  static async connect(url: string, timeoutMs = 5000): Promise<RelayClient> {
    const c = new RelayClient(url);
    c.ws = new WebSocket(url);
    await new Promise<void>((ok, bad) => {
      const t = setTimeout(() => { try { c.ws.close(); } catch { /* not open */ } bad(new Error(`relay ${url}: connect timeout`)); }, timeoutMs);
      c.ws.addEventListener("open", () => { clearTimeout(t); ok(); }, { once: true });
      c.ws.addEventListener("error", () => { clearTimeout(t); bad(new Error(`relay ${url}: connect failed`)); }, { once: true });
    });
    c.ws.addEventListener("message", (m) => c.onMessage(String(m.data)));
    c.ws.addEventListener("close", () => { c.open = false; for (const f of c.closed) f(); });
    return c;
  }

  private open = true;
  private closed: (() => void)[] = [];
  /** Called once the connection is gone, whoever closed it. */
  onClose(f: () => void) { this.closed.push(f); }
  get isOpen() { return this.open; }

  private live = new Map<string, (e: NostrEvent) => void>();
  private ended = new Map<string, (reason: string) => void>();

  /** A live subscription: `onEvent` gets every stored match and then every new one, until close().
   *  `onClosed` hears if the relay ends it (NIP-01 CLOSED: a limit, auth, an error). */
  subscribe(filters: Filter[], onEvent: (e: NostrEvent) => void, onClosed?: (reason: string) => void): { close(): void } {
    const sid = `s${++this.n}`;
    this.live.set(sid, onEvent);
    if (onClosed) this.ended.set(sid, onClosed);
    this.ws.send(JSON.stringify(["REQ", sid, ...filters]));
    return { close: () => { this.live.delete(sid); this.ended.delete(sid); this.ws.send(JSON.stringify(["CLOSE", sid])); } };
  }

  private onMessage(raw: string) {
    let m: unknown;
    try { m = JSON.parse(raw); } catch { return; }
    if (!Array.isArray(m)) return;
    if (m[0] === "OK") this.waiters.get(`ok:${m[1]}`)?.(m);
    else if (m[0] === "EVENT" && verifyEvent(m[2]) && this.live.has(String(m[1]))) this.live.get(String(m[1]))!(m[2]);
    else if (m[0] === "EVENT" && verifyEvent(m[2])) this.found.get(String(m[1]))?.push(m[2]);
    else if (m[0] === "CLOSED" && this.live.has(String(m[1]))) {
      const sid = String(m[1]), f = this.ended.get(sid);
      this.live.delete(sid); this.ended.delete(sid);
      f?.(String(m[2] ?? ""));
    }
    else if (m[0] === "EOSE" || m[0] === "CLOSED") this.waiters.get(`sub:${m[1]}`)?.(m);
  }

  private wait(key: string, timeoutMs: number): Promise<unknown[]> {
    return new Promise((ok, bad) => {
      const t = setTimeout(() => { this.waiters.delete(key); bad(new Error(`relay ${this.url}: timeout on ${key}`)); }, timeoutMs);
      this.waiters.set(key, (m) => { clearTimeout(t); this.waiters.delete(key); ok(m); });
    });
  }

  async publish(e: NostrEvent, timeoutMs = 5000): Promise<{ accepted: boolean; message: string }> {
    const p = this.wait(`ok:${e.id}`, timeoutMs);
    this.ws.send(JSON.stringify(["EVENT", e]));
    const m = await p;
    return { accepted: m[2] === true, message: String(m[3] ?? "") };
  }

  async query(...filters: Filter[]): Promise<NostrEvent[]> {
    const sid = `q${++this.n}`;
    this.found.set(sid, []);
    const p = this.wait(`sub:${sid}`, this.url.startsWith("ws://127.0.0.1") ? 5000 : 15000);
    this.ws.send(JSON.stringify(["REQ", sid, ...filters]));
    await p;
    this.ws.send(JSON.stringify(["CLOSE", sid]));
    const out = this.found.get(sid)!;
    this.found.delete(sid);
    return out;
  }

  close() { this.ws.close(); }
}

// ───────────────────────────── several relays ─────────────────────────────

type PoolSub = { filters: Filter[]; onEvent: (e: NostrEvent) => void; seen: Set<string>; handles: Map<string, { close(): void }> };

/** Several relays as one. publish() sends to every connected relay and counts as accepted if any accepts
 *  (each relay's answer is in `relays`); subscribe() and query() cover all of them and drop duplicate
 *  ids. A relay that drops is reopened with backoff (1 s doubling to 60 s), and its live subscriptions are
 *  sent again; duplicates that brings are dropped too. A subscription the relay closes (CLOSED) is sent
 *  again after 30 s. A relay that times out on a publish, or (if not on localhost) fails a probe once a
 *  minute, is closed and reopened, since a half-open socket would otherwise keep a dead subscription.
 *  Nothing here is specific to the bundled relay. */
export class RelayPool implements Relays {
  readonly urls: string[];
  private readonly conns = new Map<string, RelayClient | undefined>();
  private readonly subs = new Set<PoolSub>();
  private readonly log: (ev: Record<string, unknown>) => void;
  private stopped = false;
  private probe?: ReturnType<typeof setInterval>;

  private constructor(urls: string[], log: (ev: Record<string, unknown>) => void) { this.urls = urls; this.log = log; }

  /** Opens every URL; at least one must answer. */
  static async connect(urls: string[], log: (ev: Record<string, unknown>) => void = () => {}): Promise<RelayPool> {
    const list = [...new Set(urls.map((u) => u.trim()).filter(Boolean))];
    if (list.length === 0) throw new Error("no relay URLs");
    const p = new RelayPool(list, log);
    await Promise.all(list.map((u) => p.open(u).catch((e) => { log({ event: "relay-down", url: u, error: (e as Error).message }); p.reopen(u, 1000); })));
    if (![...p.conns.values()].some(Boolean)) { p.close(); throw new Error(`no relay reachable: ${list.join(", ")}`); }
    p.probe = setInterval(() => {
      for (const [url, c] of p.conns) {
        if (!c?.isOpen || url.startsWith("ws://127.0.0.1")) continue;
        c.query({ ids: [randomBytes(32).toString("hex")] }).catch(() => { p.log({ event: "relay-probe-failed", url }); c.close(); });
      }
    }, 60_000);
    p.probe.unref?.();
    return p;
  }

  /** Subscribe `s` on one relay; if that relay ends the subscription, send it again after 30 s. */
  private sub(url: string, c: RelayClient, s: PoolSub) {
    s.handles.set(url, c.subscribe(s.filters, (e) => this.deliver(s, e), (reason) => {
      s.handles.delete(url);
      this.log({ event: "relay-sub-closed", url, reason });
      const t = setTimeout(() => { if (!this.stopped && this.subs.has(s) && this.conns.get(url) === c && c.isOpen) this.sub(url, c, s); }, 30_000);
      t.unref?.();
    }));
  }

  /** The bundled relay's URL, or a comma-separated --relays list. */
  static parse(list: string): string[] { return list.split(",").map((s) => s.trim()).filter(Boolean); }

  get url(): string { return this.urls.join(","); }
  connected(): string[] { return [...this.conns].filter(([, c]) => c?.isOpen).map(([u]) => u); }

  private async open(url: string) {
    const c = await RelayClient.connect(url, url.startsWith("ws://127.0.0.1") ? 5000 : 15000);
    if (this.stopped) { c.close(); return; }
    this.conns.set(url, c);
    c.onClose(() => {
      this.conns.set(url, undefined);
      for (const s of this.subs) s.handles.delete(url);
      if (!this.stopped) { this.log({ event: "relay-closed", url }); this.reopen(url, 1000); }
    });
    for (const s of this.subs) this.sub(url, c, s);
  }

  private reopen(url: string, delay: number) {
    const t = setTimeout(() => {
      if (this.stopped || this.conns.get(url)) return;
      this.open(url).catch(() => this.reopen(url, Math.min(delay * 2, 60_000)));
    }, delay);
    t.unref?.();
  }

  private deliver(s: PoolSub, e: NostrEvent) {
    if (s.seen.has(e.id)) return;
    s.seen.add(e.id);
    s.onEvent(e);
  }

  async publish(e: NostrEvent, timeoutMs = 5000): Promise<{ accepted: boolean; message: string; relays: { url: string; accepted: boolean; message: string }[] }> {
    const live = [...this.conns].filter((x): x is [string, RelayClient] => !!x[1]?.isOpen);
    const relays = await Promise.all(live.map(([url, c]) => c.publish(e, timeoutMs).then((r) => ({ url, ...r }), (err) => {
      // No OK in time: treat the connection as dead and reopen it.
      if (/timeout/.test((err as Error).message)) { this.log({ event: "relay-publish-timeout", url }); c.close(); }
      return { url, accepted: false, message: (err as Error).message };
    })));
    const ok = relays.find((r) => r.accepted);
    return { accepted: !!ok, message: ok ? ok.message : relays.map((r) => `${r.url}: ${r.message}`).join("; ") || "no relay connected", relays };
  }

  subscribe(filters: Filter[], onEvent: (e: NostrEvent) => void): { close(): void } {
    const s: PoolSub = { filters, onEvent, seen: new Set(), handles: new Map() };
    this.subs.add(s);
    for (const [url, c] of this.conns) if (c?.isOpen) this.sub(url, c, s);
    return { close: () => { this.subs.delete(s); for (const h of s.handles.values()) { try { h.close(); } catch { /* gone */ } } s.handles.clear(); } };
  }

  async query(...filters: Filter[]): Promise<NostrEvent[]> {
    const live = [...this.conns.values()].filter((c): c is RelayClient => !!c?.isOpen);
    const all = await Promise.all(live.map((c) => c.query(...filters).catch(() => [] as NostrEvent[])));
    const out = new Map<string, NostrEvent>();
    for (const evs of all) for (const e of evs) out.set(e.id, e);
    return [...out.values()];
  }

  close() {
    this.stopped = true;
    if (this.probe) clearInterval(this.probe);
    for (const c of this.conns.values()) c?.close();
  }
}
