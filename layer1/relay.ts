// A minimal Nostr relay (NIP-01: EVENT, REQ, CLOSE; OK, EVENT, EOSE, CLOSED, NOTICE) on node:http with a
// hand-written RFC 6455 framer, plus a small client on Node's global WebSocket. Enough to publish receipts
// and query them back on localhost; it keeps events in memory and does no rate limiting or auth (NIP-42).

import { createHash } from "node:crypto";
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

/** One connection to one relay. publish() resolves on the relay's OK; query() collects until EOSE. */
export class RelayClient {
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
      const t = setTimeout(() => bad(new Error(`relay ${url}: connect timeout`)), timeoutMs);
      c.ws.addEventListener("open", () => { clearTimeout(t); ok(); }, { once: true });
      c.ws.addEventListener("error", () => { clearTimeout(t); bad(new Error(`relay ${url}: connect failed`)); }, { once: true });
    });
    c.ws.addEventListener("message", (m) => c.onMessage(String(m.data)));
    return c;
  }

  private onMessage(raw: string) {
    let m: unknown;
    try { m = JSON.parse(raw); } catch { return; }
    if (!Array.isArray(m)) return;
    if (m[0] === "OK") this.waiters.get(`ok:${m[1]}`)?.(m);
    else if (m[0] === "EVENT" && verifyEvent(m[2])) this.found.get(String(m[1]))?.push(m[2]);
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
    const p = this.wait(`sub:${sid}`, 5000);
    this.ws.send(JSON.stringify(["REQ", sid, ...filters]));
    await p;
    this.ws.send(JSON.stringify(["CLOSE", sid]));
    const out = this.found.get(sid)!;
    this.found.delete(sid);
    return out;
  }

  close() { this.ws.close(); }
}
