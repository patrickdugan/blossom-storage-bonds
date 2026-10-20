// Sits on BitVM's regtest esplora port (8094) in front of esplora moved to 8095, and passes every
// request through except POST /regtest/api/tx (or //tx), which it hands to the container's bitcoind with
// `bitcoin-cli -stdin sendrawtransaction`. Current esplora images answer 413 to any transaction body
// over electrs' REST limit, and BitVM's assert-commit transactions are several megabytes of hex;
// BitVM's regtest script only raises nginx's limit, which was enough for older images. Regtest only.
//
//   node zk/bitvm-check/esplora-relay.ts [container=bsb-esplora] [listen=8094] [upstream=8095]

import http from "node:http";
import { spawn } from "node:child_process";

const [container = "bsb-esplora", listen = "8094", upstream = "8095"] = process.argv.slice(2);

const bodyOf = (req: http.IncomingMessage): Promise<Buffer> =>
  new Promise((ok, fail) => { const parts: Buffer[] = []; req.on("data", (c) => parts.push(c)); req.on("end", () => ok(Buffer.concat(parts))); req.on("error", fail); });

function sendraw(hex: string): Promise<{ ok: boolean; out: string }> {
  return new Promise((ok) => {
    const p = spawn("docker", ["exec", "-i", container, "/srv/explorer/bitcoin/bin/bitcoin-cli", "-conf=/data/.bitcoin.conf",
      "-datadir=/data/bitcoin", "-stdin", "sendrawtransaction"]);
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    p.on("close", (code) => ok({ ok: code === 0, out: out.trim() }));
    p.stdin.end(hex.trim() + "\n0\n");   // maxfeerate 0: no cap
  });
}

http.createServer(async (req, res) => {
  const body = await bodyOf(req);
  if (req.method === "POST") console.log(`${new Date().toISOString()} POST ${req.url} ${body.length} bytes`);
  // BitVM's base URL ends in a slash, so its client posts to /regtest/api//tx
  if (req.method === "POST" && /^\/regtest\/api\/+tx\/?$/.test(req.url ?? "")) {
    const r = await sendraw(body.toString());
    console.log(`${new Date().toISOString()} relay tx ${body.length / 2} bytes: ${r.ok ? "accepted" : "rejected"} ${r.out.slice(0, 200)}`);
    res.writeHead(r.ok ? 200 : 400, { "content-type": "text/plain" }).end(r.out);
    return;
  }
  const up = http.request({ host: "127.0.0.1", port: Number(upstream), path: req.url, method: req.method, headers: req.headers }, (u) => {
    res.writeHead(u.statusCode ?? 502, u.headers);
    u.pipe(res);
  });
  up.on("error", (e) => res.writeHead(502).end(String(e)));
  up.end(body);
}).listen(Number(listen), "127.0.0.1", () => console.log(`esplora relay on ${listen} -> ${upstream}, POST /tx via ${container}'s bitcoind`));
