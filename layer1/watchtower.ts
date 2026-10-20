// A watchtower for public epoch proofs (phase 3b): a third party with its own bitcoind view and Nostr
// key that holds no stake in any deal.
//
//   node layer1/watchtower.ts --relay <ws url> --providers <pubkey,...> --epoch-blocks 10 --from <height>
//                             [--deadline 6] [--min-q 8] [--rpc <url>] [--dir <dir>]
//
// For every proof event (kind 4245) from a listed provider it rebuilds the statement itself: the seed
// from its own node's block hash at the claimed boundary, never the event's copy, and q and the deal
// list from the event. It fetches the proof from the URL, checks its SHA-256, and verifies it with
// bsb-zk. Each verdict goes out as a signed attestation (kind 4246, placeholder): valid, or invalid
// with the reason. A provider with no proof for a boundary `deadline` blocks after it is attested
// missing. Anyone who trusts this watchtower can act on its attestations, and anyone who does not can
// re-check them, since everything they rest on is public.

import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keyFromSeed } from "../model/schnorr.ts";
import { rpc } from "./bondtool.ts";
import { now, signEvent, type NostrEvent } from "./nostr.ts";
import { RelayClient } from "./relay.ts";
import { defaultZk, statementFor, verifyProof } from "./zk.ts";
import { KIND_ATTESTATION, KIND_EPOCH_PROOF } from "./zk-provider.ts";

const arg = (name: string, dflt?: string) => {
  const i = process.argv.indexOf(`--${name}`);
  if (i > 0) return process.argv[i + 1];
  if (dflt === undefined) throw new Error(`--${name} is required`);
  return dflt;
};
const RELAY = arg("relay"), PROVIDERS = arg("providers").split(",");
const EPOCH = Number(arg("epoch-blocks", "10")), FROM = Number(arg("from")), DEADLINE = Number(arg("deadline", "6"));
const MIN_Q = Number(arg("min-q", "8"));
const RPC = arg("rpc", process.env.BSB_RPC ?? "http://127.0.0.1:18543");
const DIR = arg("dir", join(tmpdir(), "bsb-watchtower"));
mkdirSync(DIR, { recursive: true });

const key = keyFromSeed("nostr|bsb/watchtower");
const log = (ev: Record<string, unknown>) => process.stdout.write(JSON.stringify({ t: Date.now(), watchtower: true, ...ev }) + "\n");
const rc = await RelayClient.connect(RELAY);
const seen = new Set<string>();             // `${provider}|${height}` that have a proof event
const attested = new Set<string>();
let queue = Promise.resolve();

async function attest(provider: string, height: number, result: string, extra: Record<string, unknown> = {}) {
  const k = `${provider}|${height}`;
  if (attested.has(k)) return;
  attested.add(k);
  const ev = signEvent(key, {
    created_at: now(), kind: KIND_ATTESTATION,
    tags: [["p", provider], ["h", String(height)], ["result", result], ...(extra.proofEvent ? [["e", String(extra.proofEvent)]] : [])],
    content: JSON.stringify({ provider, height, result, ...extra }),
  });
  await rc.publish(ev);
  log({ event: "attest", provider: provider.slice(0, 12), height, result, ...extra });
}

async function check(e: NostrEvent) {
  let c: any;
  try { c = JSON.parse(e.content); } catch { return; }
  const height = Number(c.height);
  if (!Number.isSafeInteger(height) || height % EPOCH !== 0 || height < FROM) return;
  const base = { proofEvent: e.id, proof: c.proof?.sha256 };
  try {
    if (Number(c.q) < MIN_Q) return attest(e.pubkey, height, "invalid", { ...base, why: `q ${c.q} is below ${MIN_Q}` });
    if (c.mode !== 1 || c.hash !== "blake") return attest(e.pubkey, height, "invalid", { ...base, why: "unsupported proof kind" });
    const seed = Buffer.from(await rpc("getblockhash", [height], RPC), "hex");
    const r = await fetch(String(c.proof.url));
    const proof = Buffer.from(await r.arrayBuffer());
    if (createHash("sha256").update(proof).digest("hex") !== c.proof.sha256) return attest(e.pubkey, height, "invalid", { ...base, why: "proof bytes do not match the announced hash" });
    const v = await verifyProof(defaultZk(), DIR, proof, statementFor(seed, Number(c.q), c.deals));
    return attest(e.pubkey, height, v.ok ? "valid" : "invalid", { ...base, deals: c.deals.length, q: c.q, ...(v.ok ? {} : { why: v.why }), verify_s: v.seconds });
  } catch (err) {
    return attest(e.pubkey, height, "invalid", { ...base, why: (err as Error).message });
  }
}

rc.subscribe([{ kinds: [KIND_EPOCH_PROOF], authors: PROVIDERS }], (e) => {
  // Mark it seen on arrival, not when its turn in the queue comes, so a proof that waits behind
  // another's verification is never attested missing.
  try { seen.add(`${e.pubkey}|${Number(JSON.parse(e.content).height)}`); } catch { /* checked below */ }
  queue = queue.then(() => check(e));
});

// Missing proofs: a boundary that passed `deadline` blocks ago with no event from a provider.
(async () => {
  for (;;) {
    try {
      const h: number = await rpc("getblockcount", [], RPC);
      for (let b = FROM; b + DEADLINE <= h; b += EPOCH) {
        for (const p of PROVIDERS) if (!seen.has(`${p}|${b}`)) queue = queue.then(() => attest(p, b, "missing", { why: `no proof ${DEADLINE} blocks after the boundary` }));
      }
    } catch (e) { log({ event: "error", error: (e as Error).message }); }
    await new Promise((r) => setTimeout(r, 500));
  }
})();

process.on("SIGTERM", () => { rc.close(); process.exit(0); });
log({ ready: true, nostr: key.x, providers: PROVIDERS.length, from: FROM, epoch: EPOCH, deadline: DEADLINE });
