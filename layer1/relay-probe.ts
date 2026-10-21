// Before a pilot names a relay in --relays: does it take this protocol's events? It publishes, from a
// throwaway key, one event of each placeholder kind the stack uses (the offer is addressable, the rest
// regular) plus deal-sized events of growing size, reads each back, and reports what each relay accepted
// and the largest size it kept. Every probe event is tagged network "probe", so no party acts on it.
//
//   node layer1/relay-probe.ts --relays wss://a,wss://b [--out results/relay-probe.json]
//
// Pointed at public relays this POSTS to them: docs/signet-pilot.md asks for a go-ahead first.

import { writeFileSync } from "node:fs";
import { KIND_DEAL, KIND_OFFER } from "./deals.ts";
import { newKey, now, signEvent, type NostrEvent } from "./nostr.ts";
import { KIND_PAYMENT_RECEIPT } from "./onchain.ts";
import { RelayClient } from "./relay.ts";
import { KIND_ATTESTATION, KIND_EPOCH_PROOF } from "./zk-provider.ts";
import { KIND_EPOCH_RECEIPT } from "./client.ts";
import { fileURLToPath } from "node:url";

export interface ProbeResult {
  url: string;
  connected: boolean;
  error?: string;
  kinds: { kind: number; accepted: boolean; readBack: boolean; message: string }[];
  sizes: { bytes: number; accepted: boolean; readBack: boolean; message: string }[];
  largestKept: number;
  roundTripMs?: number;
}

const SIZES = [4_000, 16_000, 48_000, 64_000, 100_000];

export async function probeRelay(url: string): Promise<ProbeResult> {
  const key = newKey();
  const out: ProbeResult = { url, connected: false, kinds: [], sizes: [], largestKept: 0 };
  let rc: RelayClient;
  try { rc = await RelayClient.connect(url, 15_000); out.connected = true; } catch (e) { out.error = (e as Error).message; return out; }
  const tags = [["network", "probe"], ["t", "bsb-relay-probe"]];
  const one = async (ev: NostrEvent) => {
    const t0 = Date.now();
    const r = await rc.publish(ev, 15_000).catch((e) => ({ accepted: false, message: (e as Error).message }));
    const back = r.accepted ? (await rc.query({ ids: [ev.id] }).catch(() => [])).length > 0 : false;
    out.roundTripMs ??= Date.now() - t0;
    return { accepted: r.accepted, readBack: back, message: r.message };
  };
  try {
    for (const kind of [KIND_OFFER, KIND_DEAL, KIND_EPOCH_PROOF, KIND_ATTESTATION, KIND_PAYMENT_RECEIPT, KIND_EPOCH_RECEIPT]) {
      const t = kind === KIND_OFFER ? [["d", "bsb-offer:probe"], ...tags] : tags;
      out.kinds.push({ kind, ...(await one(signEvent(key, { created_at: now(), kind, tags: t, content: JSON.stringify({ probe: true, kind }) }))) });
    }
    for (const bytes of SIZES) {
      const r = await one(signEvent(key, { created_at: now(), kind: KIND_DEAL, tags, content: JSON.stringify({ probe: true, pad: "x".repeat(bytes) }) }));
      out.sizes.push({ bytes, ...r });
      if (r.readBack) out.largestKept = bytes;
    }
  } finally { rc.close(); }
  return out;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const i = process.argv.indexOf("--relays");
  const urls = i > 0 ? process.argv[i + 1].split(",").filter(Boolean) : [];
  if (urls.length === 0) { console.error("usage: node layer1/relay-probe.ts --relays wss://a,wss://b [--out file]"); process.exit(2); }
  const res = [];
  for (const u of urls) {
    const r = await probeRelay(u);
    res.push(r);
    console.log(`${u}: ${r.connected ? `kinds ${r.kinds.filter((k) => k.readBack).length}/${r.kinds.length} kept; largest event kept ${r.largestKept} B; first round trip ${r.roundTripMs} ms` : `no connection (${r.error})`}`);
    for (const k of r.kinds) if (!k.readBack) console.log(`  kind ${k.kind}: ${k.accepted ? "accepted but not read back" : `refused: ${k.message}`}`);
  }
  const o = process.argv.indexOf("--out");
  if (o > 0) writeFileSync(process.argv[o + 1], JSON.stringify({ generated: new Date().toISOString(), relays: res }, null, 2) + "\n");
}
