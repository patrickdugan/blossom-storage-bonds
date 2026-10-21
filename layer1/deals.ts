// Offers and deals as Nostr events (docs/design.md §6). Both kinds are placeholders, not registered.
//
//   Offer (KIND_OFFER, addressable, d = "bsb-offer:<network>", signed by the provider): its terms. The
//   Blossom URL, the price per chunk-epoch, the bond key and the most it will bond, Δ, the shortest
//   term, how it is paid (Lightning node or on-chain pay key), the public-proof schedule, and a
//   failure-domain claim. A newer offer replaces the older one, on any relay.
//
//   Deal (KIND_DEAL, one kind, a "stage" tag). Four events that together are the deal signed by both:
//     propose  client:   the replica (sha256, root, n), k of M sentinels kept by cut and choose and the
//                        root of all M commitments, the term t_end, the bond size and the client's key.
//     accept   provider: e → propose. The deal file as the provider built it from its own cut-and-choose
//                        records, and Bond_0's funding outpoint, script and taproot merkle root. Or stage
//                        "reject" with a reason.
//     seal     client:   e → propose, accept. Sent once the bond has the network's confirmation depth and
//                        the client checked it on chain (bsb-bond bond-presign): the client's
//                        presignatures on every Respond_i.
//     live     provider: e → seal. The provider checked those (bond-accept), and only now hands over its
//                        presignatures on every Challenge_i, which the client checks (bond-check). The
//                        bond is armed.
//   And when the term ends, "settled" from the provider: the refund txid, for a client with no
//   orchestrator to ask.
//
// The order of the presignatures matters. Up to phase 6 the provider sent its Challenge_i signatures
// with the funding, before it held the client's Respond_i signatures. A client could then stop there,
// challenge, and take the bond after Δ, since the provider cannot answer without the client's signature
// on Respond_i. Now the provider's signatures come last: a client that stops early can challenge nothing,
// and the provider takes its bond back at t_end (offers cap the term).
//
// Every event carries ["network", <name>], and a party drops events for another network. Deal events are
// public, like the proof events: the deals a provider proves over are public by design, and so is every
// presignature here (each spend needs the other side's signature and a secret as well). The cut and
// choose itself stays on the provider's Blossom server (POST /bond/<sha>/commit and /reveal); a proposal
// is honoured only from the key that uploaded the blob.

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import type { Key } from "../model/schnorr.ts";
import type { BondTool } from "./bondtool.ts";
import type { BondSentinel, Offer, Replica } from "./client.ts";
import { confirm, type Net } from "./net.ts";
import { now, signEvent, tagValue, tagValues, verifyEvent, type NostrEvent } from "./nostr.ts";
import type { Relays } from "./relay.ts";

/** Placeholder kinds, not in the NIPs kinds table. */
export const KIND_OFFER = 34248;
export const KIND_DEAL = 4248;
export const offerD = (network: string) => `bsb-offer:${network}`;

export interface OfferTerms {
  network: string;
  /** The provider's Blossom server, as clients reach it. */
  blossom: string;
  price_msat_per_chunk_epoch: number;
  /** max_term_blocks caps how long one client can lock the provider's bond. */
  bond: { x: string; max_sats: number; delta: number; min_term_blocks: number; max_term_blocks?: number };
  pay: { kind: string; payee: string; ln_uri?: string; onchain_key?: string };
  /** Public epoch proofs (phase 3b), if the provider makes them. */
  zk?: { epoch_blocks: number; q: number; price_msat: number; hash: string; mode: number };
  failure_domain?: string;
}

export interface ProviderOffer { event: NostrEvent; pubkey: string; terms: OfferTerms; offer: Offer }

export function offerEvent(key: Key, terms: OfferTerms): NostrEvent {
  return signEvent(key, {
    created_at: now(), kind: KIND_OFFER,
    tags: [["d", offerD(terms.network)], ["network", terms.network], ["url", terms.blossom]],
    content: JSON.stringify(terms),
  });
}

const HEX64 = /^[0-9a-f]{64}$/;

/** A verified offer for `network`, or an Error saying why not. */
export function parseOffer(ev: NostrEvent, network: string): ProviderOffer | Error {
  if (!verifyEvent(ev) || ev.kind !== KIND_OFFER) return new Error("not a signed offer");
  if (tagValue(ev, "d") !== offerD(network) || tagValue(ev, "network") !== network) return new Error(`offer is not for ${network}`);
  let t: OfferTerms;
  try { t = JSON.parse(ev.content); } catch { return new Error("offer content is not JSON"); }
  if (t.network !== network) return new Error("offer content names another network");
  try { new URL(t.blossom); } catch { return new Error("offer has no Blossom URL"); }
  if (!HEX64.test(t.bond?.x ?? "") || !Number.isSafeInteger(t.bond?.max_sats) || !Number.isSafeInteger(t.price_msat_per_chunk_epoch)) return new Error("offer terms are malformed");
  if (typeof t.pay?.payee !== "string") return new Error("offer has no payee");
  return { event: ev, pubkey: ev.pubkey, terms: t, offer: { url: t.blossom.replace(/\/$/, ""), pubkey: ev.pubkey, lightningNodeId: t.pay.payee, priceMsatPerChunkEpoch: t.price_msat_per_chunk_epoch } };
}

/** The newest valid offer from each of `authors`, waiting up to `timeoutMs` for all of them. */
export async function findOffers(relays: Relays, network: string, authors: string[], timeoutMs = 30_000): Promise<Map<string, ProviderOffer>> {
  const best = new Map<string, ProviderOffer>();
  const take = (ev: NostrEvent) => {
    const o = parseOffer(ev, network);
    if (o instanceof Error || !authors.includes(o.pubkey)) return;
    const had = best.get(o.pubkey);
    if (!had || ev.created_at > had.event.created_at || (ev.created_at === had.event.created_at && ev.id < had.event.id)) best.set(o.pubkey, o);
  };
  const sub = relays.subscribe([{ kinds: [KIND_OFFER], authors, "#d": [offerD(network)] }], take);
  const t0 = Date.now();
  while (best.size < authors.length && Date.now() - t0 < timeoutMs) await new Promise((r) => setTimeout(r, 100));
  sub.close();
  const missing = authors.filter((a) => !best.has(a));
  if (missing.length) throw new Error(`no ${network} offer from ${missing.map((m) => m.slice(0, 12) + "…").join(", ")}`);
  return best;
}

/** The root a proposal names for all M cut-and-choose commitments, in the order the client sent them. */
export function commitmentsRoot(cs: { s: string; h: string; hs?: string[] }[]): string {
  const h = createHash("sha256").update("bsb/commitments|");
  for (const c of cs) { h.update(Buffer.from(c.s, "hex")); for (const x of c.hs ?? [c.h]) h.update(Buffer.from(x, "hex")); h.update("|"); }
  return h.digest("hex");
}

// ───────────────────────────── deal events ─────────────────────────────

export type Stage = "propose" | "accept" | "reject" | "seal" | "live" | "settled";

export interface Proposal {
  network: string; offer: string; sha256: string; root: string; n: number;
  m: number; k: number; commitments_root: string; t_end: number; bond_sats: number; client_x: string;
}

export function dealEvent(key: Key, network: string, stage: Stage, content: unknown, tags: string[][]): NostrEvent {
  return signEvent(key, { created_at: now(), kind: KIND_DEAL, tags: [["stage", stage], ["network", network], ...tags], content: JSON.stringify(content) });
}

export function parseDeal(ev: NostrEvent, network: string): { stage: Stage; content: any } | undefined {
  if (!verifyEvent(ev) || ev.kind !== KIND_DEAL || tagValue(ev, "network") !== network) return undefined;
  try { return { stage: tagValue(ev, "stage") as Stage, content: JSON.parse(ev.content) }; } catch { return undefined; }
}

/** Publish, retrying while no relay accepts (a relay can be reconnecting). */
export async function publishSure(relays: Relays, ev: NostrEvent, tries = 20): Promise<void> {
  let last = "";
  for (let i = 0; i < tries; i++) {
    const r = await relays.publish(ev);
    if (r.accepted) return;
    last = r.message;
    await new Promise((s) => setTimeout(s, 500 * (i + 1)));
  }
  throw new Error(`no relay accepted event ${ev.id.slice(0, 12)}…: ${last}`);
}

/** The first deal event from `author` that names `ref` in an e tag and is at one of `stages`. */
export function awaitDeal(relays: Relays, network: string, author: string, ref: string, stages: Stage[], timeoutMs: number): Promise<{ ev: NostrEvent; stage: Stage; content: any }> {
  return new Promise((ok, bad) => {
    const sub = relays.subscribe([{ kinds: [KIND_DEAL], authors: [author], "#e": [ref] }], (ev) => {
      const d = parseDeal(ev, network);
      if (!d || !stages.includes(d.stage) || !tagValues(ev, "e").includes(ref)) return;
      clearTimeout(t); sub.close(); ok({ ev, ...d });
    });
    const t = setTimeout(() => { sub.close(); bad(new Error(`no ${stages.join("/")} for ${ref.slice(0, 12)}… within ${Math.round(timeoutMs / 1000)} s`)); }, timeoutMs);
  });
}

export interface ProposeOptions {
  relays: Relays; key: Key; net: Net; offer: ProviderOffer; rep: Replica; kept: BondSentinel[];
  tEnd: number; bondSats: number; clientX: string; tool: BondTool; dealPath: string;
  /** Regtest mines the confirming block here; elsewhere it is waited for. */
  minerAddr: string;
  timeoutMs?: number;
  onWait?: (what: string) => void;
}

/** The client's side of a deal, after cut and choose: propose, check the provider's acceptance against
 *  our own records, wait for the bond to be deep enough, check it on chain and presign (bsb-bond), seal,
 *  and wait until the provider says the bond is live. */
export async function proposeDeal(o: ProposeOptions) {
  const { relays, key, net, offer, rep } = o;
  const timeoutMs = o.timeoutMs ?? 120_000;
  const cs = rep.commitments ?? [];
  const proposal: Proposal = {
    network: net.name, offer: offer.event.id, sha256: rep.sha256, root: rep.root, n: rep.n, m: cs.length, k: o.kept.length,
    commitments_root: commitmentsRoot(cs), t_end: o.tEnd, bond_sats: o.bondSats, client_x: o.clientX,
  };
  const propose = dealEvent(key, net.name, "propose", proposal, [["p", offer.pubkey], ["e", offer.event.id], ["x", rep.sha256]]);
  await publishSure(relays, propose);
  const acc = await awaitDeal(relays, net.name, offer.pubkey, propose.id, ["accept", "reject"], timeoutMs);
  if (acc.stage === "reject") throw new Error(`provider rejected the deal: ${acc.content.why}`);
  const a = acc.content;
  const want = o.kept.map((s) => ({ s: s.s, h: s.h, hs: s.hs }));
  if (JSON.stringify(a.deal?.sentinels) !== JSON.stringify(want) || a.deal.client_x !== o.clientX || a.deal.provider_x !== offer.terms.bond.x ||
    a.deal.t_end !== o.tEnd || a.deal.sha256 !== rep.sha256 || (a.deal.bond_sats ?? 100_000_000) !== o.bondSats) {
    throw new Error("the provider's deal differs from ours");
  }
  writeFileSync(o.dealPath, JSON.stringify(a.deal, null, 2));
  const pPath = o.dealPath.replace(".json", ".p.json");
  writeFileSync(pPath, JSON.stringify({ fund_txid: a.fund_txid }));
  await confirm(net, a.fund_txid, o.minerAddr, (c, w) => o.onWait?.(`bond ${a.fund_txid.slice(0, 12)}… has ${c}/${w} confirmations`));
  const c = await o.tool.run("bond-presign", o.dealPath);   // checks the bond on chain, then presigns every Respond_i
  const seal = dealEvent(key, net.name, "seal", { sig_c_respond: c.sig_c_respond, checked: c.checked }, [["p", offer.pubkey], ["e", propose.id], ["e", acc.ev.id], ["x", rep.sha256]]);
  await publishSure(relays, seal);
  const live = await awaitDeal(relays, net.name, offer.pubkey, seal.id, ["live", "reject"], timeoutMs);
  if (live.stage === "reject") throw new Error(`provider refused our presignatures: ${live.content.why}`);
  // Only now the provider's presignatures on every Challenge_i, checked before anything relies on them.
  writeFileSync(pPath, JSON.stringify({ fund_txid: a.fund_txid, sig_p_challenge: live.content.sig_p_challenge }));
  const k = await o.tool.run("bond-check", o.dealPath);
  return {
    deal: a.deal, fund_txid: a.fund_txid as string, bond0: { spk: a.bond0_spk, merkle_root: a.bond0_merkle_root },
    checked: { bond_confirmations: c.checked.bond_confirmations, provider_signatures: k.provider_signatures },
    events: { propose: propose.id, accept: acc.ev.id, seal: seal.id, live: live.ev.id },
  };
}
