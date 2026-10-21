// The epoch challenge and its answer as NIP-44 v2 encrypted Nostr events, as the design says: the nonce
// never travels in the clear, and the relay sees only two pubkeys and ciphertext.
//
//   client → provider  kind 21242 (ephemeral)  ["p", provider]               nip44({sha256, nonce, q, epoch})
//   provider → client  kind 21243 (ephemeral)  ["p", client], ["e", challenge id]  nip44(PdpAnswer)
//                                              or, over 60 kB, nip44({ref: URL, sha256}) for one GET
//
// Both kinds are placeholders and are not registered in the NIPs. They are ephemeral, so the relay
// forwards them to live subscribers and does not store them.

import { createHash } from "node:crypto";
import type { Key } from "../model/schnorr.ts";
import { conversationKey, decrypt, encrypt } from "./nip44.ts";
import { now, signEvent, tagValue, type NostrEvent } from "./nostr.ts";
import type { Relays } from "./relay.ts";
import type { PdpAnswer } from "./blossom.ts";
import type { Replica } from "./client.ts";

export const KIND_PDP_CHALLENGE = 21242;
export const KIND_PDP_ANSWER = 21243;

/** Client side: a transport for StorageClient that sends the nonce over the relay and waits for the
 *  answer addressed back to it. */
export function nostrTransport(relay: Relays, me: Key, timeoutMs = 10_000) {
  return async (rep: Replica, epoch: number, nonce: string): Promise<PdpAnswer> => {
    const ck = conversationKey(me.d, rep.offer.pubkey);
    const ev = signEvent(me, {
      created_at: now(), kind: KIND_PDP_CHALLENGE, tags: [["p", rep.offer.pubkey]],
      content: encrypt(JSON.stringify({ sha256: rep.sha256, nonce, q: rep.q, epoch }), ck),
    });
    const answer = new Promise<PdpAnswer>((ok, bad) => {
      const t = setTimeout(() => { sub.close(); bad(new Error("no answer over Nostr")); }, timeoutMs);
      const sub = relay.subscribe([{ kinds: [KIND_PDP_ANSWER], "#p": [me.x], "#e": [ev.id] }], (e) => {
        if (e.pubkey !== rep.offer.pubkey) return;
        clearTimeout(t); sub.close();
        (async () => {
          let a = JSON.parse(decrypt(e.content, ck));
          if (a.ref) {
            // Too large for one NIP-44 message: fetch it from the provider and check it against the hash
            // that arrived encrypted and signed.
            const body = await (await fetch(String(a.ref))).text();
            if (createHash("sha256").update(body).digest("hex") !== a.sha256) throw new Error("referenced answer does not match its hash");
            a = JSON.parse(body);
          }
          if (a.error) throw new Error(String(a.error));
          return a as PdpAnswer;
        })().then(ok, bad);
      });
    });
    const pub = await relay.publish(ev);
    if (!pub.accepted) throw new Error(`relay refused the challenge: ${pub.message}`);
    return answer;
  };
}

/** NIP-44 caps a plaintext at 65,535 bytes; larger answers go by reference. */
export const MAX_INLINE = 60_000;

/** Provider side: answer every challenge addressed to `me` with `answer(sha, nonce, q, epoch)`. An answer
 *  over MAX_INLINE bytes is handed to `stash`, and the encrypted reply carries its URL and SHA-256. */
export function servePdpOverNostr(
  relay: Relays, me: Key,
  answer: (sha: string, nonce: string, q: number, epoch: number) => Promise<PdpAnswer | { error: string }>,
  log: (ev: Record<string, unknown>) => void = () => {},
  stash?: (body: string) => string,
): { close(): void } {
  return relay.subscribe([{ kinds: [KIND_PDP_CHALLENGE], "#p": [me.x], since: now() - 5 }], async (e: NostrEvent) => {
    try {
      const ck = conversationKey(me.d, e.pubkey);
      const c = JSON.parse(decrypt(e.content, ck)) as { sha256: string; nonce: string; q: number; epoch: number };
      const a = await answer(String(c.sha256), String(c.nonce), Number(c.q), Number(c.epoch));
      let body = JSON.stringify(a);
      const inline = Buffer.byteLength(body) <= MAX_INLINE;
      if (!inline) {
        if (!stash) body = JSON.stringify({ error: `answer is ${Buffer.byteLength(body)} bytes, over one NIP-44 message, and this provider cannot serve it by reference` });
        else body = JSON.stringify({ ref: stash(body), sha256: createHash("sha256").update(body).digest("hex") });
      }
      const reply = signEvent(me, { created_at: now(), kind: KIND_PDP_ANSWER, tags: [["p", e.pubkey], ["e", e.id]], content: encrypt(body, ck) });
      await relay.publish(reply);
      log({ event: "pdp", epoch: c.epoch, from: e.pubkey.slice(0, 12), bytes: reply.content.length, inline });
    } catch (err) {
      log({ event: "pdp-error", id: e.id, error: (err as Error).message, p: tagValue(e, "p") });
    }
  });
}
