// Writes fixtures/sentinels.json: the sentinels the regtest harness puts in its bond chain. The harness
// rechecks every hash, so this file is the seam between the model and real transactions.
//
//   node model/fixture.ts [k]
//
// `sentinels` use the standard geometry (16-byte r, 64-byte window, one 80-byte item). `wide` is one
// sentinel in the first design's geometry (32-byte r, 488-byte window, one 520-byte item), kept so the
// harness can show that it is valid by consensus and refused by relay policy.

import { mkdirSync, writeFileSync } from "node:fs";
import { sha256 } from "./schnorr.ts";
import {
  MAX_ELEMENT, WINDOW, WINDOWS_PER_CHUNK, buildTree, chunk, encryptReplica, makeSentinel, replicaKey, sentinelResponse,
} from "./storage_bonds.ts";

const k = Number(process.argv[2] ?? 3);
const secret = Buffer.from("regtest client secret, 32 bytes!");
const blob = Buffer.from(Array.from({ length: 64_000 }, (_, i) => (i * 131 + (i >> 9)) & 0xff));
const chunks = chunk(encryptReplica(blob, replicaKey(secret, "regtest-blob", "provider-1")));
const tree = buildTree(chunks);
const held = new Map(chunks.map((c, i) => [i, c] as const));
const hex = (b: Buffer) => b.toString("hex");

const sentinels = Array.from({ length: k }, (_, i) => {
  const s = makeSentinel(secret, tree, chunks, i);
  const pre = sentinelResponse(s.r, tree.n, held)!;
  const c = Math.floor(s.idx / WINDOWS_PER_CHUNK), off = (s.idx % WINDOWS_PER_CHUNK) * WINDOW;
  const wrong = Buffer.concat([s.r, chunks[(c + 1) % tree.n].subarray(off, off + WINDOW)]);
  return { i, idx: s.idx, r: hex(s.r), s: hex(s.s), h: hex(s.h), preimage: hex(pre), wrong_preimage: hex(wrong) };
});

const wr = sha256("bsb/wide-sentinel|", secret);
const wideWindow = chunks[0].subarray(0, MAX_ELEMENT - wr.length);
const widePre = Buffer.concat([wr, wideWindow]);
const wide = { r: hex(wr), s: hex(sha256(wr)), h: hex(sha256(widePre)), preimage: hex(widePre), wrong_preimage: hex(Buffer.concat([wr, chunks[1].subarray(0, wideWindow.length)])) };

mkdirSync(new URL("../fixtures/", import.meta.url), { recursive: true });
const out = new URL("../fixtures/sentinels.json", import.meta.url);
writeFileSync(out, JSON.stringify({ n: tree.n, root: hex(tree.root), sentinels, wide }, null, 2) + "\n");
console.log(`wrote ${k} sentinels over ${tree.n} chunks, plus one wide sentinel, to fixtures/sentinels.json`);
