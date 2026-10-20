// Writes the RISC Zero holdings guest's input (witness.bin) and the verifier's statement
// (statement.json) for one epoch. See model/zk_pdp.ts (mode 1, "sha") and methods/guest/src/bin/hold.rs.
//
//   node zk/risc0/witness.ts --out DIR [--deals 1] [--q 8] [--chunks 256] [--seed HEX]
//                            [--drop J ...] [--prover-seed HEX]
//
// --drop J        the provider lost the chunk challenge J selects and sends a zero chunk with the
//                 right Merkle path in its place (it kept the leaf hashes).
// --prover-seed   the provider answers the challenges of a seed of its choosing; the statement
//                 still carries the real one.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "../../model/schnorr.ts";
import { CHUNK } from "../../model/storage_bonds.ts";
import { holdingsChallenges, journalBytes, risc0Witness, syntheticDeal, type HeldDeal } from "../../model/zk_pdp.ts";

const argv = process.argv.slice(2);
const opt = (k: string, d?: string): string | undefined => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
const all = (k: string): string[] => argv.flatMap((a, i) => (a === k ? [argv[i + 1]] : []));

const out = opt("--out") ?? (() => { throw new Error("--out DIR") })();
const nDeals = Number(opt("--deals", "1"));
const q = Number(opt("--q", "8"));
const nChunks = Number(opt("--chunks", "256"));
const seed = Buffer.from(opt("--seed") ?? sha256("bsb/zk-pdp/demo-seed").toString("hex"), "hex");
const proverSeed = opt("--prover-seed") ? Buffer.from(opt("--prover-seed")!, "hex") : seed;
const drops = all("--drop").map(Number);

const t0 = Date.now();
const full = Array.from({ length: nDeals }, (_, d) => syntheticDeal("sha", `deal-${d}-of-${nChunks}`, nChunks));
const refs = full.map((f) => ({ root: f.tree.root, n: f.tree.n }));
const held = holdingsChallenges("sha", proverSeed, refs, q);
const lost = new Set(drops.map((j) => `${held[j].deal}:${held[j].idx}`));
const deals: HeldDeal[] = full.map((f, d) => ({ tree: f.tree, chunk: (i: number) => (lost.has(`${d}:${i}`) ? undefined : f.chunk(i)) }));

const witness = risc0Witness(proverSeed, q, deals, () => Buffer.alloc(CHUNK));
const statement = {
  hash: "sha", mode: 1, seed: seed.toString("hex"), q,
  deals: refs.map((r) => ({ root: r.root.toString("hex"), n: r.n })),
  journal: journalBytes(seed, q, refs).toString("hex"),
};
mkdirSync(out, { recursive: true });
writeFileSync(join(out, "witness.bin"), witness);
writeFileSync(join(out, "statement.json"), JSON.stringify(statement, null, 1) + "\n");
console.log(JSON.stringify({ out, deals: nDeals, q, chunks: nChunks, held: held.map((c) => c.deal), witness_bytes: witness.length,
  drops, prover_seed: proverSeed.equals(seed) ? undefined : proverSeed.toString("hex"), gen_s: (Date.now() - t0) / 1000 }));
