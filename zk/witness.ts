// Writes the prover's witness (args.json) and the verifier's statement (statement.json) for one
// epoch of the aggregated storage proof. See model/zk_pdp.ts for the statement.
//
//   node zk/witness.ts --out DIR [--hash sha|blake] [--deals 4] [--q 8] [--chunks 256] [--seed HEX]
//                      [--drop D:J ...] [--prover-seed HEX]
//
// --drop D:J      the provider no longer holds the chunk challenge J of deal D selects, and sends
//                 a zero chunk with the right Merkle path in its place (it kept the leaf hashes).
// --prover-seed   the provider answers the challenges of a seed of its choosing; the statement
//                 still carries the real one.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "../model/schnorr.ts";
import { CHUNK } from "../model/storage_bonds.ts";
import { challengeIndices, statementOutput, syntheticDeal, witnessFelts, type Backend, type HeldDeal } from "../model/zk_pdp.ts";

const argv = process.argv.slice(2);
const opt = (k: string, d?: string): string | undefined => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
const all = (k: string): string[] => argv.flatMap((a, i) => (a === k ? [argv[i + 1]] : []));

const out = opt("--out") ?? (() => { throw new Error("--out DIR") })();
const backend = (opt("--hash", "sha") as Backend);
if (backend !== "sha" && backend !== "blake") throw new Error("--hash sha|blake");
const nDeals = Number(opt("--deals", "4"));
const q = Number(opt("--q", "8"));
const nChunks = Number(opt("--chunks", "256"));
const seed = Buffer.from(opt("--seed") ?? sha256("bsb/zk-pdp/demo-seed").toString("hex"), "hex");
const proverSeed = opt("--prover-seed") ? Buffer.from(opt("--prover-seed")!, "hex") : seed;
const drops = all("--drop").map((s) => s.split(":").map(Number) as [number, number]);

const t0 = Date.now();
const deals: HeldDeal[] = Array.from({ length: nDeals }, (_, d) => {
  const full = syntheticDeal(backend, `deal-${d}-of-${nChunks}`, nChunks);
  const ref = { root: full.tree.root, n: full.tree.n };
  const lost = new Set(drops.filter(([dd]) => dd === d).map(([, j]) => challengeIndices(backend, seed, ref, q)[j]));
  return { tree: full.tree, chunk: (i: number) => (lost.has(i) ? undefined : full.chunk(i)) };
});
const refs = deals.map((d) => ({ root: d.tree.root, n: d.tree.n }));

const args = witnessFelts(backend, proverSeed, q, deals, () => Buffer.alloc(CHUNK));
const statement = {
  hash: backend, seed: seed.toString("hex"), q,
  deals: refs.map((r) => ({ root: r.root.toString("hex"), n: r.n })),
  output: statementOutput(backend, seed, q, refs),
};
mkdirSync(out, { recursive: true });
writeFileSync(join(out, "args.json"), JSON.stringify(args));
writeFileSync(join(out, "statement.json"), JSON.stringify(statement, null, 1) + "\n");
console.log(JSON.stringify({ out, hash: backend, deals: nDeals, q, chunks: nChunks, felts: args.length, drops, gen_s: (Date.now() - t0) / 1000 }));
