// Writes the prover's witness (args.json) and the verifier's statement (statement.json) for one
// epoch of the aggregated storage proof. See model/zk_pdp.ts for the statement.
//
//   node zk/witness.ts --out DIR [--hash sha|blake] [--mode 0|1] [--deals 4] [--q 8] [--chunks 256]
//                      [--seed HEX] [--drop D:J ...] [--prover-seed HEX]
//
// --mode 1        holdings mode: q challenges across all deals (model/zk_pdp.ts); --drop D:J then
//                 means challenge J, and D must be the deal it falls in.
//
// --drop D:J      the provider no longer holds the chunk challenge J of deal D selects, and sends
//                 a zero chunk with the right Merkle path in its place (it kept the leaf hashes).
// --prover-seed   the provider answers the challenges of a seed of its choosing; the statement
//                 still carries the real one.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "../model/schnorr.ts";
import { CHUNK } from "../model/storage_bonds.ts";
import { challengeIndices, holdingsChallenges, statementOutput, syntheticDeal, witnessFelts, type Backend, type HeldDeal, type Mode } from "../model/zk_pdp.ts";

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
const mode = Number(opt("--mode", "0")) as Mode;
if (mode !== 0 && mode !== 1) throw new Error("--mode 0|1");

const t0 = Date.now();
const full = Array.from({ length: nDeals }, (_, d) => syntheticDeal(backend, `deal-${d}-of-${nChunks}`, nChunks));
const refs = full.map((f) => ({ root: f.tree.root, n: f.tree.n }));
const held = holdingsChallenges(backend, seed, refs, q);
const deals: HeldDeal[] = full.map((f, d) => {
  const lost = new Set(drops.filter(([dd]) => dd === d).map(([, j]) => {
    if (mode === 0) return challengeIndices(backend, seed, refs[d], q)[j];
    if (held[j].deal !== d) throw new Error(`--drop ${d}:${j}: challenge ${j} falls in deal ${held[j].deal}`);
    return held[j].idx;
  }));
  return { tree: f.tree, chunk: (i: number) => (lost.has(i) ? undefined : f.chunk(i)) };
});

const args = witnessFelts(backend, proverSeed, q, deals, () => Buffer.alloc(CHUNK), mode);
const statement = {
  hash: backend, mode, seed: seed.toString("hex"), q,
  deals: refs.map((r) => ({ root: r.root.toString("hex"), n: r.n })),
  output: statementOutput(backend, seed, q, refs, mode),
};
mkdirSync(out, { recursive: true });
writeFileSync(join(out, "args.json"), JSON.stringify(args));
writeFileSync(join(out, "statement.json"), JSON.stringify(statement, null, 1) + "\n");
console.log(JSON.stringify({ out, hash: backend, mode, deals: nDeals, q, chunks: nChunks, held: mode === 1 ? held.map((c) => c.deal) : undefined, felts: args.length, drops, gen_s: (Date.now() - t0) / 1000 }));
