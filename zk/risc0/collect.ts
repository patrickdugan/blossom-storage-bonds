// Assembles results/bitvm2-spike.json from the spike's run directories.
//
//   node zk/risc0/collect.ts --m1-fail DIR --term DIR --keys DIR --bitvm FILE [--bridge FILE] [--out FILE]
//
// --m1-fail  the failing-case runs of milestone 1 (drop/, seed/)
// --term     WORK of zk/risc0/term-run.sh
// --keys     vk.json, contributions.json and image-files.txt from the prover image, and
//            vk-compare.json (the VK's 18 coordinates against host/src/main.rs's test constants)
// --bitvm    zk/bitvm-check's --out file
// Every timed step carries its /usr/bin/time -v peak RSS.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { execSync } from "node:child_process";
import { cpus, totalmem } from "node:os";

const argv = process.argv.slice(2);
const opt = (k: string): string | undefined => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
/** A JSON file, or the last line of a file whose earlier lines are guest output. */
const lastLine = (f: string) => { const t = readFileSync(f, "utf8").trim(); try { return JSON.parse(t); } catch { return JSON.parse(t.split("\n").pop()!); } };
const jsonl = (f: string) => readFileSync(f, "utf8").trim().split("\n").map((l) => JSON.parse(l));
const time = (f: string) => {
  if (!existsSync(f)) return undefined;
  const t = readFileSync(f, "utf8");
  return {
    peak_rss_mib: Math.round(Number(/Maximum resident set size \(kbytes\): (\d+)/.exec(t)![1]) / 1024),
    wall: /Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): (.*)/.exec(t)![1],
  };
};
const step = (dir: string, name: string) => ({ ...lastLine(join(dir, `${name}.json`)), ...time(join(dir, `${name}.time`)) });
const reason = (dir: string, name: string) => readFileSync(join(dir, `${name}.reason`), "utf8").trim();
const sh = (c: string) => { try { return execSync(c, { encoding: "utf8" }).trim(); } catch { return undefined; } };

const m1Fail = opt("--m1-fail")!, term = opt("--term")!, keys = opt("--keys")!;
const g16 = JSON.parse(readFileSync(join(term, "g16", "groth16.json"), "utf8"));
const bitvm = JSON.parse(readFileSync(opt("--bitvm")!, "utf8"));
const holds = ["170", "180", "190"].map((h) => ({ height: +h, ...step(term, `hold-${h}`), check: lastLine(join(term, `hold-${h}.check.json`)) }));

const out = {
  generated: new Date().toISOString(),
  note: "Phase 6 BitVM2 feasibility spike, docs/design.md §4.6. Test keys only, regtest only, no real funds.",
  warnings: {
    "risc0-to-bitvm2": [
      "This software is experimental and should not be used in production. (README)",
      "It does not necessarily prevent the malicious actors to generate proofs for their private forks. (README, on the header chain)",
    ],
    BitVM: ["DO NOT USE IN PRODUCTION! (README)"],
  },
  environment: {
    machine: `${cpus().length} vCPU (${cpus()[0].model}), ${(totalmem() / 2 ** 30).toFixed(1)} GiB RAM, no swap, no GPU`,
    kernel: sh("uname -sr"), docker: sh("docker version --format '{{.Server.Version}}'"),
    rust_host: sh("rustc --version"), risc0_guest_toolchain: "risc0 rust 1.85.0, cpp 2024.1.5 (rzup layout, fetched from GitHub releases)",
    risc0_crates: { "risc0-zkvm": "2.0.1", "risc0-groth16": "2.0.0", "risc0-build": "2.1.0", "risc0-circuit-rv32im": "2.0.2" },
    bitcoind: sh("/home/user/bin/bitcoind --version | head -1"),
    bitcoind_source: "copied out of docker.io/blockstream/esplora:latest (BitVM's regtest image); bitcoincore.org is not reachable from this VM",
    upstream: { "risc0-to-bitvm2": "chainwayxyz/risc0-to-bitvm2@efc448e", BitVM: "BitVM/BitVM@7d1ca36" },
  },
  image_ids: { hold: holds[0].image_id, term: step(term, "term").image_id, header_chain: step(term, "term").header_chain_id },
  m1: {
    statement: "holdings mode (model/zk_pdp.ts mode 1), sha tree, journal = statementOutput felts as u32be (76 bytes)",
    runs: jsonl("results/bitvm2-spike-m1.jsonl"),
    failing: {
      missing_chunk: { config: "64 deals x 256 chunks, q = 16, challenge 5's chunk replaced by zeros with a valid path",
        exec_exit: 1, prove_exit: 1, receipt_written: existsSync(join(m1Fail, "drop", "receipt.bin")),
        guest_panic: sh(`grep -m1 -o "Guest panicked: .*" ${join(m1Fail, "drop", "exec.err")}`) },
      wrong_seed: { config: "64 deals x 256 chunks, q = 16, provider answers its own seed", ...lastLine(join(m1Fail, "seed", "check.json")) },
    },
  },
  m2: {
    header_chain: { headers: 201, network: "regtest", elf: "elfs/regtest-header-chain-guest.bin (upstream, as published)", ...step(term, "chain"),
      timing_note: "the first ~2 minutes of this proof overlapped a nice-19 rebuild of the host" },
    holds,
    term: step(term, "term"),
    failing: {
      seed_one_block_off: reason(term, "term-seed-off"),
      depth_beyond_tip: reason(term, "term-shallow"),
    },
    forge_demo: step(term, "forge"),
  },
  m3: {
    groth16: { ...g16, proof: undefined, ...time(join(term, "groth16.time")) },
    proof_json: g16.proof,
    proof_bytes: 256,
    public_output_recomputed_in_ts: lastLine(join(term, "groth16.check.json")),
    prover_image: {
      ref: g16.image,
      files: readFileSync(join(keys, "image-files.txt"), "utf8").trim().split("\n"),
      zkey_contributions: JSON.parse(readFileSync(join(keys, "contributions.json"), "utf8")),
      vk_from_zkey_vs_upstream_test: JSON.parse(readFileSync(join(keys, "vk-compare.json"), "utf8")),
    },
    bitvm: { ...bitvm, ...time(join(dirname(opt("--bitvm")!), "check.time")) },
  },
  bridge_regtest_disprove: opt("--bridge") ? JSON.parse(readFileSync(opt("--bridge")!, "utf8")) : undefined,
};
writeFileSync(opt("--out") ?? "results/bitvm2-spike.json", JSON.stringify(out, null, 1) + "\n");
console.log("wrote", opt("--out") ?? "results/bitvm2-spike.json");
