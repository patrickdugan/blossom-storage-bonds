// Public epoch proofs (phase 3b): build the holdings-mode witness from the bytes a provider stores,
// prove it with bsb-zk, and verify a proof against a statement anyone can rebuild from public data:
// the seed is a Bitcoin block hash, and the deal list travels with the proof.
//
// bsb-zk and the Cairo executables are Linux builds (README, "Run"). On Windows they run in WSL. Each
// call copies its input to the Linux filesystem first, because cairo-lang reads the witness unbuffered
// and a /mnt/c read is slow. Calls go through `wsl.exe --exec bash -c`: with `wsl.exe --`, the distro's
// login shell would expand every $ in the script before bash saw it. One proof runs at a time on this
// machine: a lock file serialises bsb-zk across processes, so providers never prove at once under
// WSL's memory cap.
//
// On Linux (phase 7c: CI and pilot hosts) the same scripts run natively under bash, and paths need no
// translation. The lock stays: proofs are memory-bound, and one at a time is the measured setting.

import { execFile } from "node:child_process";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CHUNK } from "../model/storage_bonds.ts";
import { holdingsChallenges, leafOf, statementOutput, treeOf, witnessFelts, type Backend, type HeldDeal, type Tree } from "../model/zk_pdp.ts";

export const ZK_HASH: Backend = "blake";
export const ZK_MODE = 1;

export interface ZkConfig {
  /** Linux paths, as WSL sees them. */
  bin: string;
  exeDir: string;
  distro: string;
  maxLogRows: number;
  threads: number;
}

export const defaultZk = (): ZkConfig => ({
  bin: process.env.BSB_ZK_BIN ?? "/root/build/bsb-zk-prover/release/bsb-zk",
  exeDir: process.env.BSB_ZK_EXE ?? "/root/build/bsb-zk/exe3b",
  distro: process.env.BSB_WSL_DISTRO ?? "Ubuntu-24.04",
  maxLogRows: Number(process.env.BSB_ZK_K ?? 20),
  threads: Number(process.env.BSB_ZK_THREADS ?? 4),
});

const NATIVE = process.platform !== "win32";

const wslPath = (p: string): string => {
  if (NATIVE) return p;
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(p);
  if (!m) throw new Error(`not a Windows path: ${p}`);
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, "/")}`;
};

const LOCK = join(tmpdir(), "bsb-zk.lock");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Hold the machine-wide prover lock while `f` runs. A lock older than 15 minutes is stale. */
async function withLock<T>(f: () => Promise<T>): Promise<T> {
  for (;;) {
    try { closeSync(openSync(LOCK, "wx")); break; } catch {
      try { if (Date.now() - statSync(LOCK).mtimeMs > 900_000) rmSync(LOCK, { force: true }); } catch { /* raced */ }
      await sleep(250);
    }
  }
  try { return await f(); } finally { rmSync(LOCK, { force: true }); }
}

function wsl(cfg: ZkConfig, script: string, timeoutMs = 900_000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((ok) => {
    const [cmd, argv] = NATIVE ? ["bash", ["-c", script]] : ["wsl.exe", ["-d", cfg.distro, "-u", "root", "--exec", "bash", "-c", script]];
    execFile(cmd, argv,
      { maxBuffer: 1 << 26, timeout: timeoutMs, windowsHide: true },
      (err, stdout, stderr) => ok({ code: err ? (typeof (err as any).code === "number" ? (err as any).code : 1) : 0, stdout: String(stdout), stderr: String(stderr) }));
  });
}

/** The Blake2s chunk tree of a blob: what a deal registers as its zk root. */
export function zkTree(data: Buffer): Tree {
  const n = Math.max(1, Math.ceil(data.length / CHUNK));
  const leaves: Buffer[] = [];
  for (let i = 0; i < n; i++) {
    const c = Buffer.alloc(CHUNK);
    data.copy(c, 0, i * CHUNK, Math.min((i + 1) * CHUNK, data.length));
    leaves.push(leafOf(ZK_HASH, c));
  }
  return treeOf(ZK_HASH, leaves);
}

/** The same tree from its leaves, as recorded at upload. */
export const zkTreeFromLeaves = (leaves: Buffer[]): Tree => treeOf(ZK_HASH, leaves);

export interface DealEntry { root: string; n: number }
export interface Statement { hash: Backend; mode: number; seed: string; q: number; deals: DealEntry[]; output: string[] }

export function statementFor(seed: Buffer, q: number, deals: DealEntry[]): Statement {
  const refs = deals.map((d) => ({ root: Buffer.from(d.root, "hex"), n: d.n }));
  return { hash: ZK_HASH, mode: ZK_MODE, seed: seed.toString("hex"), q, deals, output: statementOutput(ZK_HASH, seed, q, refs, ZK_MODE) };
}

/** Which deal and chunk each challenge of this epoch selects: lets a provider see in advance whether it
 *  can prove at all. */
export const challengesFor = (seed: Buffer, q: number, deals: DealEntry[]) =>
  holdingsChallenges(ZK_HASH, seed, deals.map((d) => ({ root: Buffer.from(d.root, "hex"), n: d.n })), q);

export type ProveResult = { ok: true; proof: Buffer; seconds: number; peakMiB?: number } | { ok: false; why: string; seconds: number };

/** Prove this epoch over `deals`, reading chunks through `held` (which may return what a deleting or
 *  outsourcing provider would send: zeros, or someone else's bytes). The program rejects any chunk that
 *  does not open to its root, so a dishonest provider gets no proof. */
export async function proveEpoch(cfg: ZkConfig, workDir: string, seed: Buffer, q: number, held: HeldDeal[]): Promise<ProveResult> {
  const t0 = Date.now();
  mkdirSync(workDir, { recursive: true });
  let args: string[];
  try {
    args = witnessFelts(ZK_HASH, seed, q, held, () => Buffer.alloc(CHUNK), ZK_MODE);
  } catch (e) { return { ok: false, why: (e as Error).message, seconds: 0 }; }
  const tag = createHash("sha256").update(workDir + seed.toString("hex")).digest("hex").slice(0, 12);
  const argsWin = join(workDir, "args.json"), proofWin = join(workDir, "proof.json");
  writeFileSync(argsWin, JSON.stringify(args));
  rmSync(proofWin, { force: true });
  const exe = `${cfg.exeDir}/zk_pdp_${ZK_HASH}.executable.json`;
  const lin = `/tmp/bsb-zk-${tag}`;
  const script = [
    `set -e; mkdir -p ${lin}; cp '${wslPath(argsWin)}' ${lin}/args.json`,
    `export RAYON_NUM_THREADS=${cfg.threads}`,
    `set +e; ${cfg.bin} prove --hash ${ZK_HASH} --executable ${exe} --args ${lin}/args.json --out ${lin}/proof.json --max-log-rows ${cfg.maxLogRows} > ${lin}/prove.json 2> ${lin}/prove.err; c=$?`,
    `cat ${lin}/prove.json; if [ $c -eq 0 ]; then cp ${lin}/proof.json '${wslPath(proofWin)}'; fi; rm -rf ${lin}; exit $c`,
  ].join("\n");
  const r = await withLock(() => wsl(cfg, script));
  const seconds = (Date.now() - t0) / 1000;
  let report: any = {};
  try { report = JSON.parse(r.stdout.trim().split("\n").pop() ?? "{}"); } catch { /* none */ }
  if (r.code !== 0 || !existsSync(proofWin)) return { ok: false, why: report.error ? `program rejected the witness: ${String(report.error).split("\n")[0]}` : `bsb-zk exit ${r.code}`, seconds };
  return { ok: true, proof: readFileSync(proofWin), seconds, peakMiB: report.peak_rss_mib };
}

export type VerifyResult = { ok: true; seconds: number } | { ok: false; why: string; seconds: number };

/** Check a proof against a statement the verifier built itself. */
export async function verifyProof(cfg: ZkConfig, workDir: string, proof: Buffer, st: Statement): Promise<VerifyResult> {
  const t0 = Date.now();
  mkdirSync(workDir, { recursive: true });
  const tag = createHash("sha256").update(proof).update(JSON.stringify(st)).digest("hex").slice(0, 12);
  const pWin = join(workDir, `proof-${tag}.json`), sWin = join(workDir, `statement-${tag}.json`);
  writeFileSync(pWin, proof);
  writeFileSync(sWin, JSON.stringify(st));
  const exe = `${cfg.exeDir}/zk_pdp_${st.hash}.executable.json`;
  const lin = `/tmp/bsb-zkv-${tag}`;
  const script = [
    `set -e; mkdir -p ${lin}; cp '${wslPath(pWin)}' ${lin}/proof.json; cp '${wslPath(sWin)}' ${lin}/statement.json`,
    `set +e; ${cfg.bin} verify --hash ${st.hash} --executable ${exe} --proof ${lin}/proof.json --statement ${lin}/statement.json --max-log-rows ${cfg.maxLogRows} > ${lin}/v.json 2> ${lin}/v.err; c=$?`,
    `grep -m1 -A1 'panicked at' ${lin}/v.err | tail -1; rm -rf ${lin}; exit $c`,
  ].join("\n");
  const r = await withLock(() => wsl(cfg, script, 300_000));
  rmSync(pWin, { force: true }); rmSync(sWin, { force: true });
  const seconds = (Date.now() - t0) / 1000;
  return r.code === 0 ? { ok: true, seconds } : { ok: false, why: r.stdout.trim().slice(0, 200) || `bsb-zk verify exit ${r.code}`, seconds };
}
