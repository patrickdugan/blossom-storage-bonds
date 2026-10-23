// Runs bsb-bond (regtest/src/bin/bond.rs) as one party. Each call gets that party's seed in BSB_SEED and
// nothing else, so a process can only sign as itself. The network settings (BSB_NETWORK, BSB_CONFS, the
// RPC login and fee variables) come from the environment, set once by net.ts useNetwork().

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { currentNet, defaultRpcUrl } from "./net.ts";

export { rpc } from "./net.ts";

const here = dirname(fileURLToPath(import.meta.url));

export function bondExe(): string {
  const exe = process.platform === "win32" ? "bsb-bond.exe" : "bsb-bond";
  const cands = [
    process.env.BSB_BOND,
    process.env.CARGO_TARGET_DIR && join(process.env.CARGO_TARGET_DIR, "release", exe),
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "cargo-target", "blossom-storage-bonds", "release", exe),
    join(here, "..", "regtest", "target", "release", exe),
  ].filter((x): x is string => !!x);
  const hit = cands.find((p) => existsSync(p));
  if (!hit) throw new Error(`bsb-bond not found; run cargo build --release in regtest/ (looked in ${cands.join(", ")})`);
  return hit;
}

export class BondTool {
  readonly seed: string;
  readonly rpc: string;
  readonly exe: string;
  constructor(seed: string, rpc = process.env.BSB_RPC ?? defaultRpcUrl(currentNet().name), exe = bondExe()) {
    this.seed = seed; this.rpc = rpc; this.exe = exe;
  }

  /** Run one command; resolves with its JSON result, rejects with its {"error"} message. */
  run(...args: string[]): Promise<Record<string, any>> {
    return new Promise((ok, bad) => {
      // A bond-fund on signet can wait minutes for a UTXO-set scan; a call that hangs longer is killed.
      execFile(this.exe, args, { env: { ...process.env, BSB_SEED: this.seed, BSB_RPC: this.rpc }, maxBuffer: 1 << 24, timeout: 900_000 }, (err, stdout) => {
        const line = String(stdout).trim().split("\n").pop() ?? "";
        let v: Record<string, any>;
        try { v = JSON.parse(line); } catch { return bad(new Error(`bsb-bond ${args[0]}: ${err?.message ?? "no output"} ${line}`)); }
        if (v.error && v.status === undefined) return bad(new Error(`bsb-bond ${args[0]}: ${v.error}`));
        ok(v);
      });
    });
  }
}

/** Run a bsb-bond command with extra environment (e.g. BSB_FEE_RATE for one call). */
export function runWith(tool: BondTool, env: Record<string, string>, ...args: string[]): Promise<Record<string, any>> {
  return new Promise((ok, bad) => {
    execFile(tool.exe, args, { env: { ...process.env, BSB_SEED: tool.seed, BSB_RPC: tool.rpc, ...env }, maxBuffer: 1 << 24, timeout: 900_000 }, (err, stdout) => {
      const line = String(stdout).trim().split("\n").pop() ?? "";
      let v: Record<string, any>;
      try { v = JSON.parse(line); } catch { return bad(new Error(`bsb-bond ${args[0]}: ${err?.message ?? "no output"} ${line}`)); }
      if (v.error && v.status === undefined) return bad(new Error(`bsb-bond ${args[0]}: ${v.error}`));
      ok(v);
    });
  });
}

export interface ForfeitPolicy {
  /** sat/vB to bid, in order; the last one is repeated. Each must exceed the one before (RBF). */
  rates: number[];
  /** Broadcast a forfeit at this rate; resolves with its txid. */
  broadcast: (rate: number) => Promise<string>;
  /** Wait for the next block. */
  nextBlock: () => Promise<void>;
  /** Confirmations of a txid (0 if unconfirmed or unknown). */
  confirmations: (txid: string) => Promise<number>;
  /** Whether the provider's answer to this challenge has confirmed (the forfeit lost the race). */
  answered: () => Promise<boolean>;
  /** Give up after this many blocks. */
  maxBlocks?: number;
}

export type ForfeitOutcome = { won: true; txid: string; rate: number; bids: number } | { won: false; why: "answered" | "timeout"; bids: number };

/** Phase 7C forfeit fee policy. Bid at the first eligible block, then re-bid one step higher after
 *  every block in which the forfeit has not confirmed, so a late answer must keep outbidding. Harness
 *  S1 shows both sides can replace each other on Core: this policy defeats a casual late answer, not a
 *  provider willing to bid up to the bond, which still had to hold the data to answer. */
export async function forfeitWithPolicy(p: ForfeitPolicy): Promise<ForfeitOutcome> {
  if (p.rates.length === 0 || p.rates.some((r, i) => i > 0 && r <= p.rates[i - 1])) throw new Error("rates must be non-empty and increasing");
  let bids = 0, step = 0, txid: string | undefined;
  const bid = async () => {
    try { txid = await p.broadcast(p.rates[Math.min(step, p.rates.length - 1)]); bids++; }
    catch { /* a replacement refused (e.g. outbid already confirmed); the checks below decide */ }
  };
  await bid();
  for (let b = 0; b < (p.maxBlocks ?? 12); b++) {
    await p.nextBlock();
    if (txid && (await p.confirmations(txid)) >= 1) return { won: true, txid, rate: p.rates[Math.min(step, p.rates.length - 1)], bids };
    if (await p.answered()) return { won: false, why: "answered", bids };
    if (step < p.rates.length - 1) step++;
    await bid();
  }
  return { won: false, why: "timeout", bids };
}

/** A rate schedule from a base rate, doubling up to a cap such that the forfeit's fee stays below a
 *  fraction of the bond (the client never pays more than it stands to recover). */
export function forfeitRates(base: number, bondSats: number, forfeitVsize = 138, maxShare = 0.5): number[] {
  const cap = Math.max(1, Math.floor((bondSats * maxShare) / forfeitVsize));
  const out: number[] = [];
  for (let r = Math.min(Math.max(1, base), cap); r <= cap && out.length < 12; r *= 2) out.push(r);
  return out;
}
