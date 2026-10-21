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
