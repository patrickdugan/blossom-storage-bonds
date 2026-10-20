// Runs bsb-bond (regtest/src/bin/bond.rs) as one party. Each call gets that party's seed in BSB_SEED and
// nothing else, so a process can only sign as itself.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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
  constructor(seed: string, rpc = process.env.BSB_RPC ?? "http://127.0.0.1:18543", exe = bondExe()) {
    this.seed = seed; this.rpc = rpc; this.exe = exe;
  }

  /** Run one command; resolves with its JSON result, rejects with its {"error"} message. */
  run(...args: string[]): Promise<Record<string, any>> {
    return new Promise((ok, bad) => {
      execFile(this.exe, args, { env: { ...process.env, BSB_SEED: this.seed, BSB_RPC: this.rpc }, maxBuffer: 1 << 24 }, (err, stdout) => {
        const line = String(stdout).trim().split("\n").pop() ?? "";
        let v: Record<string, any>;
        try { v = JSON.parse(line); } catch { return bad(new Error(`bsb-bond ${args[0]}: ${err?.message ?? "no output"} ${line}`)); }
        if (v.error && v.status === undefined) return bad(new Error(`bsb-bond ${args[0]}: ${v.error}`));
        ok(v);
      });
    });
  }
}

/** Bitcoin Core JSON-RPC with the regtest test credentials from scripts/regtest-node.sh. */
export async function rpc(method: string, params: unknown[] = [], url = process.env.BSB_RPC ?? "http://127.0.0.1:18543"): Promise<any> {
  const r = await fetch(url, {
    method: "POST", headers: { Authorization: "Basic " + Buffer.from("bsb:bsb-regtest-only").toString("base64") },
    body: JSON.stringify({ jsonrpc: "1.0", id: "bsb", method, params }),
  });
  const v = (await r.json()) as { result: unknown; error: { message: string } | null };
  if (v.error) throw new Error(`${method}: ${v.error.message}`);
  return v.result;
}
