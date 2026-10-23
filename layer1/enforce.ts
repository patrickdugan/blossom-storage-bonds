// Phase 7C, pilot condition 1: a client's bond enforcement that survives a crash.
//
// The client orchestrators (market.ts, full-stack.ts) keep their epoch loop in memory. Enforcement is the
// part that cannot wait: a sentinel challenge must be forfeited after Δ blocks of silence, or the provider
// refunds at t_end. This module therefore keeps no state of its own beyond one durable file per deal.
// That file holds the deal, the kept sentinels, and every challenge and forfeit it sent. Every decision
// is re-derived from the chain (bsb-bond bond-status), so the process can be killed at any point and
// started again with the same file.
//
//   node layer1/enforce.ts --state <enforce-<deal>.json> [--confs N] [--mine-to <regtest address>]
//
// The state file is written by the client when it bonds (writeEnforceState), and marked `flagged` when
// a watchtower attests the provider missing or invalid. Prints one JSON line per event, then
// {"result": ...}.

import { existsSync, readFileSync } from "node:fs";
import { BondTool, forfeitRates, forfeitWithPolicy, runWith } from "./bondtool.ts";
import { writeFileDurable } from "./ledger.ts";

export interface EnforceState {
  deal: string;                       // the client's deal file (bsb-bond's input)
  kept: { r: string }[];              // the bond's sentinels in chain order: secret r of each
  delta: number;                      // CSV of the forfeit leaf
  bondSats: number;
  flagged?: { cause: string; at: number };
  challenges: { j: number; txid?: string }[]; // written ahead of each bond-challenge
  forfeits: { j: number; rate: number; txid: string }[];
  result?: { outcome: "forfeited" | "answered" | "gone"; txid?: string; why?: string };
}

export function writeEnforceState(path: string, s: EnforceState): void { writeFileDurable(path, JSON.stringify(s, null, 2)); }
export function readEnforceState(path: string): EnforceState { return JSON.parse(readFileSync(path, "utf8")) as EnforceState; }

export interface Chain {
  /** confirmations of a txid, 0 if unknown or unconfirmed */
  confirmations(txid: string): Promise<number>;
  /** wait for (or on regtest, mine) the next block */
  nextBlock(): Promise<void>;
}

type Status = { states: { challenge: number | null; respond: number | null; challenge_txid: string; respond_txid: string }[]; height: number };

/** One enforcement run to completion. Safe to call again after a crash with the same state file. */
export async function enforce(path: string, tool: BondTool, chain: Chain, confs = 1, log: (ev: Record<string, unknown>) => void = () => {}): Promise<EnforceState["result"]> {
  const s = readEnforceState(path);
  const save = () => writeEnforceState(path, s);
  if (s.result) return s.result;
  if (!s.flagged) throw new Error("this deal is not flagged for enforcement");
  for (let guard = 0; guard < 20_000; guard++) {
    for (const f of s.forfeits) if ((await chain.confirmations(f.txid)) >= confs) {
      s.result = { outcome: "forfeited", txid: f.txid }; save(); log({ event: "forfeited", j: f.j, txid: f.txid, rate: f.rate }); return s.result;
    }
    const st = (await tool.run("bond-status", s.deal)) as unknown as Status;
    const j = st.states.findIndex((x) => !(x.respond !== null && x.respond >= 1));
    if (j < 0) { s.result = { outcome: "answered" }; save(); log({ event: "all-answered" }); return s.result; }
    const row = st.states[j];
    if (row.challenge === null) {
      // The previous sentinel must be answered (its Respond re-arms the bond this challenge spends).
      if (j > 0 && !((st.states[j - 1].respond ?? 0) >= 1)) { await chain.nextBlock(); continue; }
      if (!s.challenges.some((c) => c.j === j)) { s.challenges.push({ j }); save(); }   // write ahead
      try {
        const c = await tool.run("bond-challenge", s.deal, String(j), s.kept[j].r);
        s.challenges = s.challenges.map((x) => (x.j === j ? { j, txid: String(c.txid) } : x)); save();
        log({ event: "challenge", j, txid: c.txid });
      } catch (e) {
        const why = (e as Error).message;
        // Already in the mempool (a restart): the next status will see it. Input gone: nothing to enforce.
        if (/missingorspent|missing-inputs/.test(why) && !(await chain.confirmations(row.challenge_txid))) {
          const tries = s.challenges.filter((x) => x.j === j).length;
          if (tries > 3) { s.result = { outcome: "gone", why }; save(); return s.result; }
        }
        log({ event: "challenge-retry", j, why: why.slice(0, 160) });
      }
      await chain.nextBlock();
      continue;
    }
    if (row.challenge < s.delta) { await chain.nextBlock(); continue; }
    // Δ blocks of silence: forfeit under the fee policy, recording every bid before relying on it.
    const rates = forfeitRates(Number(process.env.BSB_FEE_RATE ?? "2"), s.bondSats);
    const o = await forfeitWithPolicy({
      rates,
      broadcast: async (rate) => {
        const r = await runWith(tool, { BSB_FEE_RATE: String(rate) }, "bond-forfeit", s.deal, String(j));
        s.forfeits.push({ j, rate, txid: String(r.txid) }); save();
        log({ event: "forfeit-bid", j, rate, txid: r.txid });
        return String(r.txid);
      },
      nextBlock: () => chain.nextBlock(),
      confirmations: (t) => chain.confirmations(t),
      answered: async () => (((await tool.run("bond-status", s.deal)) as unknown as Status).states[j].respond ?? 0) >= 1,
      maxBlocks: 24,
    });
    if (o.won) continue;   // the confirmed forfeit is found at the top of the loop
    if (o.why === "answered") { log({ event: "late-answer-won", j }); continue; }
  }
  throw new Error("enforcement did not settle");
}

if (process.argv[1]?.endsWith("enforce.ts")) {
  const arg = (n: string, d?: string) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : d; };
  const path = arg("state");
  if (!path || !existsSync(path)) { console.error("usage: node layer1/enforce.ts --state <enforce-*.json> [--confs N] [--mine-to <addr>]"); process.exit(2); }
  const seed = process.env.BSB_SEED;
  if (!seed) { console.error("BSB_SEED (the client's bond key seed) is required"); process.exit(2); }
  const tool = new BondTool(seed);
  const { rpc } = await import("./bondtool.ts");
  const mineTo = arg("mine-to");
  const chain: Chain = {
    confirmations: async (t) => { try { return (await rpc("getrawtransaction", [t, true])).confirmations ?? 0; } catch { return 0; } },
    nextBlock: async () => {
      if (mineTo) { await rpc("generatetoaddress", [1, mineTo]); await new Promise((r) => setTimeout(r, 100)); return; }
      const h = await rpc("getblockcount");
      while ((await rpc("getblockcount")) <= h) await new Promise((r) => setTimeout(r, 5_000));
    },
  };
  const log = (ev: Record<string, unknown>) => console.log(JSON.stringify(ev));
  const result = await enforce(path, tool, chain, Number(arg("confs", "1")), log);
  console.log(JSON.stringify({ result }));
}
