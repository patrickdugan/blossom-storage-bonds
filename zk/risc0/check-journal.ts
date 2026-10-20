// Checks a RISC Zero receipt's journal against the statement the verifier builds itself.
//
//   node zk/risc0/check-journal.ts statement.json result.json
//
// result.json is bsb-r0's output line (prove-hold, verify-hold or exec-hold). The expected journal
// is recomputed here from the statement's seed, q and deal list with model/zk_pdp.ts journalBytes,
// so statement.json's own `journal` field is only cross-checked, never trusted. Exits 1 on mismatch.

import { readFileSync } from "node:fs";
import { journalBytes, statementOutput } from "../../model/zk_pdp.ts";

const [statementPath, resultPath] = process.argv.slice(2);
const st = JSON.parse(readFileSync(statementPath, "utf8"));
const res = JSON.parse(readFileSync(resultPath, "utf8").trim().split("\n").pop()!);
const deals = st.deals.map((d: { root: string; n: number }) => ({ root: Buffer.from(d.root, "hex"), n: d.n }));
const seed = Buffer.from(st.seed, "hex");
const expected = journalBytes(seed, st.q, deals);
const got = Buffer.from(res.journal, "hex");
const felts = statementOutput("sha", seed, st.q, deals, 1);
const gotFelts = got.length === 76 ? Array.from({ length: 19 }, (_, i) => "0x" + got.readUInt32BE(4 * i).toString(16)) : [];
let diff = -1;
for (let i = 0; i < Math.max(expected.length, got.length); i++) if (expected[i] !== got[i]) { diff = i; break; }
const ok = diff < 0 && expected.toString("hex") === st.journal;
console.log(JSON.stringify({
  match: ok, bytes: got.length, first_diff_byte: diff < 0 ? undefined : diff,
  felts_match: JSON.stringify(felts) === JSON.stringify(gotFelts),
  expected: expected.toString("hex"), got: got.toString("hex"),
}));
process.exit(ok ? 0 : 1);
