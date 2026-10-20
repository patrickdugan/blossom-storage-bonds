#!/usr/bin/env bash
# Milestone 1 of the BitVM2 spike: cycles, proving time and peak RSS of the RISC Zero holdings
# guest against q and the number of deals, with every journal checked byte for byte against
# model/zk_pdp.ts (check-journal.ts). One JSON line per run.
#
#   zk/risc0/bench.sh [deals...]        WORK=/tmp/bsb-r0-bench OUT=results/bitvm2-spike-m1.jsonl
#                                      QS="8 16 64" KINDS="composite succinct" CHUNKS=256
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN=zk/risc0/target/release/bsb-r0
WORK=${WORK:-/tmp/bsb-r0-bench}
OUT=${OUT:-results/bitvm2-spike-m1.jsonl}
QS=${QS:-8 16 64}
KINDS=${KINDS:-composite succinct}
CHUNKS=${CHUNKS:-256}
DEALS=${*:-1 64}
mkdir -p "$WORK" "$(dirname "$OUT")"

for deals in $DEALS; do
  for q in $QS; do
    d=$WORK/d$deals-q$q
    node zk/risc0/witness.ts --out "$d" --deals "$deals" --q "$q" --chunks "$CHUNKS" > "$d.gen.json"
    $BIN exec-hold "$d/witness.bin" > "$d/exec.json"
    for kind in $KINDS; do
      extra=""; [ "$kind" = succinct ] && extra="--succinct"
      /usr/bin/time -v -o "$d/time-$kind.txt" $BIN prove-hold "$d/witness.bin" "$d/receipt-$kind.bin" $extra > "$d/prove-$kind.json"
      node zk/risc0/check-journal.ts "$d/statement.json" "$d/prove-$kind.json" > "$d/check-$kind.json" || true
      node -e '
        const fs = require("fs"), [d, kind, deals, q, chunks] = process.argv.slice(1);
        const j = (f) => JSON.parse(fs.readFileSync(`${d}/${f}`, "utf8").trim().split("\n").pop());
        const t = fs.readFileSync(`${d}/time-${kind}.txt`, "utf8");
        const rss = Number(/Maximum resident set size \(kbytes\): (\d+)/.exec(t)[1]);
        const wall = /Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): (.*)/.exec(t)[1];
        const e = j("exec.json"), p = j(`prove-${kind}.json`), c = j(`check-${kind}.json`);
        console.log(JSON.stringify({ deals: +deals, q: +q, chunks_per_deal: +chunks, kind,
          witness_bytes: p.witness_bytes, user_cycles: p.user_cycles, total_cycles: p.total_cycles,
          paging_cycles: p.paging_cycles, segments: p.segments, exec_s: e.exec_s, prove_s: p.prove_s,
          verify_s: p.verify_s, wall, peak_rss_mb: Math.round(rss / 1024), receipt_bytes: p.receipt_bytes,
          seal_bytes: p.seal_bytes, journal_matches_model: c.match, image_id: p.image_id }));
      ' "$d" "$kind" "$deals" "$q" "$CHUNKS" | tee -a "$OUT"
    done
  done
done
