#!/usr/bin/env bash
# Benchmark the aggregated storage proof: for each run "hash:deals:q:chunks", write the witness
# (node, through WSL interop), prove it, verify it, and append one JSON line to $RESULTS.
#
#   bash zk/bench.sh sha:1:1:256 blake:4:4:256 ...
#
# Every proof runs under a guard that samples RSS and swap each second and kills the prover once
# its swap passes $GUARD_SWAP_MIB: on this machine (WSL capped at 4.5 GB) a run that only finishes
# by paging is reported as memory-bound, not timed. K is the bounded preprocessed trace (2^K rows;
# stwo-cairo needs K >= 20 and K >= every component's log size); a run whose components outgrow
# 2^K is retried at K + 1.
set -u
ZK=$(cd "$(dirname "$0")" && pwd)
BIN=${BIN:-/root/build/bsb-zk-prover/release/bsb-zk}
EXE_DIR=${EXE_DIR:-/root/build/bsb-zk/exe}
NODE=${NODE:-/mnt/c/Users/patri/AppData/Local/Programs/nodejs/node.exe}
RUNS_DIR=${RUNS_DIR:-$ZK/runs}
RESULTS=${RESULTS:-$ZK/../results/zk-pdp.jsonl}
# Witness and proof are staged on ext4: cairo-lang reads the arguments file unbuffered, and over
# the WSL mount of the Windows (OneDrive) folder that alone cost about 6 s per challenged chunk.
STAGE=${STAGE:-/root/zk-bench}
GUARD_SWAP_MIB=${GUARD_SWAP_MIB:-1024}
K0=${K0:-20}
KMAX=${KMAX:-22}
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-4}

guarded() {  # log, command...: run, sampling the heaviest of it; exit 137 if the guard fired
  local log=$1; shift
  "$@" &
  local pid=$! fired=0 peak=0
  while kill -0 $pid 2>/dev/null; do
    local s; s=$(awk '/VmRSS|VmSwap/ {print $2}' /proc/$pid/status 2>/dev/null | tr '\n' ' ')
    local rss swap; rss=$(echo $s | awk '{print int($1/1024)}'); swap=$(echo $s | awk '{print int($2/1024)}')
    [ "${rss:-0}" -gt "$peak" ] && peak=$rss
    echo "$(date +%s) rss=${rss:-0} swap=${swap:-0}" >> "$log"
    if [ "${swap:-0}" -gt "$GUARD_SWAP_MIB" ]; then
      echo "guard: swap ${swap} MiB > ${GUARD_SWAP_MIB} MiB, killing" >&2; kill -9 $pid; fired=1
    fi
    sleep 1
  done
  wait $pid; local rc=$?
  [ $fired = 1 ] && return 137
  return $rc
}

for spec in "$@"; do
  IFS=: read -r hash deals q chunks <<< "$spec"
  name="$hash-d$deals-q$q-n$chunks"
  dir="$RUNS_DIR/$name"
  mkdir -p "$dir"
  (cd "$ZK/.." && "$NODE" zk/witness.ts --hash "$hash" --deals "$deals" --q "$q" --chunks "$chunks" \
    --out "zk/runs/$name") > "$dir/witness.json" || { echo "{\"run\": \"$name\", \"error\": \"witness\"}" >> "$RESULTS"; continue; }
  stage="$STAGE/$name"; rm -rf "$stage"; mkdir -p "$stage"; mv "$dir/args.json" "$stage/args.json"
  k=$K0
  while :; do
    rm -f "$dir/guard.log" "$stage/proof.json"
    guarded "$dir/guard.log" "$BIN" prove --hash "$hash" --executable "$EXE_DIR/zk_pdp_$hash.executable.json" \
      --args "$stage/args.json" --out "$stage/proof.json" --max-log-rows "$k" > "$dir/prove.json" 2> "$dir/prove.err"
    rc=$?
    if [ $rc != 0 ] && grep -q "preprocessed trace variant allows" "$dir/prove.err" && [ $k -lt $KMAX ]; then
      k=$((k + 1)); continue
    fi
    break
  done
  swap_peak=$(awk -F'swap=' '{print $2}' "$dir/guard.log" | sort -n | tail -1)
  if [ $rc = 0 ]; then
    "$BIN" verify --hash "$hash" --executable "$EXE_DIR/zk_pdp_$hash.executable.json" --proof "$stage/proof.json" \
      --statement "$dir/statement.json" --max-log-rows "$k" > "$dir/verify.json" 2> "$dir/verify.err"
    vrc=$?
    # Proofs stay out of the repo (~11 MB of JSON each); the size is in prove.json.
    rm -rf "$stage"
    python3 - "$name" "$hash" "$deals" "$q" "$chunks" "$k" "$vrc" "${swap_peak:-0}" "$dir" >> "$RESULTS" <<'EOF'
import json, sys
name, h, d, q, n, k, vrc, swap, dir = sys.argv[1:]
p = json.load(open(f"{dir}/prove.json"))
v = json.load(open(f"{dir}/verify.json")) if vrc == "0" else {"result": "REJECTED", "error": open(f"{dir}/verify.err").read()[-300:]}
p.pop("output", None)
print(json.dumps({"run": name, "hash": h, "deals": int(d), "q": int(q), "chunks_per_deal": int(n), "k": int(k),
                  "swap_peak_mib": int(swap), **p, "verify": v}))
EOF
  else
    why=$(tail -c 300 "$dir/prove.err" | tr '\n"' ' ' )
    [ $rc = 137 ] && why="memory-bound: swap passed ${GUARD_SWAP_MIB} MiB at K=$k"
    echo "{\"run\": \"$name\", \"hash\": \"$hash\", \"deals\": $deals, \"q\": $q, \"chunks_per_deal\": $chunks, \"k\": $k, \"rc\": $rc, \"swap_peak_mib\": ${swap_peak:-0}, \"error\": \"$why\"}" >> "$RESULTS"
  fi
  tail -1 "$RESULTS" | cut -c1-400
done
