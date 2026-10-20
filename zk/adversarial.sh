#!/usr/bin/env bash
# Soundness checks for the aggregated storage proof, per backend:
#
#   honest        the provider holds every chunk: the proof verifies against the statement.
#   missing       it lost one challenged chunk and sends zeros with the right Merkle path (it kept
#                 the leaf hashes, the strongest deleter): the program fails, there is no proof.
#   own-seed      it answers a seed of its choosing, for which it holds every chunk: the proof is
#                 valid but says the wrong seed, and the verifier rejects it against the statement.
#   other-deals   the honest proof, checked against a statement whose deal list differs in one
#                 root: rejected (D differs).
#   forged-output the honest proof with its public output edited to claim q + 1, checked against a
#                 statement edited to match: the STARK rejects it.
#   wrong-program the honest proof checked as if it were the other backend's program: rejected.
#
#   bash zk/adversarial.sh sha:1:1:64 blake:4:4:256      (hash:deals:q:chunks per backend)
set -u
ZK=$(cd "$(dirname "$0")" && pwd)
BIN=${BIN:-/root/build/bsb-zk-prover/release/bsb-zk}
EXE_DIR=${EXE_DIR:-/root/build/bsb-zk/exe}
NODE=${NODE:-/mnt/c/Users/patri/AppData/Local/Programs/nodejs/node.exe}
OUT=${OUT:-$ZK/../results/zk-pdp-adversarial.jsonl}
K=${K:-20}
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-4}
FAIL=0

line() { echo "{\"backend\": \"$1\", \"case\": \"$2\", \"expected\": \"$3\", \"result\": \"$4\", \"detail\": $(printf '%s' "$5" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()[-240:]))')}" | tee -a "$OUT"; }
why() { grep -m1 -A1 "panicked at" "$1" | tail -1; }

for spec in "$@"; do
  IFS=: read -r h d q n <<< "$spec"
  other=$([ "$h" = sha ] && echo blake || echo sha)
  exe=$EXE_DIR/zk_pdp_$h.executable.json
  base=$ZK/runs/adv-$h
  witness() { (cd "$ZK/.." && "$NODE" zk/witness.ts --hash "$h" --deals "$d" --q "$q" --chunks "$n" --out "zk/runs/adv-$h/$1" "${@:2}") > /dev/null; }
  prove() { "$BIN" prove --hash "$h" --executable "$exe" --args "$base/$1/args.json" --out "$base/$1/proof.json" --max-log-rows $K > "$base/$1/prove.json" 2> "$base/$1/prove.err"; }
  verify() { "$BIN" verify --hash "${3:-$h}" --executable "${4:-$exe}" --proof "$base/$1/proof.json" --statement "$2" --max-log-rows $K > "$base/$1/verify.json" 2> "$base/$1/verify.err"; }
  rm -rf "$base"; mkdir -p "$base"

  witness honest
  if prove honest && verify honest "$base/honest/statement.json"; then
    line $h honest verifies verified "$(cat $base/honest/verify.json)"
  else
    line $h honest verifies FAILED "$(tail -c 300 $base/honest/prove.err $base/honest/verify.err)"; FAIL=1; continue
  fi

  # Challenge 0 of the last deal is lost.
  witness missing --drop $((d - 1)):0
  if prove missing; then
    line $h missing no-proof "PROVED (BAD)" "$(cat $base/missing/prove.json)"; FAIL=1
  else
    line $h missing no-proof "no proof" "$(cat $base/missing/prove.json)"
  fi

  witness own-seed --prover-seed 00000000000000000000000000000000000000000000000000000000000000ff
  if prove own-seed && ! verify own-seed "$base/honest/statement.json"; then
    line $h own-seed rejected rejected "$(why $base/own-seed/verify.err)"
  else
    line $h own-seed rejected "ACCEPTED (BAD)" "$(cat $base/own-seed/verify.json)"; FAIL=1
  fi

  python3 - "$base/honest/statement.json" "$base/other-deals.json" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1]))
s["output"][-1] = hex(int(s["output"][-1], 16) ^ 1)   # the statement's D, for a different deal list
json.dump(s, open(sys.argv[2], "w"))
EOF
  if verify honest "$base/other-deals.json"; then
    line $h other-deals rejected "ACCEPTED (BAD)" ""; FAIL=1
  else
    line $h other-deals rejected rejected "$(why $base/honest/verify.err)"
  fi

  mkdir -p "$base/forged"
  python3 - "$base/honest/proof.json" "$base/honest/statement.json" "$base/forged" <<'EOF'
import json, sys
p = json.load(open(sys.argv[1])); s = json.load(open(sys.argv[2]))
out = p["claim"]["public_data"]["public_memory"]["output"]
out[8][1][0] += 1                                   # q, low limb
s["output"][8] = hex(int(s["output"][8], 16) + 1)
json.dump(p, open(sys.argv[3] + "/proof.json", "w")); json.dump(s, open(sys.argv[3] + "/statement.json", "w"))
EOF
  if verify forged "$base/forged/statement.json"; then
    line $h forged-output rejected "ACCEPTED (BAD)" ""; FAIL=1
  else
    line $h forged-output rejected rejected "$(why $base/forged/verify.err)"
  fi

  if verify honest "$base/honest/statement.json" "$other" "$EXE_DIR/zk_pdp_$other.executable.json"; then
    line $h wrong-program rejected "ACCEPTED (BAD)" ""; FAIL=1
  else
    line $h wrong-program rejected rejected "$(why $base/honest/verify.err)"
  fi
  find "$base" -name proof.json -delete; find "$base" -name args.json -delete
done
exit $FAIL
