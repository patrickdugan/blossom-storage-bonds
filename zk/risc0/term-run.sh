#!/usr/bin/env bash
# Milestones 2 and 3 of the BitVM2 spike, on a fresh regtest chain (scripts/regtest-node.sh, at
# least 200 blocks): header-chain receipt, three holdings receipts seeded by the block hashes at
# 170, 180 and 190, the term receipt that binds them, the failing cases, then the Groth16 wrap.
#
#   zk/risc0/term-run.sh <upstream risc0-to-bitvm2 checkout>     WORK=/tmp/bsb-r0-term
#
# Every step writes one JSON line to $WORK/<step>.json, and its /usr/bin/time -v report next to it.
set -euo pipefail
cd "$(dirname "$0")/../.."
UP=${1:?path to a chainwayxyz/risc0-to-bitvm2 checkout at efc448e}
BIN=zk/risc0/target/release/bsb-r0
WORK=${WORK:-/tmp/bsb-r0-term}
ELF=$UP/elfs/regtest-header-chain-guest.bin
SPV_ELF=$UP/elfs/regtest-final-spv-guest.bin
DEALS=${DEALS:-3} Q=${Q:-16} FIRST=170 STEP=10 DEPTH=6
mkdir -p "$WORK"
timed() { local name=$1; shift; /usr/bin/time -v -o "$WORK/$name.time" "$@" > "$WORK/$name.json"; }
fails() { local name=$1; shift; if "$@" > "$WORK/$name.json" 2> "$WORK/$name.err"; then echo "$name: accepted, expected a rejection" >&2; exit 1; fi
  grep -m1 -o "Guest panicked: .*" "$WORK/$name.err" > "$WORK/$name.reason" || grep -m1 "Error" "$WORK/$name.err" > "$WORK/$name.reason"; }

node zk/risc0/headers.ts --out "$WORK/chain" > "$WORK/headers.json"
seed() { node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).hashes[+process.argv[2]])' "$WORK/chain/hashes.json" "$1"; }

timed chain $BIN prove-chain "$WORK/chain/headers.bin" "$WORK/chain.bin" --elf "$ELF"

holds=()
for h in $FIRST $((FIRST + STEP)) $((FIRST + 2 * STEP)); do
  node zk/risc0/witness.ts --out "$WORK/hold-$h" --deals "$DEALS" --q "$Q" --seed "$(seed $h)" > "$WORK/hold-$h.gen.json"
  timed "hold-$h" $BIN prove-hold "$WORK/hold-$h/witness.bin" "$WORK/hold-$h.bin" --succinct
  node zk/risc0/check-journal.ts "$WORK/hold-$h/statement.json" "$WORK/hold-$h.json" > "$WORK/hold-$h.check.json"
  holds+=("$WORK/hold-$h.bin")
done

T=(--chain "$WORK/chain.bin" --headers "$WORK/chain/headers.bin" --first $FIRST --step $STEP)
timed term $BIN prove-term "$WORK/term.bin" "${T[@]}" --depth $DEPTH "${holds[@]}"

# Failing cases, executor only: a seed one block off, a depth the tip cannot give, a chain the
# genuine image only wrapped (forge-demo, which also runs upstream's final-spv).
h1=$((FIRST + STEP + 1))
node zk/risc0/witness.ts --out "$WORK/hold-off" --deals "$DEALS" --q "$Q" --seed "$(seed $h1)" > /dev/null
$BIN prove-hold "$WORK/hold-off/witness.bin" "$WORK/hold-off.bin" --succinct > "$WORK/hold-off.json"
fails term-seed-off $BIN prove-term "$WORK/x.bin" --exec "${T[@]}" --depth $DEPTH "${holds[0]}" "$WORK/hold-off.bin" "${holds[2]}"
fails term-shallow $BIN prove-term "$WORK/x.bin" --exec "${T[@]}" --depth 11 "${holds[@]}"
timed forge $BIN forge-demo "$WORK/forge" --elf "$ELF" --spv-elf "$SPV_ELF" "${T[@]}" --depth $DEPTH "${holds[@]}"

timed groth16 $BIN groth16 "$WORK/term.bin" "$WORK/g16"
node zk/risc0/check-groth16.ts "$WORK/groth16.json" "$WORK/term.json" "$WORK/hold-$FIRST/statement.json" "$WORK/chain/hashes.json" > "$WORK/groth16.check.json"
cat "$WORK"/*.json | wc -l
