#!/usr/bin/env bash
# Prove a captured local regtest storage term on a machine with existing pinned tools.
# No node, wallet, faucet, signer, relay, installer or downloader is started here.
set -euo pipefail

if (( $# != 4 )); then
  echo "usage: $0 <snapshot> <new-output-dir> <bsb-r0> <risc0-to-bitvm2-efc448e>" >&2
  exit 2
fi
SNAPSHOT=$(realpath "$1")
OUTPUT=$(realpath -m "$2")
BIN=$(realpath "$3")
UPSTREAM=$(realpath "$4")
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMAGE=ozancw/risc0-to-bitvm2-groth16-prover@sha256:840b833190a86c87eb71473cd72bcaa3e3b90cefa9bf4ae785ab2de61bc9d262

command -v python3 >/dev/null
command -v docker >/dev/null
test -x "$BIN"
test -x /usr/bin/time
test ! -e "$OUTPUT" || { echo "output must be a new directory" >&2; exit 2; }
test "$(git -C "$UPSTREAM" rev-parse HEAD)" = efc448ef016cef2a908d97e69b9d3d1f2b2cfdb5
test -f "$UPSTREAM/elfs/regtest-header-chain-guest.bin"
# Fail before any proof if the pinned image is not installed; never pull implicitly.
docker image inspect "$IMAGE" >/dev/null
python3 "$HERE/fresh_snapshot.py" check "$SNAPSHOT"

unset BONSAI_API_KEY BONSAI_API_URL
export RISC0_DEV_MODE=0 RISC0_PROVER=local
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-4}
IDS=$("$BIN" ids)
python3 - "$IDS" "$HERE" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2])
from fresh_snapshot import IDS, require
actual = json.loads(sys.argv[1])
require({k: actual[k] for k in IDS} == IDS, "guest image IDs differ from the snapshot's setup")
PY

mkdir "$OUTPUT"
printf '%s\n' "$IDS" > "$OUTPUT/ids.json"
timed() { local name=$1; shift; /usr/bin/time -v -o "$OUTPUT/$name.time" "$@" > "$OUTPUT/$name.json"; }
mapfile -t CONFIG < <(python3 - "$SNAPSHOT/snapshot.json" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))['term']
for k in ('first', 'step', 'epochs', 'depth'): print(t[k])
PY
)
FIRST=${CONFIG[0]} STEP=${CONFIG[1]} EPOCHS=${CONFIG[2]} DEPTH=${CONFIG[3]}

timed chain "$BIN" prove-chain "$SNAPSHOT/chain/headers.bin" "$OUTPUT/chain.bin" --elf "$UPSTREAM/elfs/regtest-header-chain-guest.bin"
HOLDS=()
for ((i=0; i<EPOCHS; i++)); do
  height=$((FIRST + i * STEP))
  timed "hold-$height" "$BIN" prove-hold "$SNAPSHOT/hold-$height/witness.bin" "$OUTPUT/hold-$height.bin" --succinct
  HOLDS+=("$OUTPUT/hold-$height.bin")
done
timed term "$BIN" prove-term "$OUTPUT/term.bin" --chain "$OUTPUT/chain.bin" --headers "$SNAPSHOT/chain/headers.bin" --first "$FIRST" --step "$STEP" --depth "$DEPTH" "${HOLDS[@]}"
timed groth16 "$BIN" groth16 "$OUTPUT/term.bin" "$OUTPUT/g16"
cp "$SNAPSHOT/vk.json" "$OUTPUT/g16/vk.json"
python3 "$HERE/fresh_snapshot.py" finish "$SNAPSHOT" "$OUTPUT"
echo "Proving finished. Independently verify g16/proof.json with g16/vk.json and g16/public.json before graph use."
