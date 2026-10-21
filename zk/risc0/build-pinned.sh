#!/usr/bin/env bash
# Reproduce the committed guests using preinstalled tools and cached locked dependencies.
# risc0-build 2.1.0 clears CARGO_HOME. Guest panic paths affect the image ID, so
# give only guest-target Cargo calls an explicit cache and the historical path mapping.
set -euo pipefail
if (( $# != 3 )); then
  echo "usage: $0 <installed-host-cargo> <populated-guest-cargo-home> <new-wrapper-directory>" >&2
  exit 2
fi
HOST_CARGO=$(realpath -s "$1")
GUEST_CACHE=$(realpath "$2")
WRAPPER=$(realpath -m "$3")
test -x "$HOST_CARGO"
test -d "$GUEST_CACHE/registry/src"
test ! -e "$WRAPPER" || { echo "wrapper directory must be new" >&2; exit 2; }
case "$GUEST_CACHE" in *$'\n'*|*$'\x1f'*|*=*) echo "unsupported guest cache path" >&2; exit 2;; esac
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir "$WRAPPER"
cat > "$WRAPPER/cargo" <<'CARGO'
#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
for arg in "$@"; do
  if [[ "$arg" == riscv32im-risc0-zkvm-elf ]]; then
    export CARGO_HOME="$BSB_GUEST_CARGO_HOME"
    export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS:?missing risc0-build flags}"$'\x1f'"--remap-path-prefix=$BSB_GUEST_CARGO_HOME=/root/.cargo"
    break
  fi
done
exec "$BSB_HOST_CARGO" "$@"
CARGO
chmod 700 "$WRAPPER/cargo"
export BSB_HOST_CARGO="$HOST_CARGO" BSB_GUEST_CARGO_HOME="$GUEST_CACHE"
export PATH="$WRAPPER:$PATH" CARGO_NET_OFFLINE=true RISC0_BUILD_LOCKED=1
cd "$HERE"
cargo build --release --locked --offline -p bsb-r0
TARGET_DIR=$(cargo metadata --locked --offline --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
IDS=$("$TARGET_DIR/release/bsb-r0" ids)
python3 - "$IDS" <<'PY'
import json,sys
from fresh_snapshot import IDS,require
from check_fork_research import FORK_ID,COMPACT_ID
actual=json.loads(sys.argv[1])
require({k:actual[k] for k in IDS}==IDS,"compiled guest IDs differ from the committed setup")
require(actual["fork"]==FORK_ID and actual["fork_compact"]==COMPACT_ID,"compiled fork guest IDs differ from pinned versions")
print(json.dumps({"guest_ids_match":True,"ids":actual}))
PY
