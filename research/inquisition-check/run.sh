#!/usr/bin/env bash
# ADR-018: build Bitcoin Inquisition's consensus library at a pinned tag, link inq_check.cpp against
# it, and cross-check the ADR-015/016/017 vectors. Needs cmake, g++ and the Boost headers.
# Usage: run.sh adr015.json adr016.json [workdir]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
adr015=$(realpath "$1"); adr016=$(realpath "$2"); work=${3:-$here/work}
tag=v29.4-inq
commit=3db09a1b5821b049af295091055c39e0f80846c7
mkdir -p "$work"
if [ ! -d "$work/inquisition" ]; then
  git clone -q --depth 1 --branch "$tag" https://github.com/bitcoin-inquisition/bitcoin "$work/inquisition"
fi
cd "$work/inquisition"
test "$(git rev-parse HEAD)" = "$commit"
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF \
  -DBUILD_WALLET_TOOL=OFF -DENABLE_WALLET=OFF -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DWITH_ZMQ=OFF -DENABLE_IPC=OFF \
  -DBUILD_KERNEL_LIB=OFF > "$work/cmake.log"
cmake --build build -j"$(nproc)" --target bitcoin_consensus bitcoin_util bitcoin_crypto secp256k1 > "$work/make.log"
lib() { find build -name "lib$1.a" | head -1; }
g++ -std=c++20 -O2 -I src -I build/src -I src/secp256k1/include -I src/univalue/include "$here/inq_check.cpp" \
  "$(lib bitcoin_consensus)" "$(lib bitcoin_util)" "$(lib bitcoin_crypto)" $(find build -name "libbitcoin_crypto_*.a") "$(lib secp256k1)" \
  -o "$work/inq_check"
node "$here/to-lines.mjs" "$adr015" core_valid > "$work/adr015.core.txt"
node "$here/to-lines.mjs" "$adr016" core_valid > "$work/adr016.core.txt"
node "$here/to-lines.mjs" "$adr016" bip347_valid > "$work/adr016.bip347.txt"
echo "== ADR-015 vectors, Inquisition without OP_CAT flag (must equal stock Core 26)"
"$work/inq_check" nocat < "$work/adr015.core.txt" | tail -1
echo "== ADR-016/017 vectors, Inquisition without OP_CAT flag (must equal stock Core 26)"
"$work/inq_check" nocat < "$work/adr016.core.txt" | tail -1
echo "== ADR-016/017 vectors, Inquisition with SCRIPT_VERIFY_OP_CAT (must equal the local BIP347 patch)"
"$work/inq_check" cat < "$work/adr016.bip347.txt"
