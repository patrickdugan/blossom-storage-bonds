#!/usr/bin/env bash
# ADR-016: vendor the exact bitcoinconsensus 0.106.0+26.0 crate from the cargo registry and apply the
# local BIP347 patch (three hunks in src/script/interpreter.cpp). No other source changes.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cargo fetch --manifest-path "$here/../consensus-check/Cargo.toml"
src=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/bitcoinconsensus-0.106.0+26.0 | head -1)
rm -rf "$here/vendor"
mkdir -p "$here/vendor"
cp -r "$src" "$here/vendor/"
cd "$here/vendor/bitcoinconsensus-0.106.0+26.0"
patch -p1 --forward < "$here/bip347.patch"
test "$(grep -c BIP347 depend/bitcoin/src/script/interpreter.cpp)" -eq 3
echo "patched $(pwd)"
