#!/usr/bin/env bash
# Phase 7C CI: fetch Bitcoin Core and lnd release binaries for Linux x86_64.
#   scripts/ci-fetch.sh <dir> [core|all]
#
# Each tarball must match a digest pinned here, and also its release's own checksum list. The pins
# (recorded 2026-10-23 from bitcoincore.org's SHA256SUMS and lnd's release manifest) stop a later
# compromise of either origin from swapping both the binary and its checksum (independent review). They
# are trust-on-first-use: the release signatures (Core's SHA256SUMS.asc, lnd's manifest .sig) are not
# checked here. A pilot host should check them once by hand before relying on these binaries.
set -euo pipefail
dir=$1; what=${2:-all}
core=${CORE_VERSION:-31.1}; lnd=${LND_VERSION:-v0.21.4-beta}
declare -A PIN=(
  ["bitcoin-31.1-x86_64-linux-gnu.tar.gz"]="b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"
  ["lnd-linux-amd64-v0.21.4-beta.tar.gz"]="beffe4949a5e46410d90c0e6d020a1b685468440b0004fc4d59740a6291178fb"
)
mkdir -p "$dir"; cd "$dir"

check() { # <file> <checksum list>
  local f=$1 want=${PIN[$1]:-}
  [ -n "$want" ] || { echo "no pinned digest for $f; add one before using another version" >&2; exit 1; }
  echo "$want  $f" | sha256sum -c -
  grep -qx "$want  $f" "$2" || { echo "$f: the release's own checksum list disagrees with the pin" >&2; exit 1; }
}

tar_core="bitcoin-$core-x86_64-linux-gnu.tar.gz"
curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-$core/$tar_core"
curl -fsSL "https://bitcoincore.org/bin/bitcoin-core-$core/SHA256SUMS" -o core-SHA256SUMS
check "$tar_core" core-SHA256SUMS
tar xzf "$tar_core"
cp "bitcoin-$core/bin/bitcoind" "bitcoin-$core/bin/bitcoin-cli" .

if [ "$what" = all ]; then
  tar_lnd="lnd-linux-amd64-$lnd.tar.gz"
  curl -fsSLO "https://github.com/lightningnetwork/lnd/releases/download/$lnd/$tar_lnd"
  curl -fsSL "https://github.com/lightningnetwork/lnd/releases/download/$lnd/manifest-$lnd.txt" -o lnd-manifest.txt
  check "$tar_lnd" lnd-manifest.txt
  tar xzf "$tar_lnd"
  cp "lnd-linux-amd64-$lnd/lnd" "lnd-linux-amd64-$lnd/lncli" .
fi
ls -l
