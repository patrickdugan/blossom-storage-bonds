#!/usr/bin/env bash
# Phase 7C CI: fetch Bitcoin Core and lnd release binaries for Linux x86_64, and check each against its
# release's own checksum list. GPG signatures are not checked here, so this trusts the TLS origin of
# each checksum file.
#   scripts/ci-fetch.sh <dir> [core|all]
set -euo pipefail
dir=$1; what=${2:-all}
core=${CORE_VERSION:-31.1}; lnd=${LND_VERSION:-v0.21.4-beta}
mkdir -p "$dir"; cd "$dir"

tar_core="bitcoin-$core-x86_64-linux-gnu.tar.gz"
curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-$core/$tar_core"
curl -fsSL "https://bitcoincore.org/bin/bitcoin-core-$core/SHA256SUMS" -o core-SHA256SUMS
grep " $tar_core\$" core-SHA256SUMS | sha256sum -c -
tar xzf "$tar_core"
cp "bitcoin-$core/bin/bitcoind" "bitcoin-$core/bin/bitcoin-cli" .

if [ "$what" = all ]; then
  tar_lnd="lnd-linux-amd64-$lnd.tar.gz"
  curl -fsSLO "https://github.com/lightningnetwork/lnd/releases/download/$lnd/$tar_lnd"
  curl -fsSL "https://github.com/lightningnetwork/lnd/releases/download/$lnd/manifest-$lnd.txt" -o lnd-manifest.txt
  grep " $tar_lnd\$" lnd-manifest.txt | sha256sum -c -
  tar xzf "$tar_lnd"
  cp "lnd-linux-amd64-$lnd/lnd" "lnd-linux-amd64-$lnd/lncli" .
fi
ls -l
