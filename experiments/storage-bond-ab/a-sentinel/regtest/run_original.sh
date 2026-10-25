#!/usr/bin/env bash
# Original funded A sentinel reference against real Bitcoin Core regtest.
# A's historical 1 BTC fixture differs from B's 100k-sat pooled experiment.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
cd "$ROOT"
node model/fixture.ts 3
cargo build --locked --release --manifest-path regtest/Cargo.toml
TMP="$(mktemp -d)"
DATADIR="$TMP/node"
mkdir -p "$DATADIR"
PID=""
cleanup() {
    if [[ -n "$PID" ]]; then
        "$BITCOIN_CLI_EXEC" -datadir="$DATADIR" -regtest stop >/dev/null 2>&1 || true
        kill "$PID" >/dev/null 2>&1 || true
        wait "$PID" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT
bash scripts/regtest-node.sh "$DATADIR" "$BITCOIND_EXEC" >"$TMP/bitcoind.log" 2>&1 &
PID=$!
ready=0
for i in $(seq 1 120); do
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "regtest bitcoind exited unexpectedly" >&2
        tail -100 "$TMP/bitcoind.log" >&2
        exit 1
    fi
    if "$BITCOIN_CLI_EXEC" -datadir="$DATADIR" -regtest getblockchaininfo >/dev/null 2>&1; then
        ready=1; break
    fi
    sleep 0.1
done
test "$ready" = 1 || { echo "regtest bitcoind did not answer" >&2; exit 1; }
test "$("$BITCOIN_CLI_EXEC" -datadir="$DATADIR" -regtest getblockchaininfo | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).chain')" = regtest
# This original Rust code exercises signed Taproot transactions, original
# BIP341 Schnorr/MuSig2 signing, v3/P2A packages and contextual CSV/CLTV.
cargo run --locked --release --manifest-path regtest/Cargo.toml
node - <<'JS'
const fs=require('fs');
const p=JSON.parse(fs.readFileSync('results/regtest.json','utf8'));
if(p.bond_sats!==100000000 || p.failed!==0 || p.checks.length<21)
    throw Error('original funded sentinel regtest failed');
for(const c of p.checks) if(c.pass!==true)throw Error('Core rejected expected scenario: '+c.check);
console.log(JSON.stringify({
    kind:'real-funded-sentinel-taproot-reference-NOT-MATCHED-AB',
    actual_bitcoin_core_script_checked:true,
    original_single_bond_sats:p.bond_sats,
    checks:p.checks.length,failed:p.failed,measured_transactions:p.sizes,
},null,2));
JS
OUT="$(printenv BSB_A_AB_RECEIPT_DIR || true)"
if [[ -n "$OUT" ]]; then
    mkdir -p "$OUT"
    chmod 700 "$OUT"
    (set -C; cat results/regtest.json >"$OUT/original-sentinel-regtest.json")
    chmod 600 "$OUT/original-sentinel-regtest.json"
fi
