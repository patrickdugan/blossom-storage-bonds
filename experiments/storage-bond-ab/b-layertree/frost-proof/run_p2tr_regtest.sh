#!/usr/bin/env bash
# Genuine BIP341 P2TR keypath FROST authorization, with isolated regtest node.
# Not LayerTree MID, networked FROST custody, nor Filecoin consensus.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$ROOT"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
OUT="$(printenv BSB_B_FROST_RECEIPT_DIR || true)"
test -n "$OUT" || { echo "Provide BSB_B_FROST_RECEIPT_DIR" >&2; exit 1; }
mkdir -p "$OUT"
chmod 700 "$OUT"
test ! -e "$OUT/real-frost-p2tr-regtest.json" || {
  echo "Refusing overwrite of FROST witness receipt" >&2; exit 1;
}
EVIDENCE="$(node --input-type=module -e '
  import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
  const event=scenario("storage-fault").events.find(x=>x.kind==="proof"&&x.id==="alice"&&x.epoch===2);
  const proof=challenge(event);
  if(proof.verified!==false||proof.assertedVerdict!=="fault")
    throw Error("independently sampled Alice storage failure missing");
  console.log(proof.evidenceHash);
')"
test "$(printf '%s' "$EVIDENCE" | wc -c)" -eq 64
MANIFEST=experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml
cargo build --locked --release --manifest-path "$MANIFEST" --bin p2tr-frost-regtest
TMP="$(mktemp -d)"
DATADIR="$TMP/bitcoin-node"
mkdir -p "$DATADIR"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" stop >/dev/null 2>&1 || true
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
# The private node has no historical mempool fee estimator. A local fallback
# enables only the disposable miner's coinbase-funded setup payments.
cat > "$DATADIR/bitcoin.conf" <<'CONF'
regtest=1
server=1
txindex=1
fallbackfee=0.00002
[regtest]
rpcuser=bsb
rpcpassword=bsb-regtest-only
rpcport=18543
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
port=18544
connect=0
listen=0
CONF
chmod 600 "$DATADIR/bitcoin.conf"
"$BITCOIND_EXEC" -datadir="$DATADIR" -printtoconsole=0 >"$TMP/bitcoin.log" 2>&1 &
PID=$!
ready=0
for i in $(seq 1 150); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "Bitcoin Core exited during regtest initialization" >&2
    tail -45 "$TMP/bitcoin.log" >&2
    exit 1
  fi
  if "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" getblockchaininfo >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
test "$ready" = 1 || { echo "regtest RPC unavailable" >&2; exit 1; }
cargo run --release --locked --manifest-path "$MANIFEST" --bin p2tr-frost-regtest -- \
  --bitcoin-cli "$BITCOIN_CLI_EXEC" \
  --datadir "$DATADIR" \
  --evidence-hash "$EVIDENCE" \
  --out "$OUT/real-frost-p2tr-regtest.json"
node - "$OUT/real-frost-p2tr-regtest.json" "$EVIDENCE" <<'JS'
const fs=require('node:fs');
const p=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));
if(p.schema!=="bsb-ab-p2tr-real-frost-regtest-v1"||
   p.sharedPdpEvidenceHash!==process.argv[3]||
   p.capitalSats!==100000||p.aliceSats!==60000||p.bobSats!==40000||
   p.sponsorTotalFeesSats!==6000||
   p.signatures!=="real-BIP341-sighash-P2TR-TapTweak"||
   p.missingSecondShareRejected!==true||
   p.maliciousTwoShareRedirect.broadcast!==false||
   p.maliciousTwoShareRedirect.validBitcoinMempoolSpend!==true||
   p.honestTwoSharePayout.confirmed!==true||
   p.honestTwoSharePayout.sixConfirmations!==true||
   p.limits.bitcoinCoreBip341AndP2TRKeyPathAccepted!==true||
   p.limits.realSapioMidCovenant!==false||
   p.limits.realFrostAcrossNetworkPeers!==false||
   p.limits.blossomPdpVerifiedByBitcoin!==false)
  throw Error('FROST Bitcoin witness proof or trust classification invalid');
console.log('B P2TR FROST regtest valid with unauthorized 2-share redirect control.');
JS
