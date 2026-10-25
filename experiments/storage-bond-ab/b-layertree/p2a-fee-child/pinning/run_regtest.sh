#!/usr/bin/env bash
# Run real Bitcoin Core v3/TRUC + P2A CPFP against FROST pre-signed
# owner-first AND second-owner parents. 3 disposable independent histories:
# Alice-first replacement at first package, Bob-first replacement at second,
# clean Alice-first no fee-griefing baseline.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../../.." && pwd)"
cd "$ROOT"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
: "$BSB_PINNING_RECEIPT_DIR"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
mkdir -p "$BSB_PINNING_RECEIPT_DIR"
chmod 700 "$BSB_PINNING_RECEIPT_DIR"
BIN=experiments/storage-bond-ab/b-layertree/frost-proof/target/release/p2tr-frost-regtest
cargo build --locked --release \
  --manifest-path experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml \
  --bin p2tr-frost-regtest
test -x "$BIN"
node --check experiments/storage-bond-ab/b-layertree/p2a-fee-child/pinning/probe_sibling.mjs
EVIDENCE_HASH="$(node --input-type=module -e '
import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
const e=scenario("storage-fault").events.find(x=>x.kind==="proof"&&x.id==="alice"&&x.epoch===2);
const proof=challenge(e);
if(proof.verified!==false||proof.assertedVerdict!=="fault")throw Error("PDP source sample invalid");
console.log(proof.evidenceHash);
')"
test "$(printf '%s' "$EVIDENCE_HASH" | wc -c)" -eq 64
TMP="$(mktemp -d)"
PID=""
DATADIR=""
cleanup(){
  if [[ -n "$PID" ]]; then
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" stop >/dev/null 2>&1 || true
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
    PID=""
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
for CASE in alice-first-low bob-second-low alice-first-high; do
  if [[ "$CASE" == alice-first-low ]]; then FIRST=alice;PIN_STEP=first;PIN_KIND=low
  elif [[ "$CASE" == bob-second-low ]]; then FIRST=bob;PIN_STEP=second;PIN_KIND=low
  else FIRST=alice;PIN_STEP=first;PIN_KIND=high;fi
  echo "Real adversarial v3 P2A mempool sibling test: $CASE"
  DATADIR="$TMP/node-$CASE"
  mkdir -p "$DATADIR"
  cat >"$DATADIR/bitcoin.conf" <<'CONF'
regtest=1
server=1
txindex=1
fallbackfee=0.00002
[regtest]
rpcuser=bsb-p2a-regtest
rpcpassword=disposable-no-public-bitcoin
rpcport=18482
listen=0
connect=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
  chmod 600 "$DATADIR/bitcoin.conf"
  "$BITCOIND_EXEC" -datadir="$DATADIR" -printtoconsole=0 \
    >"$TMP/bitcoind-$CASE.log" 2>&1 &
  PID=$!
  READY=0
  for i in $(seq 1 150); do
    if ! kill -0 "$PID" 2>/dev/null; then
      tail -65 "$TMP/bitcoind-$CASE.log" >&2
      exit 1
    fi
    if "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" getblockcount >/dev/null 2>&1; then
      READY=1;break
    fi
    sleep 0.1
  done
  test "$READY" = 1
  FROZEN="$TMP/p2a-frozen-$CASE"
  mkdir -p "$FROZEN"
  chmod 700 "$FROZEN"
  "$BIN" --freeze-p2a \
    --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
    --evidence-hash "$EVIDENCE_HASH" --out-dir "$FROZEN" \
    >"$TMP/signer-$CASE.json" &
  SIGNER_PID=$!
  wait "$SIGNER_PID"
  if kill -0 "$SIGNER_PID" 2>/dev/null; then
    echo "FROST signer remained active after creating v3 parents" >&2
    exit 1
  fi
  node - "$TMP/signer-$CASE.json" <<'JS'
const fs=require('fs'),v=JSON.parse(fs.readFileSync(process.argv[2]));
if(v.status!=='P2A_FROST_PARENTS_FROZEN_BEFORE_SIGNER_EXIT'||
   v.gen!==3||v.alternativeFirstBranchesPerGen!==2||
   v.signedSecondOwnersPerGen!==2||
   !v.eachFrostParentHasOnlyOneInput||
   !v.allPrincipalFullyPreserved||
   !v.noFeeInputInFrostSignature||
   !v.maliciousQuorumMayStillSteal)
  throw Error('FROST source did not freeze reviewed fee-independent P2A parents');
JS
  PIN="$(cat "$FROZEN/p2a-frozen.sha256")"
  test "$(printf '%s' "$PIN" | wc -c)" -eq 64
  for WALLET in sponsor alice bob; do
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" unloadwallet "$WALLET" >/dev/null
  done
  "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" listwallets |
    node -e 'let d="";process.stdin.on("data",v=>d+=v);process.stdin.on("end",()=>{
      const w=JSON.parse(d);if(w.length!==1||w[0]!=="miner")process.exit(1);
    })'
  # Corrupt a copy while keeping the old independent signer hash.
  BAD="$TMP/p2a-tamper-$CASE"
  mkdir -p "$BAD"
  cp "$FROZEN/p2a-frozen.json" "$FROZEN/p2a-frozen.sha256" "$BAD/"
  node - "$BAD/p2a-frozen.json" <<'JS'
const fs=require('fs'),p=process.argv[2],v=JSON.parse(fs.readFileSync(p));
v.generations[2].branches.alice.second.signedHex+='00';
fs.writeFileSync(p,JSON.stringify(v));
JS
  if node experiments/storage-bond-ab/b-layertree/p2a-fee-child/pinning/probe_sibling.mjs \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
      --frozen-dir "$BAD" --sha256 "$PIN" --first "$FIRST" \
      --pin-step "$PIN_STEP" --pin-kind "$PIN_KIND" --out "$TMP/DO-NOT-PUBLISH.json" \
      >"$TMP/tamper-$CASE.log" 2>&1; then
    echo "Modified presigned zero-fee parent accepted under original SHA256" >&2
    exit 1
  fi
  test ! -e "$TMP/DO-NOT-PUBLISH.json"
  # Truly separate Node program: no FROST share or sponsor/beneficiary
  # wallet available. It creates unrelated third-party fee wallets here.
  node experiments/storage-bond-ab/b-layertree/p2a-fee-child/pinning/probe_sibling.mjs \
    --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
    --frozen-dir "$FROZEN" --sha256 "$PIN" --first "$FIRST" \
    --pin-step "$PIN_STEP" --pin-kind "$PIN_KIND" \
    --out "$BSB_PINNING_RECEIPT_DIR/$CASE.json" >"$TMP/relay-$CASE.log"
  node - "$BSB_PINNING_RECEIPT_DIR/$CASE.json" "$FIRST" "$PIN_STEP" "$PIN_KIND" <<'JS'
const fs=require('fs');
const r=JSON.parse(fs.readFileSync(process.argv[2]));
const [who,step,kind]=process.argv.slice(3);
if(r.schema!=='bsb-frost-p2a-mempool-sibling-pinning-v1'||
   r.chosenOwnerFirst!==who||r.adversarialStep!==step||r.pinningMode!==kind||
   !r.signingCompletedBeforeAdversarialMempoolInteractions||
   !r.originalSignersAndSponsorWalletUnavailable||
   !r.independentPreconfirmedFeeWalletsAfterSignerDeath||
   r.experiments.length!==2||
   r.originalPrincipalPreservedSats!==100000||
   r.ownerPayoutsSats.alice!==60000||r.ownerPayoutsSats.bob!==40000||
   !r.allOwnersFinalConfirmationDepthAtLeast6||
   r.maliciousActive2of3QuorumStillCanSteal!==true||
   r.noNativeSapioMidCovenant!==true||
   r.globalP2PPackagePropagationVerified!==false||
   r.guaranteedResistanceToAllPinning!==false)
   throw Error('real P2A pinning proof is incomplete or overclaims global relay safety');
const affected=r.experiments.find(x=>x.step===step);
if(!affected||affected.initialChildFeeSats!==(kind==='low'?1200:12000)||
   affected.attemptedReplacementFeeSats!==5000 ||
   affected.mempoolReplacementOccurred!==(kind==='low') ||
   affected.honestLowerFeeRejected!==(kind==='high') ||
   affected.parentTxidUnmodified!==true ||
   affected.parentWtxidUnmodified!==true)
   throw Error('real TRUC sibling policy evidence does not match tested fee budget');
console.log('Confirmed TRUC sibling trial: '+who+'/'+step+'/'+kind);
JS
  "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" stop >/dev/null || true
  wait "$PID" || true
  PID=""
done
node - "$BSB_PINNING_RECEIPT_DIR" <<'JS'
const fs=require('fs'),path=require('path'),dir=process.argv[2];
const cases=['alice-first-low','bob-second-low','alice-first-high'];
const reports=cases.map(x=>JSON.parse(fs.readFileSync(path.join(dir,x+'.json'))));
if(new Set(reports.map(x=>x.frozenSha256)).size!==3)
    throw Error('mempool tests accidentally reused original FROST signing history');
console.log(JSON.stringify({
    separateBitcoinCoreRegtestHistories:3,
    confirmedOwnerReleaseParentTransactions:6,
    lowFeeIncumbentsReplaced:2,
    highFeeIncumbentRejectedLowerBudgetReplacement:1,
    originalFrostSignersInvokedAfterShutdown:0,
    ownerOutputsConserved:{alice:60000,bob:40000},
    globalRelaySafetyOrByzantineQuorumResistanceProven:false,
},null,2));
JS
