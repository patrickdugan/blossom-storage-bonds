#!/usr/bin/env bash
# Actual regtest BIP341 zero-fee parent / P2A fee-child 1P1C packages.
# Either Alice or Bob first in independent Bitcoin Core histories.
# No FROST, Sapio oracle or prior sponsor wallet after pre-signature freeze.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$ROOT"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
: "$BSB_P2A_RECEIPT_DIR"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
mkdir -p "$BSB_P2A_RECEIPT_DIR"
chmod 700 "$BSB_P2A_RECEIPT_DIR"
BIN=experiments/storage-bond-ab/b-layertree/frost-proof/target/release/p2tr-frost-regtest
cargo build --locked --release \
  --manifest-path experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml \
  --bin p2tr-frost-regtest
test -x "$BIN"
node --check experiments/storage-bond-ab/b-layertree/p2a-fee-child/core.mjs
node --check experiments/storage-bond-ab/b-layertree/p2a-fee-child/relay_p2a.mjs
EVIDENCE_HASH="$(node --input-type=module -e '
  import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
  const e=scenario("storage-fault").events.find(e=>e.kind==="proof"&&e.id==="alice"&&e.epoch===2);
  const p=challenge(e);
  if(p.verified!==false)throw Error("invalid common Blossom PDP failure fixture");
  console.log(p.evidenceHash);
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
for FIRST in alice bob; do
    echo "P2A dynamic fee FROST signer-dead recovery for $FIRST-first"
    DATADIR="$TMP/bitcoin-$FIRST"
    mkdir -p "$DATADIR"
    cat >"$DATADIR/bitcoin.conf" <<'CONF'
regtest=1
server=1
txindex=1
fallbackfee=0.00002
[regtest]
rpcuser=bsb-p2a-research
rpcpassword=disposable-p2a-regtest
rpcport=18482
listen=0
connect=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
    chmod 600 "$DATADIR/bitcoin.conf"
    "$BITCOIND_EXEC" -datadir="$DATADIR" -printtoconsole=0 \
      >"$TMP/core-$FIRST.log" 2>&1 &
    PID=$!
    STARTED=0
    for attempt in $(seq 1 150); do
        if ! kill -0 "$PID" 2>/dev/null; then
            tail -70 "$TMP/core-$FIRST.log" >&2; exit 1
        fi
        if "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" getblockchaininfo >/dev/null 2>&1; then
            STARTED=1; break
        fi
        sleep .1
    done
    test "$STARTED" = 1
    FROZEN="$TMP/frozen-$FIRST"
    mkdir -p "$FROZEN"
    chmod 700 "$FROZEN"
    "$BIN" --freeze-p2a \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
      --evidence-hash "$EVIDENCE_HASH" --out-dir "$FROZEN" \
      >"$TMP/prepared-$FIRST.json" &
    SIGNER_PID=$!
    wait "$SIGNER_PID"
    if kill -0 "$SIGNER_PID" 2>/dev/null; then
        echo "FROST signer still running after freezing transactions" >&2;exit 1
    fi
    node - "$TMP/prepared-$FIRST.json" <<'JS'
const fs=require('fs'),p=JSON.parse(fs.readFileSync(process.argv[2]));
if(p.status!=='BIP341_V3_FROST_P2A_PARENT_FREEZE_COMPLETE'||
   p.generationCount!==3||p.twoRefreshesConfirmedWithSubmitpackage!==true||
   p.privateFrostSharesExported!==false)
    throw Error('signed BIP341/P2A pre-shutdown evidence incomplete');
JS
    SHA="$(cat "$FROZEN/p2a-frozen.sha256")"
    test "$(printf '%s' "$SHA" | wc -c)" -eq 64
    for WALLET in refreshfee alice bob; do
        "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" unloadwallet "$WALLET" >/dev/null
    done
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" listwallets |
      node -e 'let data="";process.stdin.on("data",c=>data+=c);process.stdin.on("end",()=>{
         const names=JSON.parse(data).sort();
         if(names.join(",")!=="legacyfee,miner,relayfee")process.exit(1);
      })'
    # Frozen packages must be immutable even if attacker changes an
    # unrelated branch's signed bytes after the signer has disappeared.
    BAD="$TMP/tampered-$FIRST"
    mkdir -p "$BAD"
    cp "$FROZEN/p2a-frozen.json" "$FROZEN/p2a-frozen.sha256" "$BAD/"
    node - "$BAD/p2a-frozen.json" <<'JS'
const fs=require('fs'),p=process.argv[2],data=JSON.parse(fs.readFileSync(p));
data.snapshots[2].branches.alice.second.signedHex+='00';
fs.writeFileSync(p,JSON.stringify(data));
JS
    if node experiments/storage-bond-ab/b-layertree/p2a-fee-child/relay_p2a.mjs \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
      --frozen-dir "$BAD" --sha256 "$SHA" --first "$FIRST" \
      --out "$TMP/SHOULD-NEVER-EXIST.json" >"$TMP/bad.log" 2>&1; then
        echo "Modified frozen P2A exit package passed prior hash" >&2;exit 1
    fi
    test ! -e "$TMP/SHOULD-NEVER-EXIST.json"
    node experiments/storage-bond-ab/b-layertree/p2a-fee-child/relay_p2a.mjs \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
      --frozen-dir "$FROZEN" --sha256 "$SHA" --first "$FIRST" \
      --out "$BSB_P2A_RECEIPT_DIR/$FIRST-first.json" \
      >"$TMP/relay-$FIRST.json"
    node - "$BSB_P2A_RECEIPT_DIR/$FIRST-first.json" "$FIRST" <<'JS'
const fs=require('fs'),r=JSON.parse(fs.readFileSync(process.argv[2])),first=process.argv[3];
if(r.schema!=='bsb-frost-p2a-dynamic-fee-offline-regtest-v1' ||
   r.firstOwner!==first||r.realBip341FrostSignature!==true||
   r.inputBoundIntoFrozenFrostParents!==false||
   r.sameFrostParentBeforeAndAfterFeeSabotage!==true||
   r.priorCandidateSponsorSpend?.legacyFeeCandidateSpent!==true||
   r.bitcoinMinedTwoOneParentOneChildPackages!==true||
   r.firstParent.confirmations<6||r.secondParent.confirmations<6||
   r.beneficiaryPaymentsSats.alice!==60000||
   r.beneficiaryPaymentsSats.bob!==40000||
   r.feeIndependentThirdPartyPaysSats!==6000||
   r.activeMaliciousFrostQuorumCanStillSteal!==true ||
   r.bitcoinConsensusEnforcesSapioMid!==false ||
   r.indefinitelySafeRefreshesProven!==false)
    throw Error('actual FROST P2A package evidence or security limits incomplete');
console.log('Confirmed live fee-input substitution after FROST signer shutdown for '+first);
JS
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" stop >/dev/null || true
    wait "$PID" || true
    PID=""
done
node - "$BSB_P2A_RECEIPT_DIR" <<'JS'
const fs=require('fs'),path=require('path'),d=process.argv[2];
const a=JSON.parse(fs.readFileSync(path.join(d,'alice-first.json')));
const b=JSON.parse(fs.readFileSync(path.join(d,'bob-first.json')));
if(a.preShutdownFrozenSha256===b.preShutdownFrozenSha256||
   a.firstOwner===b.firstOwner)
  throw Error('fee relay A/B trials did not have separate Bitcoin Core chains');
console.log(JSON.stringify({independentRealCoreChains:2,
  confirmedZeroFeeV3Parents:4,confirmedDynamicallyFundedChildren:4,
  legacySponsorOutpointsDestroyedAfterSignerShutdown:2,
  feeInputsCommittedByFrostParent:false,
  sponsorChangeWithoutResigningP2TRParent:true,
  independentOwnerFirstOrders:['alice','bob'],
  maliciousActiveQuorumStillUnrestricted:true},null,2));
JS
