#!/usr/bin/env bash
# Owner-first (Alice OR Bob) alternate FROST-signed recovery DAG.
# PREP process: 3 generations, 2 mutually exclusive owner-first options,
# 2 presigned second-owner claims. Then PREP process terminates.
# RELAY process: Node only; fee/owner signing wallets unloaded.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$ROOT"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
: "$BSB_OWNER_BRANCH_RECEIPT_DIR"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
mkdir -p "$BSB_OWNER_BRANCH_RECEIPT_DIR"
chmod 700 "$BSB_OWNER_BRANCH_RECEIPT_DIR"
BIN=experiments/storage-bond-ab/b-layertree/frost-proof/target/release/p2tr-frost-regtest
cargo build --locked --release \
    --manifest-path experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml \
    --bin p2tr-frost-regtest
test -x "$BIN"
node --check experiments/storage-bond-ab/b-layertree/owner-paths/relay_owner_branch.mjs
EVIDENCE_HASH="$(node --input-type=module -e '
import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
const event=scenario("storage-fault").events.find(x=>x.kind==="proof"&&x.id==="alice"&&x.epoch===2);
const evidence=challenge(event);
if(evidence.verified!==false)throw Error("shared PDP should sample a genuinely deleted chunk");
console.log(evidence.evidenceHash);
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
    DATADIR="$TMP/node-$FIRST"
    mkdir -p "$DATADIR"
    cat >"$DATADIR/bitcoin.conf" <<'CONF'
regtest=1
server=1
txindex=1
fallbackfee=0.00002
[regtest]
rpcuser=bsb-branch-test
rpcpassword=throwaway-branch-only
rpcport=18482
listen=0
connect=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
    chmod 600 "$DATADIR/bitcoin.conf"
    "$BITCOIND_EXEC" -datadir="$DATADIR" -printtoconsole=0 >"$TMP/core-$FIRST.log" 2>&1 &
    PID=$!
    READY=0
    for i in $(seq 1 150); do
        if ! kill -0 "$PID" 2>/dev/null; then
            tail -60 "$TMP/core-$FIRST.log" >&2
            exit 1
        fi
        if "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" getblockchaininfo >/dev/null 2>&1; then
            READY=1
            break
        fi
        sleep .1
    done
    test "$READY" = 1
    FROZEN="$TMP/prepared-$FIRST"
    mkdir -p "$FROZEN"
    chmod 700 "$FROZEN"
    "$BIN" --freeze-owner-branches \
        --bitcoin-cli "$BITCOIN_CLI_EXEC" \
        --datadir "$DATADIR" \
        --evidence-hash "$EVIDENCE_HASH" \
        --out-dir "$FROZEN" >"$TMP/freeze-$FIRST.json" &
    SIGNER_PID=$!
    wait "$SIGNER_PID"
    if kill -0 "$SIGNER_PID" 2>/dev/null; then
        echo "FROST signer still available during supposed offline test" >&2
        exit 1
    fi
    node - "$TMP/freeze-$FIRST.json" <<'JS'
const fs=require('fs');
const report=JSON.parse(fs.readFileSync(process.argv[2]));
if(report.status!=='ALL_OWNER_BRANCHES_SIGNED_AND_FROZEN' ||
   report.generationCount!==3 ||
   report.firstExitOptionsPerGeneration!==2 ||
   report.subsequentOtherOwnerExitsPerGeneration!==2 ||
   report.privateFrostSharesPresent!==false ||
   report.maliciousLiveQuorumTheftBitcoinValid!==true)
   throw Error('BIP341 owner-specific recovery was not fully signed before shutdown');
JS
    EXPECTED="$(cat "$FROZEN/owner-frozen.sha256")"
    test "$(printf '%s' "$EXPECTED" | wc -c)" -eq 64
    for OWNER in sponsor alice bob; do
        "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" unloadwallet "$OWNER" >/dev/null
    done
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" listwallets |
      node -e 'let s="";process.stdin.on("data",c=>s+=c);process.stdin.on("end",()=>{
        const w=JSON.parse(s);if(w.length!==1||w[0]!=="miner")process.exit(1);
      })'
    CORRUPT="$TMP/corrupt-$FIRST"
    mkdir -p "$CORRUPT"
    cp "$FROZEN/owner-frozen.json" "$FROZEN/owner-frozen.sha256" "$CORRUPT/"
    node - "$CORRUPT/owner-frozen.json" <<'JS'
const fs=require('fs'),p=process.argv[2],v=JSON.parse(fs.readFileSync(p));
v.generations[2].branches.alice.second.signedHex+='00';
fs.writeFileSync(p,JSON.stringify(v));
JS
    if node experiments/storage-bond-ab/b-layertree/owner-paths/relay_owner_branch.mjs \
        --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
        --frozen-dir "$CORRUPT" --sha256 "$EXPECTED" --first "$FIRST" \
        --output "$TMP/tamper-should-fail.json" >"$TMP/tamper-$FIRST.log" 2>&1; then
        echo "Corrupt frozen child signature was not rejected" >&2
        exit 1
    fi
    test ! -e "$TMP/tamper-should-fail.json"
    node experiments/storage-bond-ab/b-layertree/owner-paths/relay_owner_branch.mjs \
        --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
        --frozen-dir "$FROZEN" --sha256 "$EXPECTED" --first "$FIRST" \
        --output "$BSB_OWNER_BRANCH_RECEIPT_DIR/$FIRST-first.json" \
        >"$TMP/relay-$FIRST.log"
    node - "$BSB_OWNER_BRANCH_RECEIPT_DIR/$FIRST-first.json" "$FIRST" <<'JS'
const fs=require('fs'),p=JSON.parse(fs.readFileSync(process.argv[2])),first=process.argv[3];
if(p.schema!=='bsb-frost-owner-specific-signer-dead-regtest-v1'||
   p.firstPublisher!==first||p.preSignedGenerations!==3||
   p.priorGenerationFirstExitsRejected!==4||
   !p.currentGenerationConflictingFirstRejected||
   !p.individualFirstClaimPublishedWithoutOnlineFederation||
   !p.otherBeneficiaryPreSignedSecondClaimConfirmed||
   p.firstExit.confirmations<6||p.secondExit.confirmations<6||
   p.independentlyConfirmedOutputs.alice.sats!==60000||
   p.independentlyConfirmedOutputs.bob.sats!==40000||
   p.externalSponsorFeesSats!==6000||
   p.securityBoundaries.activeMaliciousQuorumCanStillSteal!==true||
   p.securityBoundaries.holderExclusiveCarrierSignature!==false||
   p.securityBoundaries.anyoneWithSignedBytesCanRelay!==true||
   p.securityBoundaries.bitcoinScriptEnforcesMidPolicy!==false)
  throw Error('owner first-exit proof is incomplete or makes unsupported custody claims');
console.log('Owner-first and other-holder successive presigned exit confirmed: '+first);
JS
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" stop >/dev/null || true
    wait "$PID" || true
    PID=""
done
node - "$BSB_OWNER_BRANCH_RECEIPT_DIR" <<'JS'
const fs=require('fs'),path=require('path'),dir=process.argv[2];
const a=JSON.parse(fs.readFileSync(path.join(dir,'alice-first.json')));
const b=JSON.parse(fs.readFileSync(path.join(dir,'bob-first.json')));
if(a.firstPublisher===b.firstPublisher||a.frozenManifestSha256===b.frozenManifestSha256)
  throw Error('owner-first trials did not use independent Bitcoin histories');
console.log(JSON.stringify({
  independentBitcoinHistories:2,
  orderings:['alice-first-then-bob','bob-first-then-alice'],
  staleRootBranchRejections:8,
  totalConfirmedPayouts:4,
  noSigningOrSponsorWalletsUsedDuringRelay:true,
  active2of3FraudStillPossible:true,
  requiresPredistributedSignedBranchDAG:true,
},null,2));
JS
