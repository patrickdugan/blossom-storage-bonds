#!/usr/bin/env bash
# Two connected Bitcoin Core 30.3 processes with distinct mempool fee floors.
# Origin has the pre-signed FROST carrier; receiver has NO signing wallets.
# Opportunistic P2P delivery is checked BEFORE any receiver submitpackage RPC.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../../.." && pwd)"
cd "$ROOT"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
: "$BSB_P2P_RECEIPT_DIR"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
mkdir -p "$BSB_P2P_RECEIPT_DIR"
chmod 700 "$BSB_P2P_RECEIPT_DIR"
BIN=experiments/storage-bond-ab/b-layertree/frost-proof/target/release/p2tr-frost-regtest
cargo build --locked --release \
  --manifest-path experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml \
  --bin p2tr-frost-regtest
test -x "$BIN"
node --check experiments/storage-bond-ab/b-layertree/p2a-fee-child/p2p/probe_two_nodes.mjs
EVIDENCE_HASH="$(node --input-type=module -e '
import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
const e=scenario("storage-fault").events.find(x=>x.kind==="proof"&&x.id==="alice"&&x.epoch===2);
const proof=challenge(e);
if(proof.verified!==false||proof.assertedVerdict!=="fault")throw Error("shared Merkle sample changed");
console.log(proof.evidenceHash);
')"
test "$(printf '%s' "$EVIDENCE_HASH" | wc -c)" -eq 64
TMP="$(mktemp -d)"
ORIGIN_PID=""
RECEIVER_PID=""
ORIGIN_DIR=""
RECEIVER_DIR=""
cleanup(){
  if [[ -n "$ORIGIN_PID" ]];then
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$ORIGIN_DIR" stop >/dev/null 2>&1 || true
    kill "$ORIGIN_PID" >/dev/null 2>&1 || true
    wait "$ORIGIN_PID" >/dev/null 2>&1 || true
    ORIGIN_PID=""
  fi
  if [[ -n "$RECEIVER_PID" ]];then
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$RECEIVER_DIR" stop >/dev/null 2>&1 || true
    kill "$RECEIVER_PID" >/dev/null 2>&1 || true
    wait "$RECEIVER_PID" >/dev/null 2>&1 || true
    RECEIVER_PID=""
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
for CASE in peer-low peer-high;do
  if [[ "$CASE" == peer-low ]];then FIRST=alice;FLOOR=low;RATE=0.00002000
  else FIRST=bob;FLOOR=high;RATE=0.00025000;fi
  echo "Connected two-node FROST P2A package relay: $CASE"
  ORIGIN_DIR="$TMP/$CASE-origin"
  RECEIVER_DIR="$TMP/$CASE-receiver"
  mkdir -p "$ORIGIN_DIR" "$RECEIVER_DIR"
  cat >"$ORIGIN_DIR/bitcoin.conf" <<'CONF'
regtest=1
server=1
txindex=1
fallbackfee=0.00002
discover=0
dnsseed=0
[regtest]
rpcuser=p2p-origin
rpcpassword=disposable-local-only
rpcport=18482
port=18492
listen=1
bind=127.0.0.1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
  cat >"$RECEIVER_DIR/bitcoin.conf" <<CONF
regtest=1
server=1
txindex=1
discover=0
dnsseed=0
minrelaytxfee=$RATE
incrementalrelayfee=0.00001000
[regtest]
rpcuser=p2p-receiver
rpcpassword=disposable-local-only
rpcport=18483
port=18493
listen=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
  chmod 600 "$ORIGIN_DIR/bitcoin.conf" "$RECEIVER_DIR/bitcoin.conf"
  "$BITCOIND_EXEC" -datadir="$ORIGIN_DIR" -printtoconsole=0 \
    >"$TMP/$CASE-origin.log" 2>&1 &
  ORIGIN_PID=$!
  "$BITCOIND_EXEC" -datadir="$RECEIVER_DIR" -printtoconsole=0 \
    >"$TMP/$CASE-receiver.log" 2>&1 &
  RECEIVER_PID=$!
  for SIDE in origin receiver;do
    if [[ "$SIDE" == origin ]];then NOW_DIR="$ORIGIN_DIR";NOW_PID="$ORIGIN_PID"
    else NOW_DIR="$RECEIVER_DIR";NOW_PID="$RECEIVER_PID";fi
    READY=0
    for i in $(seq 1 150);do
      if ! kill -0 "$NOW_PID" 2>/dev/null;then
        tail -100 "$TMP/$CASE-$SIDE.log" >&2
        echo "Bitcoin Core $SIDE exited before RPC ready" >&2
        exit 1
      fi
      if "$BITCOIN_CLI_EXEC" -regtest -datadir="$NOW_DIR" getblockcount >/dev/null 2>&1;then
        READY=1;break
      fi
      sleep 0.1
    done
    test "$READY" = 1
  done
  "$BITCOIN_CLI_EXEC" -regtest -datadir="$RECEIVER_DIR" addnode 127.0.0.1:18492 add
  CONNECTED=0
  for i in $(seq 1 120);do
    C="$("$BITCOIN_CLI_EXEC" -regtest -datadir="$RECEIVER_DIR" getconnectioncount)"
    if [[ "$C" -ge 1 ]];then CONNECTED=1;break;fi
    sleep 0.1
  done
  test "$CONNECTED" = 1
  FROZEN="$TMP/$CASE-frozen"
  mkdir -p "$FROZEN"
  chmod 700 "$FROZEN"
  "$BIN" --freeze-p2a \
    --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$ORIGIN_DIR" \
    --evidence-hash "$EVIDENCE_HASH" --out-dir "$FROZEN" \
    >"$TMP/$CASE-signer.json" &
  SIGNER_PID=$!
  wait "$SIGNER_PID"
  if kill -0 "$SIGNER_PID" 2>/dev/null;then
    echo "FROST signer still active during P2P relay experiment" >&2;exit 1
  fi
  node - "$TMP/$CASE-signer.json" <<'JS'
const fs=require('fs'),v=JSON.parse(fs.readFileSync(process.argv[2]));
if(v.status!=='P2A_FROST_PARENTS_FROZEN_BEFORE_SIGNER_EXIT'||
  v.gen!==3||v.alternativeFirstBranchesPerGen!==2||
  !v.eachFrostParentHasOnlyOneInput||
  !v.allPrincipalFullyPreserved||
  !v.noFeeInputInFrostSignature||
  !v.maliciousQuorumMayStillSteal)
  throw Error('actual FROST parent preparatory Bitcoin fixture missing');
JS
  PIN="$(cat "$FROZEN/p2a-frozen.sha256")"
  test "$(printf '%s' "$PIN" | wc -c)" -eq 64
  for WALLET in sponsor alice bob;do
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$ORIGIN_DIR" unloadwallet "$WALLET" >/dev/null
  done
  "$BITCOIN_CLI_EXEC" -regtest -datadir="$ORIGIN_DIR" listwallets |
    node -e 'let s="";process.stdin.on("data",x=>s+=x);process.stdin.on("end",()=>{
      const w=JSON.parse(s);if(w.length!==1||w[0]!=="miner")process.exit(1);
    })'
  "$BITCOIN_CLI_EXEC" -regtest -datadir="$RECEIVER_DIR" listwallets |
    node -e 'let s="";process.stdin.on("data",x=>s+=x);process.stdin.on("end",()=>{
      const w=JSON.parse(s);if(w.length!==0)process.exit(1);
    })'
  # Source FROST witness is frozen and its signer has exited. The separate
  # Ed25519 delivery/ACK experiment retains each holder's identical full
  # manifest, with an independently sealed checkpoint for each toy holder.
  # This is a post-refresh transport rehearsal, not a Bitcoin refresh gate.
  node experiments/storage-bond-ab/b-layertree/p2a-fee-child/delivery/check_signed_manifest.mjs \
    --frozen-dir "$FROZEN" --sha256 "$PIN" \
    --out "$BSB_P2P_RECEIPT_DIR/$CASE-delivery.json" \
    >"$TMP/$CASE-delivery-check.json"
  node - "$BSB_P2P_RECEIPT_DIR/$CASE-delivery.json" "$PIN" <<'JS'
const fs=require('fs'),x=JSON.parse(fs.readFileSync(process.argv[2]));
if(x.schema!=='bsb-p2a-frost-manifest-holder-delivery-test-v1' ||
  x.network!=='disposable-regtest-only'||x.currentGeneration!==2||
  x.independentlyPinnedManifestSha256!==process.argv[3]||
  x.independentlySignedHolderAcks!==2||x.replaysRejected!==2||
  !x.exactRealFrozenManifestBytesDelivered||
  !x.twoDurableSeparateHolderCheckpoints||
  !x.testProcessRestartReadbackPassed||
  x.laterGenerationsPreacknowledgedBeforeOnchainRefresh!==false||
  x.coLocatedDisposableAckKeysInTest!==true||
  x.maliciousFrostQuorumCanStillSteal!==true)
  throw Error('signed recovery delivery checkpoint disagrees with frozen signer');
JS
  node experiments/storage-bond-ab/b-layertree/p2a-fee-child/p2p/probe_two_nodes.mjs \
    --bitcoin-cli "$BITCOIN_CLI_EXEC" \
    --origin-dir "$ORIGIN_DIR" --peer-dir "$RECEIVER_DIR" \
    --frozen-dir "$FROZEN" --sha256 "$PIN" \
    --first "$FIRST" --receiver-policy "$FLOOR" \
    --out "$BSB_P2P_RECEIPT_DIR/$CASE.json" >"$TMP/$CASE-proof-output.json"
  node - "$BSB_P2P_RECEIPT_DIR/$CASE.json" "$FIRST" "$FLOOR" <<'JS'
const fs=require('fs'),r=JSON.parse(fs.readFileSync(process.argv[2]));
const [who,level]=process.argv.slice(3);
if(r.schema!=='bsb-frost-p2a-two-node-opportunistic-relay-v1' ||
  r.ownerFirst!==who||r.receiverPolicy!==level||
  !r.nodeSeparation.p2pConnectionConfirmed||
  !r.nodeSeparation.independentMempools||
  !r.nodeSeparation.nodeBPassivelyReceivesWithoutSigningWallets||
  Math.abs(r.nodeSeparation.receiverMinRelayFeeSatsVb-(level==='low'?2:25))>0.001||
  r.actualPeerObservations.length!==2||
  !r.signedFrostParentsUnchangedAcrossPeerAndFeePolicy||
  r.fullBeneficiaryPayoutsConfirmed.alice!==60000||
  r.fullBeneficiaryPayoutsConfirmed.bob!==40000||
  r.claimBoundaries.worldwidePropagationGuaranteed!==false||
  r.claimBoundaries.activeTwoOfThreeQuorumCanStillSteal!==true)
  throw Error('Bitcoin P2P evidence mismatch: '+JSON.stringify({
    owner:who,policy:level,network:r.network,
    nodeSeparation:r.nodeSeparation,
    payout:r.fullBeneficiaryPayoutsConfirmed,
    claimBoundaries:r.claimBoundaries,
    count:r.actualPeerObservations?.length,
  }));
const observations=r.actualPeerObservations;
if(level==='high'&&observations.some(x=>!x.lowFeeBelowReceiverFloor||
  !x.secondFeeChildReplacement?.originalLowFeeChildRejectedAtHighFloor ||
  !x.secondFeeChildReplacement?.lowFeePeerDirectSubmissionRejected ||
  x.finalChildFeeSats!==15000))
  throw Error('receiver did not reject original insufficient-fee package');
if(level==='low'&&observations.some(x=>x.finalChildFeeSats!==5000||
  x.lowFeeBelowReceiverFloor||x.secondFeeChildReplacement!==null))
  throw Error('low-floor receiver did not accept intended fee package');
console.log(JSON.stringify({policy:level,firstOwner:who,
  actualP2PPropagation:r.opportunisticP2PPropagationAllSteps,
  receiverManualRpcFallback:r.receiverLocalRpcFallbackNeeded,
  realConfirmedOwners:2},null,2));
JS
  "$BITCOIN_CLI_EXEC" -regtest -datadir="$ORIGIN_DIR" stop >/dev/null || true
  "$BITCOIN_CLI_EXEC" -regtest -datadir="$RECEIVER_DIR" stop >/dev/null || true
  wait "$ORIGIN_PID" || true
  wait "$RECEIVER_PID" || true
  ORIGIN_PID=""
  RECEIVER_PID=""
done
node - "$BSB_P2P_RECEIPT_DIR" <<'JS'
const fs=require('fs'),path=require('path'),d=process.argv[2];
const low=JSON.parse(fs.readFileSync(path.join(d,'peer-low.json')));
const high=JSON.parse(fs.readFileSync(path.join(d,'peer-high.json')));
if(low.initialSignedManifestSha256===high.initialSignedManifestSha256)
  throw Error('two separate node-pair trials reused one FROST signing history');
console.log(JSON.stringify({
  distinctBitcoinCoreNodePairs:2,
  distinctMempools:4,
  receiverFeeFloorsSatVb:[2,25],
  actualConfirmedParentChildPairs:4,
  p2pLowFloorBothSteps:low.opportunisticP2PPropagationAllSteps,
  p2pHighFloorAfterBumpBothSteps:high.opportunisticP2PPropagationAllSteps,
  underpricedPackagesRejectedByHighFeePeer:2,
  noFrostSignerAfterFreeze:true,
  noGlobalNetworkSafetyClaim:true,
},null,2));
JS
