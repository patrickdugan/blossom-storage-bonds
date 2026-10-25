#!/usr/bin/env bash
# Disposable Bitcoin Core 30.3: holder ACKs must precede each refresh broadcast.
# The source signer remains authoritative; this tests an honest coordinator
# application gate, NOT a Bitcoin covenant or malicious FROST quorum protection.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../../.." && pwd)"
cd "$ROOT"
: "${BITCOIND_EXEC:?}" "${BITCOIN_CLI_EXEC:?}" "${BSB_GATE_RECEIPT_DIR:?}"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
mkdir -p "$BSB_GATE_RECEIPT_DIR"
chmod 700 "$BSB_GATE_RECEIPT_DIR"
BIN="$ROOT/experiments/storage-bond-ab/b-layertree/frost-proof/target/release/p2tr-frost-regtest"
GATE="$ROOT/experiments/storage-bond-ab/b-layertree/p2a-fee-child/ack-before-refresh/holder_gate.mjs"
cargo build --locked --release --manifest-path \
  experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml --bin p2tr-frost-regtest
test -x "$BIN"
node --check "$GATE"
node --check experiments/storage-bond-ab/b-layertree/p2a-fee-child/ack-before-refresh/holder_actor.mjs
EVIDENCE_HASH="$(node --input-type=module -e '
import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
const e=scenario("storage-fault").events.find(x=>x.kind==="proof"&&x.id==="alice"&&x.epoch===2);
const p=challenge(e);
if(p.verified!==false||p.assertedVerdict!=="fault")throw Error("shared Merkle fixture mismatch");
console.log(p.evidenceHash);
')"
[[ "$EVIDENCE_HASH" =~ ^[a-f0-9]{64}$ ]]
TMP="$(mktemp -d)"
NODE_DIR=""
PID=""
cleanup(){
  if [[ -n "$PID" ]];then
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$NODE_DIR" stop >/dev/null 2>&1 || true
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
for CASE in success missing-alice missing-bob tampered-envelope forged-ack partial-before-ack stale-ack-second rollback-second;do
  NODE_DIR="$TMP/$CASE-core"
  FROZEN="$TMP/$CASE-signed"
  GATESTORE="$TMP/$CASE-holder-processes"
  mkdir -p "$NODE_DIR" "$FROZEN"
  chmod 700 "$NODE_DIR" "$FROZEN"
  cat >"$NODE_DIR/bitcoin.conf" <<'CONF'
regtest=1
server=1
txindex=1
fallbackfee=0.00002
discover=0
dnsseed=0
[regtest]
rpcuser=gate-disposable
rpcpassword=gate-disposable-only
rpcport=18484
port=18494
listen=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
  chmod 600 "$NODE_DIR/bitcoin.conf"
  "$BITCOIND_EXEC" -datadir="$NODE_DIR" -printtoconsole=0 >"$TMP/$CASE-core.log" 2>&1 &
  PID=$!
  READY=0
  for i in $(seq 1 150);do
    if ! kill -0 "$PID" 2>/dev/null;then
      tail -60 "$TMP/$CASE-core.log" >&2;exit 1
    fi
    if "$BITCOIN_CLI_EXEC" -regtest -datadir="$NODE_DIR" getblockcount >/dev/null 2>&1;then READY=1;break;fi
    sleep 0.1
  done
  test "$READY" = 1
  echo "ACK-before-carrier-invalidation Bitcoin Core case: $CASE"
  STATUS=0
  "$BIN" --freeze-p2a --bitcoin-cli "$BITCOIN_CLI_EXEC" \
    --datadir "$NODE_DIR" --evidence-hash "$EVIDENCE_HASH" \
    --out-dir "$FROZEN" --gate-script "$GATE" --gate-store "$GATESTORE" \
    --gate-scenario "$CASE" >"$TMP/$CASE-signer.log" 2>"$TMP/$CASE-signer.err" || STATUS=$?
  if [[ "$CASE" == success ]];then
    if [[ "$STATUS" -ne 0 ]];then
      tail -45 "$TMP/$CASE-signer.err" >&2
      tail -45 "$TMP/$CASE-signer.log" >&2
      echo "both ACKs failed to authorize actual Bitcoin refresh" >&2;exit 1
    fi
    test -f "$FROZEN/p2a-frozen.json"
    node - "$FROZEN" "$BSB_GATE_RECEIPT_DIR/success-gates.json" <<'JS'
const fs=require('fs'),path=require('path');
const d=process.argv[2],out=process.argv[3],gates=[];
for(const i of [0,1]){
 const intent=JSON.parse(fs.readFileSync(path.join(d,'intent-g'+i+'.json')));
 const gate=JSON.parse(fs.readFileSync(path.join(d,'gate-g'+(i+1)+'.json')));
 if(gate.status!=='approved'||gate.generation!==i+1||
   gate.candidateManifestSha256!==intent.futureManifestSha256||
   gate.approvedRefreshTxid!==intent.signedRefreshTxid||
   gate.distinctHolderProcesses!==2||gate.signedAcksVerifiedByCoordinator!==2||
   !gate.durablePerHolderCheckpointsReread||
   gate.bitcoinConsensusEnforcesAcknowledgement!==false)
   throw Error('Bitcoin refresh lacks two source-bound holder ACKs');
 gates.push({generation:i+1,manifestSha256:gate.candidateManifestSha256,
   refreshTxid:gate.approvedRefreshTxid,twoAcksBeforeBroadcast:true,
   twoDistinctHolderProcesses:true});
}
const final=JSON.parse(fs.readFileSync(path.join(d,'p2a-frozen.json')));
if(final.currentGeneration!==2||
  final.generations[0].refreshBroadcast?.txid!==gates[0].refreshTxid||
  final.generations[1].refreshBroadcast?.txid!==gates[1].refreshTxid)
  throw Error('final signed recovery graph diverged from gated refreshes');
fs.writeFileSync(out,JSON.stringify({schema:'bsb-frost-gated-actual-regtest-v1',
  authorizedRefreshes:2,gateReceipts:gates,approvedBeforeBitcoinBroadcast:true,
  trustedCoordinatorOnly:true,realCrossDeviceCustody:false,
  activeMaliciousFrostQuorumStillCanTheft:true},null,2)+'\n',{flag:'wx',mode:0o600});
JS
    for WALLET in sponsor alice bob;do
      "$BITCOIN_CLI_EXEC" -regtest -datadir="$NODE_DIR" unloadwallet "$WALLET" >/dev/null
    done
    PIN="$(cat "$FROZEN/p2a-frozen.sha256")"
    node experiments/storage-bond-ab/b-layertree/p2a-fee-child/relay_dynamic.mjs \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$NODE_DIR" \
      --frozen-dir "$FROZEN" --sha256 "$PIN" \
      --first alice --attack-step none \
      --out "$BSB_GATE_RECEIPT_DIR/success-recovery.json" >"$TMP/success-p2a-confirmed.log"
    node - "$BSB_GATE_RECEIPT_DIR/success-recovery.json" <<'JS'
const r=require(process.argv[2]);
if(r.schema!=='bsb-frost-p2a-fee-independent-recovery-v1'||
  r.sixConfirmationPayouts?.aliceSats!==60000||
  r.sixConfirmationPayouts?.bobSats!==40000||
  r.FROSTKeypathResignedDuringRelay!==false||
  r.maliciousTwoShareQuorumTheftStillPossible!==true)
  throw Error('actual FROST signer-dead owner split regression');
JS
  else
    if [[ "$STATUS" -eq 0 ]];then
      echo "negative case unexpectedly authorized and broadcast carrier refresh: $CASE" >&2
      exit 1
    fi
    grep -q 'prospective carrier refresh denied without both durable ACKs' "$TMP/$CASE-signer.err"
    GEN=0
    if [[ "$CASE" == stale-ack-second || "$CASE" == rollback-second ]];then GEN=1;fi
    test -f "$FROZEN/intent-g$GEN.json"
    node - "$BITCOIN_CLI_EXEC" "$NODE_DIR" "$FROZEN/intent-g$GEN.json" \
      "$FROZEN/gate-g$((GEN+1)).json" "$BSB_GATE_RECEIPT_DIR/$CASE.json" <<'JS'
const fs=require('fs'),cp=require('child_process');
const [bin,dir,intentFile,gateFile,out]=process.argv.slice(2);
const intent=JSON.parse(fs.readFileSync(intentFile));
const gate=JSON.parse(fs.readFileSync(gateFile));
function rpc(method,...args){
 const c=cp.spawnSync(bin,['-regtest','-datadir='+dir,method,...args.map(String)],
   {encoding:'utf8',timeout:30000});
 if(c.status!==0)throw Error('Bitcoin RPC '+method+' denied: '+c.stderr.slice(0,150));
 return JSON.parse(c.stdout.trim());
}
const [txid,vout]=intent.currentCarrier.split(':');
const current=rpc('gettxout',txid,vout);
const pool=rpc('getrawmempool');
if(gate.status!=='blocked'||gate.generation!==intent.generationTo||
  !current||Number(current.value)!==0.001||
  pool.includes(intent.signedRefreshTxid)||pool.length!==0)
 throw Error('failed holder ACK still invalidated current Bitcoin carrier');
fs.writeFileSync(out,JSON.stringify({
 schema:'bsb-frost-gated-actual-regtest-v1',scenario:gate.scenario,
 rejectedGeneration:intent.generationTo,currentCarrier:intent.currentCarrier,
 prospectiveRefreshTxid:intent.signedRefreshTxid,
 oldCarrierStillUnspentOnBitcoin:true,
 rejectedRefreshAbsentFromMempool:true,
 signedRefreshWouldStillBeBroadcastableByMaliciousQuorum:true,
 coordinatorGateBlockedBeforeSendrawtransaction:true,
 gateReason:gate.reason.slice(0,180)
},null,2)+'\n',{flag:'wx',mode:0o600});
JS
  fi
  "$BITCOIN_CLI_EXEC" -regtest -datadir="$NODE_DIR" stop >/dev/null || true
  wait "$PID" || true
  PID=""
done
node - "$BSB_GATE_RECEIPT_DIR" <<'JS'
const fs=require('fs'),path=require('path'),dir=process.argv[2];
for(const x of ['missing-alice','missing-bob','tampered-envelope',
  'forged-ack','partial-before-ack','stale-ack-second','rollback-second']){
 const v=JSON.parse(fs.readFileSync(path.join(dir,x+'.json')));
 if(!v.oldCarrierStillUnspentOnBitcoin||!v.coordinatorGateBlockedBeforeSendrawtransaction)
  throw Error('missing negative Bitcoin Core refusal evidence '+x);
}
console.log(JSON.stringify({realBitcoinCoreScenarios:8,
 verifiedHonestCoordinatorRefreshes:2,failedAckNoBroadcastCases:7,
 signerDeadFinalOwnerPayoutConfirmed:true,bitcoinCovenantEnforcesAck:false}));
JS
