#!/usr/bin/env bash
# Separate FROST signer preparation process and Node-only regtest relay.
# Alice and Bob each run a separate fresh Bitcoin history to prove either
# can broadcast the SAME previously signed full-split exit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$ROOT"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
: "$BSB_OFFLINE_RECEIPT_DIR"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
mkdir -p "$BSB_OFFLINE_RECEIPT_DIR"
chmod 700 "$BSB_OFFLINE_RECEIPT_DIR"
MANIFEST=experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml
BIN=experiments/storage-bond-ab/b-layertree/frost-proof/target/release/p2tr-frost-regtest
cargo build --locked --release --manifest-path "$MANIFEST" --bin p2tr-frost-regtest
test -x "$BIN"
node --check experiments/storage-bond-ab/b-layertree/offline-exit/relay_current.mjs
EVIDENCE_HASH="$(node --input-type=module -e '
  import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
  const e=scenario("storage-fault").events.find(e=>e.kind==="proof"&&e.id==="alice"&&e.epoch===2);
  const p=challenge(e);
  if(p.verified!==false||p.assertedVerdict!=="fault")throw Error("reference PDP changed");
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
for PUBLISHER in alice bob; do
    echo "Frozen P2TR full-split relay trial: $PUBLISHER"
    DATADIR="$TMP/node-$PUBLISHER"
    mkdir -p "$DATADIR"
    cat >"$DATADIR/bitcoin.conf" <<'CONF'
regtest=1
server=1
txindex=1
fallbackfee=0.00002
[regtest]
rpcuser=bsb-offline
rpcpassword=bsb-disposable-only
rpcport=18482
listen=0
connect=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
    chmod 600 "$DATADIR/bitcoin.conf"
    "$BITCOIND_EXEC" -datadir="$DATADIR" -printtoconsole=0 >"$TMP/core-$PUBLISHER.log" 2>&1 &
    PID=$!
    READY=0
    for i in $(seq 1 150); do
        if ! kill -0 "$PID" 2>/dev/null; then
            tail -60 "$TMP/core-$PUBLISHER.log" >&2
            exit 1
        fi
        if "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" getblockchaininfo >/dev/null 2>&1; then
            READY=1; break
        fi
        sleep 0.1
    done
    test "$READY" = 1
    FROZEN="$TMP/frozen-$PUBLISHER"
    mkdir -p "$FROZEN"
    chmod 700 "$FROZEN"
    # This is the ONLY process that generates FROST shares and signs Bitcoin.
    "$BIN" --freeze-offline \
        --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
        --evidence-hash "$EVIDENCE_HASH" --out-dir "$FROZEN" \
        >"$TMP/preparation-$PUBLISHER.json" &
    SIGNER_PID=$!
    wait "$SIGNER_PID"
    if kill -0 "$SIGNER_PID" 2>/dev/null; then
        echo "FROST signer not terminated before offline Bitcoin relay" >&2
        exit 1
    fi
    node - "$TMP/preparation-$PUBLISHER.json" <<'JS'
const fs=require('fs'),p=JSON.parse(fs.readFileSync(process.argv[2]));
if(p.status!=='PRE_SIGNER_SHUTDOWN_FREEZE_COMPLETE'||
   p.signedGenerationCount!==3||p.currentGeneration!==2||
   p.privateSharesInSavedEvidence!==false||
   p.maliciousQuorumCompetingSpendWouldBeAccepted!==true||
   p.broadcastAfterThisProcessExitsOnly!==true)
   throw Error('FROST preparation did not durably freeze signed exits');
JS
    EXPECTED_SHA="$(cat "$FROZEN/sealed-exits.sha256")"
    test "$(printf '%s' "$EXPECTED_SHA" | wc -c)" -eq 64
    # Unload the fee sponsor and both holder signing wallets. Only miner
    # remains loaded for block production; relaying itself uses no wallet.
    for WALLET in sponsor alice bob; do
        "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" unloadwallet "$WALLET" >/dev/null
    done
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" listwallets |
      node -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{
        const names=JSON.parse(d);if(names.length!==1||names[0]!=="miner")process.exit(1);
      })'
    # A tampered copy is rejected against an externally frozen SHA256.
    TAMPER="$TMP/tamper-$PUBLISHER"
    mkdir -p "$TAMPER"
    cp "$FROZEN/sealed-exits.json" "$FROZEN/sealed-exits.sha256" "$TAMPER/"
    node - "$TAMPER/sealed-exits.json" <<'JS'
const fs=require('fs'),p=process.argv[2],v=JSON.parse(fs.readFileSync(p));
v.snapshots[2].exitSignedHex=v.snapshots[2].exitSignedHex.slice(0,-2)+'00';
fs.writeFileSync(p,JSON.stringify(v));
JS
    if node experiments/storage-bond-ab/b-layertree/offline-exit/relay_current.mjs \
        --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
        --frozen-dir "$TAMPER" --sha256 "$EXPECTED_SHA" \
        --publisher "$PUBLISHER" --output "$TMP/should-not-exist.json" \
        >"$TMP/tamper.log" 2>&1; then
        echo "Tampered frozen witness passed hash check" >&2
        exit 1
    fi
    test ! -e "$TMP/should-not-exist.json"
    # Separate Node-only process: FROST dealer is gone; signing wallets
    # are unloaded; all sponsor inputs are already signed and frozen.
    node experiments/storage-bond-ab/b-layertree/offline-exit/relay_current.mjs \
        --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
        --frozen-dir "$FROZEN" --sha256 "$EXPECTED_SHA" \
        --publisher "$PUBLISHER" \
        --output "$BSB_OFFLINE_RECEIPT_DIR/$PUBLISHER-signer-free-recovery.json" \
        >"$TMP/recovery-$PUBLISHER.json"
    node - "$BSB_OFFLINE_RECEIPT_DIR/$PUBLISHER-signer-free-recovery.json" "$PUBLISHER" <<'JS'
const fs=require('fs'),p=JSON.parse(fs.readFileSync(process.argv[2])),who=process.argv[3];
if(p.schema!=='bsb-frost-service-dead-fullsplit-regtest-v1'||
   p.publishedBy!==who||p.preSignedGenerations!==3||
   p.previousGenerationExitsRejected!==2||p.liveCarrierGeneration!==2||
   p.confirmations<6||p.retainedPrincipalSats!==100000||
   p.independentExternalFeeAlreadySignedSats!==3000||
   p.beneficiaries.alice.payoutSats!==60000||
   p.beneficiaries.bob.payoutSats!==40000||
   !p.signedBytesUnmodified||!p.sponsorPaysFeeWithoutWalletOnline||
   !p.jointFullSplitCanBePublishedByEitherHolder||
   p.independentIndividualCarrierClaimsProven!==false||
   p.activeMaliciousQuorumResistanceProven!==false||
   p.restrictions.nativeSapioMIDCovenant!==false)
    throw Error('pre-signed FROST outage result overclaimed or failed');
console.log('Confirmed full-split offline publisher '+who);
JS
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" stop >/dev/null || true
    wait "$PID" || true
    PID=""
done
node - "$BSB_OFFLINE_RECEIPT_DIR" <<'JS'
const fs=require('fs'),path=require('path'),dir=process.argv[2];
const a=JSON.parse(fs.readFileSync(path.join(dir,'alice-signer-free-recovery.json')));
const b=JSON.parse(fs.readFileSync(path.join(dir,'bob-signer-free-recovery.json')));
if(a.publishedBy===b.publishedBy||
   a.frozenExportSha256===b.frozenExportSha256||
   !a.restrictions.allSignersStoppedAsEnforcedByRunner||
   !b.restrictions.allSignersStoppedAsEnforcedByRunner)
    throw Error('separate publisher trials used the same Bitcoin history');
console.log(JSON.stringify({
    confirmedTrials:2,
    independentPublishers:['alice','bob'],
    totalOldGenerationsRejected:4,
    signerUsedAfterFreeze:false,
    sponsorWalletRequiredToBroadcast:false,
    exactPayoutsSats:[60000,40000],
    trueSeparateCarrierClaims:false,
    maliciousActiveQuorumCanStillSteal:true,
},null,2));
JS
