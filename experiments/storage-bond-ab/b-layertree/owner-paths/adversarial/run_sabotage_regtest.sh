#!/usr/bin/env bash
# Three independent disposable Bitcoin Core histories prove sponsor
# funding sabotage of previously FROST/BIP341 signed carrier exits.
# Never used on public Bitcoin; all keys ephemeral in regtest.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../../.." && pwd)"
cd "$ROOT"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
: "$BSB_SPONSOR_ATTACK_RECEIPT_DIR"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
mkdir -p "$BSB_SPONSOR_ATTACK_RECEIPT_DIR"
chmod 700 "$BSB_SPONSOR_ATTACK_RECEIPT_DIR"
BIN=experiments/storage-bond-ab/b-layertree/frost-proof/target/release/p2tr-frost-regtest
cargo build --release --locked \
  --manifest-path experiments/storage-bond-ab/b-layertree/frost-proof/Cargo.toml \
  --bin p2tr-frost-regtest
test -x "$BIN"
node --check experiments/storage-bond-ab/b-layertree/owner-paths/adversarial/spend_sponsor.mjs
node --check experiments/storage-bond-ab/b-layertree/owner-paths/adversarial/probe_sponsor.mjs
node --check experiments/storage-bond-ab/b-layertree/owner-paths/relay_owner_branch.mjs
EVIDENCE_HASH="$(node --input-type=module -e '
import {scenario,challenge} from "./experiments/storage-bond-ab/shared/scenario.mjs";
const e=scenario("storage-fault").events.find(x=>x.kind==="proof"&&x.id==="alice"&&x.epoch===2);
const v=challenge(e);
if(v.verified!==false)throw Error("source PDP failed to detect the missing chunk");
console.log(v.evidenceHash);
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
for MODE in alice-first both-first bob-second; do
    echo "Real Bitcoin sponsor-censorship scenario: $MODE"
    DATADIR="$TMP/node-$MODE"
    mkdir -p "$DATADIR"
    cat >"$DATADIR/bitcoin.conf" <<'CONF'
regtest=1
server=1
txindex=1
fallbackfee=0.00002
[regtest]
rpcuser=adversarial-sponsor
rpcpassword=disposable-regtest-funding-only
rpcport=18482
listen=0
connect=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
    chmod 600 "$DATADIR/bitcoin.conf"
    "$BITCOIND_EXEC" -datadir="$DATADIR" -printtoconsole=0 \
        >"$TMP/bitcoind-$MODE.log" 2>&1 &
    PID=$!
    STARTED=0
    for i in $(seq 1 150); do
        if ! kill -0 "$PID" 2>/dev/null; then
            tail -90 "$TMP/bitcoind-$MODE.log" >&2; exit 1
        fi
        if "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" getblockcount >/dev/null 2>&1; then
            STARTED=1;break
        fi
        sleep 0.1
    done
    test "$STARTED" = 1
    FROZEN="$TMP/sealed-$MODE"
    mkdir -p "$FROZEN"
    chmod 700 "$FROZEN"
    "$BIN" --freeze-owner-branches \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
      --evidence-hash "$EVIDENCE_HASH" --out-dir "$FROZEN" \
      >"$TMP/signed-$MODE.json" &
    SIGNER_PID=$!
    wait "$SIGNER_PID"
    if kill -0 "$SIGNER_PID" 2>/dev/null; then
        echo "FROST signer still active: refusing fake outage proof" >&2;exit 1
    fi
    node - "$TMP/signed-$MODE.json" <<'JS'
const fs=require('fs'),p=JSON.parse(fs.readFileSync(process.argv[2]));
if(p.status!=='ALL_OWNER_BRANCHES_SIGNED_AND_FROZEN' ||
   p.generationCount!==3||p.firstExitOptionsPerGeneration!==2||
   p.subsequentOtherOwnerExitsPerGeneration!==2||
   p.privateFrostSharesPresent!==false||
   p.maliciousLiveQuorumTheftBitcoinValid!==true)
  throw Error('complete three-generation signer-only FROST DAG not frozen');
JS
    PIN="$(cat "$FROZEN/owner-frozen.sha256")"
    test "$(printf '%s' "$PIN" | wc -c)" -eq 64
    # Sabotage AFTER signer process death, while adversarial sponsor can
    # independently spend selected 10k-sat UTXOs.
    node experiments/storage-bond-ab/b-layertree/owner-paths/adversarial/spend_sponsor.mjs \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
      --frozen-dir "$FROZEN" --sha256 "$PIN" --mode "$MODE" \
      --out "$TMP/attack-$MODE.json" >"$TMP/attacker-$MODE.log"
    # The sponsor attacks in Core, then its wallet and the beneficiary
    # wallets are made unavailable to the recovery worker.
    for WALLET in sponsor alice bob; do
        "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" unloadwallet "$WALLET" >/dev/null
    done
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" listwallets |
      node -e 'let s="";process.stdin.on("data",x=>s+=x);process.stdin.on("end",()=>{
        const w=JSON.parse(s);if(w.length!==1||w[0]!=="miner")process.exit(1);
      })'
    # A lost/corrupted second-owner package fails its original signer
    # seal without authorizing any arbitrary new transaction.
    DROP="$TMP/missing-package-$MODE"
    mkdir -p "$DROP"
    cp "$FROZEN/owner-frozen.json" "$FROZEN/owner-frozen.sha256" "$DROP/"
    node - "$DROP/owner-frozen.json" <<'JS'
const fs=require('fs'),p=process.argv[2],m=JSON.parse(fs.readFileSync(p));
delete m.generations[2].branches.alice.second.signedHex;
fs.writeFileSync(p,JSON.stringify(m));
JS
    if node experiments/storage-bond-ab/b-layertree/owner-paths/adversarial/probe_sponsor.mjs \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
      --frozen-dir "$DROP" --sha256 "$PIN" \
      --attack "$TMP/attack-$MODE.json" --mode "$MODE" \
      --out "$TMP/MISSING-PACKAGE-SHOULD-NOT-PASS.json" >"$TMP/loss-$MODE.log" 2>&1; then
        echo "Missing Bob-second pre-signed witness was accepted under old digest" >&2
        exit 1
    fi
    test ! -e "$TMP/MISSING-PACKAGE-SHOULD-NOT-PASS.json"
    node experiments/storage-bond-ab/b-layertree/owner-paths/adversarial/probe_sponsor.mjs \
      --bitcoin-cli "$BITCOIN_CLI_EXEC" --datadir "$DATADIR" \
      --frozen-dir "$FROZEN" --sha256 "$PIN" \
      --attack "$TMP/attack-$MODE.json" --mode "$MODE" \
      --out "$BSB_SPONSOR_ATTACK_RECEIPT_DIR/$MODE.json" \
      >"$TMP/verified-$MODE.log"
    node - "$BSB_SPONSOR_ATTACK_RECEIPT_DIR/$MODE.json" "$MODE" <<'JS'
const fs=require('fs'),r=JSON.parse(fs.readFileSync(process.argv[2])),mode=process.argv[3];
if(r.schema!=='bsb-frost-sponsor-liveness-counterexample-v1'||
   r.mode!==mode||r.sponsorSabotageDoesNotSpendCarrier!==true||
   r.activeFrostOrSapioSigningServiceAvailable!==false ||
   r.noNativeMidEnforcement!==true ||
   r.maliciousThresholdCanStillSteal!==true)
   throw Error('unknown or misclassified sponsor sabotage receipt');
if(mode==='alice-first'&&(!r.fallbackPresignedOtherFirstConfirmed||
   !r.bothOwnersReceivedFullCollateral||r.firstPayoutSats!==40000||
   r.secondPayoutSats!==60000||r.totalExternalSponsorFeesOfFallbackSats!==6000))
   throw Error('backup alternative Bob-first path failed after one sponsorship loss');
if(mode==='both-first'&&(!r.noFrozenOwnerFirstExitAvailable||
   r.bondedPrincipalStillLockedSats!==100000||
   r.signerFreeRecoveryPossibleFromThisSignedDAG!==false||
   r.sponsorInputsSpentBeforeOwnerPublication!==2))
   throw Error('two sponsor outages should block all signed initial exits');
if(mode==='bob-second'&&(!r.aliceFirstConfirmed||
   !r.bitcoinRefusedPreviouslySignedBobSecondExit||
   r.bobRemainderLockedSats!==40000||r.aliceUnspentPayoutSats!==60000||
   !r.bobOwnerCouldNotRedeemAfterSignerShutdown))
   throw Error('second-leg sponsor spent without demonstrating stranded Bob remainder');
console.log('Verified real sponsor adversarial case: '+mode);
JS
    "$BITCOIN_CLI_EXEC" -regtest -datadir="$DATADIR" stop >/dev/null || true
    wait "$PID" || true
    PID=""
done
node - "$BSB_SPONSOR_ATTACK_RECEIPT_DIR" <<'JS'
const fs=require('fs'),path=require('path'),d=process.argv[2];
const cases=Object.fromEntries(['alice-first','both-first','bob-second']
 .map(name=>[name,JSON.parse(fs.readFileSync(path.join(d,name+'.json')))]));
if(new Set(Object.values(cases).map(r=>r.frozenManifestSha256)).size!==3)
    throw Error('adversarial modes accidentally reused one signing process/chain');
console.log(JSON.stringify({
  independentRegtestHistories:3,
  confirmedSponsorSabotageCoinSpends:4,
  realAlternativeFallbackPassed:cases['alice-first'].bothOwnersReceivedFullCollateral,
  dualFirstSponsorAttackBlocksAllExits:cases['both-first'].noFrozenOwnerFirstExitAvailable,
  secondSponsorAttackStrandsOtherHolderSats:cases['bob-second'].bobRemainderLockedSats,
  signerUsedForRecovery:false,
  ownerSpecificConsensusRestrictionPresent:false,
},null,2));
JS
