#!/usr/bin/env bash
# Repeat the unchanged original Bitcoin Core Taproot harness at the
# A/B capital-matching sizes: Alice=60k, Bob=40k. Every receipt is public
# disposable-regtest-only; private signing keys never leave the process.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$ROOT"
: "$BITCOIND_EXEC"
: "$BITCOIN_CLI_EXEC"
case "$BITCOIND_EXEC" in /*) test -x "$BITCOIND_EXEC";; *) exit 1;; esac
case "$BITCOIN_CLI_EXEC" in /*) test -x "$BITCOIN_CLI_EXEC";; *) exit 1;; esac
MANIFEST=experiments/storage-bond-ab/a-sentinel/regtest/matched/Cargo.toml
BIN=experiments/storage-bond-ab/a-sentinel/regtest/matched/target/release/bsb-regtest
OUT="$(printenv BSB_A_AB_RECEIPT_DIR || true)"
: "$OUT"
test -n "$OUT" || { echo "Set BSB_A_AB_RECEIPT_DIR to private results folder" >&2; exit 1; }
mkdir -p "$OUT"
chmod 700 "$OUT"
for path in A-alice-60k.json A-bob-40k.json matched-A-summary.json; do
    test ! -e "$OUT/$path" || { echo "Refusing overwrite of $path" >&2; exit 1; }
done
node model/fixture.ts 3
if [[ "${BSB_A_SHARED_PDP:-0}" == 1 ]]; then
    test ! -e "$OUT/pdp" || { echo "Refusing to overwrite shared PDP evidence" >&2; exit 1; }
    node experiments/storage-bond-ab/shared/export_sentinels.mjs --out "$OUT/pdp"
fi
cargo build --locked --release --manifest-path "$MANIFEST"
test -x "$BIN"
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
        tail -80 "$TMP/bitcoind.log" >&2
        exit 1
    fi
    if "$BITCOIN_CLI_EXEC" -datadir="$DATADIR" -regtest getblockchaininfo >/dev/null 2>&1; then
        ready=1; break
    fi
    sleep 0.1
done
test "$ready" = 1
if [[ "${BSB_A_SHARED_PDP:-0}" == 1 ]]; then
    BSB_A_BOND_SATS=60000 BSB_A_SENTINELS_JSON="$OUT/pdp/alice-sentinels.json" BSB_A_RESULT_PATH="$OUT/A-alice-60k.json" "$BIN"
    BSB_A_BOND_SATS=40000 BSB_A_SENTINELS_JSON="$OUT/pdp/bob-sentinels.json" BSB_A_RESULT_PATH="$OUT/A-bob-40k.json" "$BIN"
else
    BSB_A_BOND_SATS=60000 BSB_A_RESULT_PATH="$OUT/A-alice-60k.json" "$BIN"
    BSB_A_BOND_SATS=40000 BSB_A_RESULT_PATH="$OUT/A-bob-40k.json" "$BIN"
fi
node - "$OUT" "${BSB_A_SHARED_PDP:-0}" <<'JS'
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const dir=process.argv[2],shared=process.argv[3]==='1';
const a=JSON.parse(fs.readFileSync(path.join(dir,'A-alice-60k.json')));
const b=JSON.parse(fs.readFileSync(path.join(dir,'A-bob-40k.json')));
for(const [id,report,amount] of [['alice',a,60000],['bob',b,40000]]) {
    if(report.bond_sats!==amount||report.failed!==0||
       report.checks.length<21||report.checks.some(x=>x.pass!==true))
       throw Error('real Bitcoin Core A sentinel failure for '+id);
}
let pdpEvidence=null;
if(shared) {
    const manifest=JSON.parse(fs.readFileSync(path.join(dir,'pdp/pdp-taproot-manifest.json')));
    if(manifest.schema!=='bsb-ab-pdp-to-taproot-fixture-v1' ||
       !manifest.publicCounterfactualDeletedPreimageIncluded ||
       manifest.demonstratesCryptographicStorageNonavailability!==false)
       throw Error('shared PDP evidence was misclassified');
    const hashes={};
    for(const [holder,report] of [['alice',a],['bob',b]]) {
        const record=manifest.files.find(x=>x.holder===holder);
        if(!record)throw Error('missing source PDP holder '+holder);
        const bytes=fs.readFileSync(path.join(dir,'pdp',record.file));
        const digest=crypto.createHash('sha256').update(bytes).digest('hex');
        if(digest!==record.sha256)throw Error('shared PDP file bytes substituted');
        const parsed=JSON.parse(bytes);
        if(parsed.root!==record.sourceRoot || parsed.holder!==holder ||
           parsed.sentinels.length!==3 ||
           JSON.stringify(report.ab_sentinel_h)!==
             JSON.stringify(parsed.sentinels.map(x=>x.h)))
           throw Error('Bitcoin-signed Taproot source commitments diverge from PDP fixtures');
        hashes[holder]={fixtureSha256:digest,
            referenceStorageRoot:parsed.root,
            commitmentHashes:report.ab_sentinel_h,
            pdpVerdicts:record.observations.map(x=>x.sourceVerdict),
            referenceEvidenceHashes:record.observations.map(x=>x.sourceEvidenceHash)};
    }
    if(hashes.alice.pdpVerdicts[1]!=='fault' ||
       hashes.bob.pdpVerdicts.some(x=>x!=='pass'))
       throw Error('A shared proof outcomes changed');
    pdpEvidence={
      classification:'COMMON-MERKLE-WITNESS-BITCOIN-SCRIPT-NOT-PROVIDER-ERASURE',
      manifestSchema:manifest.schema,holderFixtures:hashes,
      sourceWitnessesBoundToCoreSignedTransactions:true,
      productionStorageNonavailabilityProven:false,
      bobCounterfactualSilenceDuringS1Forfeit:true,
      epochsAndFeePoliciesFullyMatchedToB:false,
    };
}
const result={
    kind:'matched-capital-A-real-Taproot-regtest-NOT-matched-proof-epochs',
    bitcoinScriptConfirmed:true,
    principalSats:100000,
    aliceInitialSats:60000,bobInitialSats:40000,
    independentTaprootBonds:2,
    sharedPdpEvidence:pdpEvidence,
    originalTerminalFeeShavedSatsPerBond:1000,
    results:{
      alice:{checks:a.checks.length,failed:a.failed,sizes:a.sizes,
        impliedSingleTerminalReceiptSats:59000},
      bob:{checks:b.checks.length,failed:b.failed,sizes:b.sizes,
        impliedSingleTerminalReceiptSats:39000},
    },
    caveat:'Original A phase-1 fixed sentinels and transaction/fee rules remain different from the pooled B scenario. Exact A/B scenario and all external fee equalization still pending.',
};
const output=path.join(dir,'matched-A-summary.json');
fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify({principalSats:100000,
 checks:a.checks.length+b.checks.length,failures:a.failed+b.failed,
 terminalFeeNote:result.caveat},null,2));
JS
chmod 600 "$OUT"/*.json
if [[ "${BSB_A_SHARED_PDP:-0}" == 1 ]]; then
    chmod 600 "$OUT"/pdp/*.json
fi
