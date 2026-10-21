#!/usr/bin/env bash
# Same predicate, compact public journal; reuse already authenticated header receipts.
set -euo pipefail
if (( $# != 4 )); then
  echo "usage: $0 <research-input-dir> <original-proof-dir> <new-output-dir> <bsb-r0>" >&2
  exit 2
fi
INPUT=$(realpath "$1") PRIOR=$(realpath "$2") OUTPUT=$(realpath -m "$3") BIN=$(realpath "$4")
test ! -e "$OUTPUT" || { echo "output directory must be new" >&2; exit 2; }
test -x "$BIN"
unset BONSAI_API_KEY BONSAI_API_URL
export RISC0_DEV_MODE=0 RISC0_PROVER=local RAYON_NUM_THREADS=4
python3 - "$INPUT" "$PRIOR" <<'PY'
import hashlib,json,pathlib,sys
i,p=map(pathlib.Path,sys.argv[1:]);m=json.loads((i/'manifest.json').read_text());old=json.loads((p/'manifest.json').read_text())
assert m['format']=='bsb/fork-proof-research-inputs/v1' and m['network']=='regtest' and m['graph_id_is_synthetic'] is True
assert old['format']=='bsb/fork-proof-research-output/v1'
assert set(m['files'])=={'common.bin','original.bin','response.bin','candidate.bin','term-preimage.bin'}
for name,digest in m['files'].items(): assert hashlib.sha256((i/name).read_bytes()).hexdigest()==digest,name
for name in ('common','original','response','candidate'):
    for ext in ('bin','json','time'):
        f=f'{name}.{ext}';assert hashlib.sha256((p/f).read_bytes()).hexdigest()==old['files'][f],f
PY
mkdir "$OUTPUT"
for name in common original response candidate; do
  for ext in bin json time; do cp "$PRIOR/$name.$ext" "$OUTPUT/$name.$ext"; done
done
"$BIN" ids > "$OUTPUT/ids.json"
python3 - "$OUTPUT/ids.json" "$(dirname -- "$0")" <<'PY'
import json,sys
sys.path.insert(0,sys.argv[2])
from check_fork_research import FORK_ID,COMPACT_ID
from fresh_snapshot import IDS
actual=json.load(open(sys.argv[1]))
assert all(actual[k]==v for k,v in IDS.items())
assert actual['fork']==FORK_ID and actual['fork_compact']==COMPACT_ID
PY
mapfile -t VALUES < <(python3 - "$INPUT/manifest.json" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
for k in ('graph_id','divergent_height','epoch_index'):print(m[k])
PY
)
ARGS=(--original "$OUTPUT/original.bin" --response "$OUTPUT/response.bin" --candidate "$OUTPUT/candidate.bin")
timed() { local name=$1; shift; /usr/bin/time -v -o "$OUTPUT/$name.time" "$@" > "$OUTPUT/$name.json"; }
printf '%s\n' prove-compact-relative-work-certificate > "$OUTPUT/phase"
timed fork "$BIN" prove-fork-compact "$OUTPUT/fork.bin" "${ARGS[@]}" --original-headers "$INPUT/original.bin" --response-headers "$INPUT/response.bin" --candidate-headers "$INPUT/candidate.bin" --term-preimage "$INPUT/term-preimage.bin" --graph-id "${VALUES[0]}" --divergent-height "${VALUES[1]}" --epoch-index "${VALUES[2]}"
timed verify "$BIN" verify-fork-compact "$OUTPUT/fork.bin"
printf '%s\n' compact-compiled-guest-guards > "$OUTPUT/phase"
timed guards "$BIN" fork-guards-compact "$OUTPUT/fork.bin.input.bin" "${ARGS[@]}"
python3 - "$OUTPUT" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);files={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(p.iterdir()) if f.is_file() and f.name!='phase'}
(p/'manifest.json').write_text(json.dumps({'format':'bsb/fork-proof-research-output/v2','header_receipts_reused':True,'copied_timings':['common','original','response','candidate'],'files':files,'scope':'Compact projection of the complete relative-work relation. Header receipts reused from the v1 experiment. No Bitcoin collateral enforcement.'},indent=2)+'\n')
PY
printf '%s\n' compact-proof-and-guards-finished > "$OUTPUT/phase"
