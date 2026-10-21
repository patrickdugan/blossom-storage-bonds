#!/usr/bin/env bash
# Relative cumulative-work certificate research with preinstalled pinned tools.
# Uses synthetic graph identity and public regtest headers; no Bitcoin node or signer.
set -euo pipefail
if (( $# != 4 )); then
  echo "usage: $0 <research-input-dir> <new-output-dir> <bsb-r0> <pinned-regtest-header-elf>" >&2
  exit 2
fi
INPUT=$(realpath "$1") OUTPUT=$(realpath -m "$2") BIN=$(realpath "$3") ELF=$(realpath "$4")
test ! -e "$OUTPUT" || { echo "output directory must be new" >&2; exit 2; }
test -x "$BIN"; test -f "$ELF"
python3 - "$INPUT" <<'PY'
import hashlib,json,pathlib,re,sys
p=pathlib.Path(sys.argv[1]);m=json.loads((p/'manifest.json').read_text())
assert m['format']=='bsb/fork-proof-research-inputs/v1' and m['network']=='regtest' and m['graph_id_is_synthetic'] is True
assert re.fullmatch('[0-9a-f]{64}',m['graph_id'])
assert set(m['files'])=={'common.bin','original.bin','response.bin','candidate.bin','term-preimage.bin'}
for name,digest in m['files'].items(): assert hashlib.sha256((p/name).read_bytes()).hexdigest()==digest,name
assert (p/'term-preimage.bin').read_bytes().hex()==m['term_preimage']
assert hashlib.sha256((p/'term-preimage.bin').read_bytes()).hexdigest()==m['term_journal']
assert (p/'original.bin').read_bytes().startswith((p/'common.bin').read_bytes())
assert (p/'response.bin').read_bytes().startswith((p/'original.bin').read_bytes())
assert (p/'candidate.bin').read_bytes().startswith((p/'common.bin').read_bytes())
assert len((p/'common.bin').read_bytes())==(m['divergent_height'])*80
PY
unset BONSAI_API_KEY BONSAI_API_URL
export RISC0_DEV_MODE=0 RISC0_PROVER=local RAYON_NUM_THREADS=4
mkdir "$OUTPUT"
printf '%s\n' "$$" > "$OUTPUT/driver.pid"
"$BIN" ids > "$OUTPUT/ids.json"
sha256sum "$BIN" "$ELF" "$INPUT/manifest.json" > "$OUTPUT/producer.sha256"
cp "$INPUT/manifest.json" "$OUTPUT/inputs.json"
timed() { local name=$1; shift; /usr/bin/time -v -o "$OUTPUT/$name.time" "$@" > "$OUTPUT/$name.json"; }
printf '%s\n' prove-common-prefix > "$OUTPUT/phase"
timed common "$BIN" prove-chain "$INPUT/common.bin" "$OUTPUT/common.bin" --elf "$ELF"
printf '%s\n' prove-original-and-candidate > "$OUTPUT/phase"
timed original "$BIN" prove-chain "$INPUT/original.bin" "$OUTPUT/original.bin" --elf "$ELF" --prev "$OUTPUT/common.bin" & ORIGINAL_PID=$!
timed candidate "$BIN" prove-chain "$INPUT/candidate.bin" "$OUTPUT/candidate.bin" --elf "$ELF" --prev "$OUTPUT/common.bin" & CANDIDATE_PID=$!
printf '%s\n%s\n' "$ORIGINAL_PID" "$CANDIDATE_PID" > "$OUTPUT/branch-workers.pid"
set +e
wait "$ORIGINAL_PID"; ORIGINAL_RC=$?
wait "$CANDIDATE_PID"; CANDIDATE_RC=$?
set -e
test "$ORIGINAL_RC" = 0 && test "$CANDIDATE_RC" = 0
printf '%s\n' prove-response-extension > "$OUTPUT/phase"
timed response "$BIN" prove-chain "$INPUT/response.bin" "$OUTPUT/response.bin" --elf "$ELF" --prev "$OUTPUT/original.bin"
mapfile -t VALUES < <(python3 - "$INPUT/manifest.json" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
for k in ('graph_id','divergent_height','epoch_index'):print(m[k])
PY
)
ARGS=(--original "$OUTPUT/original.bin" --response "$OUTPUT/response.bin" --candidate "$OUTPUT/candidate.bin")
printf '%s\n' prove-relative-work-certificate > "$OUTPUT/phase"
timed fork "$BIN" prove-fork "$OUTPUT/fork.bin" "${ARGS[@]}" --original-headers "$INPUT/original.bin" --response-headers "$INPUT/response.bin" --candidate-headers "$INPUT/candidate.bin" --term-preimage "$INPUT/term-preimage.bin" --graph-id "${VALUES[0]}" --divergent-height "${VALUES[1]}" --epoch-index "${VALUES[2]}"
timed verify "$BIN" verify-fork "$OUTPUT/fork.bin"
printf '%s\n' compiled-guest-adversarial-checks > "$OUTPUT/phase"
timed guards "$BIN" fork-guards "$OUTPUT/fork.bin.input.bin" "${ARGS[@]}"
python3 - "$OUTPUT" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);files={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(p.iterdir()) if f.is_file() and f.name not in {'phase','driver.pid','branch-workers.pid'}}
(p/'manifest.json').write_text(json.dumps({'format':'bsb/fork-proof-research-output/v1','files':files,'scope':'Relative work proof research. No funded graph binding, Groth16 wrap or Bitcoin fork-defense spend.'},indent=2)+'\n')
PY
printf '%s\n' proof-and-guards-finished > "$OUTPUT/phase"
