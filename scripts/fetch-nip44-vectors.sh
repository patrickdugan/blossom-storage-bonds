#!/usr/bin/env bash
# Fetches the official NIP-44 test vectors into fixtures/ and checks they are the pinned version.
# layer1/nip44.test.ts runs the full set when the file is present. The file is not committed here
# because its repository (paulmillr/nip44) declares no license.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/fixtures/nip44.vectors.json"
want=269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040
curl -sSfL --max-time 30 -o "$out" https://raw.githubusercontent.com/paulmillr/nip44/main/nip44.vectors.json
got=$(sha256sum "$out" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then echo "sha256 $got is not the pinned $want" >&2; rm -f "$out"; exit 1; fi
echo "fixtures/nip44.vectors.json ok"
