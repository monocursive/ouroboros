#!/bin/bash
set -euo pipefail
umask 077
cd /home/monocursive/ouro-pi-41e6457b
ouro_temp=$(mktemp -d /tmp/ouro-installed-smoke.XXXXXXXX)
trap 'rm -rf -- "$ouro_temp"' EXIT
mkdir "$ouro_temp/config" "$ouro_temp/workspace"
export OURO_CONFIG_DIR="$ouro_temp/config" OURO_DATA_DIR="$ouro_temp/data"
mkdir installed-smoke
"$HOME/.local/bin/ouro-jail" doctor --json > installed-smoke/doctor.json
for ouro_profile in tool none; do
    "$HOME/.local/bin/ouro-jail" run --profile "$ouro_profile" \
        --workspace "$ouro_temp/workspace" --limit wall=5s \
        --receipt "$PWD/installed-smoke/$ouro_profile-receipt.json" \
        -- /bin/printf "installed-$ouro_profile\n" \
        > "installed-smoke/$ouro_profile.stdout" 2> "installed-smoke/$ouro_profile.stderr"
    "$HOME/.local/bin/ouro-ledger" verify-bundle "signing-smoke/$ouro_profile" \
        --trusted-key signing-smoke/public-key.json --json \
        > "installed-smoke/$ouro_profile-verified.json"
    cmp "installed-smoke/$ouro_profile-verified.json" "signing-smoke/$ouro_profile-verified.json"
done
python3 - <<'PY'
import json
from pathlib import Path
p=Path('installed-smoke')
doctor=json.loads((p/'doctor.json').read_text())
assert doctor['ready'] is True
assert doctor['build']['revision']=='41e6457b009065bd4fe4040b3141da291fb29c9b'
for profile in ['tool','none']:
    assert (p/f'{profile}.stdout').read_text()==f'installed-{profile}\n'
    receipt=json.loads((p/f'{profile}-receipt.json').read_text())
    assert receipt['child_protection']==('enforced' if profile=='tool' else 'unprotected')
print('Installed commands: doctor ready, tool/none launched with correct protection, both pinned bundles verified.')
PY
