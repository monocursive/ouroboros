#!/bin/bash
set -euo pipefail
umask 077
ouro_binary=/home/ubuntu/ouro-ledger-storage-20261004-r1/target/release/ouro-ledger
ouro_jail=/home/ubuntu/ouro-ledger-storage-20261004-r1/target/release/ouro-jail
ouro_output="$PWD/signing-smoke"
mkdir "$ouro_output"
ouro_temp=$(mktemp -d /tmp/ouro-signing-smoke.XXXXXXXX)
ouro_writer=
cleanup() {
  if test -n "$ouro_writer"; then
    kill "$ouro_writer" 2>/dev/null || true
    wait "$ouro_writer" 2>/dev/null || true
  fi
  rm -rf -- "$ouro_temp"
}
trap cleanup EXIT
mkdir "$ouro_temp/config" "$ouro_temp/workspace"
"$ouro_binary" bundle-keygen --output "$ouro_temp/keys" --json > "$ouro_output/public-key.json"
export OURO_CONFIG_DIR="$ouro_temp/config"
for ouro_profile in tool none; do
  ouro_data="$ouro_temp/data-$ouro_profile"
  "$ouro_binary" --data-dir "$ouro_data" serve > "$ouro_output/$ouro_profile-writer.stdout" 2> "$ouro_output/$ouro_profile-writer.stderr" &
  ouro_writer=$!
  for ouro_try in $(seq 1 100); do
    if "$ouro_binary" --data-dir "$ouro_data" doctor --json > /dev/null 2>&1; then break; fi
    sleep 0.05
  done
  "$ouro_binary" --data-dir "$ouro_data" run --jail-bin "$ouro_jail" \
    --request-id "signing-smoke-$ouro_profile" --workspace "$ouro_temp/workspace" \
    --jail "$ouro_profile" --limit wall=10s --io batch --capture stdout --capture stderr \
    --capture-limit 4 --json -- /bin/sh -c "printf 'stdout-body'; printf 'stderr-body' >&2" \
    > "$ouro_output/$ouro_profile-run.json" 2> "$ouro_output/$ouro_profile-run.stderr"
  ouro_run=$(python3 -c 'import json,sys,subprocess; print(json.load(open(sys.argv[1]))["run_id"])' "$ouro_output/$ouro_profile-run.json")
  "$ouro_binary" --data-dir "$ouro_data" bundle "$ouro_run" --output "$ouro_output/$ouro_profile" \
    --capture stdout --signing-key "$ouro_temp/keys/private-key.pk8" --json > "$ouro_output/$ouro_profile-created.json"
  kill "$ouro_writer"
  wait "$ouro_writer" 2>/dev/null || true
  ouro_writer=
  rm -rf -- "$ouro_data"
  "$ouro_binary" --data-dir "$ouro_data" verify-bundle "$ouro_output/$ouro_profile" --trusted-key "$ouro_output/public-key.json" --json \
    > "$ouro_output/$ouro_profile-verified.json"
  test ! -e "$ouro_data"
  cmp "$ouro_output/$ouro_profile-created.json" "$ouro_output/$ouro_profile-verified.json"
done
rm -rf -- "$ouro_temp/keys"
for ouro_profile in tool none; do
  "$ouro_binary" --data-dir "$ouro_temp/no-store" verify-bundle "$ouro_output/$ouro_profile" \
    --trusted-key "$ouro_output/public-key.json" --json > "$ouro_output/$ouro_profile-verified.json"
  cmp "$ouro_output/$ouro_profile-created.json" "$ouro_output/$ouro_profile-verified.json"
  "$ouro_binary" --data-dir "$ouro_temp/no-store" verify-bundle "$ouro_output/$ouro_profile" \
    --json > "$ouro_output/$ouro_profile-untrusted.json"
done
test ! -e "$ouro_temp/no-store"
python3 - "$ouro_output" <<'PY'
import json,sys,subprocess
from pathlib import Path
root=Path(sys.argv[1])
for profile in ['tool','none']:
    run=json.loads((root/f'{profile}-run.json').read_text())
    report=json.loads((root/f'{profile}-verified.json').read_text())
    manifest=json.loads((root/profile/'bundle.json').read_text())
    assert run['state']=='settled' and run['outcome']['code']==0
    assert run['capture']['stdout']['truncated'] is True
    assert manifest['run']==run
    assert (root/profile/'stdout.bin').read_bytes()==b'stdo'
    assert not (root/profile/'stderr.bin').exists()
    assert report['captures']==['stdout'] and report['authenticity']=='signed' and report['signature']['trust']=='pinned'
    assert report['external_custody'] is False and report['local_consistency'] is True
    assert report['child_protection']==('enforced' if profile=='tool' else 'unprotected')
    assert report['coverage']==run['coverage']
    assert json.loads((root/profile/'receipts.json').read_text())==run['receipts']
    untrusted=json.loads((root/f'{profile}-untrusted.json').read_text())
    assert untrusted['signature']['trust']=='untrusted'
    envelope=json.loads((root/profile/'signature.json').read_text())
    public=json.loads((root/'public-key.json').read_text())
    assert public['public_key']==envelope['public_key']
    # RFC 8410 SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key.
    (root/'public-key.der').write_bytes(bytes.fromhex('302a300506032b6570032100'+public['public_key']))
    message=b'ouro.ledger.bundle-signature/1\0'+(root/profile/'bundle.json').read_bytes()
    (root/f'{profile}-message.bin').write_bytes(message)
    (root/f'{profile}-signature.bin').write_bytes(bytes.fromhex(envelope['signature']))
    command=['openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(root/'public-key.der'),'-keyform','DER',
        '-sigfile',str(root/f'{profile}-signature.bin'),'-in',str(root/f'{profile}-message.bin')]
    good=subprocess.run(command,capture_output=True,text=True)
    assert good.returncode==0,(good.stdout,good.stderr)
    (root/f'{profile}-altered-message.bin').write_bytes(message[:-1]+b' ')
    bad=subprocess.run(command[:-1]+[str(root/f'{profile}-altered-message.bin')],capture_output=True,text=True)
    assert bad.returncode!=0
    (root/f'{profile}-openssl.txt').write_text('Original message: '+good.stdout+good.stderr+'Altered message: '+bad.stdout+bad.stderr)
    print(profile+': pinned signature and independent OpenSSL verification passed; altered message refused')
print('Two real signed launches: selected captures, exact receipts, preserved protection/coverage, offline verification after private-key/store deletion, and OpenSSL interoperability passed.')
PY
