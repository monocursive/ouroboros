#!/usr/bin/env python3
"""Check actual benchmark credential values without printing or retaining them."""
import json
from pathlib import Path
import subprocess
import sys
import tarfile

root = Path(sys.argv[1]).resolve()
values = set()
for host, auth in [('ubuntu@37.59.114.70', 'bench-ouro/auth/codex/auth.json'),
                   ('monocursive@100.83.203.10', 'bench-ouro/auth/codex/auth.json'),
                   ('monocursive@100.73.93.5', '.codex/auth.json')]:
    key = subprocess.check_output(['ssh', host, 'cat', 'bench-ouro/anthropic.key']).strip()
    if key:
        values.add(key)
    credentials = json.loads(subprocess.check_output(['ssh', host, 'cat', auth]))
    for token in credentials.get('tokens', {}).values():
        if isinstance(token, str) and len(token) >= 8:
            values.add(token.encode())
checked = 0
hits = []
def check(name, data):
    global checked
    checked += 1
    if any(value in data for value in values):
        hits.append(name)
for path in sorted(root.rglob('*')):
    if not path.is_file() or path.is_symlink() or '__pycache__' in path.parts:
        continue
    if path.name.endswith('.tar.gz'):
        with tarfile.open(path) as tar:
            for member in tar:
                if member.isfile():
                    check(str(path.relative_to(root)) + ':' + member.name, tar.extractfile(member).read())
    else:
        check(str(path.relative_to(root)), path.read_bytes())
result = {'schema': 'benchmark-credential-audit/1', 'items_checked': checked,
          'actual_credential_hits': hits, 'credential_values_retained': False}
(root / 'analysis/credential-audit.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
raise SystemExit(bool(hits))
