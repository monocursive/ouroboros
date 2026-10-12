#!/usr/bin/env python3
"""Clear only the failed Codex builder and its untagged intermediate images."""
import json
from pathlib import Path
import subprocess

root = Path.home() / 'bench-ouro-startup'
out = root / 'results/container-after-codex-build-invalid'
rows = []
def run(argv):
    r = subprocess.run(argv, capture_output=True, text=True)
    row = {'argv': argv, 'exit': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr}
    rows.append(row)
    (root / 'results/failed-build-cache-removal.json').write_text(json.dumps(rows, indent=2) + '\n')
    return r
container = '84eaa7223eaf'
assert '84eaa7223eaf' in (out / 'build.log').read_text()
lookup = run(['docker', 'inspect', container])
found = json.loads(lookup.stdout)
if found:
    info = found[0]
    assert not info['State']['Running'] and info['State']['ExitCode'] == 1
    assert info['Config']['Cmd'] == ['/bin/sh', '-c', 'chmod -R a+rX /opt/agents /opt/bench']
    assert run(['docker', 'rm', container]).returncode == 0
for image in ['998149bf1ea8', '3707554db23f']:
    assert image in (out / 'build.log').read_text()
    found = json.loads(run(['docker', 'image', 'inspect', image]).stdout)
    if not found:
        continue
    info = found[0]
    assert not info['RepoTags']
    result = run(['docker', 'image', 'rm', image])
    assert result.returncode == 0
(root / 'results/failed-build-cache-removal.json').write_text(json.dumps(rows, indent=2) + '\n')
