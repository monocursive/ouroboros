#!/usr/bin/env python3
"""Parse and execute operator vault starters with harmless fixture credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    args = p.parse_args()
    root = args.root.resolve()
    out = root / 'results/profile-examples'
    if out.exists():
        raise SystemExit('Preserve prior profile evidence')
    out.mkdir(parents=True)
    private = root / 'profile-private'
    config = private / 'config/launch'
    config.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    secret = private / 'fixture-key'
    secret.write_text('profile-fixture-token')
    secret.chmod(0o600)
    workspace = root / 'profile-workspace'
    workspace.mkdir()
    env = dict(os.environ, OURO_CONFIG_DIR=str(config.parent), OURO_DATA_DIR=str(root / 'data'))
    results = []
    for name in ['claude-vault', 'opencode-vault']:
        example = root / 'harness' / (name + '.toml')
        text = example.read_text().replace('source = "~/.config/ouro/credentials/anthropic"',
                                           'source = ' + json.dumps(str(secret)))
        target = config / example.name
        target.write_text(text)
        target.chmod(0o600)
        case = out / name
        case.mkdir()
        argv = [str(root / 'bin/ouro-jail'), 'run', '--launch', name, '--workspace', str(workspace),
                '--limit', 'wall=20s', '--receipt', str(case / 'jail.json'), '--', '/bin/sh', '-c',
                'export ANTHROPIC_API_KEY="$OURO_VAULT_ANTHROPIC"; python3 -c '
                + "'import os; print(os.environ[\"ANTHROPIC_API_KEY\"].startswith(\"vault:\"))'"]
        result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=50)
        (case / 'stdout.log').write_bytes(result.stdout)
        (case / 'stderr.log').write_bytes(result.stderr)
        receipt = json.loads((case / 'jail.json').read_text())
        trace = root / 'data/attempts' / receipt['attempt_id'] / 'trace.ndjson'
        if trace.exists():
            (case / 'trace.ndjson').write_bytes(trace.read_bytes())
        row = {'profile': name, 'template_sha256': hashlib.sha256(example.read_bytes()).hexdigest(),
               'source_override_only': True, 'exit': result.returncode,
               'pass': result.returncode == 0 and result.stdout.strip() == b'True' and
               receipt['credentials'][0]['never_staged'] is True and receipt['state_cleanup'] == 'complete',
               'actual_provider_task': False, 'artifact': str(case.relative_to(root / 'results'))}
        results.append(row)
    (out / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results))


if __name__ == '__main__':
    main()
