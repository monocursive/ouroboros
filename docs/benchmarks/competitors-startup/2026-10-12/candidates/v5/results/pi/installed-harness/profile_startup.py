#!/usr/bin/env python3
"""Diagnostic parent-only strace; never trace children owned by Ouro's tracer."""
import argparse
import json
import subprocess
from pathlib import Path
from suite import Suite

p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, required=True)
args = p.parse_args()
s = Suite(args.root, args.root / 'results', 0, 0, ['ouro-jail'])
try:
    rows = []
    for i in range(3):
        rows.append(s.run('ouro-jail', [str(s.work / 'workload'), 'noop'], 'profile-control', 'noop', i))
        cmd = s.command('ouro-jail', [str(s.work / 'workload'), 'noop'])
        trace = args.root / 'results' / ('parent-%d.strace' % i)
        r = subprocess.run(['strace', '-ttt', '-T', '-s', '120', '-o', str(trace), *cmd],
                           env=s.env, cwd=s.work, capture_output=True, timeout=40)
        rows.append({'trace': str(trace), 'exit': r.returncode,
                     'stdout': r.stdout.decode(), 'stderr': r.stderr.decode()})
    (args.root / 'results/profile.json').write_text(json.dumps(rows, indent=2) + '\n')
finally:
    s.close()
