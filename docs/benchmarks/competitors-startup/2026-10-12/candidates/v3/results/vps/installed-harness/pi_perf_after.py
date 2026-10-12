#!/usr/bin/env python3
"""Test base-image startup before choosing available container timing arms."""
import json
import subprocess
from pathlib import Path
from openshell_perf_v2 import run, IMAGE

root = Path.home() / 'bench-ouro-startup'
out = root / 'results/container-perf-availability'
out.mkdir(parents=True, exist_ok=False)
result = run(['openshell', 'sandbox', 'create', '--no-keep', '--no-tty',
              '--from', IMAGE, '--', '/bin/true'], timeout=180)
(out / 'startup.json').write_text(json.dumps(result, indent=2) + '\n')
argv = ['python3', str(root / 'harness/openshell_perf_v2.py'), '--root', str(root),
        '--out', str(root / 'results/container-perf-after'), '--samples', '30',
        '--warmup', '3', '--skip-build']
if result['exit'] != 0:
    argv.append('--docker-only')
raise SystemExit(subprocess.call(argv))
