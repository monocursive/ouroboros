#!/usr/bin/env python3
"""Retain complete instrumented no-op attempts; exclude all diagnostic timing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--label', default='boundary-diagnostic')
    args = parser.parse_args()
    root = args.root.resolve()
    assert '/' not in args.label and args.label not in ('', '.', '..')
    out = root / 'results' / args.label
    out.mkdir()
    binary = root / 'bin/ouro-jail-boundary-diagnostic'
    metadata = json.loads(subprocess.check_output([str(binary), 'version', '--json']))
    assert metadata['build']['dirty'] is True
    rows = []
    env = dict(os.environ, OURO_DATA_DIR=str(root / (args.label + '-data')),
               OURO_CONFIG_DIR=str(root / 'private/boundary-config'))
    for name in ('ANTHROPIC_API_KEY', 'OPENAI_API_KEY'):
        env.pop(name, None)
    for index in range(6):
        case = out / str(index)
        case.mkdir()
        argv = [str(binary), 'run', '--profile', 'tool', '--workspace',
                str(root / 'diagnostic-work'), '--limit', 'wall=20s',
                '--observe', 'on', '--evidence', 'strict',
                '--receipt', str(case / 'jail.json'), '--', '/bin/true']
        began = time.perf_counter_ns()
        run = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=50)
        elapsed = (time.perf_counter_ns() - began) / 1e6
        (case / 'stdout.log').write_bytes(run.stdout)
        (case / 'stderr.log').write_bytes(run.stderr)
        receipt = json.loads((case / 'jail.json').read_text())
        attempt = Path(env['OURO_DATA_DIR']) / 'attempts' / receipt['attempt_id']
        for name in ('policy.json', 'trace.ndjson'):
            if (attempt / name).exists():
                (case / name).write_bytes((attempt / name).read_bytes())
        verified = (run.returncode == 0 and receipt['phase'] == 'settled'
                    and receipt['containment'] == 'enforced'
                    and receipt['exec_observed'] is True
                    and receipt['lifetime']['tree_empty'] is True
                    and receipt['lifetime']['integrity'] == 'verified')
        rows.append({'run': index, 'exit': run.returncode, 'elapsed_ms': elapsed,
                     'argv': argv, 'settled_containment_verified': verified,
                     'diagnostics': [line for line in run.stderr.decode().splitlines()
                                     if line.startswith('OURO_') and 'DIAGNOSTIC ' in line]})
        assert verified, 'diagnostic attempt must still settle under strict containment'
    result = {'schema': 'boundary-stage-diagnostic/1', 'rows': rows,
              'excluded_from_scored_performance': True, 'reason': 'diagnostic instrumentation',
              'binary_sha256': hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest(),
              'build': metadata['build']}
    (out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
