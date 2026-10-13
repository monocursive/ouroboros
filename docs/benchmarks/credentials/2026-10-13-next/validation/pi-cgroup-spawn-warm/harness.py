#!/usr/bin/env python3
"""Component diagnostic, not Ouro code, isolation proof or scored startup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--fresh-leaf', action='store_true',
                        help='Create a different leaf for every arm, matching per-attempt placement')
    args = parser.parse_args()
    root = args.root.resolve()
    out = root / ('results/cgroup-spawn-fresh' if args.fresh_leaf else 'results/cgroup-spawn-component')
    out.mkdir()
    source = Path(__file__).with_suffix('.c')
    binary = root / 'bin/cgroup-spawn-component'
    command = ['cc', '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)]
    compile_result = subprocess.run(command, capture_output=True)
    (out / 'compile.stdout').write_bytes(compile_result.stdout)
    (out / 'compile.stderr').write_bytes(compile_result.stderr)
    assert compile_result.returncode == 0, 'actual libc headers must support the diagnostic'
    (out / 'harness.py').write_bytes(Path(__file__).read_bytes())
    (out / 'harness.c').write_bytes(source.read_bytes())
    leaf = Path('/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service' % (os.getuid(), os.getuid())) / ('ouro-benchmark-spawn-' + str(os.getpid()))
    if not args.fresh_leaf:
        leaf.mkdir()
    rows = []
    rng = random.Random(20261013)
    try:
        for index in range(30):
            modes = ['move', 'direct']
            rng.shuffle(modes)
            for mode in modes:
                target_leaf = leaf.with_name(leaf.name + ('-%02d-%s' % (index, mode))) if args.fresh_leaf else leaf
                if args.fresh_leaf:
                    target_leaf.mkdir()
                try:
                    run = subprocess.run([str(binary), str(target_leaf), mode], capture_output=True, timeout=5)
                finally:
                    if args.fresh_leaf:
                        target_leaf.rmdir()
                (out / ('%02d-%s.stdout' % (index, mode))).write_bytes(run.stdout)
                (out / ('%02d-%s.stderr' % (index, mode))).write_bytes(run.stderr)
                row = json.loads(run.stdout)
                row.update({'pair': index, 'exit': run.returncode})
                rows.append(row)
                assert run.returncode == 0 and row['membership_verified'] and row['owned_child_reaped']
    finally:
        if leaf.exists():
            leaf.rmdir()
        result = {'schema': 'cgroup-spawn-component-diagnostic/1', 'rows': rows,
                  'scored_performance': False, 'production_implementation': False,
                  'fresh_leaf_for_each_arm': args.fresh_leaf,
                  'only_owned_trusted_sleep_processes': True,
                  'owned_leaf_removed': not leaf.exists(), 'seed': 20261013,
                  'command': command, 'source_sha256': hashlib.file_digest(source.open('rb'), 'sha256').hexdigest(),
                  'binary_sha256': hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest(),
                  'libc': subprocess.check_output(['getconf', 'GNU_LIBC_VERSION'], text=True).strip(),
                  'medians_ms': {mode: statistics.median(r['elapsed_ms'] for r in rows if r['mode'] == mode)
                                 for mode in ['move', 'direct'] if any(r['mode'] == mode for r in rows)},
                  'not_tested': ['Ouro descriptor hygiene', 'Ouro parent-death window',
                                 'observer/receipt/settlement integration', 'fallback platforms']}
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['medians_ms', 'owned_leaf_removed', 'production_implementation']}))


if __name__ == '__main__':
    main()
