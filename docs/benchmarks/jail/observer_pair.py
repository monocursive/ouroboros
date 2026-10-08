#!/usr/bin/env python3
"""Paired observation-on fileops benchmark; report uncertainty and preserve failed rows."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import time


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['before', 'after', 'fixture', 'out']:
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--samples', type=int, default=60)
    p.add_argument('--rounds', type=int, default=5000)
    args = p.parse_args()
    if not 10 <= args.samples <= 100 or not 1 <= args.rounds <= 10000:
        p.error('samples must be 10..100; rounds must be 1..10000')
    os.umask(0o077)
    root = args.out.resolve(); root.mkdir()
    work = root / 'work'; work.mkdir()
    config = root / 'config'; config.mkdir()
    shutil.copyfile(args.fixture, work / 'ouro-fixture'); (work / 'ouro-fixture').chmod(0o755)
    paths = {name: getattr(args, name).resolve() for name in ['before', 'after']}
    env = {'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin', 'OURO_CONFIG_DIR': str(config),
           'XDG_RUNTIME_DIR': os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')}
    meta = {'schema': 'ouro.jail.observer-pair/1', 'seed': 20261008, 'samples': args.samples,
            'warmups': 5, 'rounds': args.rounds, 'host': list(os.uname()),
            'harness_sha256': sha256(Path(__file__)), 'fixture_sha256': sha256(args.fixture),
            'binary_sha256': {k: sha256(v) for k, v in paths.items()},
            'build': {k: json.loads(subprocess.check_output([v, 'version', '--json'])) for k,v in paths.items()},
            'acceptance': 'paired work-time ratio bootstrap 95% upper bound below 1; no receipt or workload failures',
            'status': 'running', 'rows': []}
    rng = random.Random(meta['seed'])
    def save(): (root / 'result.json').write_text(json.dumps(meta, indent=2) + '\n')
    save()
    for iteration in range(-5, args.samples):
        arms = list(paths); rng.shuffle(arms)
        for arm in arms:
            name = f'{iteration + 5:03d}-{arm}'
            destination = root / name; destination.mkdir()
            data = destination / 'data'
            command = [paths[arm], 'run', '--profile', 'tool', '--workspace', work,
                       '--limit', 'wall=30s', '--', work / 'ouro-fixture', 'fileops', str(args.rounds), '.']
            start = time.monotonic_ns()
            done = subprocess.run(command, env={**env, 'OURO_DATA_DIR': str(data)}, cwd=work,
                                  capture_output=True, timeout=45)
            elapsed = time.monotonic_ns() - start
            (destination / 'stdout.txt').write_bytes(done.stdout); (destination / 'stderr.txt').write_bytes(done.stderr)
            [attempt] = list((data / 'attempts').iterdir())
            receipt = json.loads((attempt / 'jail.json').read_text())
            shutil.copyfile(attempt / 'jail.json', destination / 'jail.json')
            with (attempt / 'trace.ndjson').open('rb') as source, gzip.open(destination / 'trace.ndjson.gz', 'wb') as target:
                shutil.copyfileobj(source, target)
            events = [json.loads(line) for line in done.stdout.splitlines()]
            first = next(e for e in events if e['op'] == 'perf-start')
            last = next(e for e in events if e['op'] == 'fileops')
            healthy = (receipt['phase'] == 'settled' and receipt['containment'] == 'enforced'
                       and receipt['lifetime']['tree_empty'] is True and receipt['lifetime']['integrity'] == 'verified'
                       and receipt['state_cleanup'] == 'complete' and receipt['outcome']['code'] == 0
                       and all(not c['gaps'] for c in receipt['coverage'].values())
                       and receipt['coverage']['fs.write']['observed_count'] == args.rounds * 3)
            # Fixture framing is the same CLOCK_MONOTONIC work interval used by xtask perf.
            row = {'name': name, 'iteration': iteration, 'arm': arm, 'exit': done.returncode,
                   'wall_ns': elapsed, 'fixture_start': first, 'fixture_end': last,
                   'load1': os.getloadavg()[0], 'receipt_healthy': healthy,
                   'trace_sha256': sha256(attempt / 'trace.ndjson')}
            meta['rows'].append(row); save()
            if not healthy or done.returncode != 0:
                meta['status'] = 'failed'; save(); raise RuntimeError(f'failed trial {name}')
            shutil.rmtree(data)
        print(f'round {iteration} complete', flush=True)
    for arm, path in paths.items():
        if sha256(path) != meta['binary_sha256'][arm]: raise ValueError('binary changed during measurement')
    meta['status'] = 'completed'; save()


if __name__ == '__main__':
    main()
