#!/usr/bin/env python3
"""Retain randomized pre-exec-placement pilots with strict, unchanged policies.

This is a candidate diagnostic, not the final clean-build competitor score.
No provider or real credential is used. Both arms run the original workload.c
no-op and have the same workspace, environment, limits and launch definitions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import time


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def verified(receipt, profile):
    active = ['exec', 'fs.write', 'fs.deny', 'net', 'limits']
    if profile == 'vault':
        active.append('proxy.net')
    return (receipt.get('phase') == 'settled'
            and receipt.get('containment') == 'enforced'
            and receipt.get('exec_observed') is True
            and receipt.get('policy', {}).get('observe') == 'on'
            and receipt.get('policy', {}).get('evidence') == 'strict'
            and receipt.get('observer', {}).get('attached') is True
            and receipt.get('observer', {}).get('backend') == 'ptrace'
            and receipt.get('lifetime', {}).get('tree_empty') is True
            and receipt.get('lifetime', {}).get('integrity') == 'verified'
            and receipt.get('outcome', {}).get('kind') == 'exited'
            and all(receipt.get('coverage', {}).get(name, {}).get('status') == 'active'
                    for name in active)
            and all(not value.get('gaps')
                    for value in receipt.get('coverage', {}).values())
            and (profile != 'tool'
                 or receipt.get('coverage', {}).get('proxy.net', {}).get('status')
                 == 'unsupported'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--workload-source', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=30)
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    work, private, output = (root / name for name in ('work', 'private', 'results'))
    for path in (work, private, output, private / 'home', private / 'config'):
        path.mkdir(mode=0o700)
    config = private / 'config' / 'launch'
    config.mkdir(mode=0o700)
    source = private / 'fixture-token'
    source.write_text('fixture-paired-token')
    source.chmod(0o600)
    profile = ('name="probe"\njail="agent"\nhome_is_state=true\n'
               '[credentials.api]\nmode="vault"\nsource=' + json.dumps(str(source))
               + '\nhosts=["http://127.0.0.1:54321"]\nallow_plaintext=true\n'
               'header={name="x-api-key"}\n[network]\nallow=["127.0.0.1:54321"]\n')
    profile_path = config / 'probe.toml'
    profile_path.write_text(profile)
    profile_path.chmod(0o600)
    shutil.copyfile(args.workload_source, root / 'workload.c')
    subprocess.run(['cc', '-O2', str(root / 'workload.c'), '-o', str(work / 'workload')],
                   check=True, capture_output=True)
    # The original suite's small repository fixture is shared by both arms.
    for name in ('inputs', 'outputs'):
        (work / name).mkdir()
    for index in range(1000):
        (work / 'inputs' / f'f{index:04d}').write_bytes(b'x' * 4096)
    subprocess.run(['git', 'init', '-q', str(work)], check=True, capture_output=True)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(private / 'home'),
           'LANG': 'C', 'LC_ALL': 'C', 'OURO_CONFIG_DIR': str(config.parent),
           'OURO_DATA_DIR': str(private / 'data'),
           'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()),
           'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/' + str(os.getuid()) + '/bus',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    binaries = {'before': args.before.resolve(), 'after': args.after.resolve()}
    versions = {name: json.loads(subprocess.check_output([str(binary), 'version', '--json']))
                for name, binary in binaries.items()}
    apparmor = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
    save(output / 'metadata.json', {
        'schema': 'preexec-placement-pilot/1', 'candidate_pilot': True,
        'excluded_from_final_competitor_scores': True, 'seed': 20261013,
        'samples': args.samples, 'warmup_rounds': 3, 'host': platform.uname()._asdict(),
        'cpu_count': os.cpu_count(), 'versions': versions,
        'binary_sha256': {name: digest(path) for name, path in binaries.items()},
        'workload_source_sha256': digest(root / 'workload.c'),
        'profile_sha256': digest(profile_path), 'environment': env,
        'bwrap': {'path': str(Path('/usr/bin/bwrap').resolve()),
                  'sha256': digest(Path('/usr/bin/bwrap'))},
        'apparmor_restrict_unprivileged_userns': apparmor.read_text().strip()
            if apparmor.exists() else None,
    })
    rows = []
    rng = random.Random(20261013)
    for pair in range(-3, args.samples):
        arms = [(name, kind) for kind in ('tool', 'vault') for name in binaries]
        rng.shuffle(arms)
        for name, kind in arms:
            case = output / f'{pair + 3:02d}-{kind}-{name}'
            case.mkdir()
            argv = [str(binaries[name]), 'run']
            argv += ['--profile', 'tool'] if kind == 'tool' else ['--launch', 'probe']
            argv += ['--workspace', str(work), '--limit', 'wall=20s', '--observe', 'on',
                     '--evidence', 'strict', '--receipt', str(case / 'jail.json'),
                     '--', str(work / 'workload'), 'noop']
            began = time.perf_counter_ns()
            run = subprocess.run(argv, env=env, capture_output=True, timeout=50)
            elapsed = (time.perf_counter_ns() - began) / 1e6
            (case / 'stdout.log').write_bytes(run.stdout)
            (case / 'stderr.log').write_bytes(run.stderr)
            receipt = json.loads((case / 'jail.json').read_text())
            attempt = private / 'data' / 'attempts' / receipt['attempt_id']
            for filename in ('policy.json', 'trace.ndjson'):
                if (attempt / filename).exists():
                    shutil.copyfile(attempt / filename, case / filename)
            try:
                payload = json.loads(run.stdout)
            except ValueError:
                payload = {}
            valid = (run.returncode == 0 and verified(receipt, kind)
                     and payload.get('workload') == 'noop' and payload.get('count') == 1
                     and payload.get('checksum') == 0)
            row = {'pair': pair, 'warmup': pair < 0, 'arm': name, 'profile': kind,
                   'argv': argv, 'exit': run.returncode, 'elapsed_ms': elapsed,
                   'load': os.getloadavg(), 'valid': valid, 'payload': payload,
                   'artifact': case.name}
            rows.append(row)
            with (output / 'timings.ndjson').open('a') as file:
                file.write(json.dumps(row) + '\n')
        print(json.dumps({'pair': pair, 'valid': all(r['valid'] for r in rows[-4:])}),
              flush=True)
    summaries = {}
    for kind in ('tool', 'vault'):
        pairs = [{r['arm']: r['elapsed_ms'] for r in rows
                  if r['pair'] == pair and r['profile'] == kind and r['valid']}
                 for pair in range(args.samples)]
        complete = [pair for pair in pairs if len(pair) == 2]
        differences = [pair['after'] - pair['before'] for pair in complete]
        boot_rng = random.Random(20261013)
        boots = sorted(statistics.median(boot_rng.choices(differences, k=len(differences)))
                       for _ in range(10000)) if differences else []
        summaries[kind] = {
            'complete_pairs': len(complete),
            'before_median_ms': statistics.median(p['before'] for p in complete)
                if complete else None,
            'after_median_ms': statistics.median(p['after'] for p in complete)
                if complete else None,
            'paired_difference_median_ms': statistics.median(differences)
                if differences else None,
            'paired_difference_bootstrap_ci95_ms': [boots[249], boots[9749]]
                if boots else None,
        }
    result = {'schema': 'preexec-placement-pilot/1', 'candidate_pilot': True,
              'excluded_from_final_competitor_scores': True, 'profiles': summaries,
              'invalid_runs': [row for row in rows if not row['valid']]}
    save(output / 'summary.json', result)
    print(json.dumps(result), flush=True)
    return int(bool(result['invalid_runs']))


if __name__ == '__main__':
    raise SystemExit(main())
