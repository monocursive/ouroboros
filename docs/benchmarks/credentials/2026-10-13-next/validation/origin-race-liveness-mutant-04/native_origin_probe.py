#!/usr/bin/env python3
"""Retain an isolated native process-origin regression attempt and source hashes.

The archive is the source tree at --revision; --override REL=PATH (and the
--origin/--proxy shorthands) replace repository files in the extracted copy,
and --record REL names further repository files whose digests are kept.
Every recorded file is copied into the results under source/REL, beside a
copy of this harness, so the run directory alone shows what was built.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

ORIGIN = 'crates/ouro-jail/src/vault/origin.rs'
PROXY = 'crates/ouro-jail/src/proxy/mod.rs'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def overrides(a):
    files = {}
    if a.origin:
        files[ORIGIN] = a.origin
    if a.proxy:
        files[PROXY] = a.proxy
    for item in a.override:
        rel, sep, actual = item.partition('=')
        assert sep and rel and actual, f'--override needs REL=PATH, got {item!r}'
        files[rel] = Path(actual)
    for rel in files:
        assert not Path(rel).is_absolute() and '..' not in Path(rel).parts, rel
    return files


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--origin', type=Path, help=f'override {ORIGIN}')
    p.add_argument('--proxy', type=Path, help=f'override {PROXY}')
    p.add_argument('--override', action='append', default=[], metavar='REL=PATH')
    p.add_argument('--record', action='append', default=[], metavar='REL')
    p.add_argument('--target', type=Path, required=True)
    p.add_argument('--revision', required=True)
    # Both modules: `tests` (portable) and `linux_tests` (the rendezvous).
    p.add_argument('--test', default='vault::origin')
    p.add_argument('--operation', choices=['test', 'clippy', 'build'], default='test')
    p.add_argument('--expected-exit', type=int, required=True)
    a = p.parse_args()
    harness = Path(__file__).resolve()
    replaced = overrides(a)
    os.umask(0o077)
    a.root.mkdir(mode=0o700)
    output, source = a.root / 'results', a.root / 'source'
    output.mkdir()
    source.mkdir()
    with tarfile.open(a.archive, 'r:gz') as archive:
        archive.extractall(source, filter='data')
    # The tree is dirty exactly when an override differs from the archive.
    archived = {rel: digest(source / rel) if (source / rel).is_file() else None
                for rel in replaced}
    for rel, actual in replaced.items():
        shutil.copyfile(actual, source / rel)
    dirty = any(archived[rel] != digest(source / rel) for rel in replaced)
    recorded = sorted(set(replaced) | set(a.record) | {ORIGIN})
    for rel in recorded:
        copy = output / 'source' / rel
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / rel, copy)
    shutil.copyfile(harness, output / harness.name)
    assert a.target.is_dir() and a.target.stat().st_uid == os.getuid()
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if proc.stat().st_uid != os.getuid():
                continue
            env = (proc / 'environ').read_bytes().split(b'\0')
            assert ('CARGO_TARGET_DIR=' + str(a.target)).encode() not in env, 'owned build cache is active'
        except (OSError, ProcessLookupError):
            pass
    env = {'HOME': str(Path.home()), 'PATH': str(Path.home() / '.cargo/bin') + ':/usr/bin:/bin',
           'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'CARGO_TARGET_DIR': str(a.target),
           'OURO_BUILD_REVISION': a.revision, 'OURO_BUILD_DIRTY': 'true' if dirty else 'false'}
    argv = ['cargo', '+1.98.1', 'test', '--release', '--jobs', '1', '-p', 'ouro-jail',
            '--lib', a.test, '--', '--nocapture', '--test-threads=1']
    if a.operation == 'clippy':
        argv = ['cargo', '+1.98.1', 'clippy', '--release', '--jobs', '1', '-p', 'ouro-jail',
                '--all-targets', '--', '-D', 'warnings']
    elif a.operation == 'build':
        argv = ['cargo', '+1.98.1', 'build', '--release', '--jobs', '1', '-p', 'ouro-jail']
    record = {'schema': 'native-origin-probe/2', 'base_revision': a.revision, 'dirty': dirty,
              'harness': harness.name, 'harness_sha256': digest(harness),
              'archive_sha256': digest(a.archive), 'argv': argv,
              'overridden_files': sorted(replaced),
              'source_files': {rel: digest(source / rel) for rel in recorded},
              'target': str(a.target), 'expected_exit': a.expected_exit,
              'operation': a.operation,
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-V'], env=env, text=True).strip(),
              # In-crate unit tests drive the rendezvous over socket pairs, not a jail.
              'scored_performance': False, 'synthetic_protocol_unit_test': a.operation == 'test',
              'started_unix': time.time()}
    (output / 'driver.json').write_text(json.dumps(record, indent=2) + '\n')
    with (output / 'test.log').open('wb') as log:
        run = subprocess.run(argv, cwd=source, env=env, stdin=subprocess.DEVNULL,
                             stdout=log, stderr=subprocess.STDOUT)
    text = (output / 'test.log').read_text()
    summaries = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed;', text)
    native_tests_ran = bool(summaries and sum(int(v[1]) + int(v[2]) for v in summaries) > 0)
    # A filter can match only the portable module and still "run" tests.
    linux_tests_ran = len(re.findall(r'^test vault::origin::linux_tests::\S+ \.\.\. (?:ok|FAILED)$',
                                     text, re.M))
    expected = run.returncode == a.expected_exit and (
        native_tests_ran if a.operation == 'test' else 'Finished `release` profile' in text)
    record.update({'exit': run.returncode, 'finished_unix': time.time(),
                   'native_tests_ran': native_tests_ran, 'linux_tests_ran': linux_tests_ran,
                   'test_summaries': summaries,
                   'expected_exit_observed': expected,
                   'test_log_sha256': digest(output / 'test.log')})
    (output / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'exit': run.returncode, 'expected_exit_observed': record['expected_exit_observed']}))
    return int(not record['expected_exit_observed'])


if __name__ == '__main__':
    raise SystemExit(main())
