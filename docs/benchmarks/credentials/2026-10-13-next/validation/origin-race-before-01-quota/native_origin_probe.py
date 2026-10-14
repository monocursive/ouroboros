#!/usr/bin/env python3
"""Retain an isolated native process-origin regression attempt and source hashes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--origin', type=Path, required=True)
    p.add_argument('--proxy', type=Path)
    p.add_argument('--target', type=Path, required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--test', default='vault::origin::tests')
    p.add_argument('--expected-exit', type=int, required=True)
    a = p.parse_args()
    os.umask(0o077)
    a.root.mkdir(mode=0o700)
    output, source = a.root / 'results', a.root / 'source'
    output.mkdir()
    source.mkdir()
    with tarfile.open(a.archive, 'r:gz') as archive:
        archive.extractall(source, filter='data')
    files = {'crates/ouro-jail/src/vault/origin.rs': a.origin}
    if a.proxy:
        files['crates/ouro-jail/src/proxy/mod.rs'] = a.proxy
    for rel, actual in files.items():
        shutil.copyfile(actual, source / rel)
        shutil.copyfile(actual, output / ('source-' + actual.name))
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
           'OURO_BUILD_REVISION': a.revision, 'OURO_BUILD_DIRTY': 'true'}
    argv = ['cargo', '+1.98.1', 'test', '--release', '--jobs', '1', '-p', 'ouro-jail',
            '--lib', a.test, '--', '--nocapture', '--test-threads=1']
    record = {'schema': 'native-origin-probe/1', 'base_revision': a.revision, 'dirty': True,
              'archive_sha256': digest(a.archive), 'argv': argv,
              'source_files': {rel: digest(source / rel) for rel in files},
              'target': str(a.target), 'expected_exit': a.expected_exit,
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-V'], env=env, text=True).strip(),
              'scored_performance': False, 'synthetic_protocol_unit_test': True,
              'started_unix': time.time()}
    (output / 'driver.json').write_text(json.dumps(record, indent=2) + '\n')
    with (output / 'test.log').open('wb') as log:
        run = subprocess.run(argv, cwd=source, env=env, stdin=subprocess.DEVNULL,
                             stdout=log, stderr=subprocess.STDOUT)
    record.update({'exit': run.returncode, 'finished_unix': time.time(),
                   'expected_exit_observed': run.returncode == a.expected_exit,
                   'test_log_sha256': digest(output / 'test.log')})
    (output / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'exit': run.returncode, 'expected_exit_observed': record['expected_exit_observed']}))
    return int(not record['expected_exit_observed'])


if __name__ == '__main__':
    raise SystemExit(main())
