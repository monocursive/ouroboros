#!/usr/bin/env python3
"""Retain and verify this run's private stopped proxy store, then reclaim space."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import time

root = Path.home() / 'bench-ouro-startup-native-final'
data = root / 'proxy/data'
archive = root / 'private-proxy-store.tar.gz'
if archive.exists():
    raise SystemExit('Archive already exists')
prefix = str(root / 'bin/greyproxy') + ' serve '
stopped = []
for line in subprocess.check_output(['ps', '-u', str(os.getuid()), '-o', 'pid=,command='], text=True).splitlines():
    bits = line.strip().split(None, 1)
    if len(bits) == 2 and bits[1].startswith(prefix):
        pid = int(bits[0])
        os.kill(pid, signal.SIGTERM)
        stopped.append(pid)
for _ in range(30):
    states = [subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True).stdout.strip() for pid in stopped]
    if all(not state or state.startswith('Z') for state in states):
        break
    time.sleep(.2)
else:
    raise SystemExit('Proxy has not stopped')
def digest(file):
    h = hashlib.sha256()
    for block in iter(lambda: file.read(1024 * 1024), b''):
        h.update(block)
    return h.hexdigest()
files = []
for path in sorted(data.iterdir()):
    assert path.is_file() and not path.is_symlink(), path
    with path.open('rb') as file:
        files.append({'name': path.name, 'bytes': path.stat().st_size, 'sha256': digest(file)})
fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as file, tarfile.open(fileobj=file, mode='w:gz') as tar:
    for row in files:
        tar.add(data / row['name'], arcname=row['name'], recursive=False)
with tarfile.open(archive, 'r:gz') as tar:
    assert sorted(tar.getnames()) == sorted(row['name'] for row in files)
    for row in files:
        with tar.extractfile(row['name']) as file:
            assert digest(file) == row['sha256'], row['name']
for row in files:
    (data / row['name']).unlink()
with archive.open('rb') as file:
    archive_digest = digest(file)
(root / 'results/proxy-store-compression.json').write_text(json.dumps({
    'stopped_pids': stopped, 'files': files, 'original_bytes': sum(row['bytes'] for row in files),
    'archive_bytes': archive.stat().st_size, 'archive_sha256': archive_digest,
    'private_archive': str(archive), 'verified_before_removal': True,
    'exported': False, 'reason': 'Private credential-bearing proxy store; public evidence retains sanitized logs and results.'}, indent=2) + '\n')
