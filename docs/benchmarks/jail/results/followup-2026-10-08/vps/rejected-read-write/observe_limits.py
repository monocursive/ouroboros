#!/usr/bin/env python3
"""Paired file-work benchmark and bounded resource probes; use private test volumes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--volume', type=Path, help='Owned, isolated 8 MiB / 64 inode tmpfs, pre-provisioned by operator')
    p.add_argument('--performance-only', action='store_true', help='Run paired workloads without the separate quota probes.')
    p.add_argument('--before', type=Path, required=True)
    p.add_argument('--after', type=Path, required=True)
    p.add_argument('--samples', type=int, default=30)
    args = p.parse_args()
    if not args.performance_only and args.volume is None:
        p.error('--volume is required unless --performance-only is selected')
    if not 1 <= args.samples <= 1000:
        p.error('--samples must be 1..1000')
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    out = root / 'results'; out.mkdir()
    work = root / 'work'; work.mkdir()
    for name in ['inputs', 'outputs']:
        (work / name).mkdir()
    for i in range(1000):
        (work / 'inputs' / f'f{i:04d}').write_bytes(bytes([i % 251]) * 4096)
    source = Path(__file__).with_name('workload.c')
    payload = work / 'workload'
    subprocess.run(['cc', '-O2', str(source), '-o', str(payload)], check=True)
    (out / 'workload.c').write_bytes(source.read_bytes())
    env = dict(os.environ, XDG_DATA_HOME=str(root / 'data'), XDG_CONFIG_HOME=str(root / 'config'))
    metadata = {'before_sha256': hashlib.sha256(args.before.read_bytes()).hexdigest(),
                'after_sha256': hashlib.sha256(args.after.read_bytes()).hexdigest(),
                'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'workload_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'host': os.uname()._asdict() if hasattr(os.uname(), '_asdict') else list(os.uname()),
                'samples': args.samples, 'seed': 20261001,
                'after_version': json.loads(subprocess.check_output([str(args.after), 'version', '--json']))}
    (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (out / 'observe_limits.py').write_bytes(Path(__file__).read_bytes())
    rows = []

    def run(arm, label, argv, *, workspace=work, limits=(), scratch=None, observe='on'):
        idx = len(rows)
        receipt = out / f'{idx:04d}.receipt.json'
        cmd = list(map(str, argv))
        if arm != 'direct':
            binary = args.before if arm == 'before' else args.after
            cmd = [str(binary), 'run', '--profile', 'tool', '--workspace', str(workspace),
                   '--observe', observe, '--receipt', str(receipt), '--limit', 'wall=10s'] + sum((['--limit', x] for x in limits), []) + (['--scratch', str(scratch)] if scratch else []) + ['--'] + cmd
        start = time.monotonic_ns()
        r = subprocess.run(cmd, cwd=workspace, env=env, capture_output=True, timeout=30)
        elapsed = time.monotonic_ns() - start
        row = {'arm': arm, 'label': label, 'command': cmd, 'exit': r.returncode,
               'elapsed_ns': elapsed, 'loadavg': os.getloadavg(), 'stdout': r.stdout.decode(errors='replace'),
               'stderr': r.stderr.decode(errors='replace')}
        if receipt.exists():
            row['receipt'] = receipt.name
            rec = json.loads(receipt.read_text())
            row['phase'] = rec['phase']
            row['limits'] = rec['applied']['limits']
            row['coverage'] = rec.get('coverage')
            row['outcome'] = rec.get('outcome')
            row['lifetime'] = rec.get('lifetime')
        rows.append(row)
        (out / 'runs.json').write_text(json.dumps(rows, indent=2) + '\n')
        return row

    rng = random.Random(20261001)
    for round_no in range(-3, args.samples):
        tasks = [(arm, mode) for arm in ['direct', 'before', 'after'] for mode in ['reads', 'writes']]
        rng.shuffle(tasks)
        for arm, mode in tasks:
            r = run(arm, f'{mode}:{round_no}', [payload, mode])
            assert r['exit'] == 0, r
            record = json.loads(r['stdout'])
            assert record['count'] == 1000
            assert record['checksum'] == (1024000 if mode == 'writes' else sum(i % 251 for i in range(1000)) * 4096)
            r['payload_ns'] = record['payload_ns']
            if mode == 'writes':
                assert all((work / 'outputs' / f'f{i:04d}').read_bytes() == b'x' * 1024 for i in range(1000))
            if arm != 'direct':
                assert r['phase'] == 'settled' and r['outcome']['kind'] == 'exited' and r['outcome']['code'] == 0, r
                assert r['lifetime']['tree_empty'] is True, r['lifetime']
                assert all(not c['gaps'] for c in r['coverage'].values()), r['coverage']
                if mode == 'writes': assert r['coverage']['fs.write']['observed_count'] >= 1000, r['coverage']
        print(f'round {round_no} complete', flush=True)
    summary = {}
    for mode in ['reads', 'writes']:
        summary[mode] = {}
        for arm in ['direct', 'before', 'after']:
            selected = [r for r in rows if r['arm'] == arm and r['label'].startswith(mode + ':') and int(r['label'].split(':')[1]) >= 0]
            summary[mode][arm] = {key.replace('_ns', '_ms'): statistics.median(r[key] / 1e6 for r in selected) for key in ['elapsed_ns', 'payload_ns']}
    (out / 'performance.json').write_text(json.dumps(summary, indent=2) + '\n')
    (out / 'runs.json').write_text(json.dumps(rows, indent=2) + '\n')

    if args.performance_only:
        for arm in ['before', 'after']:
            assert hashlib.sha256(getattr(args, arm).read_bytes()).hexdigest() == metadata[arm + '_sha256'], 'binary changed during measurement'
        (out / 'complete.json').write_text(json.dumps({'performance_samples': args.samples,
            'resource_checks': 'not_requested', 'rows': len(rows)}) + '\n')
        print(json.dumps(summary, indent=2))
        return

    volume = args.volume.resolve()
    ws, scratch = volume / 'ws', volume / 'scratch'
    ws.mkdir(exist_ok=True); scratch.mkdir(exist_ok=True)
    for observe in ['on', 'off']:
        for mode in ['bytes', 'inodes']:
            script = '''import errno,json,os,time
mode = %r
created=[]
try:
 for i in range(128):
  name='ceiling-%%d'%%i; created.append(name)
  with open(name,'wb') as f:
   if mode=='bytes': f.write(b'x'*1048576)
except OSError as e:
 assert e.errno==errno.ENOSPC, e
 print(json.dumps({'mode':mode,'errno':e.errno,'files':len(created),'free_blocks':os.statvfs('.').f_bavail,'free_inodes':os.statvfs('.').f_ffree}),flush=True)
 time.sleep(.3)
else: raise AssertionError('ceiling never stopped allocation')
finally:
 for name in created:
  if os.path.exists(name): os.unlink(name)
''' % mode
            r = run('after', f'{mode}-{observe}', ['/usr/bin/python3', '-c', script], workspace=ws, scratch=scratch, limits=['storage=8MiB', 'inodes=64'], observe=observe)
            assert r['exit'] == 0, r
            assert json.loads(r['stdout'])['errno'] == 28
            key = 'storage' if mode == 'bytes' else 'inodes'
            assert next(x for x in r['limits'] if x['key'] == key)['hit'] is True, r
        r = run('after', f'swap-zero-{observe}', ['/usr/bin/python3', '-c', 'x=bytearray(96*1024*1024); print("survived")'], limits=['mem=64MiB', 'swap=0'], observe=observe)
        assert r['exit'] != 0 and 'survived' not in r['stdout'], r
        assert next(x for x in r['limits'] if x['key'] == 'swap')['applied'] is True, r
        assert next(x for x in r['limits'] if x['key'] == 'mem')['hit'] is True, r
        assert r['outcome']['cause'] == 'memory_oom' and r['lifetime']['tree_empty'] is True, r
    for label, workspace, limits in [('too-small',ws,['storage=4MiB']), ('inodes-too-small',ws,['inodes=32']), ('unbounded',work,['storage=8MiB'])]:
        r = run('after',label,['/usr/bin/printf','TARGET_RAN'],workspace=workspace,scratch=scratch,limits=limits)
        assert r['exit'] == 125 and not r['stdout'], r
    r = run('after', 'dev-shm-sealed', ['/usr/bin/python3', '-c', 'import errno\ntry: open("/dev/shm/escape", "w")\nexcept OSError as e: assert e.errno==errno.EROFS\nelse: raise AssertionError("writable shm")'], workspace=ws,scratch=scratch,limits=['storage=8MiB','inodes=64'])
    assert r['exit'] == 0, r
    for arm in ['before', 'after']:
        assert hashlib.sha256(getattr(args, arm).read_bytes()).hexdigest() == metadata[arm + '_sha256'], 'binary changed during measurement'
    print(json.dumps(summary, indent=2))
    (out / 'complete.json').write_text(json.dumps({'performance_samples':args.samples, 'resource_checks':'passed', 'rows':len(rows)})+'\n')


if __name__ == '__main__':
    main()
