#!/usr/bin/env python3
"""Live quota checks on an operator-created, disposable ext4/XFS loop mount.

Run as root with --mount, --user, --binary and --out. Only this loop volume's
user quota is changed; jail commands run as --user. The output stays outside
the quota volume. No filesystem is created, mounted or removed by this script.
Linux x86_64 only (quotactl_fd syscall 443).
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import time


class Dq(ctypes.Structure):
    _fields_ = [(k, ctypes.c_uint64) for k in
                ['bhard', 'bsoft', 'space', 'ihard', 'isoft', 'inodes', 'btime', 'itime']]
    _fields_.append(('valid', ctypes.c_uint32))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ['mount', 'binary', 'out']:
        p.add_argument('--' + key, type=Path, required=True)
    p.add_argument('--user', required=True)
    p.add_argument('--expect-refusal', choices=['unenforced', 'realtime', 'idmapped'])
    p.add_argument('--other-mount', type=Path)
    a = p.parse_args()
    assert os.geteuid() == 0 and os.uname().machine == 'x86_64'
    a.mount, a.binary, a.out = a.mount.resolve(), a.binary.resolve(), a.out.resolve()
    mount = json.loads(subprocess.check_output(['findmnt', '--json', '--target', str(a.mount)]))['filesystems'][0]
    assert Path(mount['target']) == a.mount and mount['source'].startswith('/dev/loop')
    assert mount['fstype'] in ['ext4', 'xfs']
    assert not a.out.is_relative_to(a.mount)
    user = pwd.getpwnam(a.user)
    assert user.pw_uid != 0
    a.out.mkdir(mode=0o700)
    os.chown(a.out, user.pw_uid, user.pw_gid)
    ws, scratch = a.mount / 'workspace', a.mount / 'scratch'
    for path in [ws, scratch]:
        if a.expect_refusal == 'idmapped':
            # Root need not be mapped on this mount. Provision these two
            # directories through its source mount before running this case.
            assert path.is_dir() and path.stat().st_uid == user.pw_uid
            assert not list(path.iterdir())
            continue
        path.mkdir(exist_ok=True)
        assert not list(path.iterdir()), 'use empty disposable directories'
        os.chown(path, user.pw_uid, user.pw_gid)
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(a.mount, os.O_RDONLY)

    def quota(bhard=8192, ihard=64, bsoft=0, isoft=0):
        q = Dq(bhard=bhard, ihard=ihard, bsoft=bsoft, isoft=isoft, valid=5)
        rc = libc.syscall(443, fd, ctypes.c_uint(0x800008 << 8), user.pw_uid, ctypes.byref(q))
        assert rc == 0, os.strerror(ctypes.get_errno())
        readback = Dq()
        assert libc.syscall(443, fd, ctypes.c_uint(0x800007 << 8), user.pw_uid, ctypes.byref(readback)) == 0
        return {k: getattr(readback, k) for k, _ in Dq._fields_}

    rows = []
    binary_hash = hashlib.sha256(a.binary.read_bytes()).hexdigest()
    (a.out / 'metadata.json').write_text(json.dumps({
        'mount': mount, 'uid': user.pw_uid, 'binary_sha256': binary_hash,
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'host': list(os.uname()),
        'version': json.loads(subprocess.check_output([str(a.binary), 'version', '--json'])),
    }, indent=2) + '\n')
    (a.out / 'disk_quotas.py').write_bytes(Path(__file__).read_bytes())

    def run(label, script, *, observe='on', limits=('storage=8MiB', 'inodes=64'), extra=(), refused=False,
            reason=None,
            after_ready=None, filesystems=1):
        receipt = a.out / (label + '.receipt.json')
        command = ['runuser', '-u', a.user, '--', 'env',
                   'XDG_DATA_HOME=' + str(a.out / 'data'),
                   'XDG_CONFIG_HOME=' + str(a.out / 'config'),
                   str(a.binary), 'run', '--profile', 'tool', '--workspace', str(ws),
                   '--scratch', str(scratch), '--observe', observe, '--receipt', str(receipt),
                   '--limit', 'wall=10s']
        for limit in limits:
            command += ['--limit', limit]
        command += list(extra) + ['--', '/usr/bin/python3', '-c', script]
        start = time.monotonic_ns()
        if after_ready:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 10
                while not (ws / 'READY').exists():
                    assert process.poll() is None and time.monotonic() < deadline, 'target did not start'
                    time.sleep(.01)
                after_ready()
                stdout, stderr = process.communicate(timeout=20)
                result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                (ws / 'READY').unlink(missing_ok=True)
        else:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        row = {'label': label, 'command': command, 'exit': result.returncode,
               'stdout': result.stdout, 'stderr': result.stderr,
               'elapsed_ns': time.monotonic_ns() - start, 'receipt': receipt.name}
        rows.append(row)
        (a.out / 'runs.json').write_text(json.dumps(rows, indent=2) + '\n')
        if after_ready:
            assert result.returncode != 0 and 'SURVIVED' not in result.stdout, row
        else:
            assert result.returncode == (125 if refused else 0), row
        rec = json.loads(receipt.read_text())
        if refused:
            assert not result.stdout and not (ws / 'TARGET_RAN').exists(), row
            assert rec['outcome']['kind'] == 'refused', rec
            if reason:
                assert reason in json.dumps(rec['errors']), rec['errors']
        else:
            assert rec['phase'] == 'settled' and rec['lifetime']['tree_empty'] is True, rec
            storage = rec['lifetime']['native']['details']['storage_ceiling']
            assert storage['mechanism'] == 'filesystem-user-quota', storage
            assert storage['filesystems'] == filesystems, storage
            assert storage['capacity_bytes'] == 8388608 * filesystems, storage
            assert storage['capacity_inodes'] == 64 * filesystems, storage
            assert storage['hard_links'] == 'denied', storage
            if after_ready:
                assert rec['outcome']['cause'] == 'storage_enforcement_lost', rec
                assert storage['enforcement_lost'] == 'user quota changed after admission', storage
        print(label + ': passed', flush=True)
        return rec

    marker = "open('TARGET_RAN','w').close();print('TARGET_RAN')"
    if a.expect_refusal:
        try:
            reason = {'unenforced': 'user quota accounting and enforcement must both be active',
                      'realtime': 'XFS realtime storage quotas are not supported',
                      'idmapped': 'storage ceilings do not support idmapped writable mounts'}[a.expect_refusal]
            run(a.expect_refusal, marker, refused=True, reason=reason)
            (a.out / 'complete.json').write_text(json.dumps({'checks': len(rows), 'passed': True}) + '\n')
        finally:
            os.close(fd)
        return
    try:
        quota()
        foreign_source = a.mount / 'foreign'
        assert not foreign_source.exists()
        foreign_source.write_text('read-only foreign inode')
        foreign_source.chmod(0o666)
        for observe in ['on', 'off']:
            for mode in ['bytes', 'inodes']:
                script = '''import errno,json,os,time
mode=%r
names=[]
try:
 for i in range(128):
  name='fill-%%d'%%i; names.append(name)
  with open(name,'wb',buffering=0) as f:
   if mode=='bytes':
    for _ in range(256): f.write(b'x'*4096)
except OSError as e:
 assert e.errno==errno.EDQUOT, e
 print(json.dumps({'mode':mode,'errno':e.errno,'files':len(names)}),flush=True)
 time.sleep(.3)
else: raise AssertionError('quota did not stop allocation')
finally:
 for name in names:
  if os.path.exists(name): os.unlink(name)
''' % mode
                rec = run(mode + '-' + observe, script, observe=observe)
                key = 'storage' if mode == 'bytes' else 'inodes'
                assert next(v for v in rec['applied']['limits'] if v['key'] == key)['hit'] is True, rec
            run('hardlinks-' + observe, '''import errno,os
open('own','w').close()
for source in ['own',%r]:
 try: os.link(source,'imported')
 except OSError as e: assert e.errno==errno.EPERM,e
 else: raise AssertionError('hard link imported an inode')
os.rename('own','renamed'); os.unlink('renamed')
print('hardlinks denied; rename works')
''' % str(a.mount / 'foreign'), observe=observe,
                extra=('--ro', str(a.mount / 'foreign')))
        for label, limits in [('bytes-too-small', ('storage=4MiB',)), ('inodes-too-small', ('inodes=32',))]:
            run(label, marker, limits=limits, refused=True, reason='exceeds requested ceiling')
        for label, kwargs in [('bytes-soft-only', {'bhard': 0, 'bsoft': 8192}),
                              ('inodes-soft-only', {'ihard': 0, 'isoft': 64}),
                              ('unlimited', {'bhard': 0, 'ihard': 0})]:
            quota(**kwargs)
            run(label, marker, refused=True, reason='no hard ceiling for a requested resource')
        quota()
        foreign = ws / 'wrong-owner'
        foreign.write_text('foreign quota identity')
        foreign.chmod(0o666)
        run('foreign-owned-file', marker, refused=True, reason='different quota identity')
        run('readonly-nested-foreign', '''import errno
print(open(%r).read())
try: open(%r,'w')
except OSError as e: assert e.errno==errno.EROFS,e
else: raise AssertionError('nested readonly grant was writable')
''' % (str(foreign), str(foreign)), extra=('--ro', str(foreign)))
        foreign.unlink()
        foreign.mkdir(mode=0o777)
        run('foreign-owned-directory', marker, refused=True, reason='different quota identity')
        foreign.rmdir()
        run('foreign-writable-alias', marker, extra=('--rw', str(foreign_source)),
            refused=True, reason='different quota identity')
        # A read-only grant on an unrelated disk must not create write authority.
        run('readonly-foreign', "print(open(%r).read())" % str(a.mount / 'foreign'),
            extra=('--ro', str(a.mount / 'foreign')))
        if a.other_mount:
            other = a.other_mount.resolve() / 'workspace'
            assert other.is_dir() and other.stat().st_dev != ws.stat().st_dev
            run('two-filesystems-too-small', marker, extra=('--rw', str(other)),
                refused=True, reason='exceeds requested ceiling')
            run('two-filesystems-combined', 'print("two budgets")', extra=('--rw', str(other)),
                limits=('storage=16MiB', 'inodes=128'), filesystems=2)
        for observe in ['on', 'off']:
            quota()
            run('quota-changed-' + observe,
                "import time;open('READY','w').close();time.sleep(5);print('SURVIVED')",
                observe=observe, after_ready=lambda: quota(bhard=16384))
        assert hashlib.sha256(a.binary.read_bytes()).hexdigest() == binary_hash
        (a.out / 'complete.json').write_text(json.dumps({'checks': len(rows), 'passed': True}) + '\n')
    finally:
        quota()
        os.close(fd)


if __name__ == '__main__':
    main()
