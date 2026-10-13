#!/usr/bin/env python3
"""Temporarily lease the inactive benchmark proxy's fixed API port.

Verify exact argv/uid and absence of established connections before signalling
the benchmark-owned process through a pidfd. Preserve its environment only in
a private 0600 snapshot, then restore the same argv/environment/store in finally.
No environment values, store contents, or restore logs enter exported evidence.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import time


def birth(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--private', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('lease interrupted; restore the owned original proxy')
    signal.signal(signal.SIGTERM, interrupted)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    assert command
    # Preserve the exact invocation spelling as well as the executable's
    # identity. The frozen benchmark binary/config may be reached by symlink.
    original = [str(args.binary.absolute()), 'serve', '-C', str(args.config.absolute())]
    proc = Path(f'/proc/{args.pid}')
    raw_argv = [v.decode() for v in (proc / 'cmdline').read_bytes().split(b'\0') if v]
    assert raw_argv == original and proc.stat().st_uid == os.getuid()
    executable, expected = (proc / 'exe').stat(), args.binary.stat()
    assert (executable.st_dev, executable.st_ino) == (expected.st_dev, expected.st_ino)
    original_birth = birth(args.pid)
    pidfd = os.pidfd_open(args.pid)
    assert birth(args.pid) == original_birth
    sockets = set()
    for path in (proc / 'fd').iterdir():
        try:
            target = path.readlink().as_posix()
        except OSError:
            continue
        if target.startswith('socket:['):
            sockets.add(target.removeprefix('socket:[').removesuffix(']'))
    for table in ('tcp', 'tcp6'):
        for line in Path('/proc/net/' + table).read_text().splitlines()[1:]:
            fields = line.split()
            assert not (fields[3] == '01' and fields[9] in sockets), \
                'original benchmark proxy has an active TCP connection; leave it running'
    args.private.mkdir(mode=0o700, parents=True, exist_ok=False)
    values = (proc / 'environ').read_bytes().split(b'\0')
    environment = {k.decode(): v.decode() for k, v in
                   (entry.split(b'=', 1) for entry in values if b'=' in entry)}
    snapshot = args.private / 'restore.json'
    descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump({'pid': args.pid, 'birth': original_birth,
                   'argv': original, 'environment': environment}, output)
    assert birth(args.pid) == original_birth
    facts = {'schema': 'owned-benchmark-proxy-lease/1', 'original_pid': args.pid,
             'original_birth': original_birth, 'exact_argv_verified': True,
             'owner_uid_verified': True, 'no_original_established_tcp': True,
             'executable_inode_matches_argv_path': True,
             'private_environment_snapshot_exported': False, 'original_store_preserved': True}
    fixture = None
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        poll = select.poll()
        poll.register(pidfd, select.POLLIN)
        if not poll.poll(5000):
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            assert poll.poll(5000), 'owned original proxy did not terminate'
        facts['original_terminal_verified'] = True
        fixture = subprocess.Popen(command)
        facts['fixture_exit'] = fixture.wait()
    finally:
        if fixture is not None and fixture.poll() is None:
            fixture.terminate()
            try:
                fixture.wait(timeout=30)
            except subprocess.TimeoutExpired:
                fixture.kill()
                fixture.wait(timeout=10)
        os.close(pidfd)
        log_path = args.private / 'restored-proxy.log'
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as log:
            restored = subprocess.Popen(original, env=environment, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        # A live process alone is not readiness; verify the same restored proxy
        # owns the fixed management listener without reading its stored secrets.
        deadline = time.monotonic() + 15
        ready = False
        while time.monotonic() < deadline:
            if restored.poll() is not None:
                break
            state = subprocess.check_output(['ss', '-H', '-ltnp', 'sport = :43080'], text=True)
            if f'pid={restored.pid},' in state:
                ready = True
                break
            time.sleep(.1)
        facts.update({'restored_pid': restored.pid, 'restored_birth': birth(restored.pid)
                      if restored.poll() is None else None, 'fixed_listener_owner_verified': ready})
        args.evidence.write_text(json.dumps(facts, indent=2) + '\n')
        print(json.dumps(facts), flush=True)
        assert ready, 'restoration failed; preserve private recovery snapshot'
    return facts['fixture_exit']


if __name__ == '__main__':
    raise SystemExit(main())
