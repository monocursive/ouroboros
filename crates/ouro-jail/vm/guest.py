#!/usr/bin/env python3
"""Single-attempt guest controller. Installed root-owned outside the jail."""
import base64
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import selectors
import socket
import stat
import subprocess
import time

PORT = 1024
LEASE = 2.0
# The transport limits live here because this file is installed alone in the
# guest; run.py imports them, so both ends enforce the same values.
MAX_LINE = 2 * 1024 * 1024
MAX_BYTES = 32 * 1024 * 1024
MAX_FILE = 512 * 1024
MAX_FILES = 5000
WORKSPACE = Path('/home/ouro/workspace')
EVIDENCE = Path('/home/ouro/evidence')


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def audit(event, **fields):
    with open('/dev/hvc0', 'w') as output:
        output.write('OURO_VM ' + json.dumps({'event': event, **fields}) + '\n')


def notify():
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect('\0' + address[1:] if address.startswith('@') else address)
            sock.sendall(b'READY=1\nWATCHDOG=1')


def poweroff(reason):
    # VZ may retain its service while the Mac client is SIGSTOP'ed, even after
    # guest poweroff. First kill and verify the Linux workload boundary so
    # payload cleanup does not depend on the host processing a VM callback.
    boundary = Path('/sys/fs/cgroup/user.slice')
    try:
        with (boundary / 'cgroup.events').open() as events:
            inode = os.fstat(events.fileno()).st_ino
            (boundary / 'cgroup.kill').write_text('1')
            deadline = clock() + 1
            while True:
                events.seek(0)
                state = dict(line.split() for line in events.read().splitlines())
                if state.get('populated') == '0':
                    audit('workload_tree_empty', boundary='user.slice', events_inode=inode)
                    break
                if clock() >= deadline:
                    raise TimeoutError('cgroup did not empty')
                time.sleep(.01)
    except (OSError, ValueError, TimeoutError) as error:
        audit('workload_cleanup_unverified', error=type(error).__name__)
    audit('poweroff', reason=reason)
    subprocess.run(['/usr/bin/systemctl', 'poweroff', '--force', '--force'], check=False)
    # A failed shutdown is not a successful cleanup. The host still owns the VM.
    raise RuntimeError('poweroff returned: ' + reason)


def relative(name):
    # Same verdict as run.output_path: PurePosixPath would silently collapse
    # empty components ('a//b', 'a/'), so the raw components are checked.
    parts = PurePosixPath(name).parts
    if not parts or name.startswith('/') or '\0' in name or any(p in ('', '..', '.') for p in name.split('/')):
        raise ValueError('invalid relative path')
    return parts


def main():
    account = pwd.getpwnam('ouro')
    WORKSPACE.mkdir(mode=0o700, exist_ok=True)
    EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    for path in (WORKSPACE, EVIDENCE):
        os.chown(path, account.pw_uid, account.pw_gid)
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((socket.VMADDR_CID_ANY, PORT))
    server.listen(1)
    server.settimeout(.2)
    # Even a launcher that disappears during boot cannot leave an idle VM.
    idle_deadline = clock() + 90
    audit('ready', kernel=os.uname().release)
    while True:
        notify()
        if clock() > idle_deadline:
            poweroff('no_host')
        try:
            conn, peer = server.accept()
            break
        except socket.timeout:
            pass
    if peer[0] != socket.VMADDR_CID_HOST:
        poweroff('non_host_peer')
    conn.settimeout(.25)

    def send(value):
        conn.sendall(json.dumps(value, separators=(',', ':')).encode() + b'\n')

    send({'event': 'ready', 'kernel': os.uname().release, 'lease_seconds': LEASE})
    selector = selectors.DefaultSelector()
    selector.register(conn, selectors.EVENT_READ, 'control')
    last_ping = clock()
    last_sequence = -1
    uploaded = 0
    files = 0
    buffer = b''
    process = None
    stream_count = 0
    output_bytes = 0
    wall_deadline = None
    while True:
        notify()
        if clock() - last_ping > LEASE:
            poweroff('lease_expired')
        if wall_deadline is not None and clock() > wall_deadline:
            poweroff('outer_wall_expired')
        for key, _ in selector.select(.1):
            if key.data != 'control':
                data = os.read(key.fd, 16384)
                if data:
                    output_bytes += len(data)
                    if output_bytes > MAX_BYTES:
                        poweroff('output_limit')
                    send({'event': key.data, 'data': base64.b64encode(data).decode()})
                else:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    stream_count -= 1
                continue
            data = conn.recv(65536)
            if not data:
                poweroff('host_eof')
            buffer += data
            if len(buffer) > MAX_LINE:
                poweroff('input_limit')
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                request = json.loads(line)
                op = request['op']
                if op == 'ping':
                    sequence = request['sequence']
                    if type(sequence) is not int or sequence != last_sequence + 1:
                        poweroff('invalid_lease_sequence')
                    last_sequence = sequence
                    last_ping = clock()
                    send({'event': 'pong', 'sequence': sequence})
                elif op == 'put' and process is None:
                    parts = relative(request['path'])
                    path = WORKSPACE.joinpath(*parts)
                    payload = base64.b64decode(request['data'], validate=True)
                    uploaded += len(payload)
                    files += 1
                    if uploaded > MAX_BYTES or files > MAX_FILES:
                        poweroff('workspace_limit')
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open('xb') as output:
                        output.write(payload)
                    os.chmod(path, 0o755 if request['executable'] else 0o644)
                    for parent in [path, *path.parents]:
                        if parent == WORKSPACE.parent:
                            break
                        os.chown(parent, account.pw_uid, account.pw_gid)
                    send({'event': 'put', 'path': request['path']})
                elif op == 'run' and process is None:
                    profile = request['profile']
                    wall = request['wall_seconds']
                    if profile not in ('tool', 'build') or type(wall) is not int or not 1 <= wall <= 300:
                        poweroff('invalid_policy')
                    argv = [base64.b64decode(value, validate=True) for value in request['argv']]
                    if not argv or any(b'\0' in value for value in argv):
                        poweroff('invalid_argv')
                    command = [b'/usr/local/bin/ouro-jail', b'run', b'--profile', profile.encode(),
                               b'--workspace', os.fsencode(WORKSPACE), b'--receipt', os.fsencode(EVIDENCE / 'jail.json'),
                               b'--limit', f'wall={wall}s'.encode(), b'--limit', b'mem=512MiB',
                               b'--limit', b'swap=0', b'--limit', b'pids=64']
                    # The build baseline grants only scratch. Explicitly grant
                    # this disposable copy, never the Mac's input directory.
                    if profile == 'build':
                        command += [b'--rw', os.fsencode(WORKSPACE)]
                    command += [b'--', *argv]
                    env = {'HOME': account.pw_dir, 'USER': 'ouro', 'LOGNAME': 'ouro',
                           'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
                           'XDG_RUNTIME_DIR': f'/run/user/{account.pw_uid}'}
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, cwd=WORKSPACE, env=env,
                                               user=account.pw_uid, group=account.pw_gid, extra_groups=[])
                    for stream, name in [(process.stdout, 'stdout'), (process.stderr, 'stderr')]:
                        selector.register(stream, selectors.EVENT_READ, name)
                    stream_count = 2
                    wall_deadline = clock() + wall + 10
                    audit('running', supervisor_pid=process.pid)
                    send({'event': 'running', 'supervisor_pid': process.pid})
                elif op == 'cancel':
                    poweroff('cancelled')
                else:
                    poweroff('invalid_operation')
        if process is not None and process.poll() is not None and stream_count == 0:
            # Only regular files are transported. Never dereference guest links.
            count = 0
            total = 0
            for root, label in [(WORKSPACE, 'workspace'), (EVIDENCE, 'evidence')]:
                for directory, dirs, names in os.walk(root, followlinks=False):
                    dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
                    for name in names:
                        path = Path(directory) / name
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(fd, 'rb') as source:
                            info = os.fstat(source.fileno())
                            if not stat.S_ISREG(info.st_mode):
                                raise ValueError('nonregular output')
                            count += 1
                            total += info.st_size
                            if count > MAX_FILES or total > MAX_BYTES or info.st_size > MAX_FILE:
                                raise ValueError('export_limit')
                            payload = source.read(MAX_FILE + 1)
                        send({'event': 'file', 'group': label, 'path': str(path.relative_to(root)),
                              'executable': bool(info.st_mode & 0o111), 'data': base64.b64encode(payload).decode()})
            send({'event': 'done', 'exit_code': process.returncode})
            audit('done', exit_code=process.returncode)
            # No new run and no reboot/resume. Host tears down this VM.
            while clock() - last_ping <= LEASE:
                notify()
                time.sleep(.1)
            poweroff('completed')


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        poweroff('controller_error:' + type(error).__name__)
