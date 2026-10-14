#!/usr/bin/env python3
"""Experimental Mac launcher for an offline disposable Linux jail."""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import selectors
import signal
import stat
import subprocess
import sys
import time

# guest.py repeats these limits (it is installed alone in the guest);
# test_vm.py checks that both ends agree. MAX_LINE bounds one protocol line.
MAX_LINE = 2 * 1024 * 1024
MAX_BYTES = 32 * 1024 * 1024
MAX_FILE = 512 * 1024
MAX_FILES = 5000
EXCLUDED = {'.git', 'target', 'node_modules', '.venv', '__pycache__', '.DS_Store'}
# Exact field types per event: `type(value) is int` keeps JSON booleans out of
# integer fields. Fields the launcher does not read are not constrained.
HELPER_EVENTS = {
    'owner': {'pid': int, 'audit_token': list},
    'stopped': {'error': str},
    'data': {'data': str},
    'error': {'error': str},
}
GUEST_EVENTS = {
    'ready': {'kernel': str},
    'pong': {'sequence': int},
    'put': {'path': str},
    'running': {'supervisor_pid': int},
    'stdout': {'data': str},
    'stderr': {'data': str},
    'file': {'group': str, 'path': str, 'executable': bool, 'data': str},
    'done': {'exit_code': int},
}


def terminate_owner(token):
    # Kernel validates pidversion atomically, including after custodian death.
    if not isinstance(token, list) or len(token) != 8 or any(type(n) is not int or not 0 <= n < 2**32 for n in token):
        raise ValueError('invalid VM owner audit token')
    words = (ctypes.c_uint32 * 8)(*token)
    library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    signal_process = library.proc_signal_with_audittoken
    signal_process.argtypes = [ctypes.c_void_p, ctypes.c_int]
    signal_process.restype = ctypes.c_int
    if signal_process(ctypes.byref(words), signal.SIGKILL) != 0:
        error = ctypes.get_errno()
        if error != 3:  # ESRCH means that exact identity is already gone.
            raise OSError(error, 'could not terminate VM owner')


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def clone_disk(base, destination):
    # APFS clone: one private writable disk per attempt. Never boot the base.
    subprocess.run(['cp', '-c', str(base), str(destination)], check=True)


def snapshot(root):
    """Read regular files through directory descriptors, without following links."""
    entries = []
    total = 0
    for directory, dirs, files, fd in os.fwalk(root, follow_symlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED)
        for name in dirs:
            if stat.S_ISLNK(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                raise ValueError('workspace symlinks are not supported: ' + name)
        for name in sorted(files):
            if name in EXCLUDED:
                continue
            opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(opened, 'rb') as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                    raise ValueError('only regular files up to 512 KiB are supported: ' + name)
                data = source.read(MAX_FILE + 1)
            total += len(data)
            if len(data) > MAX_FILE or total > MAX_BYTES or len(entries) >= MAX_FILES:
                raise ValueError('workspace exceeds the preview transfer limit')
            relative = str((Path(directory) / name).relative_to(root))
            entries.append({'op': 'put', 'path': relative, 'executable': bool(info.st_mode & 0o111),
                            'data': base64.b64encode(data).decode()})
    return entries


def output_path(root, group, name):
    if group not in ('workspace', 'evidence') or not isinstance(name, str):
        raise ValueError('invalid output group/path')
    parts = PurePosixPath(name).parts
    if not parts or name.startswith('/') or '\0' in name or any(p in ('', '..', '.') for p in name.split('/')):
        raise ValueError('invalid output path')
    return root.joinpath(group, *parts)


def parse_message(line, events, source, unknown_allowed):
    """Decode one protocol line into an object with a string event and typed fields.

    Any other shape raises ValueError, so malformed helper or guest output
    ends the attempt through the same path as any other transport failure.
    """
    message = json.loads(line)
    if not isinstance(message, dict) or type(message.get('event')) is not str:
        raise ValueError(f'malformed {source} message: not an object with a string event')
    kind = message['event']
    if kind not in events:
        if unknown_allowed:
            return message
        raise ValueError(f'unexpected {source} event: {kind}')
    for name, expected in events[kind].items():
        if type(message.get(name)) is not expected:
            raise ValueError(f'invalid {source} {kind} message: {name} must be {expected.__name__}')
    return message


def parse_helper_message(line):
    # The helper also reports lifecycle events (booted, connected, stopping,
    # guest_stopped) that are only kept in events.ndjson.
    return parse_message(line, HELPER_EVENTS, 'helper', unknown_allowed=True)


def parse_guest_message(line):
    return parse_message(line, GUEST_EVENTS, 'guest', unknown_allowed=False)


def field(value, *keys):
    """Follow object keys through guest JSON; a missing key or non-object step gives None."""
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def verify_receipt(receipt, profile):
    """Never relabel a transport success as successful jail enforcement."""
    if field(receipt, 'schema') != 'ouro.jail.receipt/1' or field(receipt, 'platform', 'os') != 'linux':
        raise ValueError('missing Linux jail receipt')
    if field(receipt, 'policy', 'name') != profile:
        raise ValueError('guest receipt profile mismatch')
    if (field(receipt, 'containment') != 'enforced' or field(receipt, 'child_protection') != 'enforced'
            or field(receipt, 'exec_observed') is not True):
        raise ValueError('guest did not confirm contained execution')
    if field(receipt, 'lifetime', 'tree_empty') is not True or field(receipt, 'lifetime', 'integrity') != 'verified':
        raise ValueError('guest process-tree cleanup was not verified')
    if field(receipt, 'state_cleanup') != 'complete' or field(receipt, 'errors'):
        raise ValueError('guest evidence or cleanup failed')
    if field(receipt, 'applied', 'network', 'mode') != 'none':
        raise ValueError('guest receipt did not enforce offline execution')
    limits = field(receipt, 'applied', 'limits')
    if not isinstance(limits, list) or any(type(field(limit, 'key')) is not str for limit in limits):
        raise ValueError('malformed guest receipt limits')
    applied = {limit['key']: limit.get('applied') for limit in limits}
    if any(applied.get(key) is not True for key in ('wall', 'pids', 'mem', 'swap')):
        raise ValueError('guest did not apply every required limit')


def execute(args):
    os.umask(0o077)
    image = args.image.resolve()
    workspace = args.workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError('workspace must be a directory')
    output = args.out.resolve()
    if output == workspace or output.is_relative_to(workspace):
        raise ValueError('output must be outside the input workspace')
    entries = snapshot(workspace)
    metadata = json.loads((image / 'image.json').read_text())
    if metadata['status'] != 'prepared' or digest(image / 'base.raw') != metadata['disk_sha256'] or digest(image / 'vz') != metadata['helper_sha256'] or digest(image / 'custodian') != metadata.get('custodian_sha256') or digest(image / 'seed.iso') != metadata.get('seed_sha256'):
        raise ValueError('image/helper does not match prepared metadata')
    output.mkdir(parents=True, exist_ok=False)
    clone_disk(image / 'base.raw', output / 'guest.raw')
    started = time.monotonic()
    report = {'schema': 'ouro.vm.attempt/1', 'status': 'starting', 'host': list(os.uname()),
              'guest_os': 'linux', 'native_macos_execution': False, 'network': False,
              'shared_directories': [], 'workspace': str(workspace), 'profile': args.profile,
              'argv_base64': [base64.b64encode(os.fsencode(a)).decode() for a in args.command],
              'wall_seconds': args.wall, 'image_sha256': metadata['disk_sha256'],
              'input_files': len(entries), 'excluded_names': sorted(EXCLUDED)}

    def save():
        temporary = output / 'attempt.json.tmp'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(output / 'attempt.json')

    save()
    helper = None
    custody_write = None
    custody_ack_read = None
    owner_token = None
    guest_done = False
    stopped = False
    cancelled = False
    previous_handlers = {}

    def cancel(signum, _frame):
        nonlocal cancelled
        cancelled = True
        report['signal'] = signum

    try:
        with (output / 'helper.stderr').open('wb') as errors, (output / 'events.ndjson').open('wb') as events:
            custody_read, custody_write = os.pipe()
            custody_ack_read, custody_ack_write = os.pipe()
            os.set_blocking(custody_ack_read, False)
            try:
                helper = subprocess.Popen([str(image / 'custodian'), str(custody_read), str(custody_ack_write), str(image / 'vz'), str(output / 'guest.raw'), str(image / 'seed.iso'),
                                       str(output / 'guest.nvram'), str(output / 'console.log'), 'run'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, pass_fds=(custody_read, custody_ack_write))
            finally:
                os.close(custody_read)
                os.close(custody_ack_write)
            report.update(status='booting', launcher_pid=os.getpid(), custodian_pid=helper.pid)
            save()
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                previous_handlers[signum] = signal.signal(signum, cancel)
            selector = selectors.DefaultSelector()
            selector.register(helper.stdout, selectors.EVENT_READ)
            outer_buffer = b''
            guest_buffer = b''
            sequence = 0
            pending_ping = None
            next_ping = 0
            guest_ready = False
            awaiting_put = False
            position = 0
            run_sent = False
            exported = 0
            export_bytes = 0
            received_bytes = 0
            stop_sent = False
            stop_time = None
            custody_refresh = 0
            custody_ack = time.monotonic()

            def write_guest(message):
                encoded = base64.b64encode(json.dumps(message, separators=(',', ':')).encode() + b'\n').decode()
                helper.stdin.write(json.dumps({'op': 'write', 'data': encoded}).encode() + b'\n')
                helper.stdin.flush()

            def stop():
                nonlocal stop_sent, stop_time
                if not stop_sent:
                    helper.stdin.write(b'{"op":"stop"}\n')
                    helper.stdin.flush()
                    stop_sent = True
                    stop_time = time.monotonic()

            while True:
                now = time.monotonic()
                try:
                    if os.read(custody_ack_read, 64):
                        custody_ack = now
                except BlockingIOError:
                    pass
                if not stop_sent and now - custody_ack > 1.5:
                    raise TimeoutError('native custodian stopped acknowledging its lease')
                if now >= custody_refresh:
                    try:
                        os.write(custody_write, b'.')
                    except BrokenPipeError:
                        pass  # Drain the owner's final events before deciding.
                    custody_refresh = now + .25
                if cancelled:
                    report['status'] = 'cancelled'
                    stop()
                if now - started > 120 + args.wall + 15:
                    raise TimeoutError('host deadline expired')
                if stop_time and now - stop_time > 5:
                    raise TimeoutError('VM stop was not acknowledged')
                if guest_ready and not stop_sent:
                    if pending_ping is not None and now - pending_ping > 1.5:
                        raise TimeoutError('guest lease acknowledgement lost')
                    if pending_ping is None and now >= next_ping:
                        write_guest({'op': 'ping', 'sequence': sequence})
                        pending_ping = now
                    if not awaiting_put and not run_sent:
                        if position < len(entries):
                            write_guest(entries[position])
                            awaiting_put = True
                        else:
                            write_guest({'op': 'run', 'argv': report['argv_base64'], 'profile': args.profile,
                                         'wall_seconds': args.wall})
                            run_sent = True
                ready = selector.select(.05)
                if not ready:
                    if helper.poll() is not None:
                        break
                    continue
                chunk = os.read(helper.stdout.fileno(), 65536)
                if not chunk:
                    break
                received_bytes += len(chunk)
                if received_bytes > 128 * 1024 * 1024:
                    raise ValueError('total transport limit exceeded')
                events.write(chunk)
                events.flush()
                outer_buffer += chunk
                if len(outer_buffer) > 4 * 1024 * 1024:
                    raise ValueError('oversized helper message')
                while b'\n' in outer_buffer:
                    line, outer_buffer = outer_buffer.split(b'\n', 1)
                    message = parse_helper_message(line)
                    kind = message['event']
                    if kind == 'owner':
                        owner_token = message['audit_token']
                        if (not isinstance(owner_token, list) or len(owner_token) != 8
                                or any(type(n) is not int or not 0 <= n < 2**32 for n in owner_token)
                                or owner_token[5] != message['pid']):
                            owner_token = None
                            raise ValueError('owner PID does not match audit token')
                        report.update(helper_pid=message['pid'], owner_audit_token=owner_token)
                        save()
                    elif kind == 'stopped':
                        stopped = not message['error']
                    elif kind == 'data':
                        guest_buffer += base64.b64decode(message['data'], validate=True)
                        if len(guest_buffer) > MAX_LINE:
                            raise ValueError('oversized guest message')
                        while b'\n' in guest_buffer:
                            line, guest_buffer = guest_buffer.split(b'\n', 1)
                            response = parse_guest_message(line)
                            kind = response['event']
                            if kind == 'ready':
                                guest_ready = True
                                report.update(status='ready', guest_kernel=response['kernel'],
                                              boot_seconds=time.monotonic() - started)
                                save()
                            elif kind == 'pong':
                                if response['sequence'] != sequence or pending_ping is None:
                                    raise ValueError('unexpected lease acknowledgement')
                                sequence += 1
                                pending_ping = None
                                next_ping = time.monotonic() + .25
                            elif kind == 'put':
                                if not awaiting_put or response['path'] != entries[position]['path']:
                                    raise ValueError('unexpected workspace acknowledgement')
                                awaiting_put = False
                                position += 1
                            elif kind == 'running':
                                report.update(status='running', supervisor_pid=response['supervisor_pid'])
                                save()
                            elif kind in ('stdout', 'stderr'):
                                payload = base64.b64decode(response['data'], validate=True)
                                stream = sys.stdout.buffer if kind == 'stdout' else sys.stderr.buffer
                                stream.write(payload)
                                stream.flush()
                            elif kind == 'file':
                                path = output_path(output, response['group'], response['path'])
                                payload = base64.b64decode(response['data'], validate=True)
                                exported += 1
                                export_bytes += len(payload)
                                if exported > MAX_FILES or export_bytes > MAX_BYTES or len(payload) > MAX_FILE:
                                    raise ValueError('export limit exceeded')
                                path.parent.mkdir(parents=True, exist_ok=True)
                                with path.open('xb') as destination:
                                    destination.write(payload)
                                path.chmod(0o700 if response['executable'] else 0o600)
                            elif kind == 'done':
                                if guest_done:
                                    raise ValueError('invalid guest completion')
                                guest_done = True
                                report['guest_exit_code'] = response['exit_code']
                                stop()
                            else:
                                raise ValueError('unexpected guest event: ' + kind)
                    elif kind == 'error':
                        raise RuntimeError(message['error'])
            helper.wait(timeout=5)
            report['helper_exit_code'] = helper.returncode
            report['vm_stop_acknowledged'] = stopped
            if guest_done and stopped and helper.returncode == 0 and not cancelled:
                receipt = output / 'evidence' / 'jail.json'
                verify_receipt(json.loads(receipt.read_text()), args.profile)
                report['guest_receipt_sha256'] = digest(receipt)
                report['status'] = 'completed'
            elif not cancelled:
                raise RuntimeError('VM ended without guest completion and acknowledged stop')
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
    except BaseException as error:
        # An unforeseen failure still ends this attempt: the saved record must
        # not keep saying booting, ready or running.
        report.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        if custody_write is not None:
            os.close(custody_write)
        if custody_ack_read is not None:
            os.close(custody_ack_read)
        if owner_token is not None and not stopped:
            try:
                terminate_owner(owner_token)
            except OSError as error:
                report.update(status='failed', owner_cleanup_error=str(error))
        if helper is not None and helper.poll() is None:
            helper.terminate()
            try:
                helper.wait(timeout=5)
            except subprocess.TimeoutExpired:
                helper.kill()
                helper.wait(timeout=5)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        report['elapsed_seconds'] = time.monotonic() - started
        save()
        # Keep the disposable disk for fault inspection only. Normal runs discard it.
        if not args.keep_disk:
            (output / 'guest.raw').unlink(missing_ok=True)
    print(f"VM attempt: {report['status']}; evidence: {output / 'attempt.json'}", file=sys.stderr)
    return report.get('guest_exit_code', 125) if report['status'] == 'completed' else 125


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--profile', choices=['tool', 'build'], default='tool')
    parser.add_argument('--wall', type=int, default=30)
    parser.add_argument('--keep-disk', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ['--']:
        args.command.pop(0)
    if not args.command or not 1 <= args.wall <= 300:
        parser.error('a command and wall budget from 1 to 300 seconds are required')
    try:
        return execute(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 125


if __name__ == '__main__':
    sys.exit(main())
