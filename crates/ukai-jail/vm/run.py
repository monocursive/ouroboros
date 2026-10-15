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

# The transport limits are guest.py's: it is installed alone in the guest, so it
# cannot import them from here. MAX_LINE bounds one protocol line.
from guest import MAX_BYTES, MAX_FILE, MAX_FILES, MAX_LINE

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
    if field(receipt, 'schema') != 'ukai.jail.receipt/1' or field(receipt, 'platform', 'os') != 'linux':
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


# The statuses an attempt ends in. attempt.json is saved with one of them once the
# attempt's directory exists, whatever ends it.
TERMINAL = ('completed', 'failed', 'cancelled')
# Failures the attempt records and answers with 125; anything else is a launcher
# bug, recorded and then re-raised.
EXPECTED_FAILURES = (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError)


def load_image(image):
    """The prepared image's metadata, refused unless every artifact matches its recorded hash."""
    metadata = json.loads((image / 'image.json').read_text())
    pinned = {'base.raw': 'disk_sha256', 'vz': 'helper_sha256', 'custodian': 'custodian_sha256',
              'seed.iso': 'seed_sha256'}
    if (not isinstance(metadata, dict) or metadata.get('status') != 'prepared'
            or any(digest(image / name) != metadata.get(key) for name, key in pinned.items())):
        raise ValueError('image/helper does not match prepared metadata')
    return metadata


class Transport:
    """The launcher's half of the helper and guest protocols for one attempt.

    It keeps the custody and guest leases, uploads the workspace, starts the run,
    relays output, writes exports and asks for the stop. The attempt decides the
    outcome from what it saw.
    """

    def __init__(self, attempt, events):
        self.attempt = attempt
        self.helper = attempt.helper
        self.events = events
        # Custody lease with the native custodian.
        self.custody_ack = time.monotonic()
        self.custody_refresh = 0
        # Guest lease, upload and run.
        self.guest_ready = False
        self.sequence = 0
        self.pending_ping = None
        self.next_ping = 0
        self.position = 0
        self.awaiting_put = False
        self.run_sent = False
        # Helper output and exports.
        self.outer_buffer = b''
        self.guest_buffer = b''
        self.received_bytes = 0
        self.exported = 0
        self.export_bytes = 0
        # What the attempt decides on.
        self.owner_token = None
        self.guest_done = False
        self.stopped = False
        self.stop_time = None

    def run(self):
        """Drive both protocols until the helper's output ends or the helper exits."""
        selector = selectors.DefaultSelector()
        selector.register(self.helper.stdout, selectors.EVENT_READ)
        while True:
            self.tick(time.monotonic())
            if not selector.select(.05):
                if self.helper.poll() is not None:
                    return
                continue
            chunk = os.read(self.helper.stdout.fileno(), 65536)
            if not chunk:
                return
            self.receive(chunk)

    def tick(self, now):
        """Leases, deadlines and the next upload step, once per loop."""
        attempt = self.attempt
        self.keep_custody(now)
        if attempt.cancelled:
            attempt.report['status'] = 'cancelled'
            self.stop()
        if now - attempt.started > 120 + attempt.args.wall + 15:
            raise TimeoutError('host deadline expired')
        if self.stop_time is not None and now - self.stop_time > 5:
            raise TimeoutError('VM stop was not acknowledged')
        if self.guest_ready and self.stop_time is None:
            self.keep_guest_lease(now)
            self.advance()

    def keep_custody(self, now):
        try:
            if os.read(self.attempt.custody_ack_read, 64):
                self.custody_ack = now
        except BlockingIOError:
            pass
        if self.stop_time is None and now - self.custody_ack > 1.5:
            raise TimeoutError('native custodian stopped acknowledging its lease')
        if now >= self.custody_refresh:
            try:
                os.write(self.attempt.custody_write, b'.')
            except BrokenPipeError:
                pass  # Drain the owner's final events before deciding.
            self.custody_refresh = now + .25

    def keep_guest_lease(self, now):
        if self.pending_ping is not None and now - self.pending_ping > 1.5:
            raise TimeoutError('guest lease acknowledgement lost')
        if self.pending_ping is None and now >= self.next_ping:
            self.write_guest({'op': 'ping', 'sequence': self.sequence})
            self.pending_ping = now

    def advance(self):
        """Send the next workspace file, or the run once every file is acknowledged."""
        if self.awaiting_put or self.run_sent:
            return
        entries = self.attempt.entries
        if self.position < len(entries):
            self.write_guest(entries[self.position])
            self.awaiting_put = True
        else:
            args = self.attempt.args
            self.write_guest({'op': 'run', 'argv': self.attempt.report['argv_base64'], 'profile': args.profile,
                              'wall_seconds': args.wall})
            self.run_sent = True

    def write_guest(self, message):
        encoded = base64.b64encode(json.dumps(message, separators=(',', ':')).encode() + b'\n').decode()
        self.helper.stdin.write(json.dumps({'op': 'write', 'data': encoded}).encode() + b'\n')
        self.helper.stdin.flush()

    def stop(self):
        """Ask the helper to stop the VM, once."""
        if self.stop_time is None:
            self.helper.stdin.write(b'{"op":"stop"}\n')
            self.helper.stdin.flush()
            self.stop_time = time.monotonic()

    def receive(self, chunk):
        self.received_bytes += len(chunk)
        if self.received_bytes > 128 * 1024 * 1024:
            raise ValueError('total transport limit exceeded')
        self.events.write(chunk)
        self.events.flush()
        self.outer_buffer += chunk
        if len(self.outer_buffer) > 4 * 1024 * 1024:
            raise ValueError('oversized helper message')
        while b'\n' in self.outer_buffer:
            line, self.outer_buffer = self.outer_buffer.split(b'\n', 1)
            self.on_helper(parse_helper_message(line))

    def on_helper(self, message):
        kind = message['event']
        if kind == 'owner':
            token = message['audit_token']
            if (len(token) != 8 or any(type(n) is not int or not 0 <= n < 2**32 for n in token)
                    or token[5] != message['pid']):
                raise ValueError('owner PID does not match audit token')
            self.owner_token = token
            self.attempt.report.update(helper_pid=message['pid'], owner_audit_token=token)
            self.attempt.save()
        elif kind == 'stopped':
            self.stopped = not message['error']
        elif kind == 'data':
            self.guest_buffer += base64.b64decode(message['data'], validate=True)
            if len(self.guest_buffer) > MAX_LINE:
                raise ValueError('oversized guest message')
            while b'\n' in self.guest_buffer:
                line, self.guest_buffer = self.guest_buffer.split(b'\n', 1)
                self.on_guest(parse_guest_message(line))
        elif kind == 'error':
            raise RuntimeError(message['error'])

    def on_guest(self, response):
        kind = response['event']
        report = self.attempt.report
        if kind == 'ready':
            self.guest_ready = True
            report.update(status='ready', guest_kernel=response['kernel'],
                          boot_seconds=time.monotonic() - self.attempt.started)
            self.attempt.save()
        elif kind == 'pong':
            if response['sequence'] != self.sequence or self.pending_ping is None:
                raise ValueError('unexpected lease acknowledgement')
            self.sequence += 1
            self.pending_ping = None
            self.next_ping = time.monotonic() + .25
        elif kind == 'put':
            if not self.awaiting_put or response['path'] != self.attempt.entries[self.position]['path']:
                raise ValueError('unexpected workspace acknowledgement')
            self.awaiting_put = False
            self.position += 1
        elif kind == 'running':
            report.update(status='running', supervisor_pid=response['supervisor_pid'])
            self.attempt.save()
        elif kind in ('stdout', 'stderr'):
            payload = base64.b64decode(response['data'], validate=True)
            stream = sys.stdout.buffer if kind == 'stdout' else sys.stderr.buffer
            stream.write(payload)
            stream.flush()
        elif kind == 'file':
            self.export(response)
        elif kind == 'done':
            if self.guest_done:
                raise ValueError('invalid guest completion')
            self.guest_done = True
            report['guest_exit_code'] = response['exit_code']
            self.stop()
        else:
            raise ValueError('unexpected guest event: ' + kind)

    def export(self, response):
        path = output_path(self.attempt.output, response['group'], response['path'])
        payload = base64.b64decode(response['data'], validate=True)
        self.exported += 1
        self.export_bytes += len(payload)
        if self.exported > MAX_FILES or self.export_bytes > MAX_BYTES or len(payload) > MAX_FILE:
            raise ValueError('export limit exceeded')
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as destination:
            destination.write(payload)
        path.chmod(0o700 if response['executable'] else 0o600)


class Attempt:
    """One attempt in its own evidence directory: clone, boot, transport, verdict, cleanup.

    Once the directory exists, attempt.json is saved at every step and always ends
    with a status in TERMINAL, whatever raised and wherever.
    """

    def __init__(self, args, image, workspace, output, entries, metadata):
        self.args = args
        self.image = image
        self.output = output
        self.entries = entries
        self.started = time.monotonic()
        self.report = {'schema': 'ukai.vm.attempt/1', 'status': 'starting', 'host': list(os.uname()),
                       'guest_os': 'linux', 'native_macos_execution': False, 'network': False,
                       'shared_directories': [], 'workspace': str(workspace), 'profile': args.profile,
                       'argv_base64': [base64.b64encode(os.fsencode(a)).decode() for a in args.command],
                       'wall_seconds': args.wall, 'image_sha256': metadata['disk_sha256'],
                       'input_files': len(entries), 'excluded_names': sorted(EXCLUDED)}
        self.helper = None
        self.custody_write = None
        self.custody_ack_read = None
        self.transport = None
        self.cancelled = False
        self.previous_handlers = {}

    def save(self):
        temporary = self.output / 'attempt.json.tmp'
        temporary.write_text(json.dumps(self.report, indent=2) + '\n')
        temporary.replace(self.output / 'attempt.json')

    def run(self):
        self.save()
        try:
            clone_disk(self.image / 'base.raw', self.output / 'guest.raw')
            with (self.output / 'helper.stderr').open('wb') as errors, \
                    (self.output / 'events.ndjson').open('wb') as events:
                self.boot(errors)
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    self.previous_handlers[signum] = signal.signal(signum, self.cancel)
                self.transport = Transport(self, events)
                self.transport.run()
                self.conclude()
        except EXPECTED_FAILURES as error:
            self.report.update(status='failed', error=str(error))
        except BaseException as error:
            # An unforeseen failure still ends this attempt: the saved record must
            # not keep saying booting, ready or running.
            self.report.update(status='failed', error=f'{type(error).__name__}: {error}')
            raise
        finally:
            self.finish()
        print(f"VM attempt: {self.report['status']}; evidence: {self.output / 'attempt.json'}", file=sys.stderr)
        return self.report.get('guest_exit_code', 125) if self.report['status'] == 'completed' else 125

    def boot(self, errors):
        """Start the custodian, which runs the VZ helper under a lease this launcher keeps."""
        custody_read, self.custody_write = os.pipe()
        self.custody_ack_read, custody_ack_write = os.pipe()
        os.set_blocking(self.custody_ack_read, False)
        image, output = self.image, self.output
        try:
            self.helper = subprocess.Popen(
                [str(image / 'custodian'), str(custody_read), str(custody_ack_write), str(image / 'vz'),
                 str(output / 'guest.raw'), str(image / 'seed.iso'), str(output / 'guest.nvram'),
                 str(output / 'console.log'), 'run'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                pass_fds=(custody_read, custody_ack_write))
        finally:
            os.close(custody_read)
            os.close(custody_ack_write)
        self.report.update(status='booting', launcher_pid=os.getpid(), custodian_pid=self.helper.pid)
        self.save()

    def cancel(self, signum, _frame):
        self.cancelled = True
        self.report['signal'] = signum

    def conclude(self):
        """The verdict once the helper is done: cancelled, completed or failed."""
        transport, helper = self.transport, self.helper
        helper.wait(timeout=5)
        self.report['helper_exit_code'] = helper.returncode
        self.report['vm_stop_acknowledged'] = transport.stopped
        # A signal can land after the transport loop's last look at it; the verdict
        # reads it here too, so a cancelled attempt never stays `running`.
        if self.cancelled:
            self.report['status'] = 'cancelled'
        elif transport.guest_done and transport.stopped and helper.returncode == 0:
            receipt = self.output / 'evidence' / 'jail.json'
            verify_receipt(json.loads(receipt.read_text()), self.args.profile)
            self.report['guest_receipt_sha256'] = digest(receipt)
            self.report['status'] = 'completed'
        else:
            raise RuntimeError('VM ended without guest completion and acknowledged stop')

    def release(self, field, step, *arguments):
        """Run one cleanup step. A failure fails the attempt and is recorded under `field`."""
        try:
            step(*arguments)
        except Exception as error:  # Every later step must still run.
            self.report.update({'status': 'failed', field: f'{type(error).__name__}: {error}'})

    def finish(self):
        """Release the leases, the VM owner and the helper, then save the terminal record."""
        try:
            for descriptor in (self.custody_write, self.custody_ack_read):
                if descriptor is not None:
                    self.release('custody_cleanup_error', os.close, descriptor)
            transport = self.transport
            if transport is not None and transport.owner_token is not None and not transport.stopped:
                self.release('owner_cleanup_error', terminate_owner, transport.owner_token)
            if self.helper is not None and self.helper.poll() is None:
                self.release('helper_cleanup_error', self.stop_helper)
        finally:
            for signum, handler in self.previous_handlers.items():
                signal.signal(signum, handler)
            self.report['elapsed_seconds'] = time.monotonic() - self.started
            if self.report['status'] not in TERMINAL:
                self.report['error'] = self.report.get('error', 'the attempt ended without a verdict')
                self.report['status'] = 'failed'
            self.save()
            # Keep the disposable disk for fault inspection only. Normal runs discard it.
            if not self.args.keep_disk:
                (self.output / 'guest.raw').unlink(missing_ok=True)

    def stop_helper(self):
        self.helper.terminate()
        try:
            self.helper.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.helper.kill()
            self.helper.wait(timeout=5)


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
    metadata = load_image(image)
    output.mkdir(parents=True, exist_ok=False)
    return Attempt(args, image, workspace, output, entries, metadata).run()


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
