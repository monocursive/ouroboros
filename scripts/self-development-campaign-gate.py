#!/usr/bin/env python3
"""Bounded process helper retained for local campaign regression tests.

run_bounded receives an explicit environment and artifact path. Combined output is
drained with bounded memory; overflow marks the artifact and makes the gate fail.
The old machine-specific command shortcuts are retired. New campaigns name an
absolute executable directly in their manifest with artifact_mode: stdout.
"""
import codecs
import json
import os
import selectors
import signal
import subprocess
import sys
import threading
import time

ARTIFACT_ENV = "OUROBOROS_CAMPAIGN_ARTIFACT"
DECLARED_ENV = "OUROBOROS_CAMPAIGN_DECLARED_ENV"
MAX_REPORT_BYTES = 64 * 1024 * 1024
OVERFLOW_EXIT = 74
OVERFLOW_MARKER = b"\n[OUROBOROS_CAMPAIGN_ARTIFACT_INCOMPLETE: output limit exceeded]\n"


def _fit_utf8(value, maximum):
    value = value[:maximum]
    while value:
        try:
            value.decode("utf-8")
            return value
        except UnicodeDecodeError as error:
            value = value[:error.start]
    return b""


class _Cancelled(Exception):
    def __init__(self, signum):
        self.signum = signum


def _signal_group(process, signum):
    """Signal only the validation group created for this retained process."""
    try:
        os.killpg(process.pid, signum)
    except (ProcessLookupError, PermissionError):
        pass


def _terminate_group(process, grace=0.1):
    _signal_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    if grace:
        time.sleep(grace)
    _signal_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _read_all(fd):
    blocks = []
    while True:
        block = os.read(fd, 65536)
        if not block:
            return b"".join(blocks)
        blocks.append(block)


def _supervise(control_fd, config_fd, status_fd):
    """Remain in the validation group and clean it if the gate disappears."""
    try:
        config = json.loads(_read_all(config_fd))
        os.close(config_fd)
        child = subprocess.Popen(config["argv"], cwd=config["cwd"], env=config["environment"],
                                 stdin=subprocess.DEVNULL, stdout=None, stderr=None,
                                 shell=False, start_new_session=False)
    except OSError as error:
        payload = {"error": [error.errno, error.strerror, error.filename]}
        os.write(status_fd, json.dumps(payload).encode("utf-8"))
        os.close(status_fd)
        return 0
    finally:
        try:
            os.close(config_fd)
        except OSError:
            pass

    # The actual command and its descendants own the output pipe. Keeping a writer
    # in this supervisor would prevent the gate from observing their EOF.
    for fd in (1, 2):
        try:
            os.close(fd)
        except OSError:
            pass
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    selector = selectors.DefaultSelector()
    selector.register(control_fd, selectors.EVENT_READ)
    reported = False
    try:
        while True:
            if not reported:
                code = child.poll()
                if code is not None:
                    os.write(status_fd, json.dumps({"exit_code": code}).encode("utf-8"))
                    os.close(status_fd)
                    reported = True
            if selector.select(0.02):
                if not os.read(control_fd, 1):
                    # The sole writer belonged to the gate. EOF means that owner
                    # vanished, possibly by SIGKILL, so no in-gate grace protocol
                    # can still be running; stop this exact retained group now.
                    os.killpg(os.getpgrp(), signal.SIGKILL)
            if reported:
                time.sleep(0.02)
    finally:
        selector.close()


def _spawn_supervised(argv, cwd, environment):
    control_read, control_write = os.pipe()
    config_read, config_write = os.pipe()
    status_read, status_write = os.pipe()
    process = None
    try:
        process = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "--supervise", str(control_read),
             str(config_read), str(status_write)],
            env={}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            shell=False, start_new_session=True,
            pass_fds=(control_read, config_read, status_write))
        os.close(control_read); control_read = -1
        os.close(config_read); config_read = -1
        os.close(status_write); status_write = -1
        payload = json.dumps({"argv": argv, "cwd": cwd, "environment": environment}).encode("utf-8")
        while payload:
            payload = payload[os.write(config_write, payload):]
        os.close(config_write); config_write = -1
        return process, control_write, status_read
    except BaseException:
        if process is not None:
            _terminate_group(process)
        raise
    finally:
        for fd in (control_read, config_read, config_write, status_write):
            if fd >= 0:
                os.close(fd)


def _validation_status(fd, deadline):
    selector = selectors.DefaultSelector()
    selector.register(fd, selectors.EVENT_READ)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not selector.select(remaining):
            raise subprocess.TimeoutExpired("validation", max(0, remaining))
        payload = json.loads(_read_all(fd))
    finally:
        selector.close()
    if "error" in payload:
        number, message, filename = payload["error"]
        raise OSError(number, message, filename)
    return payload["exit_code"]


def run_bounded(argv, cwd, environment, artifact, limit=MAX_REPORT_BYTES, timeout=590):
    if limit <= len(OVERFLOW_MARKER):
        raise ValueError("artifact limit is too small")
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    written = 0
    overflow = False
    process = None
    control_fd = None
    status_fd = None
    selector = selectors.DefaultSelector()
    previous_handlers = {}

    def cancel(signum, _frame):
        if process is not None:
            _signal_group(process, signum)
        raise _Cancelled(signum)

    blocked_signals = None
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, cancel)
        if hasattr(signal, "pthread_sigmask"):
            blocked_signals = signal.pthread_sigmask(signal.SIG_BLOCK, previous_handlers)
    try:
        process, control_fd, status_fd = _spawn_supervised(argv, cwd, environment)
        assert process.stdout is not None
        if blocked_signals is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked_signals)
            blocked_signals = None
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        with open(artifact, "xb") as handle:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _terminate_group(process)
                    return 124
                for key, _ in selector.select(min(remaining, 0.25)):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    encoded = decoder.decode(block).encode("utf-8")
                    available = limit - len(OVERFLOW_MARKER) - written
                    if len(encoded) > available:
                        overflow = True
                        encoded = _fit_utf8(encoded, max(0, available))
                    if encoded:
                        handle.write(encoded); written += len(encoded)
            tail = decoder.decode(b"", final=True).encode("utf-8")
            available = limit - len(OVERFLOW_MARKER) - written
            if len(tail) > available:
                overflow = True; tail = _fit_utf8(tail, max(0, available))
            if tail:
                handle.write(tail); written += len(tail)
            exit_code = _validation_status(status_fd, deadline)
            if overflow:
                handle.write(OVERFLOW_MARKER)
                return OVERFLOW_EXIT
            return exit_code
    except _Cancelled as cancelled:
        return 128 + cancelled.signum
    finally:
        if blocked_signals is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked_signals)
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        selector.close()
        if process is not None:
            _terminate_group(process)
            if process.stdout is not None:
                process.stdout.close()
        for fd in (control_fd, status_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def declared_environment(raw):
    value = json.loads(raw)
    if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                          for k, v in value.items()):
        raise ValueError("declared environment must be a string map")
    return value


def main(_argv):
    print("campaign gate shortcuts are retired; use an absolute executable in a "
          "validated manifest with artifact_mode: stdout", file=sys.stderr)
    return 2


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--supervise":
        raise SystemExit(_supervise(*(int(value) for value in sys.argv[2:])))
    raise SystemExit(main(sys.argv))
