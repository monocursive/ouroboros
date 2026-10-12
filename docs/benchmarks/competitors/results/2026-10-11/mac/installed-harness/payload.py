#!/usr/bin/env python3
"""Owned-fixture boundary probes. All descendants self-expire within 3 seconds."""
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

mode = sys.argv[1]
start = time.monotonic_ns()
if mode == "python":
    print(json.dumps({"benchmark": 1, "workload": mode, "count": 1, "checksum": 0, "payload_ns": time.monotonic_ns() - start}))
elif mode == "git":
    result = subprocess.run(["/usr/bin/git", "status", "--porcelain=v1", "--untracked-files=no"], check=True, stdout=subprocess.PIPE)
    print(json.dumps({"benchmark": 1, "workload": mode, "count": len(result.stdout.splitlines()), "checksum": hashlib.sha256(result.stdout).hexdigest(), "payload_ns": time.monotonic_ns() - start}))
elif mode == "probe":
    operation, target = sys.argv[2:4]
    try:
        if operation == "read":
            with open(target, "rb") as f:
                data = f.read(64)
            result = {"allowed": True, "bytes": len(data)}
        elif operation == "write":
            with open(target, "wb") as f:
                f.write(b"changed-by-probe")
            result = {"allowed": True}
        elif operation == "link":
            destination = sys.argv[4]
            os.link(target, destination)
            with open(destination, "rb") as f:
                data = f.read(64)
            result = {"allowed": True, "bytes": len(data)}
        elif operation == "tcp":
            with socket.create_connection(("127.0.0.1", int(target)), timeout=0.8) as s:
                s.sendall(b"probe"); result = {"allowed": s.recv(16) == b"canary"}
        elif operation == "unix":
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(0.8); s.connect(target); s.sendall(b"probe")
                result = {"allowed": s.recv(16) == b"canary"}
        elif operation == "signal":
            os.kill(int(target), signal.SIGUSR1); result = {"allowed": True}
        else:
            raise ValueError(operation)
    except OSError as e:
        result = {"allowed": False, "errno": e.errno, "error": str(e)}
    print(json.dumps({"probe": operation, **result}))
elif mode == "lifecycle":
    marker = Path(sys.argv[2])
    child = os.fork()
    if child:
        os.waitpid(child, 0)
        print(json.dumps({"probe": "lifecycle", "root_exited": True}), flush=True)
    else:
        os.setsid()
        grandchild = os.fork()
        if grandchild:
            os._exit(0)
        null = os.open(os.devnull, os.O_RDWR)
        for fd in range(3):
            os.dup2(null, fd)
        if null > 2: os.close(null)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with marker.open("a") as f: f.write(str(time.monotonic_ns()) + "\n")
            time.sleep(0.05)
        os._exit(0)
else:
    raise SystemExit(2)
