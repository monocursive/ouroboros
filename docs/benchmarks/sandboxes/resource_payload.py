#!/usr/bin/env python3
"""Small, bounded resource fixtures; no fork bomb or unbounded allocation."""
import json
import os
import sys
import time

mode = sys.argv[1]
if mode == "wall":
    print(json.dumps({"resource": mode, "started": True}), flush=True)
    time.sleep(2)
    print(json.dumps({"resource": mode, "completed": True}), flush=True)
elif mode == "pids":
    children = []
    denied = None
    try:
        for i in range(32):
            child = os.fork()
            if child == 0:
                time.sleep(1); os._exit(0)
            children.append(child)
    except OSError as e:
        denied = e.errno
    print(json.dumps({"resource": mode, "children": len(children), "denied_errno": denied}), flush=True)
    for child in children: os.waitpid(child, 0)
elif mode == "memory":
    print(json.dumps({"resource": mode, "started": True}), flush=True)
    allocation = bytearray(80 * 1024 * 1024)
    for i in range(0, len(allocation), 4096): allocation[i] = 1
    accounting = {}
    if sys.platform.startswith("linux"):
        with open("/proc/self/status") as f:
            for line in f:
                key, _, value = line.partition(":")
                if key in ("VmRSS", "VmSwap", "VmSize"): accounting[key] = value.strip()
    print(json.dumps({"resource": mode, "bytes_touched": len(allocation), "accounting": accounting, "completed": True}), flush=True)
else:
    raise SystemExit(2)
