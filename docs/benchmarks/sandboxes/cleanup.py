#!/usr/bin/env python3
"""Remove only this run's disposable tool/state directories after a process audit."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
if root.name != "ouro-sandbox-20260930" or str(root.parent) not in ("/tmp", "/private/tmp"):
    raise SystemExit("unexpected owned-run root")
manifest = json.loads((root / "install.json").read_text())
if manifest["schema"] != "sandbox-comparison-install/1": raise SystemExit("missing run ownership metadata")
processes = []
if platform.system() == "Linux":
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid(): continue
        try:
            if proc.stat().st_uid != os.getuid(): continue
            cwd = (proc / "cwd").resolve(strict=True)
            argv = (proc / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace")
            if str(cwd).startswith(str(root) + "/") or str(root) in argv:
                # SSH parent/command shell carries the cleanup invocation.
                if "cleanup.py" not in argv:
                    processes.append({"pid": int(proc.name), "cwd": str(cwd), "argv": argv})
        except (OSError, RuntimeError): pass
else:
    rows = subprocess.check_output(["/bin/ps", "-axo", "pid=,command="]).decode().splitlines()
    for row in rows:
        pid, _, command = row.strip().partition(" ")
        if str(root) in command and "cleanup.py" not in command and int(pid) != os.getpid():
            processes.append({"pid": int(pid), "argv": command})
    # Also find helpers whose command omits the root but whose cwd is owned.
    p = subprocess.run(["/usr/sbin/lsof", "-a", "-u", str(os.getuid()), "-d", "cwd", "-Fpn"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    pid = None
    for line in p.stdout.decode().splitlines():
        if line.startswith("p"): pid = int(line[1:])
        elif line.startswith("n") and line[1:].startswith(str(root) + "/") and pid != os.getpid():
            processes.append({"pid": pid, "cwd": line[1:]})
result = {"schema": "sandbox-comparison-cleanup/1", "root": str(root), "owned_processes": processes, "removed": [], "retained_products": {}}
for p in (root / "bin").iterdir():
    if p.is_file(): result["retained_products"][p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
if processes:
    (root / "cleanup.json").write_text(json.dumps(result, indent=2) + "\n")
    raise SystemExit("owned processes still present; cleanup withheld")
for name in ("downloads", "node", "srt", "npm-cache", "fixture-home", "install-home", "private", "data", "config", "work", "greywall", "ripgrep"):
    path = root / name
    if path.is_symlink(): raise SystemExit("unexpected directory symlink: " + name)
    if path.is_dir():
        shutil.rmtree(path)
        result["removed"].append(name)
result["status"] = "complete"
(root / "cleanup.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result), flush=True)
