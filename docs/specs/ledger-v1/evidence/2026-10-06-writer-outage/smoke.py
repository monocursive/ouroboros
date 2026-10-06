#!/usr/bin/env python3
"""Real post-admission writer loss, local exit, restart, and portable recovery proof."""
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

ledger, jail, output = map(Path, sys.argv[1:])
output.mkdir(mode=0o700)

def until(predicate):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("bounded smoke deadline expired")

def rpc(data, request):
    def exact(s, n):
        result = b""
        while len(result) < n:
            part = s.recv(n - len(result))
            if not part:
                raise ConnectionError("lost reply")
            result += part
        return result
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(2)
        s.connect(str(data / "ledger/serve.sock"))
        body = json.dumps(request).encode()
        s.sendall(struct.pack(">I", len(body)) + body)
        length = struct.unpack(">I", exact(s, 4))[0]
        assert length <= 1048576
        reply = json.loads(exact(s, length))
        assert reply["status"] == "ok", reply
        return reply["value"]

reports = []
for profile in ["tool", "none"]:
    target = output / profile
    target.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="ouro-outage-proof-") as temp:
        root = Path(temp)
        data, workspace, config = [root / name for name in ["data", "workspace", "config"]]
        workspace.mkdir(mode=0o700)
        config.mkdir(mode=0o700)
        pinned = root / "ouro-jail"
        shutil.copyfile(jail, pinned)
        pinned.chmod(0o700)
        env = dict(os.environ, OURO_CONFIG_DIR=str(config))
        base = [str(ledger), "--data-dir", str(data)]
        writer = owner = None
        writer_log = (target / "writer.stderr").open("wb")
        def start_writer():
            process = subprocess.Popen(base + ["serve"], env=env, stdout=subprocess.DEVNULL, stderr=writer_log)
            def ready():
                assert process.poll() is None, "writer exited"
                try:
                    return rpc(data, {"op": "ping"})
                except (OSError, ConnectionError):
                    return None
            until(ready)
            return process
        try:
            writer = start_writer()
            command = base + ["run", "--request-id", "outage-proof", "--jail-bin", str(pinned), "--workspace", str(workspace), "--jail", profile, "--limit", "wall=20s", "--io", "batch", "--evidence", "best-effort", "--capture", "stdout", "--capture-limit", "64", "--json", "--", "/bin/sh", "-c", "printf x >> executions; touch started; while test ! -f release; do sleep 0.05; done; printf recovered-local-exit"]
            owner = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            until(lambda: (workspace / "started").exists())
            run_dir = next((data / "ledger").glob("run_*"))
            run_id = run_dir.name
            admitted = rpc(data, {"op": "show", "run_id": run_id})
            assert admitted["state"] == "admitted"
            (target / "admitted.json").write_text(json.dumps(admitted, indent=2) + "\n")
            writer.kill()
            writer.wait(timeout=5)
            pending_path = run_dir / "owner-pending.json"
            until(lambda: json.loads(pending_path.read_text())["state"]["active"])
            (workspace / "release").touch()
            stdout, stderr = owner.communicate(timeout=20)
            assert owner.returncode != 0 and b"canonical reconciliation is pending" in stderr, (owner.returncode, stdout, stderr)
            (target / "owner.stderr").write_bytes(stderr)
            pending = json.loads(pending_path.read_text())
            assert pending["state"]["completion"]["kind"] == "settled"
            (target / "local-exit.json").write_text(json.dumps(pending, indent=2) + "\n")
            writer = start_writer()
            settled = rpc(data, {"op": "show", "run_id": run_id})
            assert settled["state"] == "settled", settled
            assert settled["coverage"]["ledger"]["status"] == "degraded"
            assert (workspace / "executions").read_bytes() == b"x"
            assert not pending_path.exists()
            (target / "settled.json").write_text(json.dumps(settled, indent=2) + "\n")
            bundle = target / "bundle"
            created = subprocess.run(base + ["bundle", run_id, "--output", str(bundle), "--capture", "stdout", "--json"], env=env, capture_output=True, check=True)
            (target / "bundle-created.json").write_bytes(created.stdout)
            writer.kill()
            writer.wait(timeout=5)
            verified = subprocess.run([str(ledger), "verify-bundle", str(bundle), "--json"], env=env, capture_output=True, check=True)
            (target / "verified.json").write_bytes(verified.stdout)
            events = [json.loads(line) for line in (bundle / "events.ndjson").read_text().splitlines()]
            assert sum(e["kind"] == "evidence_gap" for e in events) == 1
            assert any(e["provenance"]["role"] == "recovery" for e in events)
            assert (bundle / "stdout.bin").read_bytes() == b"recovered-local-exit"
            reports.append({"profile": profile, "run_id": run_id, "state": settled["state"], "coverage": settled["coverage"]["ledger"], "child_protection": settled["child_protection"], "executions": 1, "owner_exit": owner.returncode, "portable_verification": "passed"})
        finally:
            for process in [owner, writer]:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            writer_log.close()
(output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
print(json.dumps(reports, indent=2))
