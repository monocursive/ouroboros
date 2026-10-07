#!/usr/bin/env python3
"""Real production CLI, local proxy denial, explicit capture and exact replay."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ledger, jail, output = map(Path, sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="ouro-redaction-proof-") as tmp:
    root = Path(tmp)
    data, workspace, config = [root / n for n in ("data", "workspace", "config")]
    for path in (data, workspace, config):
        path.mkdir(mode=0o700)
    image = root / "ouro-jail"
    shutil.copyfile(jail, image)
    image.chmod(0o700)
    base = [str(ledger), "--data-dir", str(data)]
    env = os.environ | {"OURO_CONFIG_DIR": str(config)}
    writer = subprocess.Popen(base + ["serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not (data / "ledger/serve.sock").exists():
            assert writer.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        command = base + ["run", "--jail-bin", str(image), "--workspace", str(workspace),
            "--request-id", "redaction-cli-proof", "--jail", "tool", "--limit", "wall=10s",
            "--io", "batch", "--json", "--redact", "paths", "--redact", "destinations",
            "--capture", "stdout", "--capture", "argv", "--", "/bin/sh", "-c",
            'root=$(pwd -P); printf x >> executions; printf capture-private > "$root/path-private"; mv "$root/path-private" "$root/renamed-private"; '
            'printf capture-private']
        first = subprocess.run(command, env=env, capture_output=True, timeout=30)
        assert first.returncode == 0, first.stderr
        run = json.loads(first.stdout)
        assert run["state"] == "settled" and run["child_protection"] == "enforced"
        assert run["payload"]["redact"] == ["destinations", "paths"]
        directory = data / "ledger" / run["run_id"]
        original = (directory / "events-0001.ndjson").read_bytes()
        for secret in (b"path-private", b"renamed-private", b"host-private.invalid", b"capture-private"):
            assert secret not in original and secret not in first.stdout
        events = [json.loads(line) for line in original.splitlines()]
        assert any(e.get("redaction", {}).get("fields") == ["path", "path2"] for e in events)
        assert (directory / "artifacts/stdout.bin").read_bytes() == b"capture-private"
        assert b"path-private" in (directory / "artifacts/argv.bin").read_bytes()
        repeat = subprocess.run(command, env=env, capture_output=True, timeout=30)
        assert repeat.returncode == 0 and json.loads(repeat.stdout) == run
        assert (workspace / "executions").read_bytes() == b"x"
        assert (directory / "events-0001.ndjson").read_bytes() == original
        (output / "redaction-cli.json").write_text(json.dumps(run, indent=2) + "\n")
        (output / "events-cli.ndjson").write_bytes(original)
        print("Real CLI: paths minimized, captures unchanged, exact replay, one execution")
        proxy_command = base + ["run", "--jail-bin", str(image), "--workspace", str(workspace),
            "--request-id", "proxy-cli-proof", "--jail", "agent", "--limit", "wall=10s",
            "--io", "batch", "--json", "--redact", "destinations", "--", "/bin/sh", "-c",
            'touch proxy-child-executed; curl --silent --max-time 3 --noproxy "" --proxy "$HTTP_PROXY" --proxytunnel https://host-private.invalid/ >/dev/null; test $? -ne 0']
        response = subprocess.run(proxy_command, env=env, capture_output=True, timeout=30)
        proxy_run = json.loads(response.stdout)
        proxy_bytes = (data / "ledger" / proxy_run["run_id"] / "events-0001.ndjson").read_bytes()
        proxy_events = [json.loads(line) for line in proxy_bytes.splitlines()]
        assert b"host-private.invalid" not in proxy_bytes
        if proxy_run["state"] == "denied":
            assert response.returncode == 125
            assert proxy_run["outcome"]["error"]["code"] == "missing_capability"
            assert proxy_run["outcome"]["error"]["message"] == "the host does not provide `network_proxy` (unix_socket_diagnostics_unavailable)"
            assert not (workspace / "proxy-child-executed").exists()
            assert all(r["exec_observed"] is False and r["process"] is None for r in proxy_run["receipts"])
            assert not any(e["kind"] == "admitted" for e in proxy_events)
            status = "unsupported_host_refusal_verified"
        else:
            assert response.returncode == 0 and proxy_run["state"] == "settled"
            proxy = next(e for e in proxy_events if e.get("source") == "proxy")
            assert proxy["decision"] == "deny" and proxy["fields"]["destination"] is None
            assert "destination" in proxy["redaction"]["fields"]
            status = "proxy_redaction_verified"
        (output / "proxy-cli.json").write_text(json.dumps(proxy_run, indent=2) + "\n")
        (output / "proxy-events-cli.ndjson").write_bytes(proxy_bytes)
        (output / "proxy-status.json").write_text(json.dumps({"status":status}, indent=2) + "\n")
        print(f"Real proxy CLI: {status}")
    finally:
        writer.terminate()
        writer.communicate(timeout=10)
