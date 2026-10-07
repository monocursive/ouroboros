#!/usr/bin/env python3
"""Real native CLI probe; only its private fixture writer is stopped."""
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
with tempfile.TemporaryDirectory(prefix="ouro-transcript-proof-") as tmp:
    root = Path(tmp)
    data, workspace, config = [root / name for name in ("data", "workspace", "config")]
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
            assert writer.poll() is None, "fixture writer exited"
            assert time.monotonic() < deadline, "writer startup timeout"
            time.sleep(0.01)
        def command(args):
            p = subprocess.run(base + args, env=env, capture_output=True, timeout=30)
            assert p.returncode == 0, p.stderr.decode(errors="replace")
            return json.loads(p.stdout)
        run = command(["run", "--jail-bin", str(image), "--workspace", str(workspace),
            "--request-id", "transcript-cli-proof", "--jail", "tool", "--limit", "wall=10s",
            "--io", "batch", "--json", "--capture", "stdout", "--capture", "stderr",
            "--capture-limit", "8", "--", "/bin/sh", "-c",
            r"printf 'test-output'; printf '\033\377\n' >&2"])
        assert run["state"] == "settled", run
        plain = command(["show", run["run_id"], "--json"])
        shown = command(["show", run["run_id"], "--with-transcript", "--json"])
        assert shown["run"] == plain == run
        assert "transcript" not in plain
        streams = shown["transcript"]["streams"]
        assert streams["stdout"]["state"] == "truncated"
        assert streams["stdout"]["text"] == "test-out"
        assert streams["stderr"]["text"] == r"\x1b\xff\n"
        assert streams["argv"]["state"] == "not_captured"
        (output / "transcript-cli.json").write_text(json.dumps(shown, indent=2) + "\n")
        print("Real CLI: settled, capture truncation labelled, controls escaped, metadata unchanged")
    finally:
        writer.terminate()
        writer.communicate(timeout=10)
