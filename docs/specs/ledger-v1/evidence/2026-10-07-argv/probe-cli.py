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
with tempfile.TemporaryDirectory(prefix="ouro-argv-proof-") as tmp:
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
            "--request-id", "argv-cli-proof", "--jail", "tool", "--limit", "wall=10s",
            "--io", "batch", "--json", "--capture", "stdout", "--capture", "stderr",
            "--capture", "argv", "--capture-limit", "1024", "--", "/bin/sh", "-c",
            r"printf 'test-output'; printf '\033\377\n' >&2", "", b"private-argv\xff\x1b"])
        assert run["state"] == "settled", run
        plain = command(["show", run["run_id"], "--json"])
        shown = command(["show", run["run_id"], "--with-transcript", "--json"])
        assert shown["run"] == plain == run
        assert "transcript" not in plain
        streams = shown["transcript"]["streams"]
        assert streams["stdout"]["state"] == "captured"
        assert streams["stdout"]["text"] == "test-output"
        assert streams["stderr"]["text"] == r"\x1b\xff\n"
        assert streams["argv"]["state"] == "captured"
        assert "private-argv" not in json.dumps(plain)
        expected = b"/bin/sh\0-c\0" + rb"printf 'test-output'; printf '\033\377\n' >&2" + b"\0\0private-argv\xff\x1b\0"
        artifact = data / "ledger" / run["run_id"] / "artifacts/argv.bin"
        assert artifact.read_bytes() == expected
        assert run["capture"]["argv"]["argument_count"] == 5
        keys = root / "keys"
        command(["bundle-keygen", "--output", str(keys), "--json"])
        bundle = root / "bundle"
        report = command(["bundle", run["run_id"], "--output", str(bundle),
            "--capture", "stdout", "--capture", "stderr", "--capture", "argv",
            "--signing-key", str(keys / "private-key.pk8"), "--json"])
        assert (bundle / "argv.bin").read_bytes() == expected
        manifest = json.loads((bundle / "bundle.json").read_text())
        for name, value in (("bundle-cli.json", manifest), ("bundle-verification-cli.json", report)):
            (output / name).write_text(json.dumps(value, indent=2) + "\n")
        for line in (bundle / "events.ndjson").read_bytes().splitlines():
            assert b"private-argv" not in line
        (output / "events-cli.ndjson").write_bytes((bundle / "events.ndjson").read_bytes())
        (output / "argv-cli.json").write_text(json.dumps(shown, indent=2) + "\n")
        print("Real CLI: exact native argv, controls escaped, metadata private, all three signed artifacts")
    finally:
        writer.terminate()
        writer.communicate(timeout=10)
