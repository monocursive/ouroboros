#!/usr/bin/env python3
"""Real foreground CLI: independent result descriptor, original child bytes and exit."""
import fcntl
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
with tempfile.TemporaryDirectory(prefix="ouro-control-proof-") as tmp:
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
        previous = None
        for attempt in range(2):
            # The descriptor number is transport-local, not part of the request identity.
            with tempfile.TemporaryFile() as result:
                fd = fcntl.fcntl(result.fileno(), fcntl.F_DUPFD_CLOEXEC, 200 + attempt)
                assert fd == 200 + attempt, fd
                p = subprocess.run(base + ["run", "--jail-bin", str(image),
                    "--workspace", str(workspace), "--request-id", "control-cli-proof",
                    "--jail", "tool", "--limit", "wall=10s", "--control-fd", str(fd),
                    "--capture", "stdout", "--capture", "stderr", "--capture-limit", "32",
                    "--", "/bin/sh", "-c", r'IFS= read -r line; printf "%s" "$line"; printf x >> executions; printf "test\033\377"; printf "err\000" >&2; exit 7'],
                    env=env, pass_fds=(fd,), input=b"stdin-line\n", capture_output=True, timeout=30)
                os.close(fd)
                assert p.returncode == 7, (p.returncode, p.stderr)
                result.seek(0)
                raw = result.read()
                assert raw.endswith(b"\n") and raw.count(b"\n") == 1
                run = json.loads(raw)
            assert run["state"] == "settled" and run["outcome"]["code"] == 7
            assert run["payload"]["io"] == {"mode": "foreground", "pty": False, "control": "separate_fd"}
            if attempt == 0:
                assert p.stdout == b"stdin-linetest\x1b\xff" and p.stderr == b"err\0", (p.stdout, p.stderr)
                (output / "control-cli.json").write_text(json.dumps(run, indent=2) + "\n")
                (output / "child-streams.json").write_text(json.dumps({"exit_code": p.returncode,
                    "control_fds": [200, 201], "stdout_hex": p.stdout.hex(), "stderr_hex": p.stderr.hex(), "result_frame_bytes": len(raw)}, indent=2) + "\n")
                previous = run
            else:
                assert run == previous
                assert not p.stdout and not p.stderr
        assert (workspace / "executions").read_bytes() == b"x"
        records = data / "ledger" / run["run_id"] / "events-0001.ndjson"
        (output / "events-cli.ndjson").write_bytes(records.read_bytes())
        print("Real CLI: separate result JSON, inherited stdin, exact child bytes, exit 7, different fd on replay, one execution")
    finally:
        writer.terminate()
        writer.communicate(timeout=10)
