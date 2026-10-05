"""ARM64 strict launches refuse before execution and retain replay identity."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

root = Path(__file__).resolve().parent
base = root / "refusal-smoke"
base.mkdir(mode=0o700)
for name in ["config", "workspace"]:
    (base / name).mkdir(mode=0o700)
jail = base / "ouro-jail"
shutil.copyfile(root / "target/release/ouro-jail", jail)
jail.chmod(0o700)
ledger = str(root / "target/release/ouro-ledger")
common = [ledger, "--data-dir", str(base / "data")]
env = dict(os.environ, OURO_CONFIG_DIR=str(base / "config"))


def invoke(name, args):
    result = subprocess.run(common + args, env=env, capture_output=True, timeout=30)
    (base / f"{name}.json").write_bytes(result.stdout)
    (base / f"{name}.stderr").write_bytes(result.stderr)
    return result.returncode, json.loads(result.stdout)


def run_args(profile, request, script):
    return ["run", "--request-id", request, "--jail-bin", str(jail),
            "--workspace", str(base / "workspace"), "--jail", profile,
            "--limit", "wall=10s", "--io", "batch", "--capture", "stdout", "--json",
            "--", "/bin/sh", "-c", script]


with (base / "writer.stdout").open("wb") as out, (base / "writer.stderr").open("wb") as err:
    writer = subprocess.Popen(common + ["serve"], env=env, stdout=out, stderr=err)
    try:
        deadline = time.monotonic() + 10
        while not (base / "data/ledger/serve.sock").exists():
            assert writer.poll() is None, "writer exited before binding its socket"
            assert time.monotonic() < deadline, "writer startup timed out"
            time.sleep(0.02)
        results = []
        for profile in ["tool", "none"]:
            marker = base / "workspace" / (profile + "-executions")
            args = run_args(profile, "pi-refusal-" + profile,
                            "printf unexpected >> " + marker.name)
            code, first = invoke(profile + "-first", args)
            assert code == 125 and first["state"] == "denied", (code, first)
            assert first["outcome"]["error"]["code"] == "missing_capability"
            assert "unsupported_architecture" in first["outcome"]["error"]["message"]
            assert first["child_protection"] == "unprotected"
            code, replay = invoke(profile + "-replay", args)
            assert code == 125 and replay["state"] == "denied", (code, replay)
            for field in ["run_id", "attempt_id", "chain", "outcome", "child_protection"]:
                assert replay[field] == first[field], field
            assert not marker.exists(), "refused launch executed a child"
            code, verified = invoke(profile + "-verify", ["verify", first["run_id"], "--json"])
            assert code == 0 and verified[0]["local_consistency"] is True
            assert verified[0]["child_protection"] == "unprotected"
            results.append({"profile": profile, "exit": 125, "state": "denied",
                            "refusal": first["outcome"]["error"]["message"],
                            "same_replay_identity_chain_outcome": True,
                            "child_executed": False, "local_consistency": True,
                            "child_protection": "unprotected"})
        summary = {"checks_passed": True, "launches_supported": False,
                   "containment_proof": False, "profiles": results}
        (root / "refusal-smoke-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
    finally:
        writer.terminate()
        try:
            writer.wait(timeout=10)
        except subprocess.TimeoutExpired:
            writer.kill()
            writer.wait(timeout=10)
