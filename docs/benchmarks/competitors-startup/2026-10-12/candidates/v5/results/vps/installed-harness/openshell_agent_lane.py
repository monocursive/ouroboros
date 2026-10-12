#!/usr/bin/env python3
"""OpenShell agent lane: the opencode task battery inside a sandbox.

Builds an image with the OpenCode binary and the three fixture tasks, runs
each task via `sandbox create --no-keep` under a policy that allows only
api.anthropic.com for the agent binary tree, and validates by running the
unit tests inside the container (markers on stdout). Container-class lane;
numbers are not mixed into the wrapper ratios of agentbench.py.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))
import agentbench  # noqa: E402  (task fixtures and prompts)

IMAGE = "bench-openshell-agents:latest"

POLICY = """version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/opt/opencode]
  read_write: [/tmp, /home/agent, /tasks]
network_policies:
  anthropic:
    endpoints:
      - host: api.anthropic.com
        port: 443
    binaries:
      - path: /opt/opencode/opencode
"""

RUNNER = """#!/bin/bash
set -u
task="$1"
cd "/tasks/$task" || exit 9
git config --global --add safe.directory "/tasks/$task" 2>/dev/null || true
export HOME=/home/agent
/opt/opencode/opencode run --model anthropic/claude-sonnet-4-5 "$(cat /tasks/$task.prompt)" </dev/null || echo "AGENT-EXIT=$?"
python3 -m unittest discover -s tests >/tmp/tests.log 2>&1 && echo "TESTS=PASS" || echo "TESTS=FAIL"
tail -3 /tmp/tests.log
"""


def run(command, timeout=420):
    before = time.perf_counter_ns()
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return {"argv": [str(c) for c in command], "elapsed_ms": (time.perf_counter_ns() - before) / 1e6, "exit": process.returncode, "stdout": process.stdout.decode(errors="replace"), "stderr": process.stderr.decode(errors="replace")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--openshell", default="openshell")
    parser.add_argument("--opencode-bin", default=str(Path.home() / ".opencode/bin/opencode"))
    parser.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    key = args.key_file.read_text().strip()
    context = root / "agent-image"
    context.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.opencode_bin, context / "opencode")
    (context / "runner.sh").write_text(RUNNER)
    (context / "policy.yaml").write_text(POLICY)
    dockerfile = ["FROM " + "bench-openshell:latest", "RUN (useradd -m -u 1000 agent || true) && mkdir -p /home/agent && chown -R 1000:1000 /home/agent", "COPY --chown=1000:1000 opencode /opt/opencode/opencode", "COPY runner.sh /work/runner.sh", "RUN chmod +x /opt/opencode/opencode /work/runner.sh"]
    for task in agentbench.TASKS:
        dockerfile.append("COPY --chown=1000:1000 tasks/%s /tasks/%s" % (task, task))
        (context / "tasks" / task).mkdir(parents=True, exist_ok=True)
        for name, content in agentbench.TASKS[task]["files"].items():
            target = context / "tasks" / task / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        (context / "tasks" / task / "src/__init__.py").write_text("")
        (context / "tasks" / task / "tests/__init__.py").write_text("")
        (context / "tasks" / (task + ".prompt")).write_text(agentbench.TASKS[task]["prompt"])
        dockerfile.append("COPY --chown=1000:1000 tasks/%s.prompt /tasks/%s.prompt" % (task, task))
    (context / "Dockerfile").write_text("\n".join(dockerfile) + "\n")
    build = run(["docker", "build", "-t", IMAGE, str(context)], timeout=900)
    (out / "build.json").write_text(json.dumps({k: build[k] for k in ("exit", "stderr")}, indent=2)[:6000] + "\n")
    if build["exit"] != 0:
        raise SystemExit("image build failed")

    raw = (out / "openshell-agent-runs.ndjson").open("w")
    results = []
    counter = 0
    for task in agentbench.TASKS:
        for run_id in range(args.runs):
            counter += 1
            row = run([args.openshell, "sandbox", "create", "--no-keep", "--from", IMAGE, "--policy", str(context / "policy.yaml"), "--env", "ANTHROPIC_API_KEY=" + key, "--", "/bin/bash", "/work/runner.sh", task])
            tests = re.search(r"TESTS=(PASS|FAIL)", row["stdout"])
            verdict = {"tests_pass": bool(tests and tests.group(1) == "PASS")}
            row_out = {"sequence": counter, "agent": "opencode", "mode": "openshell-ephemeral", "task": task, "run": run_id, "elapsed_ms": round(row["elapsed_ms"]), "exit": row["exit"], "checker": verdict, "stdout_tail": row["stdout"][-4000:], "stderr_tail": row["stderr"][-2000:]}
            raw.write(json.dumps(row_out, separators=(",", ":")) + "\n")
            raw.flush()
            results.append(row_out)
            print("opencode openshell", task, "run%d" % run_id, "%.0fms exit=%s tests=%s" % (row["elapsed_ms"], row["exit"], verdict["tests_pass"]), flush=True)
    raw.close()
    ok = [r["elapsed_ms"] for r in results if r["checker"]["tests_pass"]]
    summary = {"agent": "opencode", "mode": "openshell-ephemeral", "runs": len(results), "success": len(ok), "elapsed_ms_median": statistics.median(ok) if ok else None}
    (out / "openshell-agent-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    raise SystemExit(main())
