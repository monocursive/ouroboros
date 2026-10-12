#!/usr/bin/env python3
"""Provider-backed, interleaved container agent comparison with preserved outputs.

Plain Docker, ephemeral OpenShell lifecycle, and retained OpenShell sandbox exec
use the same image and immutable runner. No credentials are baked into the image.
"""
import argparse
import io
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import tarfile
import time

from agentbench import TASKS
from agentbench_v2 import execute, sha, write, scrub
import workflow_fixture
TASKS[workflow_fixture.NAME] = workflow_fixture.SPEC

IMAGE = "ouro-comparison-agents-v2:20261011"
POLICY = """version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/opt/agents, /opt/bench]
  read_write: [/tmp, /home/agent, /work]
"""
ANTHROPIC_PROFILE = """id: benchmark-anthropic-agent
display_name: Benchmark Anthropic agent
description: Claude Code and OpenCode using the Anthropic API
category: agent
inference_capable: true
credentials:
  - name: api_key
    env_vars: [ANTHROPIC_API_KEY]
    required: true
    auth_style: header
    header_name: x-api-key
discovery:
  credentials: [api_key]
endpoints:
  - host: api.anthropic.com
    port: 443
    protocol: rest
    access: read-write
    enforcement: enforce
binaries: [/opt/agents/bin/claude, /opt/agents/bin/opencode]
"""


def build(args):
    dockerfile = """FROM bench-openshell:latest
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/agents/bin /opt/bench /home/agent /work && chown 1000:1000 /home/agent /work
COPY bin/ /opt/agents/bin/
COPY harness/ /opt/bench/
RUN chmod -R a+rX /opt/agents /opt/bench
ENV HOME=/home/agent PATH=/opt/agents/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 1000:1000
WORKDIR /work
CMD ["/bin/sleep", "infinity"]
"""
    write(args.out / "Dockerfile", dockerfile)
    log = (args.out / "build.log").open("wb")
    p = subprocess.Popen(["docker", "build", "-t", IMAGE, "-"], stdin=subprocess.PIPE, stdout=log, stderr=log)
    try:
        with tarfile.open(fileobj=p.stdin, mode="w|") as tar:
            data = dockerfile.encode()
            info = tarfile.TarInfo("Dockerfile")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
            for name in ("claude", "opencode", "codex", "codex-code-mode-host"):
                tar.add((args.container_bins / name).resolve(), arcname="bin/" + name, recursive=False)
            for name in ("agentbench.py", "agentbench_v2.py", "container_agent_runner.py", "workflow_fixture.py"):
                tar.add(args.root / "harness" / name, arcname="harness/" + name, recursive=False)
    finally:
        p.stdin.close()
    if p.wait(timeout=900):
        raise RuntimeError("Agent image build failed; see build.log")
    return subprocess.check_output(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], text=True).strip()


def credentials(args):
    env = dict(os.environ, ANTHROPIC_API_KEY=args.key_file.read_text().strip())
    auth = json.loads(args.auth_file.read_text())
    for name, value in auth["tokens"].items():
        if value is not None:
            env["CODEX_AUTH_" + name.upper()] = value
    return env


def provider_setup(args, env):
    profile = args.out / "anthropic-profile.yaml"
    write(profile, ANTHROPIC_PROFILE)
    codex_profile = args.out / "codex-profile.yaml"
    source = (args.root / "harness/openshell-provider-codex.yaml").read_text()
    # Keep the official contract, changing only identity and this image's paths.
    start = source.rindex("\nbinaries:")
    source = source[:start] + "\nbinaries: [/opt/agents/bin/codex]\n"
    source = source.replace("id: codex\n", "id: benchmark-codex-agent\n")
    write(codex_profile, source)
    for path, kind, name, variables in (
            (profile, "benchmark-anthropic-agent", "benchmark-anthropic-v2", ["ANTHROPIC_API_KEY"]),
            (codex_profile, "benchmark-codex-agent", "benchmark-codex-v2", ["CODEX_AUTH_ACCESS_TOKEN", "CODEX_AUTH_REFRESH_TOKEN", "CODEX_AUTH_ACCOUNT_ID", "CODEX_AUTH_ID_TOKEN"])):
        commands = [[args.openshell, "profile", "import", "-f", str(path), "--global"],
                    [args.openshell, "provider", "create", "--name", name, "--type", kind,
                     *[arg for v in variables for arg in ("--credential", v)]]]
        rows = []
        for cmd in commands:
            row = execute(cmd, args.root, env, 60)
            rows.append(row)
            if row["exit"]:
                write(args.out / (kind + "-setup.json"), rows, env["ANTHROPIC_API_KEY"])
                raise RuntimeError("Provider setup failed (use a new provider name or inspect setup log)")
        write(args.out / (kind + "-setup.json"), rows, env["ANTHROPIC_API_KEY"])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--container-bins", type=Path)
    p.add_argument("--key-file", type=Path, required=True)
    p.add_argument("--auth-file", type=Path, required=True)
    p.add_argument("--openshell", default="openshell")
    p.add_argument("--agents", default="claude,opencode,codex")
    p.add_argument("--modes", default="docker,openshell-ephemeral,openshell-warm")
    p.add_argument("--tasks", default="add-multiply,fix-offbyone,refactor-yaml-json")
    p.add_argument("--runs", type=int, default=2)
    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--skip-provider-setup", action="store_true")
    args = p.parse_args()
    args.root, args.out = args.root.resolve(), args.out.resolve()
    args.container_bins = (args.container_bins or args.root / "bin").resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    if (args.out / "agent-runs.ndjson").exists():
        raise SystemExit("Refusing to overwrite existing evidence")
    key = args.key_file.read_text().strip()
    env = credentials(args)
    write(args.out / "policy.yaml", POLICY)
    if not args.skip_provider_setup:
        provider_setup(args, env)
    image_id = build(args) if not args.skip_build else subprocess.check_output(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], text=True).strip()
    rng = random.Random(20261011)
    schedule = []
    for agent in args.agents.split(","):
        for rep in range(args.runs):
            tasks = args.tasks.split(",")
            rng.shuffle(tasks)
            for task in tasks:
                modes = args.modes.split(",")
                rng.shuffle(modes)
                schedule.extend((agent, task, rep, mode) for mode in modes)
    write(args.out / "metadata.json", {"schema": "container-agent-comparison/2", "host": platform.uname()._asdict(),
          "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
          "image_id": image_id, "schedule": schedule, "seed": 20261011, "harness_sha256": sha(__file__),
          "container_bin_hashes": {name: sha(args.container_bins / name) for name in ("claude", "opencode", "codex", "codex-code-mode-host")}})
    warm = {}
    results = []
    try:
        with (args.out / "agent-runs.ndjson").open("w") as raw:
            for seq, (agent, task, rep, mode) in enumerate(schedule, 1):
                provider = "benchmark-codex-v2" if agent == "codex" else "benchmark-anthropic-v2"
                inner = ["/usr/bin/python3", "/opt/bench/container_agent_runner.py", agent, task]
                if mode == "docker":
                    names = ["ANTHROPIC_API_KEY"] if agent != "codex" else ["CODEX_AUTH_" + n.upper() for n in ("access_token", "refresh_token", "account_id", "id_token")]
                    argv = ["docker", "run", "--rm", *[a for n in names for a in ("-e", n)], IMAGE, *inner]
                elif mode == "openshell-ephemeral":
                    argv = [args.openshell, "sandbox", "create", "--no-keep", "--no-tty", "--from", IMAGE,
                            "--policy", str(args.out / "policy.yaml"), "--provider", provider, "--", *inner]
                else:
                    if agent not in warm:
                        name = "bench-v2-" + agent
                        create = execute([args.openshell, "sandbox", "create", "--name", name, "--detach", "--from", IMAGE,
                                          "--policy", str(args.out / "policy.yaml"), "--provider", provider,
                                          "--", "/bin/sleep", "infinity"], args.root, env, 180)
                        write(args.out / ("warm-" + agent + "-create.json"), create, key)
                        if create["exit"]:
                            raise RuntimeError("Warm sandbox creation failed")
                        warm[agent] = name
                    argv = [args.openshell, "sandbox", "exec", "-n", warm[agent], "--no-tty", "--", *inner]
                result = execute(argv, args.root, env, 300)
                parsed = None
                for line in result["stdout"].splitlines():
                    if line.startswith("CONTAINER-AGENT-RESULT="):
                        parsed = json.loads(line.split("=", 1)[1])
                success = result["exit"] == 0 and not result["timeout"] and bool(parsed and parsed["success"])
                run_dir = args.out / "runs" / ("%03d-%s-%s-%s-%d" % (seq, agent, mode, task, rep))
                write(run_dir / "stdout.log", result["stdout"], key)
                write(run_dir / "stderr.log", result["stderr"], key)
                if parsed:
                    write(run_dir / "patch.diff", parsed.pop("patch"), key)
                    for path, content in parsed.pop("files").items():
                        target = Path(path)
                        if target.is_absolute() or ".." in target.parts:
                            raise RuntimeError("Invalid returned file path")
                        write(run_dir / "workspace" / target, content, key)
                row = {"sequence": seq, "agent": agent, "mode": mode, "task": task, "repetition": rep,
                       "success": success, "exit": result["exit"], "timeout": result["timeout"],
                       "elapsed_ms": result["elapsed_ms"], "container_result": parsed, "argv": argv,
                       "load": os.getloadavg(), "artifact": str(run_dir.relative_to(args.out))}
                write(run_dir / "result.json", row, key)
                raw.write(scrub(json.dumps(row), key) + "\n")
                raw.flush()
                results.append(row)
                summary = {}
                for r in results:
                    bucket = summary.setdefault(r["agent"] + "/" + r["mode"], {"runs": 0, "success": 0, "times_ms": []})
                    bucket["runs"] += 1
                    if r["success"]:
                        bucket["success"] += 1
                        bucket["times_ms"].append(r["elapsed_ms"])
                for bucket in summary.values():
                    bucket["median_ms"] = statistics.median(bucket["times_ms"]) if bucket["times_ms"] else None
                write(args.out / "agent-summary.json", summary)
                print("%d/%d %s %s %s #%d %.1fs exit=%s success=%s" %
                      (seq, len(schedule), agent, mode, task, rep, result["elapsed_ms"] / 1000,
                       result["exit"], success), flush=True)
    finally:
        for name in warm.values():
            execute([args.openshell, "sandbox", "delete", "-n", name], args.root, env, 90)
    print("COMPLETE", flush=True)


if __name__ == "__main__":
    main()
