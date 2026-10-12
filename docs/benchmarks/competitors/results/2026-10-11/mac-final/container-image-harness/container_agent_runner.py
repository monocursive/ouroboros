#!/usr/bin/env python3
"""Immutable in-image task runner: original tests plus independent assertions."""
import argparse
import base64
import json
import os
from pathlib import Path
import resource
import subprocess
import time

from agentbench import TASKS, make_task_dir
from agentbench_v2 import independent_check, execute
import workflow_fixture
TASKS[workflow_fixture.NAME] = workflow_fixture.SPEC


def main():
    p = argparse.ArgumentParser()
    p.add_argument("agent", choices=["claude", "opencode", "codex"])
    p.add_argument("task", choices=list(TASKS))
    p.add_argument("--codex-model", default="gpt-6.1-sol")
    args = p.parse_args()
    base = Path("/work") / (args.agent + "-" + str(time.time_ns()))
    task_dir = (workflow_fixture.make_task_dir if args.task == workflow_fixture.NAME else make_task_dir)(base / "workspace", args.task)
    home = base / "home"
    home.mkdir()
    state = home / ".codex"
    state.mkdir()
    env = dict(os.environ)
    env.update({"HOME": str(home), "PWD": str(task_dir), "CODEX_HOME": str(state), "TMPDIR": "/tmp",
                "CLAUDE_CONFIG_DIR": str(home / ".claude"),
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1",
                "OPENCODE_DISABLE_AUTOUPDATE": "true", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull})
    for name, suffix in (("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"),
                         ("XDG_STATE_HOME", ".local/state"), ("XDG_CACHE_HOME", ".cache")):
        env[name] = str(home / suffix)
    prompt = TASKS[args.task]["prompt"]
    binary = "/opt/agents/bin/" + args.agent
    if args.agent == "claude":
        argv = [binary, "-p", prompt, "--model", "claude-sonnet-4-5", "--max-turns", "15",
                "--dangerously-skip-permissions", "--output-format", "json"]
    elif args.agent == "opencode":
        argv = [binary, "run", "--dir", str(task_dir), "--model", "anthropic/claude-sonnet-4-5", prompt]
    else:
        # The official OpenShell Codex provider exports OAuth credential fields.
        # Stage those fields as the CLI's ordinary auth.json, outside the image.
        tokens = {name: env.get("CODEX_AUTH_" + name.upper(), "")
                  for name in ("id_token", "access_token", "refresh_token", "account_id")}
        auth_mode = 'chatgpt'
        if not tokens['id_token'].startswith('eyJ'):
            # NVIDIA v0.1.3 examples/codex-app-server/start-codex-app-server:
            # Codex parses ID tokens locally; provider handles are opaque.
            # Use the documented non-secret identity and external-token mode.
            def b64(value):
                return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
            now = int(time.time())
            tokens['id_token'] = '.'.join((b64({'alg': 'none', 'typ': 'JWT'}),
                b64({'iss': 'https://auth.openai.com', 'aud': 'codex', 'sub': 'openshell-app-server',
                     'email': 'app-server@openshell.local', 'iat': now, 'exp': now + 3600}), 'placeholder'))
            tokens['refresh_token'] = ''
            # CLI 0.159.2 matches its selected workspace against the routing
            # discovery response. An opaque account-id handle cannot match.
            # Pass this non-secret identifier with OpenShell's ordinary --env.
            tokens['account_id'] = env.get('BENCH_CODEX_ROUTING_ACCOUNT_ID', tokens['account_id'])
            auth_mode = 'chatgptAuthTokens'
        (state / "auth.json").write_text(json.dumps({"auth_mode": auth_mode, "OPENAI_API_KEY": None,
             "tokens": tokens, "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
        (state / "auth.json").chmod(0o600)
        argv = [binary, "exec", "--ephemeral", "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox", "--model", args.codex_model,
                "-c", 'model_reasoning_effort="low"', "-C", str(task_dir), prompt]
    before = time.perf_counter_ns()
    result = execute(argv, task_dir, env, 240)
    work_ms = (time.perf_counter_ns() - before) / 1e6
    stdout, stderr = result['stdout'], result['stderr']
    print(stdout, end="")
    print(stderr, end="", file=__import__("sys").stderr)
    verdict = (workflow_fixture.independent_check if args.task == workflow_fixture.NAME else independent_check)(task_dir, args.task)
    patch = subprocess.run(["git", "diff", "--no-ext-diff", "HEAD"], cwd=task_dir,
                           stdout=subprocess.PIPE, check=True).stdout.decode(errors="replace")
    files = {str(path.relative_to(task_dir)): path.read_text(errors="replace")
             for path in task_dir.rglob("*") if path.is_file() and
             path.suffix in (".py", ".md", ".json", ".toml") and ".git" not in path.parts}
    success = result['exit'] == 0 and not result['timeout'] and all(verdict[k] for k in ("tests_pass", "tests_unchanged", "hidden_pass"))
    limits = {}
    for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"):
        path = Path("/sys/fs/cgroup") / name
        if path.exists():
            try:
                limits[name] = path.read_text().strip()
            except OSError as error:
                limits[name] = {"unreadable": str(error)}
    usage = {}
    try:
        parsed = json.loads(stdout)
        usage = {k: parsed.get(k) for k in ("total_cost_usd", "num_turns", "duration_api_ms")}
    except ValueError:
        pass
    print("CONTAINER-AGENT-RESULT=" + json.dumps({"agent": args.agent, "task": args.task,
          "agent_exit": result['exit'], "timeout": result['timeout'], "success": success, "work_ms": work_ms,
          "checker": verdict, "patch": patch, "files": files, "usage": usage,
          "peak_child_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
          "guest_kernel": list(os.uname()), "resource_limits": limits}))
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
