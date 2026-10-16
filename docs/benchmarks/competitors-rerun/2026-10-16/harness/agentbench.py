#!/usr/bin/env python3
"""Agent task battery: run coding agents under each sandbox wrapper.

Fixed three-task battery in fresh git repos per run, identical prompts and
model across wrappers, validated by an objective checker (unit tests plus
required content). Wrappers: direct (unprotected baseline), ouro-jail
(agent profile + launch profile + destination grant), greywall (deny-by-default
fs + greyproxy SOCKS5 with an api.anthropic.com allow rule and credential
injection), mxc (bubblewrap/seatbelt; egress rules are CIDR-only in v1, so
the allowlist resolves the API hostname just before each run).

The Anthropic key is read from a 0600 file and reaches processes via the
environment (or greyproxy credential injection); it is never written to any
result file. Agent stdout/stderr is retained truncated (4096 chars/pipe).
"""
import argparse
import shlex
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

MODEL = "claude-sonnet-4-5"

TASKS = {
    "add-multiply": {
        "prompt": "Add a function multiply(a, b) to src/calc.py that returns the product of two numbers. Then run the tests with: python3 -m unittest discover -s tests -v. Fix any failures until all tests pass. Do not modify the tests.",
        "files": {
            "src/calc.py": "def add(a, b):\n    return a + b\n",
            "tests/test_calc.py": "import unittest\nfrom src.calc import add\n\nclass TestCalc(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n    def test_multiply(self):\n        from src.calc import multiply\n        self.assertEqual(multiply(2, 3), 6)\n        self.assertEqual(multiply(-1, 5), -5)\n",
        },
        "check": "python3 -m unittest discover -s tests",
        "required": [("src/calc.py", "def multiply")],
    },
    "fix-offbyone": {
        "prompt": "The tests are failing. Run python3 -m unittest discover -s tests -v, find the bug in src/parse.py, and fix it so all tests pass. Do not modify the tests.",
        "files": {
            "src/parse.py": "def first_word(text):\n    # Return the first word of a space-separated string\n    parts = text.split(' ')\n    return parts[1]\n",
            "tests/test_parse.py": "import unittest\nfrom src.parse import first_word\n\nclass TestParse(unittest.TestCase):\n    def test_basic(self):\n        self.assertEqual(first_word('hello world'), 'hello')\n    def test_single(self):\n        self.assertEqual(first_word('solo'), 'solo')\n",
        },
        "check": "python3 -m unittest discover -s tests",
        "required": [("src/parse.py", "parts[0]")],
    },
    "refactor-yaml-json": {
        "prompt": "Refactor src/store.py to use the json module instead of yaml. Keep the same class names and method signatures. Make all tests pass: python3 -m unittest discover -s tests -v. Do not modify the tests.",
        "files": {
            "src/store.py": "import yaml\n\nclass Store:\n    def __init__(self, path):\n        self.path = path\n\n    def save(self, data):\n        with open(self.path, 'w') as f:\n            yaml.dump(data, f)\n\n    def load(self):\n        with open(self.path) as f:\n            return yaml.safe_load(f)\n",
            "tests/test_store.py": "import unittest, tempfile, os\nfrom src.store import Store\n\nclass TestStore(unittest.TestCase):\n    def test_roundtrip(self):\n        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as t:\n            path = t.name\n        try:\n            s = Store(path)\n            s.save({'a': 1, 'b': [1, 2]})\n            self.assertEqual(s.load(), {'a': 1, 'b': [1, 2]})\n        finally:\n            os.unlink(path)\n",
        },
        "check": "python3 -m unittest discover -s tests",
        "required": [("src/store.py", "import json")],
    },
}


def make_task_dir(base, task):
    task_dir = base / task
    if task_dir.exists():
        shutil.rmtree(task_dir)
    for name, content in TASKS[task]["files"].items():
        target = task_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    (task_dir / "src/__init__.py").write_text("")
    (task_dir / "tests/__init__.py").write_text("")
    subprocess.run(["git", "init", "-q", str(task_dir)], check=True)
    subprocess.run(["git", "add", "-A"], cwd=task_dir, check=True)
    subprocess.run(["git", "-c", "user.email=bench@local", "-c", "user.name=bench", "commit", "-qm", "fixture"], cwd=task_dir, check=True, stdout=subprocess.DEVNULL)
    return task_dir


def check(task_dir, task):
    spec = TASKS[task]
    test = subprocess.run(spec["check"].split(), cwd=task_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    content_ok = all(needle in (task_dir / path).read_text(errors="replace") for path, needle in spec["required"])
    git_dirty = subprocess.run(["git", "status", "--porcelain"], cwd=task_dir, stdout=subprocess.PIPE).stdout.decode().strip()
    return {"tests_pass": test.returncode == 0, "content_ok": content_ok, "files_changed": len(git_dirty.splitlines()), "test_output_tail": test.stdout.decode(errors="replace")[-600:]}


class GreyProxy:
    """Private greyproxy instance for the greywall agent lane."""

    def __init__(self, root, greyproxy_bin):
        self.root = root
        self.bin = greyproxy_bin
        self.base = "http://127.0.0.1"
        self.ports = {"dashboard": 43080, "socks": 43052, "http": 43051, "dns": 43053}
        self.config = root / "greyproxy.yml"
        self.config.write_text(
            "greyproxy:\n"
            "  addr: \"127.0.0.1:43080\"\n"
            "  db: \"%s\"\n"
            "services:\n"
            "  - name: http-proxy\n"
            "    addr: \"127.0.0.1:43051\"\n"
            "    handler: {type: http}\n"
            "    listener: {type: tcp}\n"
            "  - name: socks5-proxy\n"
            "    addr: \"127.0.0.1:43052\"\n"
            "    handler: {type: socks5}\n"
            "    listener: {type: tcp}\n"
            "  - name: dns-proxy\n"
            "    addr: \"127.0.0.1:43053\"\n"
            "    handler: {type: dns}\n"
            "    listener: {type: tcp}\n" % (root / "greyproxy.db")
        )
        self.process = None

    def start(self):
        self.process = subprocess.Popen([str(self.bin), "serve", "-C", str(self.config)], stdout=(self.root / "greyproxy.log").open("w"), stderr=subprocess.STDOUT)
        for _ in range(50):
            try:
                urllib.request.urlopen(self.base + ":%d/api/health" % self.ports["dashboard"], timeout=1).read()
                return True
            except Exception:
                time.sleep(0.2)
        return False

    def api(self, method, path, body=None):
        request = urllib.request.Request(self.base + ":%d%s" % (self.ports["dashboard"], path), method=method)
        data = json.dumps(body).encode() if body is not None else None
        if data:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, data, timeout=10) as response:
                return json.loads(response.read() or b"{}")
        except Exception as error:
            return {"error": str(error)}

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()


def build_task_repo(root, task):
    return make_task_dir(root / "tasks", task)


def agent_argv(agent, prompt, platform_name, home, extra_paths):
    if agent == "claude":
        claude_bin = shutil.which("claude") or "/usr/bin/claude"
        return [claude_bin, "-p", prompt, "--model", MODEL, "--max-turns", "15", "--dangerously-skip-permissions", "--output-format", "json"]
    if agent == "opencode":
        return [str(extra_paths["opencode"]), "run", "--model", "anthropic/" + MODEL, prompt]
    if agent == "codex":
        codex_bin = shutil.which("codex") or str(Path.home() / ".local/bin/codex")
        return [codex_bin, "exec", "--skip-git-repo-check", "--sandbox", "workspace-write", "-C", str(extra_paths["task_dir"]), prompt]
    raise ValueError(agent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="benchmark root with bin/ and harness/")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--agents", default="claude,opencode")
    parser.add_argument("--modes", default="direct,ouro,greywall")
    parser.add_argument("--tasks", default="add-multiply,fix-offbyone,refactor-yaml-json")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--opencode-bin", default=str(Path.home() / ".opencode/bin/opencode"))
    parser.add_argument("--wall", default="900")
    args = parser.parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    key = args.key_file.read_text().strip()
    agents = args.agents.split(",")
    modes = args.modes.split(",")
    tasks = args.tasks.split(",")
    platform_name = platform.system()
    ouro = root / "bin/ukai-jail"
    greywall = root / "bin/greywall"
    greyproxy_bin = root / "bin/greyproxy"
    mxc = root / "bin" / ("mxc-exec-mac" if platform_name == "Darwin" else "lxc-exec")

    proxy = GreyProxy(root, greyproxy_bin) if greyproxy_bin.exists() else None
    if "greywall" in modes:
        if not proxy or not proxy.start():
            print("greyproxy failed to start; dropping greywall lane", flush=True)
            modes = [m for m in modes if m != "greywall"]
        else:
            print("rule:", proxy.api("POST", "/api/rules", {"container_pattern": "*", "destination_pattern": "api.anthropic.com", "port_pattern": "443", "action": "allow", "notes": "agent-bench"}), flush=True)
            print("credential:", {k: v for k, v in proxy.api("POST", "/api/credentials", {"label": "ANTHROPIC_API_KEY", "value": key}).items() if k not in ("value", "value_preview")}, flush=True)
    grey_config = root / "greywall-agent.json"
    grey_config.write_text(json.dumps({"filesystem": {"defaultDenyRead": False, "allowWrite": ["TASKDIR", "HOMEDIR"], "denyRead": [], "denyWrite": []}, "network": {"proxyUrl": "socks5://127.0.0.1:43052", "allowLocalOutbound": False, "allowAllUnixSockets": False}}, indent=2) + "\n")
    # Operator launch-profile overrides for the ouro lane: same embedded
    # starter shape plus a literal ANTHROPIC_API_KEY binding (the contained
    # environment does not inherit the operator environment) and the provider
    # host. Mode 0600, like any operator credential config.
    ouro_config_launch = root / "ouro-config" / "launch"
    ouro_config_launch.mkdir(parents=True, exist_ok=True)
    for name, base in (("claude", 'name = "claude"\njail = "agent"\nstate_var = "CLAUDE_CONFIG_DIR"\n\n[environment]\nANTHROPIC_API_KEY = %s\n\n[network]\nallow = ["api.anthropic.com:443"]\n'), ("opencode", 'name = "opencode"\njail = "agent"\nhome_is_state = true\nstate_subdirs = ["config/opencode", "data/opencode", "cache/opencode", "state/opencode"]\n\n[environment]\nXDG_CONFIG_HOME = { state = "config" }\nXDG_DATA_HOME = { state = "data" }\nXDG_CACHE_HOME = { state = "cache" }\nXDG_STATE_HOME = { state = "state" }\nANTHROPIC_API_KEY = %s\n\n[network]\nallow = ["opencode.ai", "models.opencode.ai", "registry.npmjs.org", "api.anthropic.com:443"]\n')):
        path = ouro_config_launch / (name + ".toml")
        path.write_text(base % json.dumps(key))
        path.chmod(0o600)

    raw = (out / "agent-runs.ndjson").open("w")
    counter = 0
    results = []
    for agent in agents:
        for mode in modes:
            for task in tasks:
                for run_id in range(args.runs):
                    counter += 1
                    task_dir = build_task_repo(root, task)
                    home = root / ("home-%s-%s" % (agent, mode))
                    if home.exists():
                        shutil.rmtree(home)
                    home.mkdir(parents=True)
                    codex_home = home / ".codex"
                    if agent == "codex" and (Path.home() / ".codex" / "auth.json").exists():
                        # Codex needs a writable CODEX_HOME (aliases, app-server
                        # state); stage the login credentials into a per-run copy.
                        codex_home.mkdir(parents=True, exist_ok=True)
                        for name in ("auth.json", "config.toml", "version.json"):
                            source = Path.home() / ".codex" / name
                            if source.exists():
                                shutil.copyfile(source, codex_home / name)
                    env = dict(os.environ)
                    env.update({"HOME": str(home), "ANTHROPIC_API_KEY": key, "PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "DISABLE_TELEMETRY": "1", "CLAUDE_CONFIG_DIR": str(home / ".claude"), "OPENCODE_CONFIG_DIR": str(home / ".config/opencode"), "CODEX_HOME": str(codex_home)})
                    argv = agent_argv(agent, TASKS[task]["prompt"], platform_name, home, {"opencode": args.opencode_bin, "task_dir": task_dir})
                    command = list(argv)
                    mxc_config = None
                    if mode == "ouro":
                        launch = {"claude": "claude", "opencode": "opencode", "codex": "codex"}[agent]
                        command = [str(ouro), "run", "--profile", "agent", "--launch", launch, "--workspace", str(task_dir), "--allow-host", "api.anthropic.com:443", "--limit", "wall=" + args.wall + "s", "--receipt", str(root / ("receipt-%d.json" % counter))]
                        if agent == "opencode":
                            command += ["--ro", str(Path(args.opencode_bin).parent)]
                        command += ["--", *argv]
                        env["UKAI_DATA_DIR"] = str(root / "ouro-data")
                        env["UKAI_CONFIG_DIR"] = str(root / "ouro-config")
                    elif mode == "greywall":
                        cfg = root / ("greywall-%d.json" % counter)
                        cfg.write_text(grey_config.read_text().replace("TASKDIR", str(task_dir)).replace("HOMEDIR", str(home)))
                        command = [str(greywall), "--settings", str(cfg), "--proxy", "socks5://127.0.0.1:43052", "--http-proxy", "http://127.0.0.1:43051", "--dns", "127.0.0.1:43053", "--inject", "ANTHROPIC_API_KEY"]
                        if agent == "opencode":
                            command += ["--allow-read-path", str(Path(args.opencode_bin).parent)]
                        command += ["--", *argv]
                    elif mode == "mxc":
                        api_hosts = {"claude": ["api.anthropic.com"], "opencode": ["api.anthropic.com"], "codex": ["api.openai.com", "chatgpt.com", "auth.openai.com"]}[agent]
                        allow = []
                        for host in api_hosts:
                            for ip in sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, socket.AF_INET) if ai[0] == socket.AF_INET}):
                                allow.append({"to": [{"cidr": ip + "/32"}], "ports": [{"protocol": "tcp", "port": 443}]})
                        if platform_name == "Darwin":
                            # The Seatbelt backend rejects destination rules outright
                            # (on/off egress only), so the agent lane runs with
                            # egress allowed and relies on filesystem isolation.
                            network = {"egress": {"default": "allow"}}
                        else:
                            # DNS inside the slirp4netns namespace must be
                            # reachable or no hostname resolves at all.
                            allow.append({"to": [{"cidr": "0.0.0.0/0"}], "ports": [{"protocol": "udp", "port": 53}]})
                            allow.append({"to": [{"cidr": "0.0.0.0/0"}], "ports": [{"protocol": "tcp", "port": 53}]})
                            network = {"egress": {"default": "deny", "allow": allow}}
                        mxc_config = root / ("mxc-%d.json" % counter)
                        seatbelt_extra = {"seatbelt": {"extraMachLookups": ["com.apple.cfprefsd.agent", "com.apple.cfprefsd.daemon", "com.apple.system.notification_center", "com.apple.system.logger"]}} if platform_name == "Darwin" else {}
                        mxc_config.write_text(json.dumps({"version": "1.0.0", "containment": "seatbelt" if platform_name == "Darwin" else "bubblewrap", **seatbelt_extra, "process": {"commandLine": shlex.join([str(c) for c in argv]), "cwd": str(task_dir), "timeout": int(args.wall) * 1000, "inheritDefaultEnv": True, "env": ["ANTHROPIC_API_KEY=" + key, "HOME=" + str(home), "CLAUDE_CONFIG_DIR=" + str(home / ".claude"), "OPENCODE_CONFIG_DIR=" + str(home / ".config/opencode"), "CODEX_HOME=" + str(codex_home)]}, "filesystem": {"readonlyPaths": [str(Path(args.opencode_bin).parent)], "readwritePaths": [str(task_dir), str(home)]}, "network": network}, indent=1) + "\n")
                        command = [str(mxc), str(mxc_config)]
                    before = time.perf_counter_ns()
                    try:
                        process = subprocess.run(command, cwd=task_dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=int(args.wall) + 120)
                        exit_code, stdout, stderr, timed_out = process.returncode, process.stdout.decode(errors="replace"), process.stderr.decode(errors="replace"), False
                    except subprocess.TimeoutExpired as error:
                        exit_code, stdout, stderr, timed_out = None, (error.stdout or b"").decode(errors="replace"), (error.stderr or b"").decode(errors="replace"), True
                    elapsed = (time.perf_counter_ns() - before) / 1e6
                    verdict = check(task_dir, task)
                    usage = {}
                    try:
                        parsed = json.loads(stdout)
                        if isinstance(parsed, dict):
                            usage = {k: parsed.get(k) for k in ("total_cost_usd", "num_turns", "is_error", "duration_ms") if parsed.get(k) is not None}
                    except ValueError:
                        pass
                    row = {"sequence": counter, "agent": agent, "mode": mode, "task": task, "run": run_id, "elapsed_ms": round(elapsed), "exit": exit_code, "timeout": timed_out, "checker": verdict, "usage": usage, "argv": [str(c) for c in command if key not in str(c)], "stdout_tail": stdout[-4000:], "stderr_tail": stderr[-2000:], "mxc_resolved_ips": json.loads(mxc_config.read_text())["network"]["egress"].get("allow") if mxc_config else None}
                    receipt = root / ("receipt-%d.json" % counter)
                    if mode == "ouro" and receipt.exists():
                        row["receipt"] = json.loads(receipt.read_text())
                    raw.write(json.dumps(row, separators=(",", ":")) + "\n")
                    raw.flush()
                    results.append(row)
                    print("%s %s %s run%d: %.0fms exit=%s tests=%s content=%s" % (agent, mode, task, run_id, elapsed, exit_code, verdict["tests_pass"], verdict["content_ok"]), flush=True)
    summary = {}
    for row in results:
        key_ = row["agent"] + "/" + row["mode"]
        bucket = summary.setdefault(key_, {"runs": 0, "success": 0, "elapsed_ms": []})
        bucket["runs"] += 1
        if row["checker"]["tests_pass"] and row["checker"]["content_ok"]:
            bucket["success"] += 1
            bucket["elapsed_ms"].append(row["elapsed_ms"])
    for bucket in summary.values():
        if bucket["elapsed_ms"]:
            bucket["elapsed_ms_median"] = sorted(bucket["elapsed_ms"])[len(bucket["elapsed_ms"]) // 2]
    (out / "agent-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=1))
    if proxy:
        proxy.stop()
    raw.close()


if __name__ == "__main__":
    raise SystemExit(main())
