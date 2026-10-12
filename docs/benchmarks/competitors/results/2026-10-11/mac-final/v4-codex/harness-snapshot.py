#!/usr/bin/env python3
"""Interleaved agent benchmark with independent checks and reusable evidence.

Uses the v1 fixtures without modifying the v1 data. Each run has a fresh repo,
home and agent state. Wrapper order is randomized within task/repetition blocks.
Timing includes wrapper lifecycle and provider time; it is descriptive, not a
measurement of sandbox CPU overhead. Run offline suite.py for that measurement.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shlex
import shutil
import signal
import statistics
import subprocess
import time
import urllib.request

from agentbench import TASKS, make_task_dir

SEED = 20261011
HOSTS = ["api.anthropic.com", "chatgpt.com", "auth.openai.com", "api.openai.com",
         "ab.chatgpt.com", "cdn.openai.com", "models.opencode.ai", "opencode.ai"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def scrub(text, key):
    text = text.replace(key, "<ANTHROPIC_API_KEY>") if key else text
    text = re.sub(r"sk-ant-[A-Za-z0-9_-]+", "<ANTHROPIC_API_KEY>", text)
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "<JWT>", text)
    return text


def write(path, value, key=""):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    path.write_text(scrub(text, key))


def execute(argv, cwd, env, wall):
    before = time.perf_counter_ns()
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = p.communicate(timeout=wall)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(p.pid, signal.SIGKILL)
        stdout, stderr = p.communicate(timeout=10)
    return {"exit": p.returncode, "timeout": timed_out,
            "elapsed_ms": (time.perf_counter_ns() - before) / 1e6,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace")}


def api(method, path, body=None):
    req = urllib.request.Request("http://127.0.0.1:43080" + path, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, json.dumps(body).encode() if body else None,
                                timeout=10) as response:
        return json.loads(response.read() or b"{}")


def independent_check(task_dir, task):
    """Test originals and hidden behavioral assertions outside the agent's tree."""
    spec = TASKS[task]
    tests_unchanged = all((task_dir / p).is_file() and
                          (task_dir / p).read_text() == content
                          for p, content in spec["files"].items() if p.startswith("tests/"))
    assertions = {
        "add-multiply": "from src.calc import add,multiply; assert add(3,4)==7; assert multiply(0,9)==0; assert multiply(-3,-7)==21; assert multiply(2.5,4)==10",
        "fix-offbyone": "from src.parse import first_word; assert first_word('one two')=='one'; assert first_word('single')=='single'; assert first_word('')==''",
        "refactor-yaml-json": "from src.store import Store; import tempfile,json,pathlib; p=pathlib.Path(tempfile.mktemp()); s=Store(str(p)); value={'text':'café','n':None,'b':True,'nested':[1,{'x':2}]}; s.save(value); assert json.loads(p.read_text())==value; assert s.load()==value; p.unlink()",
    }[task]
    p = subprocess.run(["python3", "-I", "-c", "import sys;sys.path.insert(0,sys.argv[1]);" + assertions,
                        str(task_dir)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    test = subprocess.run(["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
                          cwd=task_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    return {"tests_unchanged": tests_unchanged, "tests_pass": test.returncode == 0,
            "hidden_pass": p.returncode == 0,
            "test_output": test.stdout.decode(errors="replace"),
            "hidden_output": p.stdout.decode(errors="replace")}


def prepare_proxy(args):
    cert = args.root / "proxy/data/ca-cert.pem"
    if not cert.exists():
        cert_env = dict(os.environ, GREYPROXY_DATA_HOME=str(args.root / "proxy/data"))
        cert_run = execute([str(args.root / "bin/greyproxy"), "cert", "generate"], args.root, cert_env, 30)
        write(args.out / "proxy-cert-generation.json", cert_run)
        if cert_run["exit"]:
            raise RuntimeError("Greyproxy CA generation failed")
    try:
        health = api("GET", "/api/health")
    except Exception:
        cfg = args.root / "proxy/greyproxy.yml"
        write(cfg, (args.root / "harness/greyproxy-v0.4.5.yml").read_text())
        log = (args.out / "proxy-startup.log").open("w")
        proxy_env = dict(os.environ, GREYPROXY_DATA_HOME=str(args.root / "proxy/data"))
        subprocess.Popen([str(args.root / "bin/greyproxy"), "serve", "-C", str(cfg)], env=proxy_env,
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                         start_new_session=True)
        for _ in range(50):
            try:
                health = api("GET", "/api/health")
                break
            except Exception:
                time.sleep(.2)
        else:
            raise RuntimeError("Greyproxy did not start")
    for host in HOSTS:
        api("POST", "/api/rules", {"container_pattern": "*", "destination_pattern": host,
                                  "port_pattern": "443", "action": "allow", "notes": "benchmark-v2"})
    api("POST", "/api/rules", {"container_pattern": "*", "destination_pattern": "*",
                              "port_pattern": "*", "action": "deny", "notes": "benchmark-v2-default-deny"})
    write(args.out / "proxy-health.json", health)
    settings = api("GET", "/api/settings")
    write(args.out / "proxy-settings.json", settings)
    if not settings.get("mitm", {}).get("certGenerated"):
        raise RuntimeError("The running proxy lacks its CA: restart the benchmark-owned proxy before measuring")
    write(args.out / "proxy-rules.json", api("GET", "/api/rules"))


def command(args, agent, mode, task_dir, home, state, run_dir, key):
    bins = args.root / "bin"
    binary_grants = sorted({str(bins), str((bins / agent).resolve().parent)})
    prompt = TASKS[task_dir.name]["prompt"]
    if agent == "claude":
        argv = [str(bins / "claude"), "-p", prompt, "--model", "claude-sonnet-4-5",
                "--max-turns", "15", "--dangerously-skip-permissions", "--output-format", "json"]
    elif agent == "opencode":
        argv = [str(bins / "opencode"), "run", "--model", "anthropic/claude-sonnet-4-5", prompt]
    else:
        argv = [str(bins / "codex"), "exec", "--ephemeral", "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox", "--model", args.codex_model,
                "-c", 'model_reasoning_effort="low"', "-C", str(task_dir), prompt]
    env = dict(os.environ)
    env.update({"HOME": str(home), "PATH": str(bins) + ":" + os.environ["PATH"],
                "ANTHROPIC_API_KEY": key, "CLAUDE_CONFIG_DIR": str(home / ".claude"),
                "CODEX_HOME": str(state), "DISABLE_TELEMETRY": "1",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "OPENCODE_DISABLE_AUTOUPDATE": "true", "GREYWALL_NO_GREYPROXY_INSTALL": "1"})
    for name, suffix in (("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"),
                         ("XDG_STATE_HOME", ".local/state"), ("XDG_CACHE_HOME", ".cache")):
        env[name] = str(home / suffix)
    (home / "tmp").mkdir(exist_ok=True)
    env["TMPDIR"] = str(home / "tmp")
    if agent == "codex":
        if args.auth_file and args.auth_file.exists():
            (state / "auth.json").write_bytes(args.auth_file.read_bytes())
            (state / "auth.json").chmod(0o600)
        env.pop("ANTHROPIC_API_KEY", None)
    if mode == "direct":
        return argv, env, None
    if mode == "ouro":
        cfg = run_dir / "ouro-config/launch"
        cfg.mkdir(parents=True, exist_ok=True)
        if agent == "codex":
            profile = 'name="codex"\njail="agent"\nstate_var="CODEX_HOME"\nhome_is_state=true\n[credentials.auth]\nsource=%s\ndest="auth.json"\nmode="copy_rw"\n[network]\nallow=["chatgpt.com:443","*.chatgpt.com:443","*.openai.com:443"]\n' % json.dumps(str(state / "auth.json"))
        elif agent == "claude":
            profile = 'name="claude"\njail="agent"\nstate_var="CLAUDE_CONFIG_DIR"\n[environment]\nANTHROPIC_API_KEY=%s\nCLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"\n[network]\nallow=["api.anthropic.com:443"]\n' % json.dumps(key)
        else:
            profile = 'name="opencode"\njail="agent"\nhome_is_state=true\nstate_subdirs=["config/opencode","data/opencode","cache/opencode","state/opencode"]\n[environment]\nANTHROPIC_API_KEY=%s\nOPENCODE_DISABLE_AUTOUPDATE="true"\nXDG_CONFIG_HOME={state="config"}\nXDG_DATA_HOME={state="data"}\nXDG_CACHE_HOME={state="cache"}\nXDG_STATE_HOME={state="state"}\n[network]\nallow=["api.anthropic.com:443","models.opencode.ai:443","opencode.ai:443"]\n' % json.dumps(key)
        private = cfg / (agent + ".toml")
        private.write_text(profile)
        private.chmod(0o600)
        write(run_dir / "config/launch.toml", profile, key)
        env["OURO_CONFIG_DIR"] = str(cfg.parent)
        env["OURO_DATA_DIR"] = str(args.root / "data-v2")
        grant_argv = [part for path in binary_grants for part in ("--ro", path)]
        return [str(bins / "ouro-jail"), "run", "--profile", "agent", "--launch", agent,
                "--workspace", str(task_dir), *grant_argv, "--limit", "wall=" + str(args.wall) + "s",
                "--receipt", str(run_dir / "jail.json"), "--", *argv], env, None
    if mode == "greywall":
        # Unix bridge socket names must fit sockaddr_un's 108-byte pathname.
        # Keep the wrapper's scratch path short; the agent sees its private /tmp.
        env["TMPDIR"] = "/tmp"
        cert_source = args.root / "proxy/data/ca-cert.pem"
        cert_rel = "Library/Application Support/greyproxy/ca-cert.pem" if platform.system() == "Darwin" else ".local/share/greyproxy/ca-cert.pem"
        cert_dest = home / cert_rel
        if cert_source.exists():
            cert_dest.parent.mkdir(parents=True, exist_ok=True)
            cert_dest.write_bytes(cert_source.read_bytes())
        cfg = {"filesystem": {"defaultDenyRead": True,
                 "allowRead": binary_grants, "allowWrite": [str(task_dir), str(home), str(state)]},
               "network": {"proxyUrl": "socks5://127.0.0.1:43052", "allowLocalOutbound": False,
                           "allowAllUnixSockets": False}}
        private = run_dir / "config/greywall.json"
        write(private, cfg)
        return [str(bins / "greywall"), "--settings", str(private), "--auto-profile", "--profile", agent, "--no-network-rules",
                "--proxy", "socks5://127.0.0.1:43052", "--http-proxy", "http://127.0.0.1:43051",
                "--dns", "127.0.0.1:43053", "--", *argv], env, cfg
    cfg = {"version": "1.0.0", "containment": "seatbelt" if platform.system() == "Darwin" else "bubblewrap",
           "process": {"commandLine": shlex.join(argv), "cwd": str(task_dir),
                       "timeout": args.wall * 1000, "inheritDefaultEnv": True},
           "filesystem": {"readonlyPaths": binary_grants, "readwritePaths": [str(task_dir), str(home), str(state)]},
           "network": {"egress": {"default": "deny"}},
           "runtimeConfig": {"networkProxy": "http://127.0.0.1:43051"}}
    if platform.system() == "Darwin":
        cfg["seatbelt"] = {"extraMachLookups": ["com.apple.cfprefsd.agent", "com.apple.cfprefsd.daemon"]}
        for path in (Path("/tmp/claude-%d" % os.getuid()), Path("/tmp/opencode")):
            path.mkdir(exist_ok=True)
            cfg["filesystem"]["readwritePaths"].append(str(path.resolve()))
    private = run_dir / "config/mxc.json"
    cert_source = args.root / "proxy/data/ca-cert.pem"
    if cert_source.exists():
        cert_dest = home / "proxy-ca.pem"
        cert_dest.write_bytes(cert_source.read_bytes())
        env.update({"NODE_EXTRA_CA_CERTS": str(cert_dest), "SSL_CERT_FILE": str(cert_dest),
                    "REQUESTS_CA_BUNDLE": str(cert_dest)})
    names = ("HOME", "PATH", "TMPDIR", "ANTHROPIC_API_KEY", "CODEX_HOME", "CLAUDE_CONFIG_DIR",
             "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_TELEMETRY",
             "OPENCODE_DISABLE_AUTOUPDATE", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
             "XDG_STATE_HOME", "XDG_CACHE_HOME", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
             "REQUESTS_CA_BUNDLE", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL")
    cfg["process"]["env"] = [name + "=" + env[name] for name in names if name in env]
    write(private, cfg, key)
    private = run_dir / "mxc-private.json"
    private.write_text(json.dumps(cfg))
    private.chmod(0o600)
    return [str(bins / ("mxc-exec-mac" if platform.system() == "Darwin" else "lxc-exec")), str(private)], env, cfg


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--key-file", type=Path, required=True)
    p.add_argument("--auth-file", type=Path)
    p.add_argument("--agents", default="claude,opencode,codex")
    p.add_argument("--modes", default="direct,ouro,greywall,mxc")
    p.add_argument("--tasks", default=",".join(TASKS))
    p.add_argument("--runs", type=int, default=2)
    p.add_argument("--wall", type=int, default=240)
    p.add_argument("--codex-model", default="gpt-6.1-sol")
    p.add_argument("--no-proxy-setup", action="store_true")
    args = p.parse_args()
    args.root, args.out = args.root.resolve(), args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    if (args.out / "agent-runs.ndjson").exists():
        raise SystemExit("Use a new output directory: existing raw data must be preserved")
    key = args.key_file.read_text().strip()
    if {"greywall", "mxc"} & set(args.modes.split(",")) and not args.no_proxy_setup:
        prepare_proxy(args)
    schedule = []
    rng = random.Random(SEED)
    for agent in args.agents.split(","):
        for repetition in range(args.runs):
            tasks = args.tasks.split(",")
            rng.shuffle(tasks)
            for task in tasks:
                modes = args.modes.split(",")
                rng.shuffle(modes)
                schedule.extend((agent, task, repetition, mode) for mode in modes)
    metadata = {"schema": "agent-comparison/2", "host": platform.uname()._asdict(),
                "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seed": SEED,
                "schedule": schedule, "codex_model": args.codex_model, "anthropic_model": "claude-sonnet-4-5",
                "wall_seconds": args.wall, "bins": {}, "harness_sha256": sha(__file__),
                "fixtures_sha256": sha(Path(__file__).with_name("agentbench.py"))}
    for agent in args.agents.split(","):
        path = args.root / "bin" / agent
        result = execute([str(path), "--version"], args.root, os.environ, 30)
        metadata["bins"][agent] = {"sha256": sha(path), "version": result["stdout"].strip()}
    for name in ("ouro-jail", "greywall", "greyproxy", "lxc-exec", "mxc-exec-mac"):
        path = args.root / "bin" / name
        if path.exists():
            metadata["bins"][name] = {"sha256": sha(path)}
    write(args.out / "metadata.json", metadata)
    results = []
    with (args.out / "agent-runs.ndjson").open("w") as raw:
        for seq, (agent, task, repetition, mode) in enumerate(schedule, 1):
            run_dir = args.out / "runs" / ("%03d-%s-%s-%s-%d" % (seq, agent, mode, task, repetition))
            run_dir.mkdir(parents=True)
            task_dir = make_task_dir(run_dir / "workspace", task)
            home, state = run_dir / "home", run_dir / "state"
            home.mkdir()
            state.mkdir()
            argv, env, cfg = command(args, agent, mode, task_dir, home, state, run_dir, key)
            before = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            result = execute(argv, task_dir, env, args.wall + 30)
            verdict = independent_check(task_dir, task)
            success = result["exit"] == 0 and not result["timeout"] and all(verdict[k] for k in ("tests_pass", "tests_unchanged", "hidden_pass"))
            row = {"sequence": seq, "agent": agent, "mode": mode, "task": task, "repetition": repetition,
                   "started_utc": before, "elapsed_ms": result["elapsed_ms"], "exit": result["exit"],
                   "timeout": result["timeout"], "success": success, "checker": verdict,
                   "argv": argv, "load": os.getloadavg(), "artifact": str(run_dir.relative_to(args.out))}
            write(run_dir / "stdout.log", result["stdout"], key)
            write(run_dir / "stderr.log", result["stderr"], key)
            patch = subprocess.run(["git", "diff", "--no-ext-diff", "HEAD"], cwd=task_dir,
                                   stdout=subprocess.PIPE, check=True).stdout.decode(errors="replace")
            write(run_dir / "patch.diff", patch, key)
            write(run_dir / "result.json", row, key)
            write(run_dir / "prompt.txt", TASKS[task]["prompt"])
            for log in home.rglob("*.log"):
                if log.stat().st_size <= 10 * 1024 * 1024:
                    write(run_dir / "diagnostics" / log.relative_to(home), log.read_text(errors="replace"), key)
            # Credentials and caches are transient state, not benchmark results.
            # Keep outputs, checker records, patches, and sanitized diagnostic logs.
            shutil.rmtree(home)
            shutil.rmtree(state)
            shutil.rmtree(run_dir / "ouro-config", ignore_errors=True)
            (run_dir / "mxc-private.json").unlink(missing_ok=True)
            raw.write(scrub(json.dumps(row), key) + "\n")
            raw.flush()
            results.append(row)
            print("%d/%d %s %s %s #%d %.1fs exit=%s success=%s" %
                  (seq, len(schedule), agent, mode, task, repetition,
                   result["elapsed_ms"] / 1000, result["exit"], success), flush=True)
            summary = {}
            for row in results:
                bucket = summary.setdefault(row["agent"] + "/" + row["mode"], {"runs": 0, "success": 0, "times_ms": []})
                bucket["runs"] += 1
                if row["success"]:
                    bucket["success"] += 1
                    bucket["times_ms"].append(row["elapsed_ms"])
            for bucket in summary.values():
                bucket["median_ms"] = statistics.median(bucket["times_ms"]) if bucket["times_ms"] else None
            write(args.out / "agent-summary.json", summary)
    print("COMPLETE", flush=True)


if __name__ == "__main__":
    main()
