#!/usr/bin/env python3
"""Same-host, interleaved successful-work timings and bounded canary probes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import signal
import socket
import subprocess
import threading
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(raw):
    result = []
    for line in raw.decode(errors="replace").splitlines():
        try:
            obj = json.loads(line)
            if isinstance(obj, dict): result.append(obj)
        except ValueError:
            pass
    return result


class CanaryServer:
    def __init__(self, path=None, deny=False):
        self.socket = socket.socket(socket.AF_UNIX if path else socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(str(path) if path else ("127.0.0.1", 0))
        self.address = self.socket.getsockname()
        self.socket.listen(16)
        self.socket.settimeout(0.1)
        self.stop = threading.Event()
        self.hits = 0
        self.deny = deny
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try: client, _ = self.socket.accept()
            except socket.timeout: continue
            except OSError: break
            with client:
                client.settimeout(0.2)
                try:
                    data = client.recv(256)
                    if data:
                        self.hits += 1
                        client.sendall(b"\x05\xff" if self.deny and data[0] == 5 else (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n" if self.deny else b"canary"))
                except OSError:
                    pass

    def close(self):
        self.stop.set()
        self.thread.join(1)
        self.socket.close()


class Suite:
    def __init__(self, root, out, samples, warmup):
        self.root, self.out, self.samples, self.warmup = root, out, samples, warmup
        self.out.mkdir(parents=True, exist_ok=True)
        self.work = root / "work"
        self.private = root / "private"
        self.home = root / "fixture-home"
        for p in (self.work, self.private, self.home, root / "config", root / "data"):
            p.mkdir(mode=0o700, exist_ok=True)
        self.env = {"PATH": str(root / "bin") + ":" + str(root / "node/bin") + ":/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.home), "LANG": "C", "LC_ALL": "C", "OURO_CONFIG_DIR": str(root / "config"), "OURO_DATA_DIR": str(root / "data"), "XDG_CONFIG_HOME": str(self.home / ".config"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        # Required for the existing user's delegated cgroup authority only.
        if platform.system() == "Linux":
            self.env["XDG_RUNTIME_DIR"] = "/run/user/" + str(os.getuid())
            self.env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + self.env["XDG_RUNTIME_DIR"] + "/bus"
        self.python = "/usr/bin/python3"
        self.payload = self.work / "payload.py"
        shutil.copyfile(root / "harness/payload.py", self.payload)
        self.binary = root / "bin/ouro-jail"
        subprocess.run(["/usr/bin/cc", "-O2", str(root / "harness/workload.c"), "-o", str(self.work / "workload")], check=True)
        if platform.system() == "Linux":
            subprocess.run(["/usr/bin/cc", "-O2", str(root / "harness/syscalls.c"), "-o", str(self.work / "syscalls")], check=True)
        for name in ("inputs", "outputs"):
            (self.work / name).mkdir(exist_ok=True)
        for i in range(1000): (self.work / "inputs" / ("f%04d" % i)).write_bytes(b"x" * 4096)
        (self.work / ".gitignore").write_text("outputs/\n*.heartbeat\nlink-copy\n")
        subprocess.run(["/usr/bin/git", "init", "-q", str(self.work)], env=self.env, check=True)
        subprocess.run(["/usr/bin/git", "add", "inputs", "payload.py", "workload", ".gitignore"], cwd=self.work, env=self.env, check=True)
        self.secret = self.private / "read-canary"
        self.secret.write_bytes(b"owned-fixture-secret")
        self.outside = self.private / "write-canary"
        self.outside.write_bytes(b"original")
        self.readonly = self.private / "read-only"
        self.readonly.write_bytes(b"original")
        for name, target in (("read-link", self.secret), ("write-link", self.outside)):
            link = self.work / name
            if link.is_symlink(): link.unlink()
            link.symlink_to(target)
        self.tcp = CanaryServer()
        self.unix = CanaryServer(self.private / "s")
        self.proxy = CanaryServer(deny=True)
        self.signal_marker = self.private / "signaled"
        canary_code = "import signal,time,pathlib; signal.signal(signal.SIGUSR1,lambda *a:pathlib.Path(%r).write_text('signaled'));print('ready',flush=True);time.sleep(1800)" % str(self.signal_marker)
        self.canary = subprocess.Popen([self.python, "-c", canary_code], stdout=subprocess.PIPE, env=self.env)
        if self.canary.stdout.readline().strip() != b"ready": raise RuntimeError("canary not ready")
        grey_config = {"filesystem": {"defaultDenyRead": True, "allowRead": [str(self.readonly)], "allowWrite": [str(self.work)], "denyRead": [str(self.secret)], "denyWrite": [str(self.readonly)]}, "network": {"proxyUrl": "socks5://127.0.0.1:" + str(self.proxy.address[1]), "allowLocalOutbound": False, "allowAllUnixSockets": False}}
        srt_config = {"filesystem": {"denyRead": ["/Users", "/home", "/tmp", "/private/tmp"], "allowRead": [str(self.work), str(self.readonly), str(root / "srt/node_modules/@anthropic-ai/sandbox-runtime/vendor/seccomp")], "allowWrite": [str(self.work)], "denyWrite": [str(self.readonly)]}, "network": {"allowedDomains": [], "deniedDomains": [], "allowLocalBinding": False}, "enableWeakerNestedSandbox": False, "enableWeakerNetworkIsolation": False}
        self.grey_config, self.srt_config = root / "greywall.json", root / "srt.json"
        self.grey_config.write_text(json.dumps(grey_config, indent=2) + "\n")
        self.srt_config.write_text(json.dumps(srt_config, indent=2) + "\n")
        self.tools = ["direct", "ouro-jail", "greywall", "srt"]
        self.supported = {}
        self.raw = (out / "launches.ndjson").open("w")
        self.counter = 0

    def command(self, tool, payload):
        if tool == "direct": return payload
        if tool == "ouro-jail":
            return [str(self.binary), "run", "--profile", "tool", "--workspace", str(self.work), "--ro", str(self.readonly), "--", *payload]
        if tool == "greywall":
            return [str(self.root / "greywall/greywall"), "--settings", str(self.grey_config), "--no-network-rules", "--proxy", "socks5://127.0.0.1:" + str(self.proxy.address[1]), "--http-proxy", "http://127.0.0.1:" + str(self.proxy.address[1]), "--dns", "127.0.0.1:" + str(self.proxy.address[1]), "--", *payload]
        return [str(self.root / "node/bin/node"), str(self.root / "srt/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js"), "--settings", str(self.srt_config), "--", *payload]

    def run(self, tool, payload, phase, case, round_id=None):
        self.counter += 1
        command = self.command(tool, payload)
        before = time.perf_counter_ns()
        process = subprocess.Popen(command, cwd=self.work, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try: stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=5)
        elapsed = (time.perf_counter_ns() - before) / 1e6
        row = {"sequence": self.counter, "phase": phase, "case": case, "tool": tool, "round": round_id, "argv": command, "elapsed_ms": elapsed, "exit": process.returncode, "timeout": timed_out, "stdout": stdout.decode(errors="replace"), "stderr": stderr.decode(errors="replace"), "records": records(stdout), "load": os.getloadavg()}
        if tool == "ouro-jail":
            attempts = list((self.root / "data/attempts").glob("*/jail.json"))
            if attempts:
                receipt_path = max(attempts, key=lambda p: p.stat().st_mtime_ns)
                receipt = json.loads(receipt_path.read_text())
                row["receipt"] = receipt
                row["receipt_sha256"] = sha(receipt_path)
                if phase in ("preflight", "safety"):
                    destination = self.out / "receipts" / ("%04d" % self.counter)
                    destination.mkdir(parents=True, exist_ok=True)
                    for name in ("jail.json", "trace.ndjson"):
                        source = receipt_path.parent / name
                        if source.exists(): shutil.copyfile(source, destination / name)
        self.raw.write(json.dumps(row, separators=(",", ":")) + "\n"); self.raw.flush()
        return row

    def payload_command(self, case):
        if case in ("python", "git"): return [self.python, str(self.payload), case]
        return [str(self.work / "workload"), case]

    def metadata(self):
        commands = {"ouro_version": [str(self.binary), "version", "--json"], "greywall_version": [str(self.root / "greywall/greywall"), "--version"], "node_version": [str(self.root / "node/bin/node"), "--version"], "python_version": [self.python, "--version"]}
        if platform.system() == "Linux": commands["greywall_features"] = [str(self.root / "greywall/greywall"), "--linux-features"]
        else: commands["os"] = ["/usr/bin/sw_vers"]
        result = {"schema": "sandbox-comparison/1", "host": platform.uname()._asdict(), "cpu_count": os.cpu_count(), "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "samples": self.samples, "warmup": self.warmup, "seed": 20260930, "install": json.loads((self.root / "install.json").read_text()), "hashes": {str(p.relative_to(self.root)): sha(p) for p in [self.binary, self.work / "workload", self.payload, self.grey_config, self.srt_config, *sorted((self.root / "harness").glob("*.*"))]}, "versions": {}}
        for name, command in commands.items():
            p = subprocess.run(command, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
            result["versions"][name] = {"exit": p.returncode, "output": p.stdout.decode(errors="replace")}
        return result

    def performance(self):
        cases = ["noop", "python", "git", "reads", "writes", "spawn", "cpu"]
        reference = {}
        for case in cases:
            row = self.run("direct", self.payload_command(case), "reference", case)
            if row["exit"] or len(row["records"]) != 1: raise RuntimeError("broken reference: " + case)
            reference[case] = {k: row["records"][0][k] for k in ("workload", "count", "checksum")}
        for tool in self.tools:
            row = self.run(tool, self.payload_command("noop"), "preflight", "noop")
            self.supported[tool] = row["exit"] == 0 and len(row["records"]) == 1 and row["records"][0].get("benchmark") == 1
            print("preflight", tool, "available" if self.supported[tool] else "unavailable", row["exit"], flush=True)
        rng = random.Random(20260930)
        arms = [(tool, case) for tool in self.tools if self.supported[tool] for case in cases]
        errors = []
        for round_id in range(-self.warmup, self.samples):
            rng.shuffle(arms)
            for tool, case in arms:
                row = self.run(tool, self.payload_command(case), "warmup" if round_id < 0 else "measurement", case, round_id)
                valid = row["exit"] == 0 and len(row["records"]) == 1 and all(row["records"][0].get(k) == v for k, v in reference[case].items())
                if tool == "ouro-jail":
                    receipt = row.get("receipt", {})
                    valid = valid and receipt.get("lifetime", {}).get("tree_empty") is True and receipt.get("outcome", {}).get("kind") == "exited" and all(not c["gaps"] for c in receipt.get("coverage", {}).values())
                if case == "writes":
                    valid = valid and sum(p.stat().st_size for p in (self.work / "outputs").iterdir()) == 1024000
                if not valid: errors.append(row["sequence"])
            print("round", round_id, "complete", flush=True)
        return {"available": self.supported, "invalid_sequences": errors, "reference": reference}

    def safety(self):
        probes = [
            ("private_read", ["read", str(self.secret)]),
            ("private_write", ["write", str(self.outside)]),
            ("readonly_write", ["write", str(self.readonly)]),
            ("symlink_read", ["read", str(self.work / "read-link")]),
            ("symlink_write", ["write", str(self.work / "write-link")]),
            ("hardlink_read", ["link", str(self.secret), str(self.work / "link-copy")]),
            ("host_tcp", ["tcp", str(self.tcp.address[1])]),
            ("host_unix_socket", ["unix", str(self.private / "s")]),
            ("host_signal", ["signal", str(self.canary.pid)]),
        ]
        results = []
        for tool in self.tools:
            if not self.supported[tool]:
                results.append({"tool": tool, "status": "unavailable"}); continue
            for name, arguments in probes:
                self.outside.write_bytes(b"original"); self.readonly.write_bytes(b"original")
                if self.signal_marker.exists(): self.signal_marker.unlink()
                if (self.work / "link-copy").exists(): (self.work / "link-copy").unlink()
                row = self.run(tool, [self.python, str(self.payload), "probe", *arguments], "safety", name)
                record = next((r for r in row["records"] if "probe" in r), None)
                time.sleep(0.02)
                observed = record and record.get("allowed") is True
                if name in ("private_write", "symlink_write"): observed = self.outside.read_bytes() != b"original"
                if name == "readonly_write": observed = self.readonly.read_bytes() != b"original"
                if name == "host_signal": observed = self.signal_marker.exists()
                # A Linux namespace may accept a write into its private tmpfs
                # at the same spelling. The host canary establishes the effect.
                isolated = name in ("private_write", "symlink_write") and row["exit"] == 0 and record and record.get("allowed") is True and not observed
                status = "allowed" if observed else ("isolated" if isolated else ("denied" if row["exit"] == 0 and record and record.get("allowed") is False else "inconclusive"))
                results.append({"tool": tool, "probe": name, "sequence": row["sequence"], "status": status, "detail": record})
            marker = self.work / (tool + ".heartbeat")
            if marker.exists(): marker.unlink()
            row = self.run(tool, [self.python, str(self.payload), "lifecycle", str(marker)], "safety", "detached_after_root_exit")
            before = marker.stat().st_size if marker.exists() else 0
            time.sleep(0.3)
            after = marker.stat().st_size if marker.exists() else 0
            witnessed = before > 0 or after > 0
            results.append({"tool": tool, "probe": "detached_after_root_exit", "sequence": row["sequence"], "status": "survived" if after > before else ("stopped" if witnessed else "inconclusive"), "bytes_at_return": before, "bytes_after_300ms": after})
            # The fixture expires by itself. Never remove its files while live.
            time.sleep(3.1)
            if platform.system() == "Linux":
                row = self.run(tool, [str(self.work / "syscalls")], "safety", "syscall_surface")
                results.append({"tool": tool, "probe": "syscall_surface", "sequence": row["sequence"], "status": "observed" if len(row["records"]) == 10 and row["exit"] == 0 else "inconclusive", "records": row["records"]})
            print("safety", tool, "complete", flush=True)
        return results

    def close(self):
        self.canary.terminate(); self.canary.wait(timeout=3)
        self.canary.stdout.close()
        for server in (self.tcp, self.unix, self.proxy): server.close()
        self.raw.close()
        if (self.private / "s").exists(): (self.private / "s").unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--srt-allow-unix", action="store_true", help="Separate compatibility lane: disable SRT's Unix socket seccomp helper")
    parser.add_argument("--tools", help="Comma-separated subset of available arm names")
    args = parser.parse_args()
    if not 1 <= args.samples <= 1000 or not 0 <= args.warmup <= 20: parser.error("invalid sample count")
    suite = Suite(args.root.resolve(), args.out.resolve(), args.samples, args.warmup)
    try:
        if args.srt_allow_unix:
            config = json.loads(suite.srt_config.read_text())
            config["network"]["allowAllUnixSockets"] = True
            suite.srt_config.write_text(json.dumps(config, indent=2) + "\n")
            suite.tools[suite.tools.index("srt")] = "srt-unix-compat"
        if args.tools:
            selected = args.tools.split(",")
            if not set(selected).issubset(suite.tools) or len(selected) != len(set(selected)) or "direct" not in selected:
                parser.error("tools must be a unique subset including direct")
            suite.tools = selected
        metadata = suite.metadata()
        metadata["policy_notes"] = {"srt-unix-compat": "allowAllUnixSockets=true; the Unix-socket seccomp helper is disabled; this is a relaxed compatibility profile"} if args.srt_allow_unix else {}
        (suite.out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        performance = suite.performance()
        (suite.out / "performance-status.json").write_text(json.dumps(performance, indent=2) + "\n")
        safety = suite.safety()
        (suite.out / "safety.json").write_text(json.dumps(safety, indent=2) + "\n")
        (suite.out / "package-lock.json").write_bytes((suite.root / "srt/package-lock.json").read_bytes())
        for name in ("greywall.json", "srt.json"): shutil.copyfile(suite.root / name, suite.out / name)
        (suite.out / "complete.json").write_text(json.dumps({"finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "launches_sha256": sha(suite.out / "launches.ndjson"), "invalid_measurements": performance["invalid_sequences"], "binary_sha256_after": sha(suite.binary)}, indent=2) + "\n")
    finally:
        suite.close()
    return 1 if performance["invalid_sequences"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
