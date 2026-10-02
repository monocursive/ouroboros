#!/usr/bin/env python3
"""Native macOS lifecycle research. Temporary launchd jobs; fixture PIDs only.

No root, entitlements, installed services, VM, or production backend changes.
The permissive Seatbelt profiles isolate lifecycle tests, not filesystem policy.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import plistlib
import signal
import shutil
import statistics
import subprocess
import tempfile
import time
import uuid


class AuditToken(ctypes.Structure):
    _fields_ = [("val", ctypes.c_uint32 * 8)]


libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
libproc.proc_signal_with_audittoken.argtypes = [ctypes.POINTER(AuditToken), ctypes.c_int]
libproc.proc_signal_with_audittoken.restype = ctypes.c_int


def signal_token(row, sig, stale=False):
    values = row["audit_token"].copy()
    if stale:
        values[7] ^= 1  # Same PID, deliberately wrong kernel PID version.
    token = AuditToken((ctypes.c_uint32 * 8)(*values))
    ctypes.set_errno(0)
    rc = libproc.proc_signal_with_audittoken(ctypes.byref(token), sig)
    return {"rc": rc, "errno": ctypes.get_errno()}


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                          timeout=8, **kwargs)


def json_lines(text):
    # stdout is a growing file during readiness checks: its final line may
    # still be in flight. Each complete line is mandatory valid JSON.
    return [json.loads(line) for line in text.splitlines(keepends=True)
            if line.startswith("{") and line.endswith("\n")]


def wait_until(check, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if value := check():
            return value
        time.sleep(.01)
    raise TimeoutError("fixture condition did not become true")


def snapshot(exe, row):
    result = run([exe, "info", row["pid"]], check=True)
    now = json_lines(result.stdout)[0]
    now["same_process"] = now["unique_bytes"] == 56 and now["uniqueid"] == row["uniqueid"]
    now["alive"] = now["same_process"] and now["bsd_bytes"] == 136 and now["status"] != 5
    return now


def lifecycle(exe, directory, action):
    directory.mkdir()
    output = directory / "stdout"
    errors = directory / "stderr"
    label = "com.monocursive.ouro-native-probe." + uuid.uuid4().hex
    target = f"gui/{os.getuid()}/{label}"
    plist = directory / "job.plist"
    argv = ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", str(exe), "tree", str(directory)]
    plist.write_bytes(plistlib.dumps({
        "Label": label, "ProgramArguments": argv, "RunAtLoad": True,
        "KeepAlive": False, "AbandonProcessGroup": False, "ExitTimeOut": 1,
        "StandardOutPath": str(output), "StandardErrorPath": str(errors),
    }))
    known = []
    loaded = False
    try:
        start = time.perf_counter_ns()
        bootstrap = run(["launchctl", "bootstrap", f"gui/{os.getuid()}", plist], check=True)
        loaded = True

        def ready():
            nonlocal known
            rows = json_lines(output.read_text()) if output.exists() else []
            known = [r for r in rows if "audit_token" in r]
            return rows if any(r.get("ready") for r in rows) else None

        wait_until(ready)
        ready_ms = (time.perf_counter_ns() - start) / 1e6
        by_role = {r["role"]: r for r in known}
        assert set(by_role) == {"root", "plain", "setsid", "double-fork", "stubborn"}, known
        root = by_role["root"]
        assert root["pgid"] == root["pid"], root
        assert all(r["coalitions"] == root["coalitions"] for r in known), known
        assert all(r["coalition_bytes"] == 40 for r in known), known
        assert by_role["plain"]["pgid"] == root["pgid"], known
        assert all(by_role[r]["pgid"] != root["pgid"] for r in ("setsid", "double-fork")), known

        # A wrong version must not signal the live fixture. This tests the
        # PID-version check, not actual wraparound of the machine's PID space.
        stale = signal_token(by_role["setsid"], signal.SIGKILL, stale=True)
        assert stale == {"rc": errno.ESRCH, "errno": errno.ESRCH}, stale
        assert snapshot(exe, by_role["setsid"])["alive"]
        stop_start = time.perf_counter_ns()
        if action == "bootout":
            result = run(["launchctl", "bootout", target], check=True)
            loaded = False
            stop = {"rc": result.returncode, "stderr": result.stderr}
        else:
            stop = signal_token(root, signal.SIGKILL)
            assert stop["rc"] == 0, stop
        wait_until(lambda: not snapshot(exe, root)["alive"])
        root_dead_ms = (time.perf_counter_ns() - stop_start) / 1e6
        sizes_before = {r: (directory / f"{r}.heartbeat").stat().st_size
                        for r in ("setsid", "double-fork")}
        # Observe beyond the configured one-second ExitTimeOut. Timer coalescing
        # means a fixed number of usleep ticks is not a wall-clock deadline.
        checkpoints = []
        for offset in (.2, .5, 1.0, 2.0):
            remaining = stop_start / 1e9 + offset - time.perf_counter_ns() / 1e9
            if remaining > 0:
                time.sleep(remaining)
            checkpoints.append({"elapsed_ms": (time.perf_counter_ns() - stop_start) / 1e6,
                "heartbeats": {r: (directory / f"{r}.heartbeat").stat().st_size for r in sizes_before}})
        observation_ms = (time.perf_counter_ns() - stop_start) / 1e6
        after = {role: snapshot(exe, row) for role, row in by_role.items()}
        return {"action": action, "bootstrap": bootstrap.returncode, "ready_ms": ready_ms,
                "root_dead_ms": root_dead_ms, "processes": known, "stale_token_signal": stale,
                "stop": stop, "after": after, "observation_ms": observation_ms,
                "heartbeat_before": sizes_before,
                "heartbeat_after": {r: (directory / f"{r}.heartbeat").stat().st_size for r in sizes_before},
                "checkpoints": checkpoints,
                "tree_empty_at_checkpoint": not any(r["alive"] for r in after.values())}
    finally:
        # The label is unique and the plist is temporary, outside LaunchAgents.
        if loaded:
            result = run(["launchctl", "bootout", target])
            if result.returncode:
                raise RuntimeError(f"could not remove temporary job {target}: {result.stderr}")
        if output.exists():
            known = [r for r in json_lines(output.read_text()) if "audit_token" in r]
        for row in known:
            result = signal_token(row, signal.SIGKILL)
            if result["rc"] and result["errno"] != errno.ESRCH:
                raise RuntimeError(f"fixture cleanup failed: {result}")
        for row in known:
            wait_until(lambda row=row: not snapshot(exe, row)["alive"])
        # No diagnostic output from unrelated jobs is collected.
        assert run(["launchctl", "print", target]).returncode != 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=10)
    args = parser.parse_args()
    assert platform.system() == "Darwin"
    assert 1 <= args.samples <= 30
    assert not args.out.exists(), "choose a new result path"
    source = Path(__file__).with_suffix(".c").resolve()
    results = {"host": platform.uname()._asdict(), "sw_vers": run(["sw_vers"], check=True).stdout,
               "uid": os.getuid(), "started_unix": time.time(),
               "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "scope": "native mechanism research; no complete containment claim",
               "syscalls": [], "lifecycle": []}
    sdk = Path(run(["xcrun", "--show-sdk-path"], check=True).stdout.strip())
    results["sdk"] = {"path": str(sdk), "version": run(["xcrun", "--show-sdk-version"], check=True).stdout.strip(),
                      "xcode": run(["xcodebuild", "-version"], check=True).stdout, "header_sha256": {}}
    for relative in ("usr/include/EndpointSecurity/ESClient.h", "usr/include/EndpointSecurity/ESTypes.h",
                     "usr/include/libproc.h", "usr/include/sys/spawn.h"):
        results["sdk"]["header_sha256"][relative] = hashlib.sha256((sdk / relative).read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="ouro-native-research-") as tmp:
        directory = Path(tmp).resolve()
        exe = directory / "fixture"
        cc = run(["cc", "-O2", "-fblocks", "-Wall", "-Wextra", "-Werror", source,
                  "-lEndpointSecurity", "-o", exe], check=True)
        results["compiler"] = run(["cc", "--version"], check=True).stdout
        results["compile_stderr"] = cc.stderr
        results["binary_sha256"] = hashlib.sha256(exe.read_bytes()).hexdigest()
        results["capabilities"] = json_lines(run([exe, "capabilities"], check=True).stdout)
        results["runner_context"] = json_lines(run([exe, "self", "runner-context"], check=True).stdout)[0]
        base = "(version 1)(allow default)"
        profiles = {
            "control": base,
            "deny_group_syscalls": base + "(deny syscall-unix (syscall-number SYS_setsid SYS_setpgid))",
            "deny_group_and_spawn_syscalls": base + "(deny syscall-unix (syscall-number SYS_setsid SYS_setpgid SYS_posix_spawn))",
        }
        for name, policy in profiles.items():
            result = run(["/usr/bin/sandbox-exec", "-p", policy, exe, "syscalls"], check=True)
            events = json_lines(result.stdout)
            probes = {r["probe"]: r for r in events if "probe" in r}
            for call in ("setsid", "setpgid"):
                assert (probes[call]["rc"] >= 0) == (name == "control"), events
            for call in ("spawn-group", "spawn-session", "spawn-normal"):
                assert (probes[call]["rc"] == 0) == (name != "deny_group_and_spawn_syscalls"), events
            results["syscalls"].append({"case": name, "policy": policy, "events": events, "stderr": result.stderr})
            print(name, "verified", flush=True)
        node = shutil.which("node")
        results["node_compatibility"] = {"binary": node, "rows": []}
        if node:
            results["node_compatibility"]["version"] = run([node, "--version"], check=True).stdout.strip()
            script = "try { require('child_process').execFileSync('/usr/bin/true'); console.log('child-exec-ok'); } catch(e) { console.log(JSON.stringify({code:e.code,syscall:e.syscall})); process.exitCode=1; }"
            for name in ("control", "deny_group_and_spawn_syscalls"):
                command = ["/usr/bin/sandbox-exec", "-p", profiles[name], node, "-e", script]
                result = run(command)
                results["node_compatibility"]["rows"].append({"case": name, "argv": command,
                    "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
                assert result.returncode == (0 if name == "control" else 1), result
                if name != "control":
                    assert json.loads(result.stdout)["code"] == "EPERM", result
        for i in range(args.samples):
            for action in ("root_sigkill", "bootout"):
                row = lifecycle(exe, directory / f"{i}-{action}", action)
                assert row["processes"][0]["coalitions"][0] != results["runner_context"]["coalitions"][0]
                results["lifecycle"].append(row)
                print(action, i + 1, "survivors:", [k for k,v in row["after"].items() if v["alive"]],
                      "; fixtures cleaned", flush=True)
    results["finished_unix"] = time.time()
    results["cleanup_verified"] = True
    results["timings"] = {}
    for action in ("root_sigkill", "bootout"):
        rows = [r for r in results["lifecycle"] if r["action"] == action]
        results["timings"][action] = {}
        for field in ("ready_ms", "root_dead_ms"):
            values = sorted(r[field] for r in rows)
            results["timings"][action][field] = {"median": statistics.median(values),
                "p95": values[math.ceil(.95 * len(values)) - 1], "n": len(values)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results["timings"], indent=2))


if __name__ == "__main__":
    main()
