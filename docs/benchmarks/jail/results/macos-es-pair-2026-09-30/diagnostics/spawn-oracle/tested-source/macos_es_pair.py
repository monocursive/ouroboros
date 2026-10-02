#!/usr/bin/env python3
"""Measure reciprocal ES custody; preserve the simultaneous-death counterexample.

This runs controlled native fixtures, never enables ouro-jail execution, and
never equates known fixture death with complete process-tree proof.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time

from macos_es import build, development_settings, run
from macos_native import json_lines, signal_token, snapshot, wait_until

HERE = Path(__file__).resolve().parent
ROLES = {"root", "plain", "stubborn", "setsid", "double-fork", "spawn-group", "spawn-session"}
CASES = ("wall", "cancel", "root_death", "guardian_death", "ward_death",
         "guardian_stop", "ward_stop", "guardian_gap", "ward_gap", "both_death")


def rows(path):
    return json_lines(path.read_text()) if path.exists() else []


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def token_key(token):
    return token[5], token[7]  # kernel PID and PID version, not user-supplied PID alone


def inspect_custodian(fixture, release):
    pid = release["custodian_pid"]
    result = run([fixture, "info", str(pid)], check=True)
    row = json_lines(result.stdout)[0]
    require(row["unique_bytes"] == 56 and row["bsd_bytes"] == 136, "custodian identity unavailable")
    token = release["custodian_token"]
    require(token_key(token) == (row["pid"], row["pidversion"]), "custodian audit-token identity mismatch")
    row["audit_token"] = token
    return row


def kill_owned(row, sig):
    result = signal_token(row, sig)
    require(result["rc"] == 0, f"owned process signal failed: {result}")


def trial(exe, fixture, directory, case, auth_exec=False):
    directory.mkdir()
    workload, guard_events, ward_events = (directory / name for name in
                                         ("workload.jsonl", "guardian.jsonl", "ward.jsonl"))
    errors = directory / "stderr.txt"
    # Isolate signal custody; filesystem policy is intentionally not evaluated
    # by this experiment. The VM has no operator files, keys or network route.
    policy = "(version 1)(allow default)(deny signal)(allow signal (target same-sandbox))"
    argv = [str(exe), "--guardian", "3", str(workload), str(ward_events), "--",
            "/usr/bin/sandbox-exec", "-p", policy, str(fixture), "tree-spawn", str(directory)]
    known, custodians = [], {}
    environment = os.environ.copy()
    environment.pop("OURO_ES_PAIR_AUTH_EXEC", None)
    if auth_exec:
        environment["OURO_ES_PAIR_AUTH_EXEC"] = "1"
    start = time.monotonic()
    with guard_events.open("w") as output, errors.open("w") as stderr:
        parent = subprocess.Popen(argv, stdout=output, stderr=stderr, env=environment)
        try:
            def ready():
                nonlocal known
                current = rows(workload)
                known = [row for row in current if "audit_token" in row]
                require(parent.poll() is None, "guardian exited before readiness")
                return any(row.get("ready") for row in current)
            wait_until(ready)
            ready_ms = (time.monotonic() - start) * 1000
            by_role = {row["role"]: row for row in known}
            require(set(by_role) == ROLES and len(known) == len(ROLES), "unexpected fixture membership")
            require(all(row.get("custody_fds_open") is False for row in known), "custody descriptor inherited by workload")
            attacks = [row for row in rows(workload) if row.get("probe") == "custodian_signal"]
            require(len(attacks) == 4 and all(row["rc"] == -1 and row["errno"] == errno.EPERM for row in attacks),
                    "workload can signal a custodian")
            root = by_role["root"]
            require(all(by_role[role]["pgid"] != root["pgid"] for role in
                        ("setsid", "double-fork", "spawn-group", "spawn-session")), "fixture failed to detach")
            # Both clients must have independently seen every known process
            # before fault injection. One client's log cannot stand in for its peer.
            def subscribed():
                expected = {token_key(row["audit_token"]) for row in known}
                return all(expected <= {token_key(row["token"]) for row in rows(path) if "token" in row}
                           for path in (guard_events, ward_events))
            wait_until(subscribed)
            if auth_exec:
                for path in (guard_events, ward_events):
                    configs = [row for row in rows(path) if row.get("kind") == "auth_config"]
                    require(configs == [{"kind": "auth_config", "fail_closed": True,
                                         "deadline_max_ms": 250, "cache": False}], "AUTH_EXEC fail-closed setup not verified")
                    require(any(row.get("kind") == "auth_exec" and row["authorized"] for row in rows(path)),
                            "no independently delivered AUTH_EXEC event")
            guard_release = next(row for row in rows(guard_events) if row.get("kind") == "release")
            ward_release = next(row for row in rows(ward_events) if row.get("kind") == "release")
            require(guard_release["released"] and ward_release["released"], "workload admission failed")
            require(guard_release["custodian_pid"] == parent.pid, "guardian identity mismatch")
            custodians = {"guardian": inspect_custodian(fixture, guard_release),
                          "ward": inspect_custodian(fixture, ward_release)}
            require(ward_release["custodian_pid"] == custodians["ward"]["pid"], "ward identity mismatch")
            require({row["target"] for row in attacks} == {row["pid"] for row in custodians.values()},
                    "signal attack missed a custodian")
            heartbeat_before = {role: (directory / f"{role}.heartbeat").stat().st_size for role in ROLES - {"root"}}
            stop = time.monotonic()
            if case == "cancel":
                kill_owned(custodians["guardian"], signal.SIGTERM)
            elif case == "root_death":
                kill_owned(root, signal.SIGKILL)
            elif case == "both_death":
                # Freeze both first so neither cleans up during sequential kills.
                kill_owned(custodians["guardian"], signal.SIGSTOP)
                kill_owned(custodians["ward"], signal.SIGSTOP)
                kill_owned(custodians["guardian"], signal.SIGKILL)
                kill_owned(custodians["ward"], signal.SIGKILL)
            elif case != "wall":
                role, action = case.split("_")
                sig = {"death": signal.SIGKILL, "stop": signal.SIGSTOP, "gap": signal.SIGUSR1}[action]
                kill_owned(custodians[role], sig)
            exec_probe = None
            if case == "both_death" or (auth_exec and case.endswith("_stop")):
                (directory / "after-loss.trigger").write_text("owned fixture exec probe\n")
                wait_until(lambda: rows(directory / "after-loss-exec.json"))
                exec_probe = json.loads((directory / "after-loss-exec.json").read_text()) | {
                    "marker_created": (directory / "after-loss.exec").exists()}
                if case != "both_death":
                    require(exec_probe["spawn_errno"] != 0 and not exec_probe["marker_created"],
                            "paused fail-closed AUTH_EXEC client allowed the probe")
            if case == "both_death":
                time.sleep(.5)
            else:
                wait_until(lambda: all(not snapshot(fixture, row)["alive"] for row in known), timeout=6)
                expected_log = (ward_events if case in ("guardian_death", "guardian_stop") else guard_events)
                # Fixture death precedes the peer's final ES drain. Observe that
                # settlement separately; an early file read must not turn an
                # in-flight drain into a mechanism failure.
                wait_until(lambda: any(row.get("kind") == "settled" for row in rows(expected_log)))
            after = {role: snapshot(fixture, row) for role, row in by_role.items()}
            fixture_empty = not any(row["alive"] for row in after.values())
            observation_ms = (time.monotonic() - stop) * 1000
            guardian_rows, ward_rows = rows(guard_events), rows(ward_events)
            settled = [row for row in guardian_rows + ward_rows if row.get("kind") == "settled"]
            intact_settlement = any(row["observed_live_members"] == 0 and not row["gap"] and
                                    row["synced"] and row["root_reaped"] for row in settled)
            # A synthetic integrity fault must refuse, even if the known
            # fixture members happened to be cleaned up successfully.
            if case.endswith("_gap"):
                target_rows = guardian_rows if case.startswith("guardian") else ward_rows
                require(any(row.get("reason") == "event_integrity" for row in target_rows),
                        "synthetic integrity fault was not handled")
                require(any(row.get("kind") == "settled" and row["gap"] for row in target_rows),
                        "integrity fault lost at settlement")
            heartbeat_after = {role: (directory / f"{role}.heartbeat").stat().st_size for role in heartbeat_before}
            expected = fixture_empty if case != "both_death" else (
                all(row["alive"] for row in after.values()) and
                all(heartbeat_after[role] > heartbeat_before[role] for role in heartbeat_before))
            require(expected, f"unexpected {case} fixture outcome")
            if case not in ("both_death", "guardian_gap"):
                require(intact_settlement, "no independent intact custodian settlement")
            return {"case": case, "argv": argv, "ready_ms": ready_ms, "observation_ms": observation_ms,
                    "guardian_events": guardian_rows, "ward_events": ward_rows, "stderr": errors.read_text(),
                    "fixture_processes": known, "custodians": custodians, "after": after,
                    "custodian_signal_attacks": attacks,
                    "auth_exec_fail_closed": auth_exec,
                    "exec_probe": exec_probe,
                    "heartbeat_before": heartbeat_before, "heartbeat_after": heartbeat_after,
                    "guardian_exit_at_snapshot": parent.poll(),
                    "fixture_tree_empty_before_runner_cleanup": fixture_empty,
                    "intact_custodian_settlement": intact_settlement,
                    "expected_mechanism_outcome": expected, "lifetime_contract_verified": False}
        except Exception as error:
            (directory / "failure.json").write_text(json.dumps({
                "case": case, "error": str(error), "fixture_processes": known, "custodians": custodians,
                "guardian_events": rows(guard_events), "ward_events": rows(ward_events),
                "stderr": errors.read_text(), "fixture_cleanup_verified": False,
                "lifetime_contract_verified": False}, indent=2) + "\n")
            raise
        finally:
            # Emergency cleanup is separate from the recorded experiment outcome.
            # It can never turn a survivor into a passing mechanism observation.
            for row in custodians.values():
                result = signal_token(row, signal.SIGKILL)
                require(result["rc"] in (0, errno.ESRCH), f"custodian cleanup failed: {result}")
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=5)
            known = [row for row in rows(workload) if "audit_token" in row]
            tokens = known + [{"audit_token": row["token"]} for path in (guard_events, ward_events)
                              for row in rows(path) if "token" in row]
            for row in tokens:
                result = signal_token(row, signal.SIGKILL)
                require(result["rc"] in (0, errno.ESRCH), f"fixture cleanup failed: {result}")
            for row in known + list(custodians.values()):
                wait_until(lambda row=row: not snapshot(fixture, row)["alive"])
            if (directory / "failure.json").exists():
                failure = json.loads((directory / "failure.json").read_text())
                failure["fixture_cleanup_verified"] = True
                (directory / "failure.json").write_text(json.dumps(failure, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--identity", default="-")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--development-vm", action="store_true")
    parser.add_argument("--auth-exec", action="store_true", help="Also gate exec with fail-closed 250ms ES authorization")
    args = parser.parse_args()
    if platform.system() != "Darwin" or not 1 <= args.samples <= 20:
        parser.error("Requires macOS 27; samples must be 1..20")
    if args.development_vm and (args.profile or args.identity != "-"):
        parser.error("Development VM tests use ad-hoc signing")
    try:
        development = development_settings() if args.development_vm else None
    except ValueError as error:
        parser.error(str(error))
    directory = args.out.resolve()
    exe, signing = build(directory, args.identity, args.profile, args.development_vm, HERE / "macos_es_pair.c")
    sources = ["macos_es_pair.c", "macos_es_pair.py", "macos_es.c", "macos_es.py", "macos_native.c", "macos_native.py"]
    result = {"host": platform.uname()._asdict(), "sw_vers": run(["sw_vers"], check=True).stdout,
              "sdk": run(["xcrun", "--show-sdk-version"], check=True).stdout.strip(),
              "compiler": run(["cc", "--version"], check=True).stdout,
              "uid": os.getuid(), "started_unix": time.time(), "signing": signing, "development": development,
              "source_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in sources},
              "binary_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "cases": [],
              "lifetime_contract_verified": False, "production_execution_enabled": False,
              "auth_exec_fail_closed": args.auth_exec,
              "fixture_cleanup_verified": False}
    capability = run([exe, "--probe"])
    result["capability"] = {"exit": capability.returncode, "stdout": capability.stdout, "stderr": capability.stderr}
    if capability.returncode == 125:
        require(json_lines(capability.stdout) == [{"kind": "capability", "result": 3, "workload_released": False}],
                "unexpected capability refusal")
        marker = directory / "must-not-exist"
        negative = run([exe, "--guardian", "1", directory / "must-not-open-workload",
                        directory / "must-not-open-ward", "--", "/usr/bin/touch", marker])
        require(negative.returncode == 125 and not marker.exists() and
                not (directory / "must-not-open-workload").exists() and
                not (directory / "must-not-open-ward").exists(), "refusal released or opened workload")
        result["refusal_test"] = {"exit": negative.returncode, "stdout": negative.stdout,
                                  "stderr": negative.stderr, "marker_created": marker.exists()}
        result["status"] = "not_entitled_refused_before_spawn"
        (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        return 125
    require(capability.returncode == 0, "ES capability probe failed")
    fixture = directory / "native-fixture"
    run(["cc", "-O2", "-fblocks", "-Wall", "-Wextra", "-Werror", HERE / "macos_native.c",
         "-lEndpointSecurity", "-o", fixture], check=True)
    for sample in range(args.samples):
        for case in CASES:
            try:
                record = trial(exe, fixture, directory / f"trial-{sample + 1:02d}-{case}", case, args.auth_exec)
            except Exception:
                result["status"] = "experiment_failed"
                result["failed_case"] = {"sample": sample + 1, "case": case}
                (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
                raise
            record["sample"] = sample + 1
            result["cases"].append(record)
            (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps({"sample": sample + 1, "case": case,
                              "fixture_empty": record["fixture_tree_empty_before_runner_cleanup"]}), flush=True)
    result["fixture_cleanup_verified"] = True
    result["status"] = "single_custodian_failures_measured_full_lifetime_gate_open"
    (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return 125  # Explicit: the full production lifetime gate has NOT passed.


if __name__ == "__main__":
    raise SystemExit(main())
