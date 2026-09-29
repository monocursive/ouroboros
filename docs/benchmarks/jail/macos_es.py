#!/usr/bin/env python3
"""Build/sign the ES research app and run capability-gated lifecycle tests."""
import argparse
import datetime
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import signal
import subprocess
import tempfile
import time

from macos_native import json_lines, signal_token, snapshot, wait_until

HERE = Path(__file__).resolve().parent
BUNDLE_ID = "com.monocursive.ouroboros.jail"
ENTITLEMENT = "com.apple.developer.endpoint-security.client"


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=20, **kwargs)


def development_settings():
    virtualized = run(["sysctl", "-n", "kern.hv_vmm_present"], check=True).stdout.strip()
    sip = run(["csrutil", "status"], check=True).stdout.strip()
    if virtualized != "1" or sip != "System Integrity Protection status: disabled.":
        raise ValueError("Development testing requires a disposable macOS VM with SIP disabled")
    return {"virtualized": True, "sip": sip, "approved_entitlement": False,
            "authenticated_root": run(["csrutil", "authenticated-root", "status"], check=True).stdout.strip(),
            "boot_args": run(["nvram", "boot-args"], check=True).stdout.strip()}


def build(directory, identity, profile, development_vm=False):
    entitlements = {ENTITLEMENT: True} if development_vm else {}
    if profile:
        result = subprocess.run(["security", "cms", "-D", "-i", str(profile)], capture_output=True, check=True)
        data = plistlib.loads(result.stdout)
        allowed = data.get("Entitlements", {})
        if allowed.get(ENTITLEMENT) is not True:
            raise ValueError("Provisioning profile does not authorize Endpoint Security")
        if data["ExpirationDate"] <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
            raise ValueError("Provisioning profile has expired")
        team = data["TeamIdentifier"][0]
        app_id = team + "." + BUNDLE_ID
        if not fnmatch.fnmatchcase(app_id, allowed.get("com.apple.application-identifier", "")):
            raise ValueError("Provisioning profile does not authorize " + app_id)
        if identity == "-":
            raise ValueError("An Apple signing identity is required with a provisioning profile")
        entitlements = {ENTITLEMENT: True, "com.apple.application-identifier": app_id,
                        "com.apple.developer.team-identifier": team}
        if allowed.get("com.apple.security.get-task-allow"):
            entitlements["com.apple.security.get-task-allow"] = True
    directory.mkdir(parents=True, exist_ok=False)
    app = directory / "OuroJailResearch.app"
    contents = app / "Contents"
    macos = contents / "MacOS"
    macos.mkdir(parents=True)
    exe = macos / "ouro-jail-research"
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": BUNDLE_ID, "CFBundleExecutable": exe.name,
        "CFBundleName": "OuroJailResearch", "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1", "LSMinimumSystemVersion": "27.0", "LSBackgroundOnly": True,
    }))
    (contents / "PkgInfo").write_bytes(b"APPL????")
    if profile:
        shutil.copyfile(profile, contents / "embedded.provisionprofile")
    compile_command = ["cc", "-O2", "-fblocks", "-Wall", "-Wextra", "-Werror", HERE / "macos_es.c",
                       "-lEndpointSecurity", "-lbsm", "-o", exe]
    run(compile_command, check=True)
    claim = directory / "entitlements.plist"
    claim.write_bytes(plistlib.dumps(entitlements))
    sign = ["codesign", "--force", "--sign", identity, "--timestamp=none", "--options", "runtime",
            "--entitlements", claim, app]
    run(sign, check=True)
    run(["codesign", "--verify", "--strict", app], check=True)
    metadata = run(["codesign", "-d", "-vv", "--entitlements", ":-", app], check=True)
    return exe, {"bundle_id": BUNDLE_ID, "identity": identity,
                 "development_vm": development_vm,
                 "profile_supplied": profile is not None, "entitlements": entitlements,
                 "compile_argv": list(map(str, compile_command)), "codesign": metadata.stderr,
                 "signed_entitlements": metadata.stdout}


def lifecycle(exe, fixture, directory, mode):
    directory.mkdir()
    workload = directory / "workload.jsonl"
    events = directory / "events.jsonl"
    stderr = directory / "stderr"
    policy = "(version 1)(allow default)(deny signal)(allow signal (target same-sandbox))"
    argv = [str(exe), "2", str(workload), "--", "/usr/bin/sandbox-exec", "-p", policy,
            str(fixture), "tree", str(directory)]
    known = []
    start = time.monotonic()
    with events.open("w") as output, stderr.open("w") as errors:
        parent = subprocess.Popen(argv, stdout=output, stderr=errors)
        try:
            def ready():
                nonlocal known
                rows = json_lines(workload.read_text()) if workload.exists() else []
                known = [r for r in rows if "audit_token" in r]
                if parent.poll() is not None:
                    raise RuntimeError("ES custodian exited before fixture readiness: " + events.read_text())
                return any(r.get("ready") for r in rows)
            wait_until(ready)
            ready_ms = (time.monotonic() - start) * 1000
            by_role = {r["role"]: r for r in known}
            assert set(by_role) == {"root", "plain", "stubborn", "setsid", "double-fork"}
            if mode == "cancel":
                parent.terminate()
            elif mode == "supervisor_death":
                assert signal_token(by_role["root"], signal.SIGKILL)["rc"] == 0
            elif mode == "custodian_death":
                parent.kill()
            stopped = time.monotonic()
            parent.wait(timeout=10)
            # Observe potential kernel cleanup beyond custodian exit. Never
            # use our later emergency cleanup to pass this lifecycle check.
            if mode == "custodian_death":
                time.sleep(2)
            after = {role: snapshot(fixture, row) for role, row in by_role.items()}
            return {"case": mode, "argv": argv, "exit": parent.returncode,
                    "ready_ms": ready_ms, "observation_ms": (time.monotonic() - stopped) * 1000,
                    "events": json_lines(events.read_text()), "stderr": stderr.read_text(),
                    "fixture_processes": known, "after": after,
                    "fixture_tree_empty_before_runner_cleanup": not any(r["alive"] for r in after.values()),
                    "lifetime_contract_verified": False}
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait(timeout=5)
            if workload.exists():
                known = [r for r in json_lines(workload.read_text()) if "audit_token" in r]
            # Include kernel-reported tokens in case startup failed before the
            # suspended workload could produce its fixture registration.
            tokens = known + [{"audit_token": r["token"]} for r in json_lines(events.read_text()) if "token" in r]
            for row in tokens:
                result = signal_token(row, signal.SIGKILL)
                if result["rc"] not in (0, 3):
                    raise RuntimeError(f"Fixture cleanup signal failed: {result}")
            for row in known:
                wait_until(lambda row=row: not snapshot(fixture, row)["alive"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New build/evidence directory")
    parser.add_argument("--identity", default="-", help="codesign identity; default ad-hoc capability test")
    parser.add_argument("--profile", type=Path, help="Apple-issued ES provisioning profile")
    parser.add_argument("--development-vm", action="store_true",
                        help="Ad-hoc ES testing in a disposable SIP-disabled VM; no Apple approval claimed")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("Requires macOS 27 and SDK 27")
    if args.development_vm and (args.profile or args.identity != "-"):
        parser.error("--development-vm uses ad-hoc signing without an Apple provisioning profile")
    try:
        development = development_settings() if args.development_vm else None
    except ValueError as error:
        parser.error(str(error))
    directory = args.out.resolve()
    exe, signing = build(directory, args.identity, args.profile, args.development_vm)
    result = {"host": platform.uname()._asdict(), "uid": os.getuid(), "started_unix": time.time(), "signing": signing,
              "sw_vers": run(["sw_vers"], check=True).stdout,
              "compiler": run(["cc", "--version"], check=True).stdout,
              "xcode": run(["xcodebuild", "-version"]).stdout,
              "sdk": run(["xcrun", "--show-sdk-version"], check=True).stdout.strip(),
              "development": development,
              "source_sha256": hashlib.sha256((HERE / "macos_es.c").read_bytes()).hexdigest(),
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "fixture_sha256": hashlib.sha256((HERE / "macos_native.c").read_bytes()).hexdigest(),
              "fixture_runner_sha256": hashlib.sha256((HERE / "macos_native.py").read_bytes()).hexdigest(),
              "binary_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "cases": [],
              "fixture_cleanup_verified": False}
    capability = run([exe, "--probe"])
    result["capability"] = {"exit": capability.returncode, "stdout": capability.stdout, "stderr": capability.stderr}
    if capability.returncode == 125 and json_lines(capability.stdout) == [
            {"kind": "capability", "result": 3, "workload_released": False}]:
        # Exercise refusal with an actual requested command; no fixture or
        # target may be released, and the command must not create its marker.
        marker = directory / "must-not-exist"
        negative = run([exe, "1", directory / "must-not-open.jsonl", "--", "/usr/bin/touch", marker])
        assert negative.returncode == 125 and not marker.exists() and not (directory / "must-not-open.jsonl").exists()
        assert json_lines(negative.stdout) == [{"kind": "capability", "result": 3, "workload_released": False}]
        result["refusal_test"] = {"exit": negative.returncode, "stdout": negative.stdout, "marker_created": False}
        result["status"] = "blocked_missing_entitlement"
    elif capability.returncode == 0:
        fixture = directory / "fixture"
        run(["cc", "-O2", "-fblocks", "-Wall", "-Wextra", "-Werror", HERE / "macos_native.c",
             "-lEndpointSecurity", "-o", fixture], check=True)
        try:
            with tempfile.TemporaryDirectory(prefix="ouro-es-live-") as temporary:
                for mode in ("wall", "cancel", "supervisor_death", "custodian_death"):
                    result["cases"].append(lifecycle(exe, fixture, Path(temporary) / mode, mode))
            result["fixture_cleanup_verified"] = True
            result["status"] = "prototype_completed"
            if any(not row["fixture_tree_empty_before_runner_cleanup"] for row in result["cases"]):
                result["status"] = "lifetime_gate_failed"
            elif any(row["exit"] != (-signal.SIGKILL if row["case"] == "custodian_death" else 0)
                     for row in result["cases"]):
                result["status"] = "prototype_inconclusive"
        except Exception as error:
            result["status"] = "prototype_failed"
            result["error"] = str(error)
    else:
        result["status"] = "capability_probe_failed"
    result["finished_unix"] = time.time()
    result["lifetime_contract_verified"] = False
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "result": str(directory / "result.json")}, indent=2))
    return 0 if result["status"] == "prototype_completed" else 125


if __name__ == "__main__":
    raise SystemExit(main())
