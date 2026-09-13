#!/usr/bin/env python3
"""Qualify old BEAM + new process helpers, authenticated stop and session recovery.

Only disposable installations/profiles are modified. The previous published binary
is checksum-verified before execution. No model prompt or account is used.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

PREVIOUS = "0.1.2"
REPOSITORY = "https://github.com/monocursive/ouroboros"
TARGETS = {"aarch64-apple-darwin", "x86_64-apple-darwin",
           "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"}


def download_previous(directory, target):
    asset = f"ouro-{PREVIOUS}-{target}"
    base = f"{REPOSITORY}/releases/download/v{PREVIOUS}"
    for name in ("SHA256SUMS", asset):
        subprocess.run(["curl", "--disable", "--fail", "--silent", "--show-error",
                        "--location", "--proto", "=https", "--proto-redir", "=https",
                        "--connect-timeout", "15", "--max-time", "600", "--retry", "2",
                        "--output", str(directory / name), f"{base}/{name}"], check=True, timeout=1900)
    sums = [line.split() for line in (directory / "SHA256SUMS").read_text().splitlines()]
    hashes = [fields[0] for fields in sums if len(fields) == 2 and fields[1] == asset]
    binary = directory / asset
    with binary.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(stream.read()).hexdigest()
    if hashes != [actual]:
        raise ValueError("previous release checksum missing, duplicated or mismatched")
    binary.chmod(0o755)
    return binary


def smoke(candidate, version, target):
    state = Path(tempfile.mkdtemp(prefix="ouro-update-smoke-"))
    stopped = True
    try:
        previous = download_previous(state, target)
        for name in ("home", "data", "config", "cache", "tmp", "bin", "helper-check", "workspace"):
            (state / name).mkdir(mode=0o700)
        installed = state / "bin/ouro"
        shutil.copyfile(previous, installed)
        installed.chmod(0o755)
        env = {"HOME": str(state / "home"), "XDG_CONFIG_HOME": str(state / "config"),
               "XDG_DATA_HOME": str(state / "data"), "XDG_CACHE_HOME": str(state / "cache"),
               "OUROBOROS_DATA_DIR": str(state / "data"), "OUROBOROS_DIST": "none",
               "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SHELL": "/bin/sh",
               "LANG": "en_US.UTF-8", "TMPDIR": str(state / "tmp")}

        def run(*args, environment=None):
            result = subprocess.run(args, cwd=state, env=environment or env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            if result.returncode:
                raise RuntimeError(f"{Path(args[0]).name} {args[1]} failed: {result.stdout}\n{result.stderr}")
            return result.stdout

        def stop():
            nonlocal stopped
            # gateway.json can disappear while the runtime still owns its data.
            # Only an authenticated, confirmed stop permits profile cleanup.
            output = run(str(installed), "stop")
            if "the runtime accepted runtime.shutdown" not in output or not re.search(r"the runtime stopped \(pid [0-9]+\)", output):
                raise ValueError("authenticated runtime shutdown was not confirmed")
            stopped = True

        try:
            if run(str(installed), "--version") != f"ouro {PREVIOUS}\n":
                raise ValueError("previous release version mismatch")
            stopped = False
            run(str(installed), "daemon")
            old_gateway = json.loads((state / "data/gateway.json").read_text())
            old_owner = (state / "data/runtime.owner").read_bytes()
            # An empty session exercises durable state without sending a model prompt.
            created = run(str(installed), "new", "--print", "--workspace", str(state / "workspace"))
            ids = re.findall(r"(?m)^([A-Za-z0-9_-]{16,})$", created)
            if len(ids) != 1:
                raise ValueError(f"expected one durable session id: {created!r}")
            session_id = ids[0]
            if session_id not in run(str(installed), "agents", "--json"):
                raise ValueError("created session is not visible")
            old_releases = list((state / "cache/ouroboros/releases").glob("*/bin/ouroboros"))
            if len(old_releases) != 1:
                raise ValueError("expected one old embedded release")
            old_release = old_releases[0]

            # Transaction qualification uses the same bytes in the Rust test harness.
            # Here the actual previous CLI lacks `update`; replace the disposable copy
            # to specifically exercise the old BEAM/new native-helper combination.
            staged = state / "bin/candidate"
            shutil.copyfile(candidate, staged)
            staged.chmod(0o755)
            os.replace(staged, installed)
            if run(str(installed), "--version") != f"ouro {version}\n":
                raise ValueError("new executable version mismatch")
            if json.loads((state / "data/gateway.json").read_text()) != old_gateway or (state / "data/runtime.owner").read_bytes() != old_owner:
                raise ValueError("binary replacement changed the running runtime")
            run(str(installed), "attach", "--print")

            # Run the published old BEAM module in its old release, with the new CLI
            # as helper. RuntimeOwner.init invokes BOTH process-birth and the recovery
            # lock helper. It owns only a separate temporary directory.
            helper_env = dict(env, OUROBOROS_PROCESS_ID_HELPER=str(installed),
                              OUROBOROS_DATA_DIR=str(state / "helper-check"))
            expr = f'''
Application.load(:ouroboros)
true = to_string(Application.spec(:ouroboros, :vsn)) == "{PREVIOUS}"
{{:ok, _}} = Application.ensure_all_started(:crypto)
{{:ok, owner}} = Ouroboros.RuntimeOwner.start_link(data_dir: System.fetch_env!("OUROBOROS_DATA_DIR"))
claim = Ouroboros.RuntimeOwner.claim(owner)
true = is_binary(claim.birth) and byte_size(claim.birth) > 0
:ok = GenServer.stop(owner)
IO.puts("old-runtime helper contract passed")
'''
            if "old-runtime helper contract passed" not in run(str(old_release), "eval", expr, environment=helper_env):
                raise ValueError("old helper contract did not pass")
            if session_id not in run(str(installed), "agents", "--json"):
                raise ValueError("new client cannot see old runtime session")
            stop()
            stopped = False
            run(str(installed), "daemon")
            if session_id not in run(str(installed), "agents", "--json"):
                raise ValueError("durable session did not recover after restart")
            expected = f"  release   {version} (sha256 "
            if expected not in run(str(installed), "version"):
                raise ValueError("new embedded release version mismatch")
            stop()
        finally:
            if not stopped:
                stop()
        print(f"update smoke passed: {PREVIOUS} -> {version} {target} (helpers, live runtime, stop, durable session recovery)")
    except BaseException:
        print(f"Update smoke failed; isolated state retained at {state}; shutdown confirmed: {stopped}")
        raise
    else:
        shutil.rmtree(state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("version")
    parser.add_argument("target", choices=sorted(TARGETS))
    args = parser.parse_args()
    smoke(args.binary.resolve(), args.version, args.target)
