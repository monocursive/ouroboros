#!/usr/bin/env python3
"""Boot a shipped binary away from its checkout with no developer environment."""
import argparse
import http.client
import json
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


MACHO_MAGIC = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}


@contextmanager
def scratch():
    state = Path(tempfile.mkdtemp(prefix="ouro-release-smoke-"))
    try:
        yield state
    except BaseException:
        # Do not delete a failed daemon's state while its shutdown is unconfirmed.
        print(f"Release smoke failed; isolated state retained for inspection: {state}")
        raise
    else:
        shutil.rmtree(state)


def smoke(binary, version, target, *, require_self_update=False):
    with scratch() as state:
        for name in ("home", "data", "config", "cache", "tmp", "bin"):
            (state / name).mkdir(mode=0o700)
        installed = state / "bin/ouro"
        shutil.copyfile(binary, installed)
        installed.chmod(0o755)
        env = {
            "HOME": str(state / "home"), "XDG_CONFIG_HOME": str(state / "config"),
            "XDG_DATA_HOME": str(state / "data"), "XDG_CACHE_HOME": str(state / "cache"),
            "OUROBOROS_DATA_DIR": str(state / "data"), "OUROBOROS_DIST": "none",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SHELL": "/bin/sh",
            "LANG": "en_US.UTF-8", "TMPDIR": str(state / "tmp"),
        }

        def run(*argv):
            return subprocess.run(argv, cwd=state, env=env, check=True, timeout=120,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        output = run(str(installed), "version")
        if not output.startswith(f"ouro {version}\n") or f"  release   {version} (sha256 " not in output:
            raise ValueError("client and embedded runtime must both match the release tag")
        # Exercise the shipped CLI's build policy without depending on a mutable
        # public latest tag. This PATH substitution exists only in the smoke harness;
        # the binary has no repository or verification override. All runtime probes
        # below keep their system-only PATH.
        check_tools = state / "update-check-tools"
        check_tools.mkdir()
        curl = check_tools / "curl"
        curl.write_text("#!/bin/sh\nprintf 'https://github.com/monocursive/ouroboros/releases/tag/v0.0.0'\n")
        curl.chmod(0o755)
        before = {p.relative_to(state) for p in state.rglob("*")}
        checked = subprocess.run([str(installed), "update", "--check"], cwd=state,
                                 env=dict(env, PATH=str(check_tools)), text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if checked.returncode not in (0, 10) or "0.0.0" not in checked.stdout:
            raise ValueError("packaged update check failed: " + checked.stderr)
        if require_self_update and "local build" in checked.stdout:
            raise ValueError("official packaged binary must enable standalone self-update")
        if before != {p.relative_to(state) for p in state.rglob("*")}:
            raise ValueError("packaged update check wrote files")
        try:
            run(str(installed), "daemon")
            status = json.loads(run(str(installed), "wasm", "doctor", "--json"))
            if status["helper"]["present"] is not True:
                raise ValueError("bundled WebAssembly helper missing")
            releases = list((state / "cache/ouroboros/releases").glob("*/bin/ouroboros"))
            if len(releases) != 1:
                raise ValueError("expected exactly one extracted runtime")
            release = releases[0].parent.parent
            helpers = list(release.glob("lib/ouroboros-*/priv/wasm/ouro-wasm"))
            if len(helpers) != 1:
                raise ValueError("expected exactly one packaged helper")
            doctor = json.loads(run(str(helpers[0]), "doctor"))
            if doctor["usable"] is not True or doctor["target"] != target:
                raise ValueError("helper cannot run or has the wrong architecture")
            # macOS runners contain Homebrew libraries a user's machine may not have.
            # Inspect every Mach-O, including crypto/sqlite NIFs, for such dependencies.
            if target.endswith("apple-darwin"):
                for path in [installed, *release.rglob("*")]:
                    if not path.is_file() or path.is_symlink():
                        continue
                    with path.open("rb") as stream:
                        magic = stream.read(4)
                    if magic in MACHO_MAGIC:
                        expected_arch = "arm64" if target.startswith("aarch64-") else "x86_64"
                        if expected_arch not in run("/usr/bin/lipo", "-archs", str(path)).split():
                            raise ValueError(f"wrong architecture in {path.name}")
                        # otool -L includes LC_ID_DYLIB (the library's own build-time
                        # install name). It is not a dependency loaded by the host.
                        identities = set(run("/usr/bin/otool", "-D", str(path)).splitlines()[1:])
                        for line in run("/usr/bin/otool", "-L", str(path)).splitlines()[1:]:
                            library = line.strip().split(" (", 1)[0]
                            if (library not in identities and library.startswith("/")
                                    and not library.startswith(("/usr/lib/", "/System/Library/"))):
                                raise ValueError(f"non-system dynamic dependency in {path.name}: {library}")
            run(str(installed), "web", "--print")
            web = json.loads((state / "data/web.json").read_text())
            connection = http.client.HTTPConnection("127.0.0.1", web["port"], timeout=10)
            try:
                connection.request("GET", "/")
                if connection.getresponse().status != 401:
                    raise ValueError("unauthenticated web request was not refused")
            finally:
                connection.close()
        finally:
            # A missing gateway publication does not prove its runtime stopped.
            # Always use this isolated client's authenticated control path; an
            # unavailable or unconfirmed shutdown retains the profile for inspection.
            stopped = run(str(installed), "stop")
            if "the runtime accepted runtime.shutdown" not in stopped or not re.search(r"the runtime stopped \(pid [0-9]+\)", stopped):
                raise ValueError("packaged runtime shutdown was not confirmed")
        print(f"release smoke passed: {version} {target} (boot, helper, web refusal, stop)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("version")
    parser.add_argument("target")
    parser.add_argument("--require-self-update", action="store_true",
                        help="require an official build with standalone self-update enabled")
    args = parser.parse_args()
    smoke(args.binary.resolve(), args.version, args.target,
          require_self_update=args.require_self_update)
