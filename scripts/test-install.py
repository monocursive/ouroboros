#!/usr/bin/env python3
"""Exercise the real Bash installer with local release downloads and platform probes."""
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "https://github.com/monocursive/ouroboros"
STUB = r'''
import json, os, sys
from pathlib import Path
config = json.loads(Path(os.environ["INSTALL_FIXTURE"]).read_text())
command = Path(sys.argv[0]).name
args = sys.argv[1:]
if command == "uname":
    print(config["os"] if args == ["-s"] else config["arch"])
elif command == "getconf":
    print(config["libc"])
    sys.exit(1 if config["libc"] == "musl" else 0)
elif command == "sysctl":
    print(config.get("rosetta", "0"))
elif command == "sw_vers":
    print(config.get("macos_version", "15.0"))
elif command == "curl":
    with open(config["calls"], "a") as stream:
        stream.write(json.dumps(args) + "\n")
    url = args[-1]
    if "--head" in args:
        print(config["latest"], end="")
    elif url in config["files"]:
        Path(args[args.index("--output") + 1]).write_bytes(Path(config["files"][url]).read_bytes())
    else:
        sys.exit(22)
else:
    sys.exit(19)
'''


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ouro-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "installed bin"
        self.bin.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.config_path = self.root / "fixture.json"
        self.calls = self.root / "curl-calls"
        self.config = {"os": "Darwin", "arch": "arm64", "libc": "glibc 2.39",
                       "latest": REPO + "/releases/tag/v0.1.0", "calls": str(self.calls), "files": {}}
        self.env = dict(os.environ, HOME=str(self.home), TMPDIR=str(self.root),
                        PATH=f"{self.tools}:/usr/bin:/bin", INSTALL_FIXTURE=str(self.config_path))
        for command in ("curl", "uname", "getconf", "sysctl", "sw_vers"):
            self.stub(command)

    def stub(self, command):
        # Use the interpreter running this suite; the installer itself needs no Python.
        import sys
        path = self.tools / command
        path.write_text(f"#!{sys.executable}\n" + STUB)
        path.chmod(0o755)

    def release(self, tag="v0.1.0", target="aarch64-apple-darwin", payload=b"new ouro binary\n"):
        name = f"ouro-{tag[1:]}-{target}"
        binary = self.root / name
        binary.write_bytes(payload)
        sums = self.root / f"{tag}.sums"
        sums.write_text(f"{hashlib.sha256(payload).hexdigest()}  {name}\n")
        base = f"{REPO}/releases/download/{tag}"
        self.config["files"].update({f"{base}/{name}": str(binary), f"{base}/SHA256SUMS": str(sums)})
        return binary, sums

    def run_install(self, *args, success=True, custom_bin=True):
        self.config_path.write_text(json.dumps(self.config))
        argv = ["/bin/bash", str(ROOT / "install.sh")]
        if custom_bin:
            argv.extend(("--bin-dir", str(self.bin)))
        result = subprocess.run([*argv, *args], env=self.env, text=True, capture_output=True, timeout=20)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.bin.glob(".ouro-install.*")), [])
        self.assertEqual(list(self.root.glob("ouro-install.*")), [])
        return result

    def test_latest_resolves_once_and_verifies_exact_tag_over_https(self):
        self.release()
        self.run_install()
        self.assertEqual((self.bin / "ouro").read_bytes(), b"new ouro binary\n")
        self.assertEqual((self.bin / "ouro").stat().st_mode & 0o777, 0o755)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0][-1], REPO + "/releases/latest")
        for call in calls:
            self.assertIn("--fail", call)
            self.assertEqual(call[call.index("--proto") + 1], "=https")
            self.assertEqual(call[call.index("--proto-redir") + 1], "=https")
        self.assertTrue(all("/download/v0.1.0/" in call[-1] for call in calls[1:]))

    def test_explicit_old_version_and_prerelease(self):
        for tag in ("v0.0.1", "v0.2.0-rc.1"):
            with self.subTest(tag=tag):
                self.release(tag, payload=tag.encode())
                self.run_install("--version", tag)
                self.assertEqual((self.bin / "ouro").read_text(), tag)
        self.assertNotIn("--head", self.calls.read_text())

    def test_default_directory(self):
        self.release()
        self.run_install(custom_bin=False)
        self.assertTrue((self.home / ".local/bin/ouro").is_file())

    def test_corruption_and_missing_download_leave_old_install(self):
        binary, _ = self.release()
        old = self.bin / "ouro"
        old.write_text("old installation")
        binary.write_text("corrupted")
        result = self.run_install(success=False)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(old.read_text(), "old installation")
        self.config["files"] = {}
        self.run_install(success=False)
        self.assertEqual(old.read_text(), "old installation")

    def test_missing_binary_leaves_old_install(self):
        binary, _ = self.release()
        del self.config["files"][next(url for url in self.config["files"] if url.endswith(binary.name))]
        (self.bin / "ouro").write_text("old")
        self.run_install(success=False)
        self.assertEqual((self.bin / "ouro").read_text(), "old")

    def test_ambiguous_invalid_or_missing_checksum(self):
        _, sums = self.release()
        original = sums.read_text()
        for value in (original * 2, "not-a-hash  " + original.split("  ")[1], ""):
            with self.subTest(value=value):
                sums.write_text(value)
                self.run_install(success=False)
                self.assertFalse((self.bin / "ouro").exists())

    def test_unrelated_checksum_entries_are_not_used(self):
        _, sums = self.release()
        sums.write_text("0" * 64 + "  unrelated\n" + sums.read_text())
        self.run_install()

    def test_invalid_arguments_never_download(self):
        for args in (("--version", "v01.2.3"), ("--version", "../../file"),
                     ("--version", "v1.2.3;echo bad"), ("--version",), ("--unknown",),
                     ("--bin-dir", "relative")):
            with self.subTest(args=args):
                self.run_install(*args, success=False)
                self.assertFalse(self.calls.exists())

    def test_bad_latest_redirects(self):
        for latest in ("https://example.com/releases/tag/v0.1.0", REPO + "/releases/tag/v0.1.0-rc.1"):
            self.config["latest"] = latest
            self.run_install(success=False)
            self.assertFalse((self.bin / "ouro").exists())

    def test_supported_native_platforms(self):
        for system, arch, target in (("Darwin", "x86_64", "x86_64-apple-darwin"),
                                     ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
                                     ("Linux", "aarch64", "aarch64-unknown-linux-gnu")):
            with self.subTest(target=target):
                self.config.update(os=system, arch=arch)
                self.release(target=target)
                self.run_install()

    def test_shared_updater_release_contract(self):
        contract = json.loads((ROOT / "test/support/release-contract.json").read_text())
        for case in contract["targets"]:
            self.config.update(os=case["uname"], arch=case["arch"],
                               libc=case["version"], rosetta="1" if case["rosetta"] else "0",
                               macos_version=case["version"])
            for tag in contract["stable_tags"]:
                self.config["latest"] = REPO + "/releases/tag/" + tag
                self.release(tag, case["target"])
                self.run_install()
        self.config.update(os="Darwin", arch="arm64", macos_version="15.0")
        for tag in contract["invalid_latest_tags"]:
            self.config["latest"] = REPO + "/releases/tag/" + tag
            before = len(self.calls.read_text().splitlines())
            self.run_install(success=False)
            calls = self.calls.read_text().splitlines()[before:]
            self.assertEqual(len(calls), 1, "invalid latest tags must fail before asset downloads")

    def test_old_macos_is_refused(self):
        self.config["macos_version"] = "14.9"
        self.run_install(success=False)
        self.assertFalse(self.calls.exists())

    def test_rosetta_uses_arm64(self):
        self.config.update(arch="x86_64", rosetta="1")
        self.release()
        self.run_install()
        self.assertIn("aarch64-apple-darwin", self.calls.read_text())

    def test_unsupported_os_arch_and_libc(self):
        for values in ({"os": "Windows"}, {"arch": "armv7l"}, {"os": "Linux", "libc": "musl"},
                       {"os": "Linux", "libc": "glibc 2.38"}):
            with self.subTest(values=values):
                self.config.update(os="Darwin", arch="arm64", libc="glibc 2.39")
                self.config.update(values)
                self.run_install(success=False)
                self.assertFalse(self.calls.exists())

    def test_symlink_and_directory_destinations_are_preserved(self):
        self.release()
        outside = self.root / "outside"
        outside.write_text("untouched")
        destination = self.bin / "ouro"
        destination.symlink_to(outside)
        self.run_install(success=False)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(outside.read_text(), "untouched")
        destination.unlink()
        destination.mkdir()
        self.run_install(success=False)
        self.assertTrue(destination.is_dir())

    def test_failed_replace_preserves_old_binary_and_cleans_staging(self):
        self.release()
        (self.bin / "ouro").write_text("old")
        self.stub("mv")
        self.run_install(success=False)
        self.assertEqual((self.bin / "ouro").read_text(), "old")

    def test_pipe_install(self):
        self.release()
        self.config_path.write_text(json.dumps(self.config))
        result = subprocess.run(["/bin/bash", "-s", "--", "--bin-dir", str(self.bin)],
                                input=(ROOT / "install.sh").read_text(), env=self.env,
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.bin / "ouro").exists())


if __name__ == "__main__":
    unittest.main()
