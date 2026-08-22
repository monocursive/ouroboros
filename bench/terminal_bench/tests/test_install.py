"""The container-install and run command lines, without a container.

The install script is exercised for real against a temporary directory: `sh -c` runs it
with a fake "binary" and with a tarball containing one, which is as close to the container
as this machine can get without docker. The run command is checked for quoting, because a
task instruction is untrusted text that ends up on a command line.
"""

import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from ouroboros_agent import install as sh


class InstallScriptAgainstRealFiles(unittest.TestCase):
    """Run the actual script with `sh`, in a temp dir standing in for the container."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ouro-install-test-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.install_dir = self.root / "opt"

    def _run(self, upload: Path):
        script = sh.install_script(str(upload), str(self.install_dir))
        return subprocess.run(
            ["sh", "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _fake_binary(self, path: Path, version: str = "ouro 0.1.0"):
        path.write_text(f'#!/bin/sh\necho "{version}"\n', encoding="utf-8")
        path.chmod(0o755)

    def test_a_bare_binary_is_copied_and_runs(self):
        upload = self.root / "ouro-dist"
        self._fake_binary(upload)

        done = self._run(upload)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("ouro 0.1.0", done.stdout)
        installed = self.install_dir / "ouro"
        self.assertTrue(installed.is_file())
        self.assertTrue(os.access(installed, os.X_OK))

    def test_a_tarball_is_unpacked_and_the_binary_found_at_depth(self):
        inner = self.root / "stage" / "ouro-0.1.0-x86_64-unknown-linux-gnu"
        inner.parent.mkdir(parents=True)
        self._fake_binary(inner, "ouro 0.1.0 (from tarball)")

        upload = self.root / "dist.tar.gz"
        with tarfile.open(upload, "w:gz") as tar:
            tar.add(inner, arcname="nested/ouro-0.1.0-x86_64-unknown-linux-gnu")

        done = self._run(upload)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("from tarball", done.stdout)
        self.assertTrue((self.install_dir / "ouro").is_file())

    def test_a_missing_artifact_fails_loudly(self):
        done = self._run(self.root / "does-not-exist")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("no dist artifact", done.stderr)

    def test_an_empty_artifact_fails_loudly(self):
        upload = self.root / "empty"
        upload.write_bytes(b"")
        done = self._run(upload)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("no dist artifact", done.stderr)

    def test_an_archive_with_no_ouro_inside_fails_loudly(self):
        junk = self.root / "readme.txt"
        junk.write_text("nothing useful", encoding="utf-8")
        upload = self.root / "wrong.tar.gz"
        with tarfile.open(upload, "w:gz") as tar:
            tar.add(junk, arcname="readme.txt")

        done = self._run(upload)

        self.assertNotEqual(done.returncode, 0)
        self.assertIn("no ouro binary inside the archive", done.stderr)

    def test_the_script_never_fetches_anything(self):
        # A task container may have its network policy closed. An install that reaches
        # for a package index fails on those tasks for a reason unrelated to the model.
        script = sh.install_script()
        for forbidden in ("curl", "wget", "npm", "pip", "apt-get", "apk add"):
            self.assertNotIn(forbidden, script)


class Classification(unittest.TestCase):
    def test_is_tarball(self):
        self.assertTrue(sh.is_tarball("/tmp/dist.tar.gz"))
        self.assertTrue(sh.is_tarball("/tmp/DIST.TGZ"))
        self.assertTrue(sh.is_tarball("/tmp/dist.tar"))
        self.assertFalse(sh.is_tarball("/tmp/ouro-0.1.0-x86_64-unknown-linux-gnu"))


class RunCommand(unittest.TestCase):
    def test_it_carries_the_flags_the_adapter_promises(self):
        command = sh.run_command("do the thing", "/app", 900)
        self.assertIn("--provider native", command)
        self.assertIn("--approve-all", command)
        self.assertIn("--stream-json", command)
        self.assertIn("--timeout 900", command)
        # `shlex.quote` leaves a token needing no quoting alone, so the assertion asks
        # for what quoting produces rather than assuming it always adds quotes.
        self.assertIn(f"--workspace {shlex.quote('/app')}", command)
        self.assertIn("OUROBOROS_DATA_DIR=", command)

    def test_a_hostile_instruction_stays_data(self):
        # A task instruction is untrusted text. If it can break out of the quoting it can
        # run anything as the agent user, which is both a security hole and a way to
        # score points without solving the task.
        nasty = "fix it; rm -rf / #$(touch /pwned)`touch /pwned2` 'quoted' \"double\"\nnewline"
        command = sh.run_command(nasty, "/app", 60)

        done = subprocess.run(
            ["sh", "-c", command.replace("/opt/ouroboros/ouro", "printf %s\\n")],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("rm -rf /", done.stdout)
        self.assertFalse(Path("/pwned").exists())
        self.assertFalse(Path("/pwned2").exists())

    def test_the_stream_is_redirected_when_a_path_is_given(self):
        command = sh.run_command("hello", "/app", 60, stream_path="/logs/agent/stream.ndjson")
        self.assertIn(f"> {shlex.quote('/logs/agent/stream.ndjson')}", command)

    def test_timeout_is_coerced_to_an_integer(self):
        self.assertIn("--timeout 60", sh.run_command("hello", "/app", 60.9))


class DaemonAndStop(unittest.TestCase):
    def test_the_daemon_carries_the_model_and_never_the_key(self):
        command = sh.daemon_command(model_spec="anthropic:claude-opus-4-1")
        self.assertIn(
            f"OUROBOROS_NATIVE_MODEL={shlex.quote('anthropic:claude-opus-4-1')}", command
        )
        self.assertIn("daemon", command)
        self.assertNotIn("API_KEY", command)

    def test_the_data_dir_is_created_private(self):
        self.assertIn("chmod 0700", sh.daemon_command())

    def test_dev_mode_is_never_used(self):
        # `ouro --dev` runs `mix run --no-halt` in a checkout; a task container has none.
        self.assertNotIn("--dev", sh.daemon_command())

    def test_stop_is_scoped_to_our_data_dir(self):
        command = sh.stop_command()
        self.assertIn("OUROBOROS_DATA_DIR=", command)
        self.assertTrue(command.rstrip().endswith("|| true"))


class VersionParsing(unittest.TestCase):
    def test_it_finds_a_version_in_plausible_output(self):
        self.assertEqual(sh.parse_version("ouro 0.1.0"), "0.1.0")
        self.assertEqual(sh.parse_version("client: v1.2.3\nprotocol: 4"), "1.2.3")
        self.assertEqual(sh.parse_version("  \n  ouro version = 2.0.10  \n"), "2.0.10")

    def test_it_returns_none_rather_than_guessing(self):
        self.assertIsNone(sh.parse_version(""))
        self.assertIsNone(sh.parse_version("no version here"))


if __name__ == "__main__":
    unittest.main()
