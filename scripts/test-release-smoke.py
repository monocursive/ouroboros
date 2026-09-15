#!/usr/bin/env python3
"""Exercise smoke-harness policy and cleanup with disposable files and CLI doubles.

These regressions do not replace the native packaged-binary qualification jobs.
"""
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RELEASE = load("release-smoke")
UPDATE = load("update-smoke")
TARGET = "x86_64-unknown-linux-gnu"
SESSION = "durable-session-fixture"
CONFIRMED_STOP = "the runtime accepted runtime.shutdown\nthe runtime stopped (pid 123)\n"


class Harness:
    def __init__(self, root):
        self.state = root / "profile"
        self.state.mkdir()
        self.candidate = root / "candidate"
        self.candidate.write_text("0.1.3")
        self.previous = root / "previous"
        self.previous.write_text(UPDATE.PREVIOUS)
        self.local = False
        self.check_exit = 0
        self.check_writes = False
        self.drop_publication = None
        self.fail_start = False
        self.stop_output = CONFIRMED_STOP
        self.stop_exit = 0
        self.live = False
        self.commands = []
        self.agents_calls = 0
        self.output = io.StringIO()

    def command(self, args, **kwargs):
        self.commands.append(args[1])
        stdout, status = self.response(args)
        result = subprocess.CompletedProcess(args, status, stdout, "fixture failure" if status else "")
        if kwargs.get("check") and status:
            raise subprocess.CalledProcessError(status, args, result.stdout, result.stderr)
        return result

    def response(self, args):
        command = args[1]
        data = self.state / "data"
        publication = data / "gateway.json"
        if command == "--version":
            return f"ouro {Path(args[0]).read_text()}\n", 0
        if command == "version":
            return "ouro 0.1.3\n  release   0.1.3 (sha256 fixture)\n", 0
        if command == "update":
            if self.check_writes:
                (data / "unexpected").touch()
            label = " (local build)" if self.local else ""
            return f"ouro 0.1.3{label} is ahead of latest stable 0.0.0; no downgrade performed\n", self.check_exit
        if command == "daemon":
            self.live = True
            publication.write_text(json.dumps({"pid": 123}))
            (data / "runtime.owner").write_text("live fixture owner")
            release = self.state / "cache/ouroboros/releases/fixture"
            for name in ("bin/ouroboros", "lib/ouroboros-fixture/priv/wasm/ouro-wasm", "lib/ouroboros-fixture/priv/media/ouro-media"):
                artifact = release / name
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.touch()
                artifact.chmod(0o755)
            if self.fail_start:
                publication.unlink()
                return "startup failed after claiming ownership", 1
            return "started", 0
        if command == "wasm":
            return json.dumps({"helper": {"present": True}}), 0
        if command == "doctor":
            return json.dumps({"usable": True, "target": TARGET}), 0
        if command == "new":
            return SESSION + "\n", 0
        if command == "agents":
            self.agents_calls += 1
            if self.drop_publication == self.agents_calls:
                publication.unlink()
            return json.dumps([SESSION]), 0
        if command == "attach":
            return "attached", 0
        if command == "eval":
            return "old-runtime helper contract passed", 0
        if command == "web":
            (data / "web.json").write_text(json.dumps({"port": 12345}))
            if self.drop_publication == "web":
                publication.unlink()
            return "web started", 0
        if command == "stop":
            if not publication.exists():
                return "no runtime publication was found", 0
            if self.stop_exit == 0 and self.stop_output == CONFIRMED_STOP:
                self.live = False
                publication.unlink()
                (data / "runtime.owner").unlink()
            return self.stop_output, self.stop_exit
        raise AssertionError(f"unexpected command: {args}")

    def invoke(self, module, **kwargs):
        with ExitStack() as stack:
            stack.enter_context(patch.object(module.tempfile, "mkdtemp", return_value=str(self.state)))
            stack.enter_context(patch.object(module.subprocess, "run", side_effect=self.command))
            stack.enter_context(redirect_stdout(self.output))
            if module is UPDATE:
                stack.enter_context(patch.object(module, "download_previous", return_value=self.previous))
            else:
                connection = Mock()
                connection.getresponse.return_value.status = 401
                stack.enter_context(patch.object(module.http.client, "HTTPConnection", return_value=connection))
            module.smoke(self.candidate, "0.1.3", TARGET, **kwargs)


class SmokeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ouro-smoke-harness-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def harness(self):
        root = self.root / str(len(list(self.root.iterdir())))
        root.mkdir()
        return Harness(root)

    def assert_retained(self, harness):
        self.assertTrue(harness.live)
        self.assertTrue((harness.state / "data/runtime.owner").exists())
        self.assertIn("stop", harness.commands)
        self.assertNotIn("smoke passed", harness.output.getvalue())

    def test_local_packaging_accepts_disabled_self_update(self):
        harness = self.harness()
        harness.local = True
        harness.invoke(RELEASE)
        self.assertEqual(harness.commands.count("stop"), 1)
        self.assertFalse(harness.live)
        self.assertFalse(harness.state.exists())

    def test_official_packaging_requires_enabled_self_update(self):
        harness = self.harness()
        harness.local = True
        with self.assertRaisesRegex(ValueError, "must enable standalone self-update"):
            harness.invoke(RELEASE, require_self_update=True)
        self.assertNotIn("daemon", harness.commands)
        self.assertNotIn("stop", harness.commands)
        self.assertTrue(harness.state.exists())

    def test_confirmed_shutdown_allows_cleanup_in_both_harnesses(self):
        for module, expected_stops in ((RELEASE, 1), (UPDATE, 2)):
            with self.subTest(module=module.__name__):
                harness = self.harness()
                options = {"require_self_update": True} if module is RELEASE else {}
                harness.invoke(module, **options)
                self.assertEqual(harness.commands.count("stop"), expected_stops)
                self.assertFalse(harness.live)
                self.assertFalse(harness.state.exists())

    def test_check_failures_and_writes_still_refuse_local_and_official_builds(self):
        for official in (False, True):
            for fault, message in (("check_exit", "update check failed"),
                                   ("check_writes", "update check wrote files")):
                with self.subTest(official=official, fault=fault):
                    harness = self.harness()
                    harness.local = not official
                    setattr(harness, fault, 1)
                    with self.assertRaisesRegex(ValueError, message):
                        harness.invoke(RELEASE, require_self_update=official)
                    self.assertNotIn("daemon", harness.commands)

    def test_missing_publication_retains_live_state_before_each_shutdown(self):
        for module, phase in ((RELEASE, "web"), (UPDATE, 2), (UPDATE, 3)):
            with self.subTest(module=module.__name__, phase=phase):
                harness = self.harness()
                harness.drop_publication = phase
                with self.assertRaisesRegex(ValueError, "shutdown was not confirmed"):
                    harness.invoke(module)
                self.assert_retained(harness)
                if module is UPDATE:
                    self.assertIn("shutdown confirmed: False", harness.output.getvalue())
                    self.assertEqual(harness.commands.count("daemon"), phase - 1)

    def test_start_failure_without_publication_also_retains_state(self):
        for module in (RELEASE, UPDATE):
            with self.subTest(module=module.__name__):
                harness = self.harness()
                harness.fail_start = True
                with self.assertRaisesRegex(ValueError, "shutdown was not confirmed"):
                    harness.invoke(module)
                self.assert_retained(harness)

    def test_incomplete_shutdown_receipt_or_failed_stop_retains_state(self):
        for module in (RELEASE, UPDATE):
            for output, status in (("the runtime accepted runtime.shutdown\n", 0),
                                   ("the runtime stopped (pid 123)\n", 0),
                                   (CONFIRMED_STOP, 1)):
                with self.subTest(module=module.__name__, output=output, status=status):
                    harness = self.harness()
                    harness.stop_output, harness.stop_exit = output, status
                    with self.assertRaises((ValueError, RuntimeError, subprocess.CalledProcessError)):
                        harness.invoke(module)
                    self.assert_retained(harness)


if __name__ == "__main__":
    unittest.main()
