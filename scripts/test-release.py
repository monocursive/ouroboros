#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

GH_STUB = r'''
import json, os, sys
from pathlib import Path
state_path = Path(os.environ["PUBLISH_FIXTURE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
state["calls"].append(args)
if args[0] == "api":
    if state.get("api_failure"):
        sys.exit(1)
    print(json.dumps(state["history"]))
elif args[:2] == ["release", "create"]:
    state["history"].append({"tag_name": os.environ["TAG"], "draft": True,
                             "prerelease": os.environ["PRERELEASE"] == "true"})
elif args[:2] == ["release", "upload"]:
    if state.get("upload_failure"):
        state_path.write_text(json.dumps(state))
        sys.exit(1)
    state["assets"] = sorted(set(state.get("assets", []) + [Path(p).name for p in args[3:] if p != "--clobber"]))
elif args[:2] == ["release", "view"]:
    print("\n".join(state["assets"]))
elif args[:2] == ["release", "edit"]:
    state["published"] = True
else:
    raise RuntimeError(args)
state_path.write_text(json.dumps(state))
'''


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "tui").mkdir()
        self.versions("0.1.0")
        (self.root / "install.sh").write_text("installer fixture")

    def versions(self, version):
        (self.root / "mix.exs").write_text(f'      version: "{version}",\n')
        (self.root / "tui/Cargo.toml").write_text(f'[package]\nversion = "{version}"\n')
        (self.root / "tui/Cargo.lock").write_text(f'[[package]]\nname = "ouro"\nversion = "{version}"\n')

    def artifacts(self):
        directory = self.root / "assets"
        directory.mkdir()
        for target in release.TARGETS:
            (directory / f"ouro-0.1.0-{target}").write_text(target)
        return directory

    def test_versions_and_candidate_tags(self):
        for version in ("0.1.0", "1.2.3-alpha.0", "1.2.3-beta.3", "1.2.3-rc.10"):
            self.versions(version)
            self.assertEqual(release.check("v" + version, self.root), version)

    def test_mismatched_manifests_and_lock_are_rejected(self):
        for path in ("mix.exs", "tui/Cargo.toml", "tui/Cargo.lock"):
            self.versions("0.1.0")
            source = self.root / path
            source.write_text(source.read_text().replace("0.1.0", "0.2.0"))
            with self.assertRaises(ValueError):
                release.check("v0.1.0", self.root)

    def test_bad_tags(self):
        for tag in ("0.1.0", "v01.0.0", "v1.0", "v1.0.0-rc.01", "v1.0.0+build", "v1.2.3\n", "../x"):
            with self.assertRaises(ValueError):
                release.check(tag, self.root)

    def test_complete_matrix_collects_installer_and_verifiable_checksums(self):
        directory = self.artifacts()
        release.collect("v0.1.0", directory, self.root)
        self.assertEqual(len(list(directory.iterdir())), 6)
        for line in (directory / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((directory / name).read_bytes()).hexdigest())

    def test_incomplete_or_unexpected_assets_are_rejected(self):
        directory = self.artifacts()
        binary = next(directory.iterdir())
        binary.unlink()
        with self.assertRaises(ValueError):
            release.collect("v0.1.0", directory, self.root)
        binary.write_text("restored")
        (directory / "old-binary").write_text("old")
        with self.assertRaises(ValueError):
            release.collect("v0.1.0", directory, self.root)

    def test_empty_and_symlinked_binary_are_rejected(self):
        directory = self.artifacts()
        binary = next(directory.iterdir())
        binary.write_bytes(b"")
        with self.assertRaises(ValueError):
            release.collect("v0.1.0", directory, self.root)
        binary.unlink()
        binary.symlink_to(self.root / "install.sh")
        with self.assertRaises(ValueError):
            release.collect("v0.1.0", directory, self.root)

    def test_latest_handles_first_release_backports_candidates_and_pagination(self):
        history = json.dumps([{"tag_name": "v0.2.0", "draft": False, "prerelease": False}])
        history += '\n' + json.dumps([{"tag_name": "v3.0.0", "draft": True, "prerelease": False},
                                      {"tag_name": "v4.0.0-rc.1", "draft": False, "prerelease": True}])
        self.assertTrue(release.latest("v0.1.0", "[]"))
        self.assertFalse(release.latest("v0.1.1", history))
        self.assertFalse(release.latest("v0.3.0-rc.1", history))
        self.assertTrue(release.latest("v0.10.0", history))
        with self.assertRaises(ValueError):
            release.latest("v0.3.0", "broken API response")

    def publisher(self, tag="v0.1.0", history=None, **overrides):
        self.versions(tag[1:])
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copyfile(Path(__file__).with_name("release.py"), scripts / "release.py")
        assets = self.root / "_build/release-assets"
        assets.mkdir(parents=True)
        for name in ("binary-one", "binary-two", "SHA256SUMS", "install.sh"):
            (assets / name).write_text("fixture")
        tools = self.root / "tools"
        tools.mkdir()
        gh = tools / "gh"
        gh.write_text(f"#!{sys.executable}\n" + GH_STUB)
        gh.chmod(0o755)
        state_path = self.root / "publish.json"
        state_path.write_text(json.dumps(dict(history=history or [], calls=[], **overrides)))

        def invoke():
            env = dict(os.environ, TAG=tag, GH_REPO="test/repository", GITHUB_SHA="a" * 40,
                       PRERELEASE=str("-" in tag).lower(), PUBLISH_FIXTURE=str(state_path),
                       PATH=f"{tools}:{os.environ['PATH']}")
            result = subprocess.run(["bash", str(Path(__file__).with_name("publish-release.sh"))],
                                    cwd=self.root, env=env, capture_output=True, text=True, timeout=20)
            return result, json.loads(state_path.read_text())
        return invoke, state_path

    def test_publish_complete_draft_then_promote_stable(self):
        invoke, _ = self.publisher()
        result, state = invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state["published"])
        create = next(c for c in state["calls"] if c[:2] == ["release", "create"])
        self.assertIn("--draft", create)
        self.assertIn("--verify-tag", create)
        self.assertIn("--latest=true", state["calls"][-1])

    def test_publish_prerelease_does_not_promote_latest(self):
        invoke, _ = self.publisher("v0.2.0-rc.1")
        result, state = invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--latest=false", state["calls"][-1])
        self.assertIn("--prerelease=true", state["calls"][-1])

    def test_publish_backport_does_not_promote_latest(self):
        invoke, _ = self.publisher(history=[{"tag_name": "v0.2.0", "draft": False, "prerelease": False}])
        result, state = invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--latest=false", state["calls"][-1])

    def test_published_release_never_mutated(self):
        invoke, _ = self.publisher(history=[{"tag_name": "v0.1.0", "draft": False, "prerelease": False}])
        result, state = invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already published", result.stderr)
        self.assertTrue(all(c[0] == "api" for c in state["calls"]))

    def test_failed_upload_leaves_draft_and_retry_resumes_it(self):
        invoke, state_path = self.publisher(upload_failure=True)
        result, state = invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("published", state)
        self.assertTrue(state["history"][0]["draft"])
        state["upload_failure"] = False
        state_path.write_text(json.dumps(state))
        result, state = invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state["published"])
        self.assertEqual(sum(c[:2] == ["release", "create"] for c in state["calls"]), 1)

    def test_unexpected_draft_assets_block_publication(self):
        invoke, _ = self.publisher(assets=["unexpected"])
        result, state = invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("published", state)

    def test_failed_history_request_blocks_publication(self):
        invoke, _ = self.publisher(api_failure=True)
        result, state = invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["calls"], [])


if __name__ == "__main__":
    unittest.main()
