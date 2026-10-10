import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from prepare_release import TARGETS, assemble, stage
from publish_release import ROOT, check, publication_gates, verify_remote_assets
from test_release import INPUTS, REVISION, version


@unittest.skipUnless(shutil.which('minisign'), 'minisign is required')
class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ouro-publish-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(['minisign', '-G', '-W', '-s', str(self.root / 'key'),
                        '-p', str(self.root / 'public')], check=True, capture_output=True)
        self.key = (self.root / 'public').read_text().splitlines()[1]
        stages = []
        for target, machine in TARGETS.items():
            binary = self.root / target
            contents = bytearray(64)
            contents[:6] = b'\x7fELF\x02\x01'
            contents[18:20] = machine.to_bytes(2, 'little')
            binary.write_bytes(contents)
            destination = self.root / ('stage-' + target)
            with patch('prepare_release.subprocess.check_output', return_value=json.dumps(version(target)).encode()):
                stage(binary, target, REVISION, INPUTS, destination, '0.1.0-rc.1')
            stages.append(destination)
        self.candidate = self.root / 'candidate'
        self.plan = assemble(stages, REVISION, INPUTS, '0.1.0-rc.1', self.candidate,
                             self.root / 'key', self.key)

    def test_signed_candidate_and_pinned_bootstrap(self):
        plan, names = check(self.candidate, self.key)
        self.assertEqual(plan['target_commit'], REVISION)
        self.assertEqual(plan['publication_scope'], 'linux-preview')
        self.assertEqual(plan['unsupported_clauses'], ['K22.2', 'K23.1', 'K24.1', 'K26.1', 'K29.1'])
        self.assertEqual(len(names), 8)
        bootstrap = (self.candidate / 'bootstrap.sh').read_text()
        self.assertIn(f"public_key='{self.key}'", bootstrap)
        self.assertIn('version=0.1.0-rc.1', bootstrap)

    def test_metadata_scripts_archive_and_signature_tampering_refuse(self):
        for name in ['release-plan.json', 'RELEASE_NOTES.md', 'bootstrap.sh', 'install.sh',
                     self.plan['artifacts'][0]['archive'], 'SHA256SUMS.minisig']:
            with self.subTest(name=name):
                file = self.candidate / name
                original = file.read_bytes()
                file.write_bytes(b'tampered')
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    check(self.candidate, self.key)
                file.write_bytes(original)

    def test_a_valid_signature_cannot_claim_a_broader_release_scope(self):
        # Signing authorizes bytes, not a macOS support claim. Re-sign the
        # modified metadata correctly, so failure is the scope check itself.
        plan_path = self.candidate / 'release-plan.json'
        plan = json.loads(plan_path.read_text())
        plan['publication_scope'] = 'all-platforms'
        plan_path.write_text(json.dumps(plan) + '\n')
        manifest = self.candidate / 'SHA256SUMS'
        lines = manifest.read_text().splitlines()
        manifest.write_text('\n'.join(
            (hashlib.sha256(plan_path.read_bytes()).hexdigest() + '  release-plan.json')
            if line.endswith('  release-plan.json') else line for line in lines
        ) + '\n')
        signature = self.candidate / 'SHA256SUMS.minisig'
        signature.unlink()
        subprocess.run(['minisign', '-Sm', str(manifest), '-s', str(self.root / 'key'),
                        '-x', str(signature)], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, 'invalid signed release plan'):
            check(self.candidate, self.key)

    def test_worktree_revision_and_required_ci_gates_refuse(self):
        trusted = (ROOT / 'crates/ouro-jail/dist/release.pub').read_text().splitlines()[1]
        for outputs in [['b' * 40], [REVISION, ' M file']]:
            with patch('publish_release.run', side_effect=outputs):
                with self.assertRaises(ValueError):
                    publication_gates(self.plan, trusted)
        with patch('publish_release.run', side_effect=[REVISION, '']):
            with self.assertRaisesRegex(ValueError, 'production key'):
                publication_gates(self.plan, self.key)
        runs = [{'databaseId': i, 'workflowName': name, 'status': 'completed', 'conclusion': 'success'}
                for i, name in enumerate(['rust', 'contracts', 'conformance'])]
        for bad_workflow in ['rust', 'contracts', 'conformance']:
            failed = [dict(r, conclusion='failure') if r['workflowName'] == bad_workflow else r for r in runs]
            with patch('publish_release.run', side_effect=[REVISION, '']), \
                    patch('publish_release.subprocess.run'), \
                    patch('publish_release.gh_json', side_effect=[failed, {'jobs': []}]):
                with self.assertRaises(ValueError):
                    publication_gates(self.plan, trusted)
        with patch('publish_release.run', side_effect=[REVISION, '']), \
                patch('publish_release.subprocess.run'), \
                patch('publish_release.gh_json', side_effect=[runs, {'jobs': [{'name': 'not-configured-notice', 'conclusion': 'success'}]}]):
            with self.assertRaisesRegex(ValueError, 'actually run'):
                publication_gates(self.plan, trusted)
        with patch('publish_release.run', side_effect=[REVISION, '', 'b' * 40]), \
                patch('publish_release.subprocess.run'), \
                patch('publish_release.gh_json', side_effect=[runs, {'jobs': [{'name': 'reference-host', 'conclusion': 'success'}]}]):
            with self.assertRaisesRegex(ValueError, 'immutable release tag'):
                publication_gates(self.plan, trusted)

    def test_remote_extra_missing_and_corrupted_assets_refuse(self):
        _, names = check(self.candidate, self.key)
        release = {'tag_name': self.plan['tag'], 'prerelease': True,
                   'assets': [{'id': i, 'name': name} for i, name in enumerate(names)]}
        with patch('publish_release.subprocess.check_output', side_effect=[(self.candidate / name).read_bytes() for name in names]):
            verify_remote_assets(self.plan, self.candidate, names, release)
        with patch('publish_release.subprocess.check_output', return_value=b'tampered'):
            with self.assertRaises(ValueError):
                verify_remote_assets(self.plan, self.candidate, names, release)
        for assets in [release['assets'][:-1], release['assets'] + [{'id': 9, 'name': 'surprise'}]]:
            with self.assertRaises(ValueError):
                verify_remote_assets(self.plan, self.candidate, names, dict(release, assets=assets))


if __name__ == '__main__':
    unittest.main()
