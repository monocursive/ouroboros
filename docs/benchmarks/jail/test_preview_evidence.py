import json
from pathlib import Path
import shutil
import tempfile
import unittest

from verify_preview_evidence import verify


class PreviewEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'record'
        shutil.copytree(Path(__file__).parent / 'results/release-preview-2026-10-10', self.root)
        self.result_path = self.root / 'guest/result.json'
        self.result = json.loads(self.result_path.read_text())
        self.inputs = self.result['expected_inputs']

    def write_result(self):
        self.result_path.write_text(json.dumps(self.result))

    def test_recorded_onboarding_and_learning_pass(self):
        verify(self.root, self.inputs, 'onboarding')
        verify(self.root, self.inputs, 'learning')

    def test_stale_inputs_and_slow_or_unclean_onboarding_refuse(self):
        with self.assertRaisesRegex(ValueError, 'stale build inputs'):
            verify(self.root, 'sha256:' + '0' * 64, 'learning')
        self.result['workflow_seconds'] = 600
        self.write_result()
        with self.assertRaisesRegex(ValueError, 'ten minutes'):
            verify(self.root, self.inputs, 'onboarding')
        self.result['workflow_seconds'] = 1
        self.result['rust_after']['cargo'] = '/usr/bin/cargo'
        self.write_result()
        with self.assertRaisesRegex(ValueError, 'Rust was installed'):
            verify(self.root, self.inputs, 'onboarding')

    def test_accepted_corruption_or_failed_vendor_cannot_pass_onboarding(self):
        row = next(r for r in self.result['rows'] if r['name'] == 'corrupt-archive')
        row['exit'] = 0
        self.write_result()
        with self.assertRaisesRegex(ValueError, 'was accepted'):
            verify(self.root, self.inputs, 'onboarding')
        row['exit'] = 1
        next(r for r in self.result['rows'] if r['name'] == 'opencode')['exit'] = 1
        self.write_result()
        with self.assertRaisesRegex(ValueError, 'opencode failed'):
            verify(self.root, self.inputs, 'onboarding')

    def test_a_changed_receipt_or_uncited_grant_cannot_pass_learning(self):
        path = self.root / 'guest/opencode-learn-jail.json'
        original = path.read_bytes()
        path.write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'receipt bytes'):
            verify(self.root, self.inputs, 'learning')
        path.write_bytes(original)
        proposal = self.root / 'guest/opencode-learned.toml'
        content = proposal.read_text()
        proposal.write_text(content.replace('read_only = [', 'read_only = ["/uncited/parent", ', 1))
        with self.assertRaisesRegex(ValueError, 'grant without evidence'):
            verify(self.root, self.inputs, 'learning')

    def test_rewritten_coverage_and_mixed_attempt_journals_refuse(self):
        proposal = self.root / 'guest/opencode-learned.toml'
        original = proposal.read_text()
        self.assertIn('"status":"active"', original)
        proposal.write_text(original.replace('"status":"active"', '"status":"degraded"', 1))
        with self.assertRaisesRegex(ValueError, 'coverage was rewritten'):
            verify(self.root, self.inputs, 'learning')
        proposal.write_text(original)
        trace = self.root / 'guest/opencode-learn-trace.ndjson'
        lines = trace.read_text().splitlines()
        event = json.loads(lines[0])
        event['attempt_id'] = 'att_00000000-0000-4000-8000-000000000001'
        lines[0] = json.dumps(event)
        trace.write_text('\n'.join(lines) + '\n')
        with self.assertRaisesRegex(ValueError, 'mixed attempt'):
            verify(self.root, self.inputs, 'learning')
