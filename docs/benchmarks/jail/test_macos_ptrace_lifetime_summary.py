"""Evidence acceptance regressions; no macOS libraries or live workloads."""
import copy
import json
from pathlib import Path
import unittest

from macos_ptrace_lifetime_summary import summarize

ROOT = Path(__file__).resolve().parent / 'results/macos-ptrace-lifetime-2026-10-10'


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.result = json.loads((ROOT / 'results.json').read_text())
        self.after = json.loads((ROOT / 'after-hashes.json').read_text())

    def summary(self):
        return summarize(self.result, ROOT / 'tested-source', self.after)

    def row(self, case):
        return next(row for row in self.result['cases'] if row['case'] == case)

    def reject(self):
        with self.assertRaises(ValueError):
            self.summary()

    def test_complete_evidence_preserves_successes_and_counterexamples(self):
        summary = self.summary()
        self.assertEqual(summary['trials'], 80)
        self.assertFalse(summary['native_execution_ready'])
        self.assertFalse(summary['lifetime_contract_verified'])
        self.assertEqual(summary['cases']['registered_death']['known_fixture_empty'], 10)
        for case in summary['cases']:
            if case != 'registered_death':
                self.assertEqual(summary['cases'][case]['known_fixture_empty'], 0)

    def test_production_readiness_claim_rejected(self):
        self.result['native_execution_ready'] = True
        self.reject()

    def test_full_lifetime_claim_rejected(self):
        self.result['lifetime_contract_verified'] = True
        self.reject()

    def test_missing_trial_rejected(self):
        self.result['cases'].pop()
        self.reject()

    def test_duplicate_trial_rejected(self):
        self.result['cases'][-1] = copy.deepcopy(self.result['cases'][0])
        self.reject()

    def test_missing_source_inventory_rejected(self):
        self.result['source_sha256'] = {}
        self.after['source_sha256'] = {}
        self.reject()

    def test_changed_tested_source_rejected(self):
        self.result['source_sha256']['macos_ptrace_lifetime.c'] = '0' * 64
        self.reject()

    def test_changed_measured_binary_rejected(self):
        self.after['binary_sha256']['ptrace-research'] = '0' * 64
        self.reject()

    def test_ordinary_user_results_cannot_be_presented_as_root_control(self):
        self.result['actor_uid'] = self.result['actor_euid'] = 501
        self.reject()

    def test_runner_cleanup_cannot_be_counted_as_kernel_lifetime(self):
        row = self.row('fork')
        row['after'] = copy.deepcopy(row['after_runner_cleanup'])
        row['fixture_empty_before_runner_cleanup'] = True
        self.reject()

    def test_snapshot_of_different_process_rejected(self):
        self.row('fork')['after']['late-child']['uniqueid'] += 1
        self.reject()

    def test_falsified_death_snapshot_rejected(self):
        self.row('registered_stop')['after']['root']['alive'] = False
        self.reject()

    def test_audit_token_identity_mismatch_rejected(self):
        self.row('fork')['fixture_processes'][-1]['audit_token'][7] += 1
        self.reject()

    def test_failed_registration_rejected(self):
        self.row('fork')['attach_events'][0]['rc'] = -1
        self.reject()

    def test_tracer_readiness_missing_rejected(self):
        self.row('fork')['tracer_events'].pop()
        self.reject()

    def test_survivor_without_executed_work_rejected(self):
        row = self.row('fork')
        row['heartbeat_after'] = copy.deepcopy(row['heartbeat_before'])
        self.reject()

    def test_missing_deny_attach_counterexample_rejected(self):
        self.row('deny-attach')['workload_events'] = []
        self.reject()

    def test_unverified_emergency_cleanup_rejected(self):
        self.row('fork')['cleanup_verified'] = False
        self.reject()


if __name__ == '__main__':
    unittest.main()
