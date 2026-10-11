"""Evidence acceptance regressions; no macOS libraries or live workloads."""
import copy
import json
from pathlib import Path
import unittest

from macos_mach_lifetime_summary import summarize

ROOT = Path(__file__).resolve().parent / 'results/macos-mach-lifetime-2026-10-10'


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.result = json.loads((ROOT / 'results.json').read_text())
        self.after = json.loads((ROOT / 'after-hashes.json').read_text())

    def row(self, case):
        return next(r for r in self.result['cases'] if r['case'] == case)

    def summary(self):
        return summarize(self.result, ROOT / 'tested-source', self.after)

    def reject(self):
        with self.assertRaises(ValueError):
            self.summary()

    def test_complete_evidence_preserves_counterexamples_and_positive_controls(self):
        result = self.summary()
        self.assertEqual(result['trials'], 24)
        self.assertEqual(result['owner_death_trials'], 21)
        self.assertEqual(result['owner_death_known_process_survivors'], 39)
        self.assertEqual(result['breakpoint_delivery_controls'], 3)
        self.assertFalse(result['native_execution_ready'])
        self.assertFalse(result['lifetime_contract_verified'])

    def test_readiness_claim_rejected(self):
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

    def test_changed_source_rejected(self):
        self.result['source_sha256']['macos_mach_lifetime.c'] = '0' * 64
        self.reject()

    def test_changed_binary_rejected(self):
        self.after['binary_sha256']['mach-research'] = '0' * 64
        self.reject()

    def test_absent_fatal_port_cannot_be_reported_as_available(self):
        self.result['fatal_port_size_query']['rc'] = 0
        self.reject()

    def test_false_empty_claim_rejected(self):
        self.row('fork')['fixture_empty_before_runner_cleanup'] = True
        self.reject()

    def test_runner_cleanup_cannot_replace_before_cleanup_snapshot(self):
        row = self.row('fork')
        row['after'] = copy.deepcopy(row['after_runner_cleanup'])
        self.reject()

    def test_dead_handler_inspection_missing_rejected(self):
        row = self.row('fork')
        row['workload_events'] = [r for r in row['workload_events'] if r.get('phase') != 'after_owner_loss']
        self.reject()

    def test_child_without_inherited_handler_rejected(self):
        event = next(r for r in self.row('spawn-session')['workload_events']
                     if r.get('role') == 'late-child' and r.get('phase') == 'before_owner_loss')
        event['live_mask'] = 0
        self.reject()

    def test_live_control_without_delivered_exception_rejected(self):
        row = self.row('breakpoint-control')
        row['custodian_events'] = [r for r in row['custodian_events'] if r.get('kind') != 'exception_message']
        self.reject()

    def test_breakpoint_cannot_be_counted_as_owner_death(self):
        row = self.row('breakpoint-control')
        row['custodian_after'] = copy.deepcopy(row['after_runner_cleanup']['root'])
        self.reject()

    def test_removal_without_proof_of_initial_handler_rejected(self):
        row = self.row('clear-exception')
        row['workload_events'] = [r for r in row['workload_events'] if r.get('phase') != 'before_clear']
        self.reject()

    def test_survivor_without_work_progress_rejected(self):
        row = self.row('fork')
        row['heartbeat_after'] = copy.deepcopy(row['heartbeat_before'])
        self.reject()

    def test_snapshot_identity_tamper_rejected(self):
        self.row('fork')['after']['late-child']['uniqueid'] += 1
        self.reject()


if __name__ == '__main__':
    unittest.main()
