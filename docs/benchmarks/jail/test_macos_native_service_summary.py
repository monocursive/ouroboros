"""Portable tamper regressions for native-service research; no live workloads."""
import copy
import json
from pathlib import Path
import unittest

from macos_native_service_summary import xpc_summary, recovery_summary

BASE = Path(__file__).resolve().parent / 'results'


class XPCEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.root = BASE / 'macos-xpc-lifetime-2026-10-10/private-session'
        self.result = json.loads((self.root / 'results.json').read_text())
        self.after = json.loads((self.root / 'after-hashes.json').read_text())

    def summary(self):
        return xpc_summary(self.result, self.root / 'tested-source', self.after)

    def reject(self):
        with self.assertRaises(ValueError):
            self.summary()

    def test_both_sessions_and_long_observations_preserve_survivors(self):
        for lane, trials in [('private-session', 15), ('shared-session', 15), ('long-observation', 2)]:
            p = self.root.parent / lane
            summary = xpc_summary(json.loads((p / 'results.json').read_text()), p / 'tested-source',
                                  json.loads((p / 'after-hashes.json').read_text()))
            self.assertEqual(summary['trials'], trials)
            self.assertEqual(summary['known_workload_survivors'], trials * 7)
            self.assertEqual(summary['post_fault_exec_controls'], trials)
            self.assertFalse(summary['native_execution_ready'])
            self.assertFalse(summary['lifetime_contract_verified'])

    def test_readiness_claim_rejected(self):
        self.result['native_execution_ready'] = True; self.reject()

    def test_lifetime_claim_rejected(self):
        self.result['lifetime_contract_verified'] = True; self.reject()

    def test_missing_case_rejected(self):
        self.result['cases'].pop(); self.reject()

    def test_duplicate_case_rejected(self):
        self.result['cases'][-1] = copy.deepcopy(self.result['cases'][0]); self.reject()

    def test_source_mismatch_rejected(self):
        self.result['source_sha256']['macos_xpc_lifetime.c'] = '0' * 64; self.reject()

    def test_binary_mismatch_rejected(self):
        self.after['binary_sha256']['worker'] = '0' * 64; self.reject()

    def test_ad_hoc_signature_cannot_be_claimed_as_approved_profile(self):
        self.result['signing']['approved_profile'] = True; self.reject()

    def test_launchservices_scope_missing_rejected(self):
        self.result['launch_services'] = False; self.reject()

    def test_wrong_audit_session_rejected(self):
        row = self.result['cases'][0]
        row['anchors']['service']['audit_token'][6] = row['anchors']['host']['audit_token'][6]; self.reject()

    def test_coalition_escape_rejected(self):
        self.result['cases'][0]['fixture_processes'][0]['coalitions'][0] += 1; self.reject()

    def test_live_service_cannot_be_reported_as_os_cleanup(self):
        row = self.result['cases'][0]
        row['anchors_after']['service'] = copy.deepcopy(row['anchors']['service'])
        row['anchors_after']['service'].update(same_process=True, alive=True); self.reject()

    def test_runner_cleanup_cannot_substitute_for_fault_result(self):
        row = self.result['cases'][0]
        row['after'] = {k: v for k, v in row['after_runner_cleanup'].items() if k not in ('host', 'service')}
        self.reject()

    def test_heartbeat_progress_missing_rejected(self):
        row = self.result['cases'][0]; row['heartbeat_after'] = copy.deepcopy(row['heartbeat_before']); self.reject()

    def test_new_execution_control_missing_rejected(self):
        self.result['cases'][0]['exec_marker_created'] = False; self.reject()

    def test_short_observation_rejected(self):
        self.result['cases'][0]['observation_ms'] = 500; self.reject()


class RecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.root = BASE / 'macos-launchd-recovery-2026-10-10/formal'
        self.result = json.loads((self.root / 'results.json').read_text())
        self.after = json.loads((self.root / 'after-hashes.json').read_text())

    def summary(self):
        return recovery_summary(self.result, self.root / 'tested-source', self.after)

    def reject(self):
        with self.assertRaises(ValueError):
            self.summary()

    def row(self, case):
        return next(r for r in self.result['cases'] if r['case'] == case)

    def test_crash_recovery_controls_do_not_qualify_native_lifetime(self):
        summary = self.summary()
        self.assertEqual(summary['known_crash_recovery_controls'], 3)
        self.assertEqual(summary['paused_custodian_survivors'], 21)
        self.assertFalse(summary['native_execution_ready'])
        self.assertFalse(summary['lifetime_contract_verified'])

    def test_readiness_claim_rejected(self):
        self.result['native_execution_ready'] = True; self.reject()

    def test_closed_set_recovery_cannot_claim_tree_lifetime(self):
        self.row('custodian-death')['recovery']['lifetime_contract_verified'] = True; self.reject()

    def test_restart_generation_missing_rejected(self):
        self.row('custodian-death')['custodians'].pop(); self.reject()

    def test_recovery_completion_missing_rejected(self):
        self.row('custodian-death')['recovery'] = None; self.reject()

    def test_stop_survivors_cannot_be_replaced_with_runner_cleanup(self):
        row = self.row('custodian-stop')
        row['after'] = {r['role']: row['after_runner_cleanup'][r['role'] + ':' + str(r['uniqueid'])]
                        for r in row['fixture_processes']}; self.reject()

    def test_stopped_custodian_must_be_observed(self):
        self.row('custodian-stop')['custodian_after']['status'] = 2; self.reject()

    def test_missing_trial_rejected(self):
        self.result['cases'].pop(); self.reject()

    def test_changed_binary_rejected(self):
        self.after['binary_sha256']['native-fixture'] = '0' * 64; self.reject()

    def test_snapshot_identity_tamper_rejected(self):
        self.row('custodian-death')['recovery']['after']['root']['pid'] += 1; self.reject()


if __name__ == '__main__':
    unittest.main()
