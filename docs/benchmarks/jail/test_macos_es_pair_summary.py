"""Evidence acceptance regressions; no macOS libraries or live workloads."""
import copy
import json
from pathlib import Path
import unittest

from macos_es_pair_summary import summarize

ROOT = Path(__file__).resolve().parent / "results/macos-es-pair-2026-09-30"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.result = json.loads((ROOT / "auth/results.json").read_text())
        self.after = json.loads((ROOT / "after-hashes.json").read_text())["auth"]

    def summary(self):
        return summarize(self.result, ROOT / "auth/tested-source", self.after)

    def row(self, case):
        return next(row for row in self.result["cases"] if row["case"] == case)

    def test_complete_evidence_never_claims_execution_ready(self):
        result = self.summary()
        self.assertEqual(result["trials"], 100)
        self.assertFalse(result["native_execution_ready"])
        self.assertEqual(result["cases"]["both_death"]["exec_probe"]["markers_created"], 10)

    def test_missing_trial_rejected(self):
        self.result["cases"].pop()
        with self.assertRaises(ValueError): self.summary()

    def test_duplicate_trial_rejected(self):
        self.result["cases"][-1] = copy.deepcopy(self.result["cases"][0])
        with self.assertRaises(ValueError): self.summary()

    def test_changed_source_rejected(self):
        self.result["source_sha256"]["macos_es_pair.c"] = "0" * 64
        with self.assertRaises(ValueError): self.summary()

    def test_changed_helper_rejected(self):
        self.after["helper_sha256"] = "0" * 64
        with self.assertRaises(ValueError): self.summary()

    def test_spawn_success_with_killed_child_does_not_mean_exec_success(self):
        probe = self.row("guardian_stop")["exec_probe"]
        self.assertEqual(probe["spawn_errno"], 0)
        self.assertEqual(probe["wait_status"], 9)
        self.assertFalse(probe["marker_created"])
        self.summary()

    def test_completed_paused_client_probe_rejected(self):
        self.row("guardian_stop")["exec_probe"]["marker_created"] = True
        with self.assertRaises(ValueError): self.summary()

    def test_missing_independent_observation_rejected(self):
        self.row("ward_death")["ward_events"] = []
        with self.assertRaises(ValueError): self.summary()

    def test_false_tree_empty_claim_rejected(self):
        self.row("both_death")["fixture_tree_empty_before_runner_cleanup"] = True
        with self.assertRaises(ValueError): self.summary()

    def test_inherited_custody_descriptor_rejected(self):
        self.row("wall")["fixture_processes"][0]["custody_fds_open"] = True
        with self.assertRaises(ValueError): self.summary()

    def test_production_support_claim_rejected(self):
        self.result["production_execution_enabled"] = True
        with self.assertRaises(ValueError): self.summary()


if __name__ == "__main__":
    unittest.main()
