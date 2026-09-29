"""Exercise K17 verdicts with the recorded J5 run and damaged copies of it."""
import copy
import json
from pathlib import Path
import unittest

from performance import evaluate


class PerformanceVerdict(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / "specs/jail-v1/evidence/perf-2026-09-25-ouro-ci/summary.json"
        cls.recorded = json.loads(path.read_text())

    def setUp(self):
        self.summary = copy.deepcopy(self.recorded)
        self.cell = next(c for c in self.summary["comparisons"]
                         if c["profile"] == "tool" and c["kind"] == "off_vs_direct")

    def test_recorded_run_meets_the_stated_k17_limits(self):
        self.assertEqual(evaluate(self.summary)["verdict"], "pass")

    def test_missing_and_duplicate_cells_withhold_a_verdict(self):
        self.summary["comparisons"].remove(self.cell)
        self.assertEqual(evaluate(self.summary)["verdict"], "unverified")
        self.summary["comparisons"].extend([self.cell, self.cell])
        self.assertEqual(evaluate(self.summary)["verdict"], "unverified")

    def test_excluded_or_insufficient_samples_withhold_a_verdict(self):
        self.cell["subject_excluded"] = 1
        self.assertEqual(evaluate(self.summary)["verdict"], "unverified")
        self.cell.update(subject_excluded=0, baseline_valid=29)
        self.assertEqual(evaluate(self.summary)["verdict"], "unverified")

    def test_loaded_or_unbounded_runs_withhold_a_verdict(self):
        for threshold in (0, None):
            self.summary["gate"]["max_load"] = threshold
            self.assertEqual(evaluate(self.summary)["verdict"], "unverified")

    def test_shortened_fixtures_cannot_pass(self):
        self.summary["parameters"]["fileops_rounds"] = 1
        self.assertEqual(evaluate(self.summary)["verdict"], "unverified")

    def test_missing_warmup_or_broken_integrity_cannot_pass(self):
        self.summary["parameters"]["warmup"] = 0
        self.assertEqual(evaluate(self.summary)["verdict"], "unverified")
        self.summary["parameters"]["warmup"] = 1
        self.summary["gate"]["integrity_ok"] = False
        self.assertEqual(evaluate(self.summary)["verdict"], "unverified")

    def test_startup_limit_is_exclusive(self):
        self.cell["added_startup_ms"]["p95"] = 500
        self.assertEqual(evaluate(self.summary)["verdict"], "fail")

    def test_post_start_limit_is_inclusive(self):
        cell = next(c for c in self.summary["comparisons"] if c["profile"] == "tool"
                    and c["kind"] == "off_vs_direct" and c["workload"] == "fileops")
        cell["post_start_overhead_pct"]["median"] = 100
        self.assertEqual(evaluate(self.summary)["verdict"], "pass")
        cell["post_start_overhead_pct"]["median"] = 100.01
        self.assertEqual(evaluate(self.summary)["verdict"], "fail")


if __name__ == "__main__":
    unittest.main()
