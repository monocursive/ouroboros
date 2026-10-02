"""Damaged benchmark evidence must never produce a winner."""
import hashlib
import json
from pathlib import Path
import unittest

from summarize import evaluate


class EvidenceIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).parent / "results/2026-09-30/linux"
        cls.metadata = json.loads((cls.root / "metadata.json").read_text())
        cls.status = json.loads((cls.root / "performance-status.json").read_text())
        cls.complete = json.loads((cls.root / "complete.json").read_text())
        cls.raw = (cls.root / "launches.ndjson").read_bytes()

    def damaged(self, change):
        rows = [json.loads(line) for line in self.raw.splitlines()]
        change(rows)
        raw = b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"
        complete = self.complete | {"launches_sha256": hashlib.sha256(raw).hexdigest()}
        return evaluate(self.metadata, self.status, complete, raw)

    def test_recorded_run_validates(self):
        result = evaluate(self.metadata, self.status, self.complete, self.raw)
        self.assertTrue(result["valid"], result["problems"])
        self.assertEqual(len(result["comparisons"]), 7)

    def test_failed_payload_cannot_win(self):
        result = self.damaged(lambda rows: next(r for r in rows if r["phase"] == "measurement").update(exit=1))
        self.assertFalse(result["valid"])
        self.assertEqual(result["comparisons"], [])

    def test_wrong_completed_work_cannot_win(self):
        def change(rows):
            next(r for r in rows if r["phase"] == "measurement")["records"][0]["count"] = -1
        self.assertFalse(self.damaged(change)["valid"])

    def test_missing_and_duplicate_samples_cannot_win(self):
        self.assertFalse(self.damaged(lambda rows: rows.pop(next(i for i, r in enumerate(rows) if r["phase"] == "measurement")))["valid"])
        self.assertFalse(self.damaged(lambda rows: rows.append(next(r for r in rows if r["phase"] == "measurement")))["valid"])

    def test_missing_or_degraded_receipt_cannot_win(self):
        def remove(rows):
            next(r for r in rows if r["phase"] == "measurement" and r["tool"] == "ouro-jail").pop("receipt")
        self.assertFalse(self.damaged(remove)["valid"])

    def test_modified_bytes_cannot_win(self):
        result = evaluate(self.metadata, self.status, self.complete, self.raw + b"\n")
        self.assertFalse(result["valid"])

    def test_modified_binary_cannot_win(self):
        complete = self.complete | {"binary_sha256_after": "0" * 64}
        self.assertFalse(evaluate(self.metadata, self.status, complete, self.raw)["valid"])


if __name__ == "__main__":
    unittest.main()
