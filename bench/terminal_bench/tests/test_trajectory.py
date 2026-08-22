"""The trajectory summary, against the same captured stream."""

import json
import unittest
from pathlib import Path

from ouroboros_agent.trajectory import MAX_TEXT, SCHEMA, build_trajectory

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class BuildFromCapturedStream(unittest.TestCase):
    def setUp(self):
        stream = (FIXTURES / "completed_stream.ndjson").read_text(encoding="utf-8")
        self.trajectory = build_trajectory(stream, "add a build stamp", "anthropic:x")

    def test_it_does_not_claim_to_be_atif(self):
        # Labelling an unvalidated file ATIF-v1.7 would be a claim nobody checked.
        self.assertEqual(self.trajectory["schema"], SCHEMA)
        self.assertIn("Not ATIF", self.trajectory["note"])
        self.assertNotIn("ATIF-v", self.trajectory["schema"])

    def test_tool_calls_and_results_are_paired_by_call_id(self):
        calls = {s["call_id"]: s for s in self.trajectory["steps"] if s["kind"] == "tool_call"}
        results = {s["call_id"]: s for s in self.trajectory["steps"] if s["kind"] == "tool_result"}
        self.assertEqual(set(calls), set(results))
        self.assertEqual({c["name"] for c in calls.values()}, {"write", "bash"})

    def test_the_approval_is_recorded(self):
        approvals = [s for s in self.trajectory["steps"] if s["kind"] == "approval_requested"]
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["approval_kind"], "command")
        self.assertEqual(self.trajectory["totals"]["approvals"], 1)

    def test_totals(self):
        self.assertEqual(self.trajectory["totals"]["tool_calls"], 2)
        self.assertEqual(self.trajectory["totals"]["tool_errors"], 0)

    def test_the_result_object_is_carried_verbatim(self):
        self.assertEqual(self.trajectory["result"]["type"], "result")
        self.assertEqual(self.trajectory["result"]["status"], "completed")

    def test_it_is_serialisable(self):
        json.dumps(self.trajectory)

    def test_steps_are_in_stream_order(self):
        sequences = [s["sequence"] for s in self.trajectory["steps"] if s["sequence"] is not None]
        self.assertEqual(sequences, sorted(sequences))


class Bounds(unittest.TestCase):
    def test_long_tool_output_is_clipped_and_says_so(self):
        stream = json.dumps(
            {
                "type": "tool_result",
                "sequence": 1,
                "payload": {"name": "bash", "call_id": "c1", "output": "x" * 50_000},
            }
        )
        trajectory = build_trajectory(stream, "run it")
        output = trajectory["steps"][0]["output"]
        self.assertLess(len(output), 50_000)
        self.assertIn("clipped", output)
        self.assertTrue(output.startswith("x" * MAX_TEXT))

    def test_a_deeply_nested_input_is_bounded(self):
        deep = {"a": {"b": {"c": {"d": {"e": {"f": "too far"}}}}}}
        stream = json.dumps(
            {"type": "tool_call", "sequence": 1, "payload": {"name": "t", "call_id": "c", "input": deep}}
        )
        trajectory = build_trajectory(stream, "x")
        rendered = json.dumps(trajectory["steps"][0]["input"])
        self.assertIn("nested past depth 4", rendered)

    def test_a_stream_with_no_result_still_produces_a_trajectory(self):
        trajectory = build_trajectory("", "nothing happened")
        self.assertEqual(trajectory["steps"], [])
        self.assertIsNone(trajectory["result"])
        self.assertEqual(trajectory["totals"]["tool_calls"], 0)


if __name__ == "__main__":
    unittest.main()
