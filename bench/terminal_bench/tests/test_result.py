"""The result mapping, against a stream captured from a real `ouro run --stream-json`.

`fixtures/completed_stream.ndjson` and `fixtures/completed_result.json` are not written
by hand: they are the output of `bench/local/run.sh --filter 17-auto-edit --keep` on
2026-08-23, with paths left exactly as the client emitted them. That is what makes this
a test of the contract rather than a test of my idea of the contract.
"""

import json
import unittest
from pathlib import Path

from ouroboros_agent.result import UNOBSERVED, parse_stream

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class ParseCapturedStream(unittest.TestCase):
    """A real, complete turn."""

    def setUp(self):
        self.result = parse_stream(fixture("completed_stream.ndjson"), exit_code=0)

    def test_status_and_identity(self):
        self.assertEqual(self.result.status, "completed")
        self.assertEqual(self.result.exit_code, 0)
        self.assertEqual(self.result.provider, "native")
        self.assertTrue(self.result.session_id.startswith("ouro-cli-"))
        self.assertTrue(self.result.turn_id.startswith("ouro-run:"))
        self.assertIsNone(self.result.error)
        self.assertFalse(self.result.crashed)

    def test_usage_matches_the_result_object(self):
        declared = json.loads(fixture("completed_result.json"))["usage"]
        self.assertEqual(self.result.input_tokens, declared["input_tokens"])
        self.assertEqual(self.result.output_tokens, declared["output_tokens"])
        self.assertEqual(self.result.total_tokens, declared["total_tokens"])
        # cache_read + cache_creation, both zero in this run but summed, not guessed.
        self.assertEqual(self.result.cache_tokens, 0)

    def test_cost_comes_from_turn_completed_not_the_result_object(self):
        # The result object carries no cost field at all; `Native.Cost` publishes it on
        # `turn_completed`. A mapping that only read the result object would report None
        # for every run and quietly under-report a leaderboard's cost column.
        self.assertNotIn("cost_usd", json.loads(fixture("completed_result.json")))
        self.assertIsNotNone(self.result.cost_usd)
        self.assertIsInstance(self.result.cost_usd, float)

    def test_iterations_and_tools(self):
        self.assertEqual(self.result.iterations, 3)
        self.assertEqual(self.result.tool_calls, ["write", "bash"])

    def test_approvals(self):
        self.assertEqual(self.result.approvals_requested, 1)
        self.assertEqual(self.result.approvals_answered, 1)

    def test_files_changed_is_deduplicated(self):
        # `ouro run` names the same file twice: the payload's absolute path and the
        # relative path parsed out of the diff header. Harbor only sees a count, so
        # reporting two would be reporting a file that does not exist.
        raw = json.loads(fixture("completed_result.json"))["files_changed"]
        self.assertEqual(len(raw), 2)
        self.assertEqual(len(self.result.files_changed), 1)
        self.assertTrue(self.result.files_changed[0].endswith("/STAMP"))

    def test_metadata_is_json_serialisable(self):
        # It goes into `AgentContext.metadata`, which is written to result.json.
        json.dumps(self.result.as_metadata())


class ParseEdgeCases(unittest.TestCase):
    def test_an_empty_stream_is_unobserved_not_failed(self):
        result = parse_stream("", exit_code=None)
        self.assertEqual(result.status, UNOBSERVED)
        self.assertTrue(result.crashed)

    def test_an_exit_code_alone_still_names_the_status(self):
        self.assertEqual(parse_stream("", exit_code=4).status, "timeout")
        self.assertEqual(parse_stream("", exit_code=1).status, "failed")
        self.assertEqual(parse_stream("", exit_code=64).status, "refused")

    def test_an_unknown_exit_code_stays_unobserved(self):
        self.assertEqual(parse_stream("", exit_code=137).status, UNOBSERVED)

    def test_a_failed_turn_is_not_a_crash(self):
        stream = json.dumps(
            {"type": "result", "status": "failed", "error": "model call failed", "usage": {}}
        )
        result = parse_stream(stream, exit_code=1)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.error, "model call failed")
        # The task's own tests score a failed turn. It is a measurement, not an error.
        self.assertFalse(result.crashed)

    def test_a_refusal_object_is_a_crash(self):
        stream = json.dumps({"type": "error", "error": "no provider was named"})
        result = parse_stream(stream, exit_code=64)
        self.assertEqual(result.status, "refused")
        self.assertEqual(result.error, "no provider was named")
        self.assertTrue(result.crashed)

    def test_a_lost_turn_is_never_rounded_up(self):
        stream = json.dumps({"type": "result", "status": "lost", "usage": {}})
        result = parse_stream(stream, exit_code=3)
        self.assertEqual(result.status, "lost")
        self.assertTrue(result.crashed)

    def test_garbage_lines_are_skipped_not_fatal(self):
        stream = "\n".join(
            [
                "not json at all",
                "[1, 2, 3]",
                "",
                json.dumps({"type": "result", "status": "completed", "usage": {"total_tokens": 5}}),
            ]
        )
        result = parse_stream(stream, exit_code=0)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.total_tokens, 5)

    def test_missing_usage_stays_none_rather_than_zero(self):
        # A token count nobody reported is not a token count of zero, and a leaderboard
        # that averages the difference would be averaging a lie.
        result = parse_stream(json.dumps({"type": "result", "status": "completed"}), exit_code=0)
        self.assertIsNone(result.input_tokens)
        self.assertIsNone(result.output_tokens)
        self.assertIsNone(result.cache_tokens)
        self.assertIsNone(result.cost_usd)

    def test_a_relative_path_without_a_matching_absolute_survives(self):
        stream = json.dumps(
            {
                "type": "result",
                "status": "completed",
                "files_changed": ["/abs/lib/a.ex", "lib/a.ex", "docs/b.md"],
                "usage": {},
            }
        )
        result = parse_stream(stream, exit_code=0)
        self.assertEqual(result.files_changed, ["/abs/lib/a.ex", "docs/b.md"])


if __name__ == "__main__":
    unittest.main()
