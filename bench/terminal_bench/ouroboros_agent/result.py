"""Reading `ouro run --stream-json` and mapping it onto what Harbor asks for.

The contract this parses is the one `tui/src/run.rs` publishes and `docs/TUI.md` §3.1
documents: one JSON object per normalised event, then exactly one
`{"type": "result", …}` object. Under a refusal there is instead a
`{"type": "error", …}` object. Nothing here invents a field the client did not send.

**Success is not ours to decide.** Terminal-Bench scores a trial by running the task's
own `tests/test.sh` in the container after the agent stops. This module never reports
pass or fail — it reports what the run cost and whether the client crashed, which is all
an agent is entitled to say about itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

#: Exit codes `ouro run` documents. Anything else is the client failing to start.
EXIT_STATUS = {
    0: "completed",
    1: "failed",
    2: "interrupted",
    3: "lost",
    4: "timeout",
    64: "refused",
}

#: A turn that produced no result object at all. Deliberately not "failed": not knowing
#: is a different thing from knowing it went wrong, and rounding one to the other is how
#: benchmark numbers stop meaning anything.
UNOBSERVED = "unobserved"


@dataclass
class OuroRunResult:
    """One `ouro run` invocation, as the adapter understands it."""

    status: str = UNOBSERVED
    exit_code: int | None = None
    session_id: str | None = None
    turn_id: str | None = None
    provider: str | None = None
    node: str | None = None
    error: str | None = None
    duration_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_tokens: int | None = None
    total_tokens: int | None = None
    cost_usd: float | None = None
    iterations: int | None = None
    files_changed: list[str] = field(default_factory=list)
    approvals_requested: int = 0
    approvals_answered: int = 0
    tool_calls: list[str] = field(default_factory=list)
    event_count: int = 0

    @property
    def crashed(self) -> bool:
        """Whether the client itself failed, as opposed to the turn going badly.

        A `failed` turn is a normal outcome — the model gave up, a tool refused — and the
        task's tests will say what it was worth. `lost`, `refused` and an unparseable run
        are the cases where the adapter, not the agent, is what went wrong.
        """
        return self.status in {UNOBSERVED, "lost", "refused"}

    def as_metadata(self) -> dict:
        """Everything Harbor has nowhere else to put, for `AgentContext.metadata`."""
        return {
            "ouro_status": self.status,
            "ouro_exit_code": self.exit_code,
            "ouro_session_id": self.session_id,
            "ouro_turn_id": self.turn_id,
            "ouro_provider": self.provider,
            "ouro_node": self.node,
            "ouro_error": self.error,
            "ouro_duration_ms": self.duration_ms,
            "ouro_iterations": self.iterations,
            "ouro_total_tokens": self.total_tokens,
            "ouro_files_changed": len(self.files_changed),
            "ouro_approvals_requested": self.approvals_requested,
            "ouro_approvals_answered": self.approvals_answered,
            "ouro_tool_calls": len(self.tool_calls),
            "ouro_tools_used": sorted(set(self.tool_calls)),
            "ouro_events": self.event_count,
        }


def parse_stream(stdout: str, exit_code: int | None = None) -> OuroRunResult:
    """Fold an NDJSON stream into one result.

    Tolerant on the way in and strict about what it claims: a line that is not JSON is
    skipped rather than raising, because the run is over by the time this is called and
    losing the numbers to a stray line would be the worse failure. What it never does is
    guess — a field the stream did not carry stays `None`.
    """
    result = OuroRunResult(exit_code=exit_code)

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(event, dict):
            continue

        kind = event.get("type")
        if kind == "result":
            _fold_result(result, event)
        elif kind == "error":
            result.status = "refused"
            result.error = _text(event.get("error"))
        elif kind == "tool_call":
            name = (event.get("payload") or {}).get("name")
            if isinstance(name, str):
                result.tool_calls.append(name)
            result.event_count += 1
        elif kind == "turn_completed":
            _fold_turn(result, event.get("payload") or {})
            result.event_count += 1
        else:
            result.event_count += 1

    if result.status == UNOBSERVED and exit_code is not None:
        # The stream said nothing but the process still has an opinion; an exit code the
        # client documents is better evidence than nothing at all.
        named = EXIT_STATUS.get(exit_code)
        if named:
            result.status = named

    return result


def _fold_result(result: OuroRunResult, event: dict) -> None:
    result.status = _text(event.get("status")) or result.status
    result.session_id = _text(event.get("session_id"))
    result.turn_id = _text(event.get("turn_id"))
    result.provider = _text(event.get("provider"))
    result.node = _text(event.get("node"))
    result.error = _text(event.get("error")) or result.error
    result.duration_ms = _int(event.get("duration_ms"))

    usage = event.get("usage")
    if isinstance(usage, dict):
        result.input_tokens = _int(usage.get("input_tokens"))
        result.output_tokens = _int(usage.get("output_tokens"))
        result.total_tokens = _int(usage.get("total_tokens"))
        cached = [
            _int(usage.get("cache_read_tokens")),
            _int(usage.get("cache_creation_tokens")),
        ]
        present = [value for value in cached if value is not None]
        result.cache_tokens = sum(present) if present else None

    files = event.get("files_changed")
    if isinstance(files, list):
        # `ouro run` names one changed file twice — the payload's absolute path and the
        # relative path parsed out of the diff header. Harbor only ever sees a count, so
        # deduplicating here is the difference between "one file" and "two".
        seen: list[str] = []
        for entry in files:
            if isinstance(entry, str) and entry not in seen:
                seen.append(entry)
        result.files_changed = _collapse_paths(seen)

    approvals = event.get("approvals")
    if isinstance(approvals, dict):
        result.approvals_requested = _int(approvals.get("requested")) or 0
        result.approvals_answered = _int(approvals.get("answered")) or 0


def _fold_turn(result: OuroRunResult, payload: dict) -> None:
    # Cost is on `turn_completed`, not on the result object: `Native.Cost` computes it
    # from `llm_db` pricing rather than trusting a provider, and it is published as an
    # event like everything else.
    cost = payload.get("cost_usd")
    if isinstance(cost, (int, float)):
        result.cost_usd = float(cost)
    result.iterations = _int(payload.get("iterations")) or result.iterations


def _collapse_paths(paths: list[str]) -> list[str]:
    """Drop a relative path that some absolute path in the same list already ends with."""
    absolutes = [path for path in paths if path.startswith("/")]
    kept = list(absolutes)
    for path in paths:
        if path.startswith("/"):
            continue
        if any(absolute.endswith("/" + path) or absolute.endswith(path) for absolute in absolutes):
            continue
        kept.append(path)
    return kept


def _text(value) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None
