"""The trajectory a reviewer reads.

Harbor's own interchange format is **ATIF** (`schema_version: "ATIF-v1.7"` at the time
this was written), and an agent that emits it sets `SUPPORTS_ATIF = True`. This adapter
does **not** claim ATIF conformance, and that is a decision rather than an omission: the
schema was not available to validate against while this was written, and a file labelled
`ATIF-v1.7` that has never been checked against the v1.7 models is worse than an
unlabelled file — it is a claim nobody verified, which is exactly what this repository's
docs promise not to ship.

So two files are written, and the README says which is which:

  * `trajectory.ndjson` — the raw `ouro run --stream-json` output, byte for byte. This is
    the trajectory of record. It is the golden-pinned event contract (`docs/TUI.md` §2.5),
    not a rendering of it, so nothing can drift between what the runtime published and
    what a reviewer reads.
  * `trajectory.json` — the summary below: steps, tools, and totals, in an obviously
    Ouroboros-shaped schema that says so in its own `schema` field.

Converting to ATIF is a small job for whoever runs the first submission, against the
`harbor.models.trajectories` models of the version they install.
"""

from __future__ import annotations

import json

SCHEMA = "ouroboros-run-stream/1"

#: A trajectory is a review artifact, not a log dump. Tool output is what makes these
#: files enormous, so it is clipped and the clip is stated.
MAX_TEXT = 4000
MAX_STEPS = 2000


def build_trajectory(stdout: str, instruction: str, model_spec: str | None = None) -> dict:
    """Summarise one run's NDJSON into a reviewable object."""
    steps: list[dict] = []
    totals = {"tool_calls": 0, "tool_errors": 0, "approvals": 0}
    result: dict | None = None
    truncated = False

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
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}

        if kind == "result":
            result = event
            continue

        if len(steps) >= MAX_STEPS:
            truncated = True
            continue

        if kind == "tool_call":
            totals["tool_calls"] += 1
            steps.append(
                {
                    "kind": "tool_call",
                    "sequence": event.get("sequence"),
                    "timestamp": event.get("timestamp"),
                    "call_id": payload.get("call_id"),
                    "name": payload.get("name"),
                    "input": _clip_value(payload.get("input")),
                }
            )
        elif kind == "tool_result":
            if payload.get("is_error") is True:
                totals["tool_errors"] += 1
            steps.append(
                {
                    "kind": "tool_result",
                    "sequence": event.get("sequence"),
                    "timestamp": event.get("timestamp"),
                    "call_id": payload.get("call_id"),
                    "name": payload.get("name"),
                    "is_error": payload.get("is_error"),
                    "output": _clip(payload.get("output")),
                }
            )
        elif kind == "output_text_final":
            steps.append(
                {
                    "kind": "assistant_text",
                    "sequence": event.get("sequence"),
                    "timestamp": event.get("timestamp"),
                    "text": _clip(payload.get("text")),
                }
            )
        elif kind == "approval_requested":
            totals["approvals"] += 1
            steps.append(
                {
                    "kind": "approval_requested",
                    "sequence": event.get("sequence"),
                    "timestamp": event.get("timestamp"),
                    "approval_kind": payload.get("kind"),
                    "payload": _clip_value(payload),
                }
            )
        elif kind in ("plan_updated", "turn_failed", "session_failed"):
            steps.append(
                {
                    "kind": kind,
                    "sequence": event.get("sequence"),
                    "timestamp": event.get("timestamp"),
                    "payload": _clip_value(payload),
                }
            )

    return {
        "schema": SCHEMA,
        "note": (
            "Not ATIF. The raw stream in trajectory.ndjson is the trajectory of record; "
            "this file is a summary of it."
        ),
        "agent": "ouroboros",
        "model": model_spec,
        "instruction": _clip(instruction),
        "steps": steps,
        "steps_truncated": truncated,
        "totals": totals,
        "result": result,
    }


def _clip(value) -> str | None:
    if not isinstance(value, str):
        return None
    if len(value) <= MAX_TEXT:
        return value
    return value[:MAX_TEXT] + f"\n… clipped, {len(value) - MAX_TEXT} more characters"


def _clip_value(value):
    """Clip every string inside a small structure, bounded in depth as well as width."""
    return _clip_depth(value, 0)


def _clip_depth(value, depth: int):
    if depth > 4:
        return "… nested past depth 4"
    if isinstance(value, str):
        return _clip(value)
    if isinstance(value, dict):
        return {key: _clip_depth(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_clip_depth(item, depth + 1) for item in value[:100]]
    return value
