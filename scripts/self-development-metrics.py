#!/usr/bin/env python3
"""Collect and evaluate bounded Ouroboros self-development benchmark telemetry."""

import argparse
import collections
import datetime as dt
import json
import os
import re
import sys
from typing import Any

TOKEN_FIELDS = ("input_tokens", "cache_read_tokens", "output_tokens")
AGGREGATE_TYPES = {"turn_completed", "run_completed", "session_completed", "summary"}


def load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_actions(path: str) -> list:
    """Load either the documented JSON action log or a retained NDJSON export."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        actions = []
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                action = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid supervisor-action NDJSON at line %d: %s" % (line_no, exc)) from exc
            if not isinstance(action, dict):
                raise ValueError("supervisor-action NDJSON line %d is not an object" % line_no)
            actions.append(action)
        return actions
    actions = document.get("actions", document) if isinstance(document, dict) else document
    if not isinstance(actions, list):
        raise ValueError("supervisor actions must be JSON/NDJSON objects or a JSON actions array")
    return actions


def payload(event: dict) -> dict:
    value = event.get("payload", {})
    return value if isinstance(value, dict) else {}


def event_type(event: dict) -> str:
    return str(event.get("type", event.get("event", event.get("kind", "")))).lower()


def parse_time(value: Any):
    if not isinstance(value, str):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalize_error(data: dict) -> str:
    text = " ".join(str(data.get(k, "")) for k in ("reason", "error", "output", "message")).lower()
    structured = str(data.get("reason", data.get("error_class", ""))).lower()
    rules = (
        ("timeout", r"timed?_?out|timeout|deadline"),
        ("sandbox_environment", r"nested.*sandbox|sandbox.*(unavailable|backend|operation not permitted)"),
        ("permission_denied", r"permission|denied|not permitted|approval.*(declin|refus)"),
        ("invalid_argument", r"invalid[_ ]?(argument|args|input)|bad request"),
        ("not_found", r"not[_ ]found|no such file|enoent"),
        ("environment", r"environment|prerequisite|unsupported host|connection refused"),
        ("cancelled", r"cancelled|canceled|interrupt"),
    )
    probe = structured + " " + text
    for name, pattern in rules:
        if re.search(pattern, probe):
            return name
    return structured or "tool_error"


def read_events(path: str):
    events, duplicates, malformed = [], 0, []
    seen = set()
    with open(path, encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event is not an object")
            except (json.JSONDecodeError, ValueError) as exc:
                malformed.append({"line": line_no, "error": str(exc)})
                continue
            session = event.get("session_id", event.get("session"))
            sequence = event.get("sequence", event.get("seq"))
            if session is not None and sequence is not None:
                key = (str(session), str(sequence))
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
            events.append(event)
    return events, duplicates, malformed


def collect(events_path: str, actions_path: str) -> dict:
    events, duplicate_events, malformed = read_events(events_path)
    actions = load_actions(actions_path)

    report = {
        "schema_version": 1,
        "source": {"events": events_path, "supervisor_actions": actions_path},
        "event_integrity": {"retained_events": len(events), "duplicate_replays_ignored": duplicate_events, "malformed": malformed},
        "metadata": {},
        "tool_calls": {"total": 0, "failed": 0, "by_name": {}, "normalized_errors": {}, "unchanged_retries": 0, "repeated_commands": 0},
        "read_scope": {"unique_files": [], "file_count": 0, "broad_reads": 0, "events_with_missing_path": 0},
        "questions": {"asked": 0, "answered": 0, "declined": 0, "unresolved": 0},
        "usage": {"input_tokens": 0, "cached_input_tokens": 0, "non_cached_input_tokens": 0, "output_tokens": 0, "usage_events": 0, "aggregate_turn_totals_ignored": 0, "missing_counters": {}},
        "context": {"max_utilization": None, "samples": 0, "compactions": 0, "handoffs": 0},
        "supervision": {"total": len(actions), "by_type": {}, "actions": actions},
        "wall_time_seconds": None,
        "telemetry_missing": [],
        "findings": [],
    }
    calls, pending_questions, reads, command_counts = {}, {}, set(), collections.Counter()
    previous_call = None
    non_cached_complete = True
    times = []

    for event in events:
        typ, data = event_type(event), payload(event)
        stamp = parse_time(event.get("timestamp", event.get("at")))
        if stamp:
            times.append(stamp)
        if typ in ("benchmark_metadata", "run_metadata"):
            report["metadata"].update(data)
        if typ == "finding":
            report["findings"].append(data)
        if typ == "tool_call":
            name = str(data.get("name", data.get("tool", "unknown"))).lower()
            call_id = str(data.get("call_id", data.get("id", "event:%s" % len(calls))))
            inputs = data.get("input", {}) if isinstance(data.get("input", {}), dict) else {"value": data.get("input")}
            signature = canonical([name, inputs])
            report["tool_calls"]["total"] += 1
            report["tool_calls"]["by_name"][name] = report["tool_calls"]["by_name"].get(name, 0) + 1
            if previous_call and previous_call.get("signature") == signature and previous_call.get("failed"):
                report["tool_calls"]["unchanged_retries"] += 1
            calls[call_id] = {"name": name, "input": inputs, "signature": signature}
            previous_call = calls[call_id]
            if name in ("bash", "shell", "command"):
                command = inputs.get("command")
                if command is not None:
                    command_counts[str(command)] += 1
            if name in ("read", "functions.read"):
                path = inputs.get("path", inputs.get("file_path"))
                if path:
                    reads.add(str(path))
                else:
                    report["read_scope"]["events_with_missing_path"] += 1
                limit = inputs.get("limit")
                if not path or limit is None or (isinstance(limit, (int, float)) and limit > 500):
                    report["read_scope"]["broad_reads"] += 1
        elif typ == "tool_result":
            call_id = str(data.get("call_id", data.get("id", "")))
            failed = data.get("is_error") is True or str(data.get("status", "")).lower() in ("failed", "error", "refused", "timed_out")
            if failed:
                report["tool_calls"]["failed"] += 1
                reason = normalize_error(data)
                report["tool_calls"]["normalized_errors"][reason] = report["tool_calls"]["normalized_errors"].get(reason, 0) + 1
                if call_id in calls:
                    calls[call_id]["failed"] = reason
        elif typ == "usage":
            report["usage"]["usage_events"] += 1
            aliases = {"input_tokens": "input_tokens", "cache_read_tokens": "cached_input_tokens", "cached_input_tokens": "cached_input_tokens", "output_tokens": "output_tokens"}
            present = set()
            for source, target in aliases.items():
                if source in data and target not in present and isinstance(data[source], (int, float)):
                    report["usage"][target] += data[source]
                    present.add(target)
            for target in ("input_tokens", "cached_input_tokens", "output_tokens"):
                if target not in present:
                    report["usage"]["missing_counters"][target] = report["usage"]["missing_counters"].get(target, 0) + 1
            input_tokens = data.get("input_tokens")
            cached_tokens = data.get("cache_read_tokens", data.get("cached_input_tokens"))
            if isinstance(input_tokens, (int, float)) and isinstance(cached_tokens, (int, float)) and 0 <= cached_tokens <= input_tokens:
                report["usage"]["non_cached_input_tokens"] += input_tokens - cached_tokens
            else:
                non_cached_complete = False
            used, window = data.get("context_used"), data.get("context_window")
            if isinstance(used, (int, float)) and isinstance(window, (int, float)) and window > 0:
                utilization = used / window
                old = report["context"]["max_utilization"]
                report["context"]["max_utilization"] = utilization if old is None else max(old, utilization)
                report["context"]["samples"] += 1
        elif typ in AGGREGATE_TYPES and any(key in data for key in TOKEN_FIELDS):
            report["usage"]["aggregate_turn_totals_ignored"] += 1
        elif typ in ("compaction", "provider_event_compaction"):
            report["context"]["compactions"] += 1
        elif "handoff" in typ:
            report["context"]["handoffs"] += 1
        elif typ == "approval_requested" and data.get("kind") == "question":
            request_id = str(event.get("request_id", data.get("request_id", "question:%s" % len(pending_questions))))
            pending_questions[request_id] = "unresolved"
            report["questions"]["asked"] += 1
        elif typ in ("approval_resolved", "approval_answered"):
            request_id = str(event.get("request_id", data.get("request_id", "")))
            if request_id in pending_questions:
                answer = data.get("answer")
                decision = str(data.get("decision", "")).lower()
                if isinstance(answer, str) and answer.strip():
                    pending_questions[request_id] = "answered"
                elif decision in ("decline", "declined", "deny", "denied", "refuse", "refused"):
                    pending_questions[request_id] = "declined"

    report["read_scope"]["unique_files"] = sorted(reads)
    report["read_scope"]["file_count"] = len(reads)
    report["tool_calls"]["repeated_commands"] = sum(count - 1 for count in command_counts.values() if count > 1)
    for state in pending_questions.values():
        report["questions"][state] += 1
    for action in actions:
        kind = str(action.get("type", action.get("method", "unknown"))) if isinstance(action, dict) else "invalid"
        report["supervision"]["by_type"][kind] = report["supervision"]["by_type"].get(kind, 0) + 1
    if len(times) >= 2:
        report["wall_time_seconds"] = (max(times) - min(times)).total_seconds()
    if not times:
        report["telemetry_missing"].append("timestamps")
    elif len(times) == 1:
        report["telemetry_missing"].append("wall_time_boundary")
    if report["usage"]["usage_events"] == 0:
        report["telemetry_missing"].append("usage_events")
    for counter in ("input_tokens", "cached_input_tokens", "output_tokens"):
        if report["usage"]["missing_counters"].get(counter):
            report["telemetry_missing"].append(counter)
    if report["context"]["samples"] == 0:
        report["telemetry_missing"].append("context_utilization")
    if not non_cached_complete:
        report["usage"]["non_cached_input_tokens"] = None
        report["telemetry_missing"].append("non_cached_input_tokens")
    return report


def evaluate(candidate: dict, baseline: dict) -> dict:
    reasons = []
    candidate_meta, baseline_meta = candidate.get("metadata", {}), baseline.get("metadata", {})
    for field in ("scope", "bounds", "environment"):
        if not candidate_meta.get(field) or not baseline_meta.get(field):
            reasons.append("missing %s evidence" % field)
        elif candidate_meta[field] != baseline_meta[field]:
            reasons.append("%s differs from baseline" % field)
    for side, meta in (("candidate", candidate_meta), ("baseline", baseline_meta)):
        evidence = meta.get("environment_evidence")
        if not isinstance(evidence, dict) or evidence.get("valid") is not True:
            reasons.append("%s environment evidence is absent or invalid" % side)
    invalid_findings = []
    for finding in candidate.get("findings", []):
        if str(finding.get("classification", "")).lower() in ("confirmed", "reproduced defect", "confirmed defect"):
            evidence = finding.get("evidence", {})
            if not isinstance(evidence, dict) or evidence.get("scope_valid") is not True or evidence.get("environment_valid") is not True:
                invalid_findings.append(finding.get("id", "unnamed"))
    if invalid_findings:
        reasons.append("confirmed findings have invalid scope/environment evidence: " + ", ".join(map(str, invalid_findings)))

    comparison = {}
    paths = {
        "tool_calls": ("tool_calls", "total"),
        "supervisor_actions": ("supervision", "total"),
        "non_cached_input_tokens": ("usage", "non_cached_input_tokens"),
        "wall_time_seconds": ("wall_time_seconds",),
    }
    def at(document, path):
        value = document
        for key in path:
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
        return value
    for name, path in paths.items():
        current, old = at(candidate, path), at(baseline, path)
        reduction = None
        if isinstance(current, (int, float)) and isinstance(old, (int, float)) and old > 0:
            reduction = (old - current) / old
        comparison[name] = {"candidate": current, "baseline": old, "reduction_fraction": reduction}
    valid = not reasons
    return {
        "schema_version": 1,
        "valid_comparison": valid,
        "verdict": "evaluated" if valid else "invalid",
        "invalid_reasons": reasons,
        "invalid_confirmations": invalid_findings,
        "comparison": comparison if valid else None,
        "note": "Static evaluator behavior validates these rules only; it is not proof of live-model judgment.",
    }


def emit(value: Any, output: str | None):
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--events", required=True)
    collect_parser.add_argument("--supervisor-actions", required=True)
    collect_parser.add_argument("--output")
    evaluate_parser = sub.add_parser("evaluate")
    evaluate_parser.add_argument("--candidate", required=True)
    evaluate_parser.add_argument("--baseline", required=True)
    evaluate_parser.add_argument("--output")
    args = parser.parse_args()
    try:
        if args.command == "collect":
            emit(collect(args.events, args.supervisor_actions), args.output)
        else:
            emit(evaluate(load_json(args.candidate), load_json(args.baseline)), args.output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("self-development-metrics: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
