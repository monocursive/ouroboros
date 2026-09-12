#!/usr/bin/env python3
"""Render a bounded, conservative status projection from explicit retained evidence."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from typing import Any

MAX_BYTES = 1_048_576
MAX_INPUTS = 64
MAX_ITEMS = 256
MAX_DEPTH = 32
MAX_TEXT_BYTES = 4096
MAX_REFS = 16
MAX_REF_BYTES = 512
MAX_CRITERIA = 16
MAX_CRITERION_BYTES = 500
MAX_CHECKPOINT_AGE = 86_400
SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
STATES = {"planned", "investigating", "blocked", "change_proposed", "checking", "reviewing", "accepted", "failed"}
STATUSES = {"pending", "in_progress", "completed"}
DELIVERABLES = {"analysis", "implementation", "validation"}
SETTLEMENTS = {"unsettled", "completed", "failed", "cancelled", "lost"}
BLOCKERS = {"missing_input", "scope_too_broad", "unsupported_environment", "needs_parent_integration", "dependency_failed", "other"}
PROGRAM_IDS = ("P0", "P1", "P2", "P3", "P4", "P5", "X1", "X2", "X3", "X4")
PROGRAM_STATUSES = {"passed", "failed", "pending", "blocked", "unknown"}
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


class Error(ValueError):
    pass


def _campaign_module():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "self-development-campaign.py")
    spec = importlib.util.spec_from_file_location("ouroboros_self_development_campaign", path)
    if spec is None or spec.loader is None:
        raise Error("cannot load P2 validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P2 = _campaign_module()


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def digest(value: Any, prefix: bool = False) -> str:
    value_digest = hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()
    return ("sha256:" if prefix else "") + value_digest


def exact(value: Any, name: str, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict):
        raise Error(name + " must be an object")
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        raise Error(name + " missing keys: " + ", ".join(sorted(missing)))
    if unknown:
        raise Error(name + " unknown keys: " + ", ".join(sorted(unknown)))
    return value


def text(value: Any, name: str, maximum: int = MAX_TEXT_BYTES, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum or CONTROL.search(value):
        raise Error(name + " must be bounded control-free text")
    if identifier and not IDENT.fullmatch(value):
        raise Error(name + " must be a bounded identifier")
    return value


def string_list(value: Any, name: str, count: int, size: int, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > count or (nonempty and not value):
        raise Error(name + " must be a bounded list")
    result = [text(item, name + "[]", size) for item in value]
    if len(set(result)) != len(result):
        raise Error(name + " contains duplicates")
    return result


def integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Error("%s must be an integer from %d through %d" % (name, low, high))
    return value


def sha(value: Any, name: str, prefixed: bool = False) -> str:
    text(value, name, 71 if prefixed else 64)
    pattern = SHA if prefixed else re.compile(r"^[0-9a-f]{64}$")
    if not pattern.fullmatch(value):
        raise Error(name + " must be a canonical SHA-256 digest")
    return value


def instant(value: Any, name: str) -> float:
    text(value, name, 64)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        timestamp = parsed.timestamp()
    except (OverflowError, ValueError):
        raise Error(name + " must be an RFC3339 timestamp with offset")
    if not timestamp.is_integer():
        raise Error(name + " must have whole-second precision")
    return timestamp


def inspect_nested(value: Any, name: str = "JSON", depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise Error(name + " exceeds nesting bound")
    if isinstance(value, str):
        text(value, name)
    elif isinstance(value, dict):
        if len(value) > 4096:
            raise Error(name + " exceeds object bound")
        for key, item in value.items():
            text(key, name + " key", 256)
            inspect_nested(item, name, depth + 1)
    elif isinstance(value, list):
        if len(value) > 100_000:
            raise Error(name + " exceeds list bound")
        for item in value:
            inspect_nested(item, name, depth + 1)
    elif isinstance(value, float):
        if not __import__("math").isfinite(value):
            raise Error(name + " contains a non-finite number")
    elif value is not None and not isinstance(value, (bool, int)):
        raise Error(name + " contains an unsupported value")


def load_json(path: str) -> tuple[Any, tuple[int, int]]:
    try:
        P2.canonical_path(path, "JSON file", must_exist=True)
        fd, info = P2._open_regular(path, "JSON file", MAX_BYTES)
        try:
            data = b""
            while len(data) <= MAX_BYTES:
                block = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
                if not block:
                    break
                data += block
            if len(data) > MAX_BYTES:
                raise Error("JSON document exceeds %d bytes" % MAX_BYTES)
            document = json.loads(data.decode("utf-8"), object_pairs_hook=P2._no_duplicates, parse_constant=lambda value: (_ for _ in ()).throw(P2.ContractError("non-finite JSON number: %s" % value)))
        finally:
            os.close(fd)
    except (P2.ContractError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Error(str(exc))
    inspect_nested(document)
    return document, (info.st_dev, info.st_ino)


def load_key(path: str) -> tuple[bytes, tuple[int, int]]:
    try:
        P2.canonical_path(path, "key file", must_exist=True)
        fd, info = P2._open_regular(path, "key file", 64)
        try:
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise P2.ContractError("key file permissions must deny group/other access")
            key = os.read(fd, 65)
        finally:
            os.close(fd)
        if len(key) < 32 or len(key) > 64:
            raise P2.ContractError("key file must contain 32 through 64 bytes")
        return key, (info.st_dev, info.st_ino)
    except (P2.ContractError, OSError) as exc:
        raise Error(str(exc))


def validate_blocker(value: Any, state: str) -> str | None:
    if value is None:
        if state == "blocked":
            raise Error("blocked item requires a blocker")
        return None
    blocker = exact(value, "work item blocker", {"type", "resolvable_by_parent"}, {"detail"})
    if blocker["type"] not in BLOCKERS or not isinstance(blocker["resolvable_by_parent"], bool):
        raise Error("invalid work item blocker")
    detail = text(blocker["detail"], "work item blocker detail", 500) if "detail" in blocker else blocker["type"]
    if state != "blocked":
        raise Error("only a blocked item may carry a blocker")
    return detail


def validate_acceptance(value: Any) -> dict:
    acceptance = exact(value, "work item acceptance", {"actor", "decision_source", "basis", "evidence_validation", "deterministic"})
    text(acceptance["actor"], "acceptance actor", 128, True)
    if acceptance["decision_source"] != "parent_model" or acceptance["basis"] != "model_judgment" or acceptance["evidence_validation"] != "unchecked_references" or acceptance["deterministic"] is not False:
        raise Error("work item acceptance does not match the P0 runtime schema")
    return acceptance


def checkpoint(path: str, as_of: int, max_age: int) -> tuple[dict, tuple[int, int]]:
    document, identity = load_json(path)
    exact(document, "checkpoint", {"version", "digest", "updated_at", "messages", "plan"}, {"offset", "rewind_floor", "plan_digest"})
    if document["version"] != 3:
        raise Error("checkpoint version 3 is required")
    if not isinstance(document["messages"], list):
        raise Error("checkpoint messages must be a list")
    sha(document["digest"], "checkpoint digest")
    if document["digest"] != digest(document["messages"]):
        raise Error("checkpoint message digest mismatch")
    sha(document.get("plan_digest"), "checkpoint plan digest")
    if document["plan_digest"] != digest(document["plan"]):
        raise Error("checkpoint plan digest mismatch")
    timestamp = instant(document["updated_at"], "checkpoint.updated_at")
    if timestamp > as_of + 5 or as_of - timestamp > max_age:
        raise Error("checkpoint is stale or future-dated")
    plan = exact(document["plan"], "checkpoint.plan", {"plan"}, {"explanation"}) if document["plan"] is not None else {"plan": []}
    if "explanation" in plan:
        text(plan["explanation"], "checkpoint plan explanation")
    items = plan["plan"]
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise Error("checkpoint plan exceeds item bound")
    seen, output = set(), []
    expected_status = {"planned": "pending", "investigating": "in_progress", "blocked": "pending", "change_proposed": "completed", "checking": "in_progress", "reviewing": "in_progress", "accepted": "completed", "failed": "completed"}
    for index, raw in enumerate(items):
        item = exact(raw, "work item[%d]" % index, {"id", "step", "status", "deliverable", "work_state", "criteria", "evidence", "child_settlement"}, {"owner_task_id", "blocker", "acceptance"})
        item_id = text(item["id"], "work item id", 64, True)
        if item_id in seen:
            raise Error("duplicate work item id: " + item_id)
        seen.add(item_id)
        title = text(item["step"], "work item step", 200)
        state = item["work_state"]
        if state not in STATES or item["status"] not in STATUSES or item["status"] != expected_status[state]:
            raise Error("work item status/work_state conflict")
        if item["deliverable"] not in DELIVERABLES or item["child_settlement"] not in SETTLEMENTS:
            raise Error("invalid work item deliverable or child settlement")
        criteria = string_list(item["criteria"], "work item criteria", MAX_CRITERIA, MAX_CRITERION_BYTES)
        evidence = string_list(item["evidence"], "work item evidence", MAX_REFS, MAX_REF_BYTES)
        if "owner_task_id" in item:
            text(item["owner_task_id"], "work item owner_task_id", 128, True)
        reason = validate_blocker(item.get("blocker"), state)
        if state == "accepted":
            if not criteria or not evidence or "acceptance" not in item:
                raise Error("accepted item lacks P0 acceptance fields")
            validate_acceptance(item["acceptance"])
            phase, reason = "unknown", "reported accepted in an unauthenticated checkpoint; authoritative replay was not supplied"
        elif "acceptance" in item:
            raise Error("non-accepted item cannot carry acceptance")
        else:
            phase = "blocked" if state in ("blocked", "failed") else "pending"
            reason = reason or "parent acceptance is absent"
        unestablished = {
            "establishment": "not_established",
            "observed": None,
            "reason": "no authoritative runtime observation was supplied",
        }
        output.append({
            "id": item_id,
            "title": title,
            "phase": phase,
            "work_state": {"declared": state, **unestablished},
            "child_settlement": {"declared": item["child_settlement"], **unestablished},
            "evidence": evidence,
            "reason": reason,
        })
    return {"path": path, "updated_at": document["updated_at"], "timestamp": int(timestamp), "digest": document["plan_digest"], "items": output}, identity


def validation_receipt(receipt_path: str, manifest_path: str, key_path: str, as_of: int) -> tuple[dict, list[tuple[int, int]]]:
    receipt_document, receipt_identity = load_json(receipt_path)
    manifest_document, manifest_identity = load_json(manifest_path)
    try:
        key, key_identity = load_key(key_path)
        manifest = P2.validate_manifest(manifest_document)
        P2.validate_receipt(receipt_document, key, manifest, as_of)
        result = P2.adjudicate(manifest, receipt_document, key, verify_live=False, now=as_of)
    except (P2.ContractError, OSError) as exc:
        raise Error(str(exc))
    classification = result["classification"]
    status = "passed" if classification == "passed" else "unknown" if classification in ("missing", "inconclusive") else "failed"
    reasons = result["reasons"] or (["P2 validator and adjudicator accepted every declared command binding"] if status == "passed" else ["P2 adjudication: " + classification])
    projected = {"status": status, "classification": classification, "path": receipt_path, "manifest": manifest_path, "source": receipt_document["source"], "issued_at": receipt_document["issued_at"], "reason": "; ".join(reasons), "trust": "local HMAC integrity only; possession of the caller-supplied local key does not prove independent execution, review, or current program truth"}
    return projected, [receipt_identity, manifest_identity, key_identity]


def program_evidence(path: str, as_of: int) -> tuple[dict, tuple[int, int]]:
    document, identity = load_json(path)
    exact(document, "program evidence", {"schema_version", "scope", "as_of", "complete_inventory", "items", "unknowns"})
    if document["schema_version"] != 1 or document["scope"] != "current_program":
        raise Error("program evidence schema or scope is unsupported")
    timestamp = instant(document["as_of"], "program evidence as_of")
    if timestamp > as_of + 5 or as_of - timestamp > MAX_CHECKPOINT_AGE:
        raise Error("program evidence is stale or future-dated")
    if document["complete_inventory"] is not True:
        raise Error("program evidence must explicitly cover the complete P0-P5/X1-X4 inventory")
    unknowns = string_list(document["unknowns"], "program evidence unknowns", 64, 500)
    if not isinstance(document["items"], list) or len(document["items"]) != len(PROGRAM_IDS):
        raise Error("program evidence must contain exactly P0-P5 and X1-X4")
    items, seen = [], set()
    for raw in document["items"]:
        item = exact(raw, "program item", {"id", "status", "reason", "evidence"})
        item_id = text(item["id"], "program item id", 2, True)
        if item_id not in PROGRAM_IDS or item_id in seen:
            raise Error("program evidence has an unknown or duplicate item")
        seen.add(item_id)
        if item["status"] not in PROGRAM_STATUSES:
            raise Error("program item status is unsupported")
        reason = text(item["reason"], "program item reason", 1000)
        evidence = string_list(item["evidence"], "program item evidence", MAX_REFS, MAX_REF_BYTES)
        for evidence_path in evidence:
            try:
                P2.canonical_path(evidence_path, "program item evidence", must_exist=True)
                fd, _info = P2._open_regular(evidence_path, "program item evidence", MAX_BYTES)
                os.close(fd)
            except (P2.ContractError, OSError) as exc:
                raise Error(str(exc))
        if item["status"] == "passed":
            raise Error("program declarations cannot establish passed status; a typed authoritative validator is required")
        items.append({"id": item_id, "status": item["status"], "reason": reason, "evidence": evidence})
    if set(PROGRAM_IDS) != seen:
        raise Error("program evidence inventory is incomplete")
    items.sort(key=lambda item: PROGRAM_IDS.index(item["id"]))
    overall = "failed" if any(item["status"] == "failed" for item in items) else "blocked" if any(item["status"] == "blocked" for item in items) else "pending" if any(item["status"] in ("pending", "unknown") for item in items) else "passed"
    return {"status": overall, "as_of": document["as_of"], "path": path, "items": items, "unknowns": unknowns,
            "trust": "current projection from one explicit complete inventory; each linked receipt retains its own authority and limitations"}, identity


def md(value: Any) -> str:
    rendered = str(value)
    if CONTROL.search(rendered):
        raise Error("Markdown value must be control-free text")
    return rendered.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")


def markdown(document: dict) -> str:
    checkpoint_document = document["checkpoint"]
    heading = "# Current self-development program status" if document["scope"] == "current_program_projection" else "# Self-development status regression projection"
    disclaimer = "> The current program inventory below is an explicit conservative declaration; checkpoint replay is digest-only and any P2 HMAC proves local integrity only." if document["scope"] == "current_program_projection" else "> Fixture and historical P2 rendering is regression evidence only, not actual program truth. P0 is digest-only and P2 HMAC is local integrity only."
    lines = [heading, "", disclaimer, "", "Selection: newest timestamp among %d explicitly supplied inputs; authoritative checkpoint completeness is **unknown**." % checkpoint_document["input_count"], "", "Checkpoint: `%s` (`%s`, `%s`)" % (md(checkpoint_document["path"]), md(checkpoint_document["updated_at"]), md(checkpoint_document["digest"])), ""]
    if checkpoint_document["older_supplied_inputs"]:
        lines += ["Older supplied inputs (no supersession claim): " + ", ".join("`%s` (%s)" % (md(item["path"]), md(item["updated_at"])) for item in checkpoint_document["older_supplied_inputs"]), ""]
    lines += ["## Work items", "", "Checkpoint work-state and child-settlement values below are digest-consistent declarations only. No runtime observation or child identity authority was supplied, so both fields are **not established** for every row.", "", "| ID | Phase | Declared state (not established) | Declared child settlement (not established) | Reason / evidence |", "|---|---|---|---|---|"]
    for item in document["items"]:
        evidence = ", ".join(md(value) for value in item["evidence"])
        lines.append("| %s | %s | %s | %s | %s |" % (md(item["id"]), md(item["phase"]), md(item["work_state"]["declared"]), md(item["child_settlement"]["declared"]), evidence or md(item["reason"])))
    lines += ["", "## Validation", ""]
    if document["validation"]["status"] == "unknown" and not document["validation"]["receipts"]:
        lines.append("- **unknown** — no P2 receipt was supplied")
    for receipt in document["validation"]["receipts"]:
        lines.append("- **%s** — `%s`: %s. %s" % (md(receipt["status"]), md(receipt["path"]), md(receipt["reason"]), md(receipt["trust"])))
    lines += ["", "## Current program inventory", ""]
    program = document["program_projection"]
    if program.get("status") == "unknown" and "items" not in program:
        lines.append("- **unknown** — %s" % md(program["reason"]))
    else:
        lines += ["Overall declaration: **%s**. %s" % (md(program["status"]), md(program["trust"])), "", "| ID | Status | Reason | Evidence |", "|---|---|---|---|"]
        for item in program["items"]:
            evidence = ", ".join("`%s`" % md(value) for value in item["evidence"]) or "none supplied"
            lines.append("| %s | %s | %s | %s |" % (md(item["id"]), md(item["status"]), md(item["reason"]), evidence))
        lines += ["", "Explicit unknowns:"]
        lines += ["- " + md(value) for value in program["unknowns"]] or ["- none declared"]
    lines += ["", "## Load", "", "- **unknown** — no supported load-controller receipt contract exists"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", action="append", required=True)
    parser.add_argument("--receipt", action="append", default=[])
    parser.add_argument("--manifest", action="append", default=[])
    parser.add_argument("--key", action="append", default=[])
    parser.add_argument("--program")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--as-of", type=int, default=int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
    parser.add_argument("--max-checkpoint-age", type=int, default=MAX_CHECKPOINT_AGE)
    arguments = parser.parse_args(argv)
    try:
        integer(arguments.as_of, "as-of", 0, 2**63 - 1)
        integer(arguments.max_checkpoint_age, "max-checkpoint-age", 1, MAX_CHECKPOINT_AGE)
        all_paths = arguments.checkpoint + arguments.receipt + arguments.manifest + arguments.key + ([arguments.program] if arguments.program else [])
        if len(arguments.checkpoint) > MAX_INPUTS or len(all_paths) > MAX_INPUTS * 4 or len(set(all_paths)) != len(all_paths):
            raise Error("input paths must be textually unique and bounded")
        if not (len(arguments.receipt) == len(arguments.manifest) == len(arguments.key)):
            raise Error("each receipt requires one manifest and one key")
        checkpoints, identities = [], []
        for path in arguments.checkpoint:
            value, identity = checkpoint(path, arguments.as_of, arguments.max_checkpoint_age)
            checkpoints.append(value); identities.append(identity)
        checkpoints.sort(key=lambda value: value["timestamp"])
        if len(checkpoints) > 1 and checkpoints[-1]["timestamp"] == checkpoints[-2]["timestamp"]:
            raise Error("newest supplied checkpoint is ambiguous: duplicate timestamp")
        receipts = []
        for paths in zip(arguments.receipt, arguments.manifest, arguments.key):
            value, receipt_identities = validation_receipt(*paths, arguments.as_of)
            receipts.append(value); identities.extend(receipt_identities)
        program = None
        if arguments.program:
            program, program_identity = program_evidence(arguments.program, arguments.as_of)
            identities.append(program_identity)
        if len(set(identities)) != len(identities):
            raise Error("input paths alias the same file identity")
        current = checkpoints[-1]
        checkpoint_projection = {key: current[key] for key in ("path", "updated_at", "digest")}
        checkpoint_projection.update({"selection_basis": "newest_timestamp_among_explicit_inputs", "input_count": len(checkpoints), "completeness": "unknown", "older_supplied_inputs": [{key: value[key] for key in ("path", "updated_at", "digest")} for value in checkpoints[:-1]]})
        validation_status = "unknown" if not receipts else "failed" if any(item["status"] == "failed" for item in receipts) else "unknown" if any(item["status"] == "unknown" for item in receipts) else "passed"
        scope = "current_program_projection" if program else "regression_evidence_not_program_truth"
        trust = program["trust"] if program else "derived only from explicit supplied inputs; authoritative discovery, P0 replay, and program completeness are unknown"
        document = {"schema_version": 3, "projection": "self-development-status", "scope": scope, "trust": trust, "checkpoint": checkpoint_projection, "items": current["items"], "validation": {"status": validation_status, "reason": "not_supplied" if not receipts else "projected_from_supplied_receipts", "receipts": receipts}, "load": {"status": "unknown", "reason": "unsupported_no_receipt_contract"}, "program_projection": program or {"status": "unknown", "reason": "no authoritative current-program projection exists"}}
        print(canonical(document) if arguments.format == "json" else markdown(document), end="\n" if arguments.format == "json" else "")
        return 0
    except (Error, P2.ContractError, OSError, TypeError, ValueError, OverflowError) as exc:
        print("self-development-status: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
