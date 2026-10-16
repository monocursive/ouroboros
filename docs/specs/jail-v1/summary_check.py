#!/usr/bin/env python3
"""Recompute an end-of-run summary's numbers from the archived evidence.

jail-launch-and-summary.md §6.2, K52: "an independent script recomputes every
number from the archived receipt and journal". This script reads an attempt's
`jail.json` and `trace.ndjson` and a `ukai-jail tail --summary --json` object,
recomputes every count and bound the summary states, from §4.2's rules as
written there and nothing of ukai-jail's code, and fails on the first
difference.

Run: python3 -I docs/specs/jail-v1/summary_check.py ATTEMPT_DIR SUMMARY_JSON

Standard library only, Python 3.9 or later, so it runs wherever the receipt
was archived.
"""

import hashlib
import json
import sys
from pathlib import Path

CLASSES = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"]
WRITE_OPERATIONS = {"fs.create", "fs.write", "fs.rename", "fs.unlink"}
SCAN_CAP = 16 * 1024 * 1024
FRAME_MAX = 1024 * 1024 + 1


def fail(message):
    print(f"summary_check: {message}")
    sys.exit(1)


def canonical_digest(receipt):
    """sha256 over RFC 8785 bytes. Receipts hold no floats and only ASCII
    keys, so sorted keys, no whitespace and JSON's minimal string escaping
    are the canonical form."""
    text = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def class_of(event):
    source, operation = event.get("source"), event.get("operation")
    if source == "audit":
        if operation in ("proc.exec", "proc.exit"):
            return "exec"
        if operation in WRITE_OPERATIONS:
            return "fs.write"
        if operation == "fs.deny":
            return "fs.deny"
        if operation == "net.connect":
            return "net"
    if source == "proxy" and operation == "net.connect":
        return "proxy.net"
    return None


def read_journal(data, digest):
    """The trusted frames and whether the journal is complete (jail-v1
    §§13.1, 13.3): every line one JSON object ending in LF, source_seq
    strictly increasing per source and consecutive until a recorded
    transport loss, and the last frame the receipt note of this receipt."""
    frames, broken, hole = [], False, False
    last_seq, loss = {}, False
    lines = data.split(b"\n")
    torn = lines.pop() != b""
    for line in lines:
        try:
            frame = json.loads(line) if len(line) < FRAME_MAX else None
        except ValueError:
            frame = None
        if not isinstance(frame, dict) or not isinstance(frame.get("source_seq"), int):
            broken = True
            break
        fields = frame.get("fields") or {}
        if (frame.get("source") == "wrapper" and frame.get("operation") == "note"
                and fields.get("kind") == "coverage_gap" and fields.get("reason") == "trace_transport_loss"):
            loss = True
        source, seq = frame.get("source"), frame["source_seq"]
        previous = last_seq.get(source, 0)
        if seq <= previous:
            broken = True
            break
        if seq != previous + 1 and not loss:
            hole = True
        last_seq[source] = seq
        frames.append(frame)
    else:
        broken = torn
    last = frames[-1] if frames else {}
    ends_on_note = (not broken and last.get("source") == "wrapper" and last.get("operation") == "jail.receipt"
                    and (last.get("fields") or {}).get("receipt_digest") == digest)
    return frames, ends_on_note and not hole


def bound_of(receipt, name, frames, state):
    coverage = (receipt.get("coverage") or {}).get(name) or {}
    status = coverage.get("status", "unsupported")
    if status not in ("active", "degraded"):
        return "not_observed"
    if state not in ("complete", "incomplete") or name == "limits":
        return "unavailable"
    counted = sum(1 for frame in frames if class_of(frame) == name)
    observed = coverage.get("observed_count")
    if status == "active" and state == "complete":
        return "exact" if observed == counted else "disagree"
    if observed is not None and counted > observed:
        return "disagree"
    return "at_least"


def expect(what, actual, expected):
    if actual != expected:
        fail(f"{what}: the summary says {actual!r}, the evidence gives {expected!r}")


def counted(bound, value):
    return value if bound in ("exact", "at_least") else None


def main():
    if len(sys.argv) != 3:
        fail("usage: summary_check.py ATTEMPT_DIR SUMMARY_JSON")
    attempt, summary = Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text())
    receipt = json.loads((attempt / "jail.json").read_text())
    digest = canonical_digest(receipt)
    expect("receipt_digest", summary["receipt_digest"], digest)
    expect("attempt_id", summary["attempt_id"], receipt["attempt_id"])
    trace = attempt / "trace.ndjson"
    if not trace.exists():
        frames, state = [], "absent"
    elif trace.stat().st_size > SCAN_CAP:
        frames, state = [], "not_scanned"
    else:
        frames, complete = read_journal(trace.read_bytes(), digest)
        state = "complete" if complete else "incomplete"
    expect("journal", summary["journal"], state)
    lines = {line["line"]: line["facts"] for line in summary["lines"]}
    bounds = {name: bound_of(receipt, name, frames, state) for name in CLASSES}

    # Workspace (§4.2): distinct named workspace paths of successful
    # write-class results; unnamed ones; refused file writes.
    opened, renamed, removed, unnamed, refused = set(), set(), set(), 0, 0
    for frame in frames:
        fields, operation = frame.get("fields") or {}, frame.get("operation")
        if frame.get("source") != "audit":
            continue
        if operation == "fs.deny" and fields.get("attempted_operation") in WRITE_OPERATIONS:
            refused += 1
        if operation not in WRITE_OPERATIONS or (frame.get("outcome") or {}).get("ok") is not True:
            continue
        if operation == "fs.write" and fields.get("action") not in ("opened_for_mutation", "truncated"):
            continue
        paths = [fields[key] for key in ("path", "path2") if isinstance(fields.get(key), dict)]
        if any(path.get("kind") in ("unavailable", "digest") for path in paths):
            unnamed += 1
        for path in paths:
            if path.get("kind") == "workspace_relative" and "value" in path:
                key = json.dumps(path["value"])
                {"fs.rename": renamed, "fs.unlink": removed}.get(operation, opened).add(key)
    workspace = lines["workspace"]
    write, deny = bounds["fs.write"], bounds["fs.deny"]
    expect("workspace bound", workspace["bound"], write)
    expect("refused bound", workspace["refused_bound"], deny)
    expect("opened for writing", workspace["opened_for_writing"], counted(write, len(opened)))
    expect("renamed", workspace["renamed"], counted(write, len(renamed)))
    expect("removed", workspace["removed"], counted(write, len(removed)))
    expect("unnamed", workspace["unnamed"], counted(write, unnamed))
    expect("refused", workspace["refused"], counted(deny, refused))
    named = len(opened | renamed | removed) if write in ("exact", "at_least") else 0
    expect("paths listed and omitted", len(workspace["paths"]) + workspace["omitted"], named)

    # Network (§4.2): proxy results by destination and decision.
    network = lines["network"]
    mode = ((receipt.get("applied") or {}).get("network") or {}).get("mode", "pending")
    proxy = bounds["proxy.net"]
    expect("network bound", network["bound"], proxy if mode == "proxy" else "not_observed")
    allowed, denied, uses, refusals = {}, {}, {}, 0
    for frame in frames:
        if class_of(frame) != "proxy.net":
            continue
        fields = frame.get("fields") or {}
        destination, reason = fields.get("destination"), fields.get("reason") or ""
        if frame.get("decision") == "allow":
            results, failed = allowed.get(destination, (0, 0))
            ok = (frame.get("outcome") or {}).get("ok") is True
            allowed[destination] = (results + 1, failed + (0 if ok else 1))
        else:
            denied[(destination, reason)] = denied.get((destination, reason), 0) + 1
        if reason.startswith("credential_"):
            refusals += 1
        for credential in set(fields.get("credentials") or []):
            uses[credential] = uses.get(credential, 0) + 1
    if mode == "proxy" and proxy in ("exact", "at_least"):
        for entry in network["allowed"]:
            expect(f"allowed {entry['destination']}", (entry["results"], entry["connect_failed"]),
                   allowed.get(entry["destination"], (0, 0)))
        for entry in network["denied"]:
            expect(f"denied {entry['destination']} {entry['reason']}", entry["results"],
                   denied.get((entry["destination"], entry["reason"]), 0))
        expect("network entries", len(network["allowed"]) + len(network["denied"]) + network["omitted"],
               len(allowed) + len(denied))
    else:
        expect("network entries", (network["allowed"], network["denied"]), ([], []))

    # Credentials (§4.2, §4.3): uses are proxy results naming the id, from a
    # journal whose credential notes say uses are recorded.
    marked = {(frame.get("fields") or {}).get("credential_id") for frame in frames
              if frame.get("source") == "wrapper" and (frame.get("fields") or {}).get("kind") == "credential"
              and (frame.get("fields") or {}).get("uses_recorded") is True}
    credentials = receipt.get("credentials") or []
    if credentials:
        facts = lines["credentials"]
        for credential, stated in zip(credentials, facts["credentials"]):
            expect("credential id", stated["id"], credential["id"])
            if credential["mode"] != "vault":
                expect(f"{credential['id']} uses", stated["uses"], None)
                continue
            bound = proxy
            if bound in ("exact", "at_least") and credential["id"] not in marked:
                bound = "not_recorded"
            expect(f"{credential['id']} uses bound", stated["uses_bound"], bound)
            expect(f"{credential['id']} uses", stated["uses"], counted(bound, uses.get(credential["id"], 0)))
        vault = any(credential["mode"] == "vault" for credential in credentials)
        expect("refusals", facts["refusals"], counted(proxy, refusals) if vault else None)
    elif "credentials" in lines:
        fail("a credentials line for a receipt without credentials")

    # Evidence: the class statuses and the disagreements.
    evidence = lines["evidence"]
    for name in CLASSES:
        expect(f"{name} status", evidence["classes"][name],
               ((receipt.get("coverage") or {}).get(name) or {}).get("status", "unsupported"))
    expect("disagreements", evidence["disagree"], [name for name in CLASSES if bounds[name] == "disagree"])
    print(f"summary_check: {attempt.name}: every number recomputed ({state} journal, {len(frames)} frames)")


if __name__ == "__main__":
    main()
