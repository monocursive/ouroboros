#!/usr/bin/env python3
"""Recompute an end-of-run summary from the archived evidence.

jail-launch-and-summary.md §6.2, K52: "an independent script recomputes every
number from the archived receipt and journal". This script reads an attempt's
`jail.json` and `trace.ndjson` and a `ukai-jail tail --summary --json`
object, and recomputes the whole summary from §4.2's rules as written there
and operating.md's account of them, with no code of ukai-jail: every line
present, its order, every fact (each count with its bound), and every line's
text, character for character. It fails on the first difference.

Run: python3 -I docs/specs/jail-v1/summary_check.py ATTEMPT_DIR SUMMARY_JSON

Standard library only, Python 3.9 or later, so it runs wherever the receipt
was archived.
"""

import calendar
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

CLASSES = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"]
AUDIT_CLASSES = ["exec", "fs.write", "fs.deny", "net"]
STATUSES = ["supported", "active", "degraded", "unsupported"]
WRITE_OPERATIONS = ("fs.create", "fs.write", "fs.rename", "fs.unlink")
SCAN_CAP = 16 * 1024 * 1024
RECEIPT_MAX = 4 * 1024 * 1024
# jail-v1 §13.1: an event is at most 64 KiB; a longer line is no frame.
EVENT_MAX = 64 * 1024
TERMINAL_LIST = 5
JSON_LIST = 64
U64_MAX = 2 ** 64 - 1


def fail(message):
    print(f"summary_check: {message}")
    sys.exit(1)


# --------------------------------------------------------------------------
# Escaping: control characters, bidi controls and invisible format
# characters become <U+XXXX> (operating.md, "Every child-chosen string is
# escaped").

BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
INVISIBLE = ({0x2028, 0x2029, 0xFEFF} | set(range(0x200B, 0x200E)) | set(range(0x2060, 0x2065))
             | set(range(0xE0000, 0xE0080)))


def esc(text):
    out = []
    for character in text:
        code = ord(character)
        if unicodedata.category(character) == "Cc" or code in BIDI or code in INVISIBLE:
            out.append("<U+%04X>" % code)
        else:
            out.append(character)
    return "".join(out)


def canonical_digest(receipt):
    """sha256 over RFC 8785 bytes. Receipts hold no floats and only ASCII
    keys, so sorted keys, no whitespace and JSON's minimal string escaping
    are the canonical form."""
    text = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def pointer(value, *keys):
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
            value = value[key]
        else:
            return None
    return value


def string(value, *keys):
    found = pointer(value, *keys)
    return found if isinstance(found, str) else None


def unsigned(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= U64_MAX else None


# --------------------------------------------------------------------------
# Reading the journal (jail-v1 §§13.1, 13.3): a frame is one JSON object
# ending in LF; nothing from the first line that is not one is evidence.


class Frame(dict):
    """A JSON object, remembering the keys it held more than once."""


def object_pairs(pairs):
    frame = Frame()
    frame.repeated = set()
    for key, value in pairs:
        if key in frame:
            frame.repeated.add(key)
        frame[key] = value
    return frame


def no_constant(name):
    raise ValueError(f"not JSON: {name}")


TOP = {"attempt_id": str, "source": str, "source_seq": "u64", "operation": str, "decision": str,
       "monotonic_ns": str, "outcome": dict, "fields": dict}
FIELDS = {"kind": str, "transition": str, "phase": str, "receipt_digest": str, "action": str,
          "attempted_operation": str, "destination": str, "reason": str, "credential_id": str,
          "uses_recorded": bool, "credentials": "ids", "credentials_unconfirmed": "ids",
          "path": "path", "path2": "path"}


def typed(value, kind):
    """Whether a present key holds what the reader expects (null is absent)."""
    if value is None:
        return True
    if kind == "u64":
        return unsigned(value) is not None
    if kind == "ids":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if kind == "path":
        if not isinstance(value, dict) or getattr(value, "repeated", set()) & {"kind", "value"}:
            return False
        if not isinstance(value.get("kind"), str):
            return False
        name = value.get("value")
        return (name is None or isinstance(name, str)
                or (isinstance(name, dict) and name.get("encoding") == "base64" and isinstance(name.get("data"), str)))
    if kind is bool:
        return isinstance(value, bool)
    return isinstance(value, kind) and not (kind is int and isinstance(value, bool))


def well_formed(frame):
    if not isinstance(frame, Frame) or frame.repeated & set(TOP):
        return False
    if not all(typed(frame.get(key), kind) for key, kind in TOP.items()):
        return False
    outcome = frame.get("outcome") or {}
    if "ok" in getattr(outcome, "repeated", set()) or not typed(outcome.get("ok"), bool):
        return False
    fields = frame.get("fields") or {}
    if getattr(fields, "repeated", set()) & set(FIELDS):
        return False
    return all(typed(fields.get(key), kind) for key, kind in FIELDS.items())


def read_journal(data, digest, attempt_id):
    frames, broken, hole, loss, last_seq = [], False, False, False, {}
    lines = data.split(b"\n")
    torn = lines.pop() != b""
    for line in lines:
        frame = None
        if len(line) <= EVENT_MAX and line.lstrip(b" \t\n\x0c\r")[:1] == b"{":
            try:
                frame = json.loads(line.decode("utf-8"), object_pairs_hook=object_pairs,
                                   parse_constant=no_constant)
            except ValueError:
                frame = None
        if frame is None or not well_formed(frame):
            broken = True
            break
        if frame.get("attempt_id") != attempt_id or frame.get("source_seq") is None:
            broken = True
            break
        fields = frame.get("fields") or {}
        if (frame.get("source") == "wrapper" and frame.get("operation") == "note"
                and fields.get("kind") == "coverage_gap" and fields.get("reason") == "trace_transport_loss"):
            loss = True
        source, seq = frame.get("source") or "", frame["source_seq"]
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
    note = None
    if last.get("source") == "wrapper" and last.get("operation") == "jail.receipt":
        fields = last.get("fields") or {}
        if isinstance(fields.get("phase"), str) and isinstance(fields.get("receipt_digest"), str):
            note = fields["receipt_digest"]
    complete = not broken and not hole and note is not None and note == digest
    another = not complete and not broken and not hole and note is not None
    return frames, complete, another


def class_of(frame):
    source, operation = frame.get("source"), frame.get("operation")
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


def status_of(receipt, name):
    coverage = pointer(receipt, "coverage", name)
    if not isinstance(coverage, dict) or "status" not in coverage:
        return "unsupported"
    return coverage["status"] if coverage["status"] in STATUSES else "unknown"


def claim_of(receipt, name, frames, state):
    """exact, at_least, not_observed, unavailable (no journal) or disagree."""
    status = status_of(receipt, name)
    if status not in ("active", "degraded"):
        return "not_observed"
    if state not in ("complete", "incomplete") or name == "limits":
        return "unavailable"
    counted = sum(1 for frame in frames if class_of(frame) == name)
    observed = unsigned(pointer(receipt, "coverage", name, "observed_count"))
    if status == "active" and state == "complete":
        return "exact" if observed == counted else "disagree"
    if observed is not None and counted > observed:
        return "disagree"
    return "at_least"


def counts(claim):
    return claim in ("exact", "at_least")


def number(claim, n):
    return f"at least {n}" if claim == "at_least" else str(n)


def noun(n, one, many):
    return one if n == 1 else many


def capped(items, separator):
    shown = separator.join(items[:TERMINAL_LIST])
    more = len(items) - TERMINAL_LIST
    return shown + (f" +{more} more" if more > 0 else "")


def missing(state, size):
    return {"not_scanned": f"journal not scanned ({-(-size // (1024 * 1024))} MiB)",
            "absent": "no local journal", "unreadable": "journal unreadable"}.get(state)


def duration(ms):
    seconds = ms // 1000
    if seconds == 0:
        return f"{ms}ms"
    if seconds < 60:
        return f"{seconds}.{(ms % 1000) // 100}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m{seconds % 60:02d}s"


STAMP = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$")


def epoch_ms(stamp):
    match = STAMP.match(stamp) if isinstance(stamp, str) else None
    if not match:
        return None
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour <= 23 and minute <= 59 and second <= 60):
        return None
    millis = int((match.group(7) or "")[:3].ljust(3, "0"))
    return calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0)) * 1000 + millis


def clock(frame):
    text = frame.get("monotonic_ns")
    return int(text) if isinstance(text, str) and text.isascii() and text.isdigit() else None


# --------------------------------------------------------------------------
# The lines


def status_line(receipt, frames, scanned):
    phase = string(receipt, "phase") or "unknown"
    parts = ["settled" if phase == "settled" else f"NOT settled ({esc(phase)})"]
    kind = string(receipt, "outcome", "kind") or "unknown"
    code, signal = unsigned(pointer(receipt, "outcome", "code")), unsigned(pointer(receipt, "outcome", "signal"))
    cause = string(receipt, "outcome", "cause")
    if kind == "exited" and code is not None:
        outcome = f"exited {code}"
    elif kind == "signaled" and signal is not None:
        outcome = f"signaled {signal}"
    elif kind == "exec_error":
        outcome = "exec failed"
    elif kind == "refused":
        outcome = "" if phase == "refused" else "refused"
    elif kind == "pending":
        outcome = "outcome pending"
    else:
        outcome = "outcome unknown"
    if cause is not None:
        outcome += (" " if outcome else "") + f"({esc(cause)})"
    if outcome:
        parts.append(outcome)
    start = next((clock(frame) for frame in frames
                  if frame.get("source") == "wrapper" and frame.get("operation") == "note"
                  and (frame.get("fields") or {}).get("kind") == "lifecycle"
                  and (frame.get("fields") or {}).get("transition") == "exec_confirmed"
                  and clock(frame) is not None), None)
    end = None
    for frame in frames:
        if (frame.get("source") == "wrapper" and frame.get("operation") == "jail.receipt"
                and (frame.get("fields") or {}).get("phase") == "settled" and clock(frame) is not None):
            end = clock(frame)
    journal_ms = (end - start) // 1_000_000 if start is not None and end is not None and end >= start else None
    wall_ms = None
    if not scanned:
        created, updated = epoch_ms(string(receipt, "created_at")), epoch_ms(string(receipt, "updated_at"))
        if created is not None and updated is not None and updated >= created:
            wall_ms = updated - created
    if journal_ms is not None:
        parts.append(f"{duration(journal_ms)} exec→settled")
    elif wall_ms is not None:
        parts.append(f"{duration(wall_ms)} attempt (wall clock)")
    tree_empty = pointer(receipt, "lifetime", "tree_empty")
    scope = string(receipt, "lifetime", "verification_scope")
    if tree_empty is True and scope == "registered_boundary":
        parts.append("survivors: none (verified, registered cgroup only)")
        survivors = "none_verified_registered_boundary"
    elif tree_empty is True and scope == "attempt_tree":
        parts.append("survivors: none (verified)")
        survivors = "none_verified"
    else:
        parts.append("survivors: NOT verified")
        survivors = "not_verified"
    codes = []
    for error in pointer(receipt, "errors") or []:
        code_text = string(error, "code")
        if code_text is not None and code_text not in codes:
            codes.append(code_text)
    if codes:
        rendered = ["tree_unknown: run ukai-jail gc" if each == "tree_unknown" else esc(each) for each in codes]
        parts.append("errors: " + capped(rendered, ", "))
    integrity = string(receipt, "lifetime", "integrity")
    if integrity == "lost":
        parts.append("integrity lost: state retained")
    facts = {"phase": phase, "outcome": kind, "code": code, "signal": signal, "cause": cause,
             "exec_to_settled_ms": journal_ms, "attempt_wall_ms": wall_ms, "survivors": survivors,
             "errors": codes, "integrity": integrity}
    return " · ".join(parts), facts


def workspace_line(receipt, frames, claims, state, size):
    opened, renamed, removed, named, unnamed, refused = set(), set(), set(), {}, 0, 0
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
            value = path.get("value")
            if path.get("kind") != "workspace_relative" or value is None:
                continue
            key = ("t", value) if isinstance(value, str) else ("b", value["data"])
            named[key] = value if isinstance(value, str) else {"encoding": "base64", "data": value["data"]}
            {"fs.rename": renamed, "fs.unlink": removed}.get(operation, opened).add(key)
    write, deny = claims["fs.write"], claims["fs.deny"]
    observe_off = string(receipt, "policy", "observe") == "off"
    if write == "not_observed":
        text = "not observed (--observe off)" if observe_off else "not observed"
    elif write == "unavailable":
        text = missing(state, size)
    elif write == "disagree":
        text = "journal and receipt disagree on fs.write"
    else:
        seen = []
        if opened or write == "exact":
            seen.append(f"{number(write, len(opened))} {noun(len(opened), 'path', 'paths')} opened for writing")
        for n, what in [(len(renamed), "in renames"), (len(removed), "removed")]:
            if n:
                seen.append(f"{number(write, n)} {what}")
        text = ", ".join(seen) if seen else "none recorded (a lower bound)"
        if unnamed:
            text += f" · {number(write, unnamed)} " + noun(unnamed, "result with an unnamed path",
                                                          "results with unnamed paths")
    text = "workspace: " + text
    if counts(deny) and refused:
        text += f" · {number(deny, refused)} {noun(refused, 'refused write', 'refused writes')}"
    elif deny == "disagree":
        text += " · refused writes: journal and receipt disagree on fs.deny"
    order = sorted(key for key in named if key[0] == "t") + sorted(key for key in named if key[0] == "b")
    listed = [{"kind": "workspace_relative", "value": named[key]} for key in order] if counts(write) else []
    value = lambda n: n if counts(write) else None
    facts = {"bound": write, "opened_for_writing": value(len(opened)), "renamed": value(len(renamed)),
             "removed": value(len(removed)), "unnamed": value(unnamed),
             "refused": refused if counts(deny) else None, "refused_bound": deny,
             "paths": listed[:JSON_LIST], "omitted": max(0, len(listed) - JSON_LIST)}
    return text, facts


def option_key(destination):
    return (0, "") if destination is None else (1, destination)


def proxy_tally(frames):
    allowed, denied, uses, unconfirmed, refusals = {}, {}, {}, {}, 0
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
        if frame.get("decision") == "deny" and reason.startswith("credential_"):
            refusals += 1
        for key, tally in (("credentials", uses), ("credentials_unconfirmed", unconfirmed)):
            for credential in set(fields.get(key) or []):
                tally[credential] = tally.get(credential, 0) + 1
    return allowed, denied, uses, unconfirmed, refusals


def network_line(receipt, frames, claims, state, size):
    mode = string(receipt, "applied", "network", "mode") or "pending"
    claim = claims["proxy.net"]
    resolver = unsigned(pointer(receipt, "coverage", "proxy.net", "resolver_refused"))
    allowed, denied, _, _, _ = proxy_tally(frames)
    label = lambda destination: "(no destination)" if destination is None else esc(destination)
    allowed_order = sorted(allowed.items(), key=lambda item: (-item[1][0], option_key(item[0])))
    by_destination = {}
    for (destination, _), n in denied.items():
        by_destination[destination] = by_destination.get(destination, 0) + n
    denied_order = sorted(by_destination.items(), key=lambda item: (-item[1], option_key(item[0])))
    if mode == "none":
        text = "none"
    elif mode == "host":
        text = "host, not observed"
    elif mode == "proxy" and claim == "not_observed":
        text = "proxy, not observed"
    elif mode == "proxy" and claim == "unavailable":
        text = "proxy, " + missing(state, size)
    elif mode == "proxy" and claim == "disagree":
        text = "proxy, journal and receipt disagree on proxy.net"
    elif mode == "proxy":
        parts = []
        if allowed_order:
            items = []
            for destination, (results, failed) in allowed_order:
                item = f"{label(destination)} ({number(claim, results)}"
                if failed:
                    item += f", {number(claim, failed)} connect failed"
                items.append(item + ")")
            parts.append("allowed " + capped(items, ", "))
        if denied_order:
            parts.append("denied " + capped([f"{label(d)} ({number(claim, n)})" for d, n in denied_order], ", "))
        if not parts:
            parts.append("proxy, no connections" if claim == "exact" else "proxy, none recorded (a lower bound)")
        if resolver is not None:
            parts.append(f"{resolver} refused for resolver capacity, not policy")
        text = " · ".join(parts)
    else:
        text = "not applied"
    counted = mode == "proxy" and counts(claim)
    pairs = sorted(denied.items(), key=lambda item: (-item[1], option_key(item[0][0]), item[0][1])) if counted else []
    entries = allowed_order if counted else []
    facts = {"mode": mode, "bound": claim if mode == "proxy" else "not_observed",
             "allowed": [{"destination": d, "results": r, "connect_failed": f} for d, (r, f) in entries[:JSON_LIST]],
             "denied": [{"destination": d, "reason": reason, "results": n} for (d, reason), n in pairs[:JSON_LIST]],
             "omitted": max(0, len(entries) - JSON_LIST) + max(0, len(pairs) - JSON_LIST),
             "resolver_refused": resolver}
    return "network: " + text, facts


def credentials_line(receipt, frames, claims, state, size):
    credentials = pointer(receipt, "credentials")
    if not isinstance(credentials, list) or not credentials:
        return None
    claim = claims["proxy.net"]
    _, _, uses, unconfirmed, refusals = proxy_tally(frames)
    marked, transitions = set(), {}
    for frame in frames:
        fields = frame.get("fields") or {}
        if frame.get("source") != "wrapper" or frame.get("operation") != "note" or fields.get("kind") != "credential":
            continue
        identity = fields.get("credential_id")
        if identity is None:
            continue
        if fields.get("uses_recorded") is True:
            marked.add(identity)
        if fields.get("transition") is not None:
            seen = transitions.setdefault(identity, [])
            if fields["transition"] not in seen:
                seen.append(fields["transition"])
    parts, facts, vault = [], [], False
    for credential in credentials:
        identity = string(credential, "id") or ""
        mode = string(credential, "mode") or "unknown"
        never_staged = pointer(credential, "never_staged")
        never_staged = never_staged if isinstance(never_staged, bool) else None
        part = f"{esc(identity)}: {esc(mode)}"
        used, bound = None, "not_observed"
        if mode == "vault":
            vault = True
            if never_staged is True:
                part += ", never staged"
            if claim == "unavailable":
                part += " · uses: " + missing(state, size)
                bound = "unavailable"
            elif claim == "not_observed":
                part += " · uses not observed"
            elif claim == "disagree":
                part += " · uses: journal and receipt disagree on proxy.net"
                bound = "disagree"
            elif identity not in marked:
                part += " · uses not recorded"
                bound = "not_recorded"
            else:
                used, maybe = uses.get(identity, 0), unconfirmed.get(identity, 0)
                bound = "at_least" if maybe else claim
                if bound == "at_least" and used == 0 and maybe == 0:
                    part += " · uses: none recorded (a lower bound)"
                else:
                    part += f" · used on {number(bound, used)} {noun(used, 'proxy result', 'proxy results')}"
                if maybe:
                    part += f" (+{maybe} not confirmed sent)"
        else:
            part += ", staged (readable by the agent)"
        notable = [esc(t) for t in transitions.get(identity, []) if t not in ("loaded", "refresh_started")]
        if notable:
            part += " · " + ", ".join(notable)
        parts.append(part)
        facts.append({"id": identity, "mode": mode, "never_staged": never_staged, "uses": used,
                      "uses_bound": bound,
                      "unconfirmed": None if used is None else unconfirmed.get(identity, 0),
                      "transitions": transitions.get(identity, [])})
    text = ("credential " if len(parts) == 1 else "credentials ") + capped(parts, "; ")
    refused = None
    if vault and counts(claim):
        refused = refusals
        if not (claim == "at_least" and refusals == 0):
            text += f" · {number(claim, refusals)} {noun(refusals, 'credential refusal', 'credential refusals')}"
    return text, {"credentials": facts[:JSON_LIST], "omitted": max(0, len(facts) - JSON_LIST),
                  "refusals": refused, "refusals_bound": claim if vault else "not_observed"}


def evidence_line(receipt, claims, state, size, another):
    observe = string(receipt, "policy", "observe") or "on"
    observe_off = observe == "off"
    attached = pointer(receipt, "observer", "attached")
    parts, gaps = [], []
    statuses = {name: status_of(receipt, name) for name in CLASSES}
    if observe_off:
        parts.append("observation off: exec, file and connect classes not observed")
    else:
        if attached is False:
            parts.append("observer not attached")
        active = sum(1 for name in CLASSES if statuses[name] == "active" and claims[name] != "disagree")
        observer_gaps = pointer(receipt, "observer", "gaps")
        observer_gaps = len(observer_gaps) if isinstance(observer_gaps, list) else 0
        if active == 6 and state == "complete" and observer_gaps == 0 and attached is not False:
            parts.append("6/6 classes active, no gaps")
        else:
            parts.append(f"{active}/6 classes active")
    not_started, not_observed = [], []
    for name in CLASSES:
        if observe_off and name in AUDIT_CLASSES:
            continue
        status = statuses[name]
        if status == "degraded":
            class_gaps = pointer(receipt, "coverage", name, "gaps")
            class_gaps = class_gaps if isinstance(class_gaps, list) else []
            item = f"{name} degraded"
            if class_gaps:
                reason = string(class_gaps[0], "reason") or "?"
                lost = unsigned(pointer(class_gaps[0], "lost_count"))
                item += f" ({esc(reason)}, lost {'unknown' if lost is None else lost}"
                if len(class_gaps) > 1:
                    item += f", +{len(class_gaps) - 1} more gaps"
                item += ")"
            parts.append(item)
            for gap in class_gaps:
                gaps.append({"class": name, "reason": pointer(gap, "reason"), "lost_count": pointer(gap, "lost_count")})
        elif status == "supported":
            not_started.append(name)
        elif status != "active":
            not_observed.append(name)
    for names, said in ((not_started, "not started"), (not_observed, "not observed")):
        if names:
            parts.append(", ".join(names) + " " + said)
    disagree = [name for name in CLASSES if claims[name] == "disagree"]
    parts.extend(f"journal and receipt disagree on {name}" for name in disagree)
    if state == "incomplete":
        parts.append("journal ends on another receipt's note: counts above are lower bounds" if another
                     else "journal incomplete: counts above are lower bounds")
    elif state != "complete":
        parts.append(missing(state, size))
    if not observe_off and any(statuses[name] in ("active", "degraded") for name in AUDIT_CLASSES):
        parts.append("reads and file contents are not observed")
    facts = {"observe": observe, "evidence": string(receipt, "policy", "evidence"),
             "attached": attached if isinstance(attached, bool) else None,
             "classes": statuses, "gaps": gaps, "disagree": disagree}
    return "evidence: " + " · ".join(parts), facts


def limits_line(receipt):
    limits = pointer(receipt, "applied", "limits")
    if not isinstance(limits, list):
        return None
    hit, not_applied = [], []
    for limit in limits:
        pair = (string(limit, "key") or "?", string(limit, "requested") or "?")
        if pointer(limit, "hit") is True:
            hit.append(pair)
        if pointer(limit, "applied") is False:
            not_applied.append(pair)
    if not hit and not not_applied:
        return None
    render = lambda pairs: capped([f"{esc(key)} ({esc(requested)})" for key, requested in pairs], ", ")
    parts = ([f"hit {render(hit)}"] if hit else []) + ([f"not applied: {render(not_applied)}"] if not_applied else [])
    listed = lambda pairs: [{"key": key, "requested": requested} for key, requested in pairs]
    return "limits: " + " · ".join(parts), {"hit": listed(hit), "not_applied": listed(not_applied)}


def cleanup_line(receipt):
    cleanup, protection = string(receipt, "state_cleanup"), string(receipt, "child_protection")
    parts = (["vendor state cleanup pending: run ukai-jail gc"] if cleanup == "pending" else []) + \
        (["uncontained (none): nothing above was enforced"] if protection == "unprotected" else [])
    if not parts:
        return None
    return " · ".join(parts), {"state_cleanup": cleanup, "child_protection": protection}


def main():
    if len(sys.argv) != 3:
        fail("usage: summary_check.py ATTEMPT_DIR SUMMARY_JSON")
    attempt, summary = Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text())
    receipt_bytes = (attempt / "jail.json").read_bytes()
    if len(receipt_bytes) > RECEIPT_MAX:
        fail("the receipt is over its size bound")
    receipt = json.loads(receipt_bytes)
    digest = canonical_digest(receipt)
    expect = lambda what, stated, recomputed: recomputed == stated or fail(
        f"{what}: the summary says {stated!r}, the evidence gives {recomputed!r}")
    expect("schema", summary.get("schema"), "ukai.jail.summary/1")
    expect("receipt_digest", summary.get("receipt_digest"), digest)
    attempt_id = string(receipt, "attempt_id") or ""
    expect("attempt_id", summary.get("attempt_id"), attempt_id)
    trace, frames, size, another = attempt / "trace.ndjson", [], 0, False
    if not trace.exists():
        state = "absent"
    elif trace.stat().st_size > SCAN_CAP:
        state, size = "not_scanned", trace.stat().st_size
    else:
        frames, complete, another = read_journal(trace.read_bytes(), digest, attempt_id)
        state = "complete" if complete else "incomplete"
    expect("journal", summary.get("journal"), state)
    scanned = state in ("complete", "incomplete")
    claims = {name: claim_of(receipt, name, frames, state) for name in CLASSES}
    lines = [("status", status_line(receipt, frames, scanned)),
             ("workspace", workspace_line(receipt, frames, claims, state, size)),
             ("network", network_line(receipt, frames, claims, state, size)),
             ("credentials", credentials_line(receipt, frames, claims, state, size)),
             ("evidence", evidence_line(receipt, claims, state, size, another)),
             ("limits", limits_line(receipt)),
             ("cleanup", cleanup_line(receipt))]
    lines = [(name, line) for name, line in lines if line is not None]
    stated = summary.get("lines") or []
    expect("the lines", [line.get("line") for line in stated], [name for name, _ in lines])
    for (name, (text, facts)), line in zip(lines, stated):
        expect(f"{name} facts", line.get("facts"), facts)
        expect(f"{name} text", line.get("text"), text)
    print(f"summary_check: {attempt.name}: every line, fact and number recomputed "
          f"({state} journal, {len(frames)} frames)")


if __name__ == "__main__":
    main()
