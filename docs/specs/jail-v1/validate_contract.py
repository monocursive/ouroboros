# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
"""Validate specification artifacts, not live jail/backend conformance.

Run: uv run docs/specs/jail-v1/validate_contract.py
The checked-in fixture corpus is also input to the Rust P01/R01 suite.

J5-C: the semantic rules below are the port of ouro_jail::records::semantic.
Both run fixtures/semantic-cases.json and must name the same rule for every
case; both run fixtures/gate-frames.json against the §8.2 frame rules. The
frozen wire schemas and the artifacts behind the other announced identifiers
are pinned by frozen-schemas.toml.

Parity with the Rust validator (jsonschema-rs): `date-time` is checked
(rfc3339-validator), and `pattern` has ECMA-262 semantics, where `$` matches
only at the end of the string (Python's `$` also matches before a final LF).
"""

import base64
import copy
import hashlib
import ipaddress
import json
import posixpath
import re
import struct
import tomllib
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from jsonschema import validators as jsonschema_validators
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent
DECIMAL = re.compile(r"(0|[1-9][0-9]*)\Z")


def ecma_pattern(validator, pattern, instance, schema):
    """JSON Schema `pattern` with ECMA-262 `$`: only the end of the string."""
    if not validator.is_type(instance, "string"):
        return
    anchored = re.sub(r"(?<!\\)\$", r"\\Z", pattern)
    if not re.search(anchored, instance):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


ContractValidator = jsonschema_validators.extend(Draft202012Validator, {"pattern": ecma_pattern})


def load_schemas(root):
    """Every `*.schema.json` under root by stem, refusing a second file that
    declares an `$id` already declared: a registry keeps one of them, so a
    duplicate would silently replace a frozen schema."""
    schemas, owners = {}, {}
    for file in sorted(root.glob("*.schema.json")):
        schema = json.loads(file.read_text())
        identifier = schema["$id"]
        assert identifier not in owners, (
            f"{file.name} declares {identifier}, already declared by {owners[identifier]}")
        owners[identifier] = file.name
        schemas[file.stem.removesuffix(".schema")] = schema
    return schemas


def build_validators(schemas):
    registry = Registry()
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return {
        name: ContractValidator(schema, registry=registry, format_checker=FormatChecker())
        for name, schema in schemas.items()
    }


def read(path):
    return json.loads((ROOT / path).read_text())


def native_bytes(value):
    if isinstance(value, str):
        raw = value.encode("utf-8", errors="strict")
    else:
        assert set(value) == {"encoding", "data"}
        assert value["encoding"] == "base64"
        assert isinstance(value["data"], str), "a byte object's data is not a string"
        raw = base64.b64decode(value["data"], validate=True)
        assert base64.b64encode(raw).decode() == value["data"]
        try:
            raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        else:
            raise AssertionError("UTF-8 bytes must use the JSON string form")
    assert b"\0" not in raw, "native value contains NUL"
    return raw


def check_byte_objects(node):
    if isinstance(node, dict):
        if node.get("encoding") == "base64":
            native_bytes(node)
        else:
            for value in node.values():
                check_byte_objects(value)
    elif isinstance(node, list):
        for value in node:
            check_byte_objects(value)


# ---------------------------------------------------------------------------
# Semantic rules: the port of ouro_jail::records::semantic (J5-C). Each checker
# returns every violation as (rule, where, detail); the rule identifiers and
# their citations are fixtures/semantic-cases.json's "rules".
# ---------------------------------------------------------------------------


def violations_in_bytes(node, at, out):
    if isinstance(node, dict):
        if node.get("encoding") == "base64":
            try:
                native_bytes(node)
            except (AssertionError, ValueError, UnicodeError) as error:
                out.append(("native_string", at, str(error) or "not a canonical native string"))
            return
        for key, value in node.items():
            violations_in_bytes(value, f"{at}.{key}", out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            violations_in_bytes(value, f"{at}[{index}]", out)


def decimal(value):
    return int(value) if isinstance(value, str) and DECIMAL.match(value) else None


def gap_interval(gap, at, out):
    start, end = decimal(gap.get("start_ns")), decimal(gap.get("end_ns"))
    if start is not None and end is not None and end < start:
        out.append(("gap_interval_reversed", at, f"ends at {end} before it starts at {start}"))


def semantic_receipt(record):
    out = []
    violations_in_bytes(record, "$", out)
    for path, items, key, rule in [
        ("$.credentials", record["credentials"], "id", "credential_id_unique"),
        ("$.applied.limits", record["applied"]["limits"], "key", "limit_key_unique"),
    ]:
        seen = set()
        for index, item in enumerate(items):
            value = json.dumps(item.get(key))
            if value in seen:
                out.append((rule, f"{path}[{index}]", f"duplicate {key} {value}"))
            seen.add(value)
    for name, coverage in record["coverage"].items():
        if coverage["status"] != "unsupported" and coverage["sources"]:
            source = coverage["sources"][0]
            if record["observer"]["sources"].get(source) == "unsupported":
                out.append(("coverage_source_unsupported", f"$.coverage.{name}", source))
        for index, gap in enumerate(coverage.get("gaps", [])):
            gap_interval(gap, f"$.coverage.{name}.gaps[{index}]", out)
    for index, gap in enumerate(record["observer"]["gaps"]):
        gap_interval(gap, f"$.observer.gaps[{index}]", out)
    return out


def is_note(event, kind):
    fields = event.get("fields") or {}
    return event.get("source") == "wrapper" and event.get("operation") == "note" and fields.get("kind") == kind


def semantic_event(event):
    out = []
    violations_in_bytes(event.get("fields"), "$.fields", out)
    if is_note(event, "coverage_gap"):
        gap_interval(event["fields"], "$.fields", out)
    return out


def is_loss_note(event):
    return is_note(event, "coverage_gap") and event["fields"].get("reason") == "trace_transport_loss"


def sequence_number(value):
    """A JSON integer, or a number without a fractional part (JSON Schema's
    `integer` admits 2.0), as Rust's semantic::sequence_number reads it."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, float) and value.is_integer() and 0 <= value < 2**53:
        return int(value)
    return None


def phase_may_follow(before, after):
    return before == after or (before, after) in {
        ("prepared", "enforced"), ("prepared", "settled"), ("prepared", "refused"), ("enforced", "settled")}


def semantic_trace(events):
    out = []
    for index, event in enumerate(events):
        out += [(rule, f"[{index}]{at[1:]}", detail) for rule, at, detail in semantic_event(event)]
    if events:
        for index, event in enumerate(events):
            if event.get("attempt_id") != events[0].get("attempt_id"):
                out.append(("trace_attempt_mixed", f"[{index}]", event.get("attempt_id")))
    # Holes are recorded loss only from the first loss note on (§13.3).
    first_loss = next((index for index, event in enumerate(events) if is_loss_note(event)), len(events))
    for source in ["wrapper", "audit", "proxy"]:
        numbered = [(index, sequence_number(event.get("source_seq"))) for index, event in enumerate(events)
                    if event.get("source") == source and sequence_number(event.get("source_seq")) is not None]
        backwards = [pair for pair in zip(numbered, numbered[1:]) if pair[1][1] <= pair[0][1]]
        if backwards:
            (_, before), (index, after) = backwards[0]
            out.append(("source_seq_order", f"[{index}]", f"{source} {after} after {before}"))
            continue
        for position, (index, seq) in enumerate(numbered):
            if index >= first_loss:
                break
            if seq != position + 1:
                out.append(("source_seq_gap", f"[{index}]", f"{source} {seq} where {position + 1} was due"))
                break
    previous = None
    for index, event in enumerate(events):
        phase = (event.get("fields") or {}).get("phase") if event.get("operation") == "jail.receipt" else None
        if not isinstance(phase, str):
            continue
        if previous is not None and not phase_may_follow(previous, phase):
            out.append(("receipt_note_order", f"[{index}]", f"{phase} after {previous}"))
        previous = phase
    return out


def receipt_digest(record):
    return hash_bytes(rfc8785.dumps(record))


def trace_ends_with(events, receipt):
    at = f"[{max(len(events) - 1, 0)}]"
    if not events:
        return [("trace_final_receipt", at, "an empty trace for an attempt with a receipt")]
    last = events[-1]
    fields = last.get("fields") or {}
    expected = ("wrapper", "jail.receipt", receipt["attempt_id"], receipt["phase"], receipt_digest(receipt))
    found = (last.get("source"), last.get("operation"), last.get("attempt_id"),
             fields.get("phase"), fields.get("receipt_digest"))
    out = [] if found == expected else [("trace_final_receipt", at, f"{found} is not {expected}")]
    return out + loss_recorded(events, receipt)


def loss_recorded(events, receipt):
    """The loss note and the final receipt's loss gaps agree (§13.3)."""
    recorded = [(cls, gap) for cls, entry in receipt["coverage"].items()
                for gap in entry.get("gaps", []) if gap.get("reason") == "trace_transport_loss"]
    note = next((event for event in events if is_loss_note(event)), None)
    if note is None:
        return [("trace_loss_recorded", f"$.coverage.{recorded[0][0]}", "no loss note")] if recorded else []
    fields = note["fields"]
    named = [name for name in fields.get("classes", []) if isinstance(name, str)]
    out = []
    for cls, gap in recorded:
        within = all(name in named for name in gap.get("classes", []))
        if gap.get("source") != fields.get("source") or gap.get("start_ns") != fields.get("start_ns") or not within:
            out.append(("trace_loss_recorded", f"$.coverage.{cls}", "not the note's loss"))
    for cls in named:
        status = receipt["coverage"].get(cls, {}).get("status")
        if isinstance(status, str) and status != "unsupported" and not any(name == cls for name, _ in recorded):
            out.append(("trace_loss_recorded", f"$.coverage.{cls}", "covered class without the loss"))
    return out


def kind_may_follow(before, after):
    return (before, after) in {
        ("prepared", "exec_confirmed"), ("prepared", "refused"), ("prepared", "settled"),
        ("prepared", "unsettled"), ("exec_confirmed", "settled"), ("exec_confirmed", "unsettled")}


def semantic_control(messages):
    out = []
    for index, message in enumerate(messages):
        if message.get("attempt_id") != messages[0].get("attempt_id"):
            out.append(("control_attempt_mixed", f"[{index}]", message.get("attempt_id")))
    for index, (before, after) in enumerate(zip(messages, messages[1:]), start=1):
        if isinstance(before.get("seq"), int) and isinstance(after.get("seq"), int) and after["seq"] <= before["seq"]:
            out.append(("control_seq_order", f"[{index}]", f"{after['seq']} after {before['seq']}"))
        if not kind_may_follow(before.get("kind"), after.get("kind")):
            out.append(("control_kind_order", f"[{index}]", f"{after.get('kind')} after {before.get('kind')}"))
    return out


def assert_clean(found, what):
    assert not found, (what, found)


def apply(record, change):
    if not change["path"]:
        return change["value"]  # an empty path replaces the whole instance
    node = record
    for part in change["path"][:-1]:
        node = node[part]
    last = change["path"][-1]
    if change.get("delete"):
        del node[last]
    else:
        node[last] = change["value"]
    return record


def check_semantic_corpus(validators):
    corpus = read("fixtures/semantic-cases.json")
    rules = set(corpus["rules"])
    named = set()
    positive = 0
    schema_of = {"receipt": "jail-receipt", "trace": "jail-event", "control": "jail-control"}
    for case in corpus["cases"]:
        record = read(case["base"])
        for change in case["changes"]:
            record = apply(record, change)
        instances = [record] if case["check"] == "receipt" else record
        for instance in instances:
            errors = [e.message for e in validators[schema_of[case["check"]]].iter_errors(instance)]
            assert not errors, (case["name"], "the schema must accept it", errors)
        if case["check"] == "receipt":
            found = semantic_receipt(record)
        elif case["check"] == "trace":
            found = semantic_trace(record)
            if "receipt" in case:
                found += trace_ends_with(record, read(case["receipt"]))
        else:
            found = semantic_control(record)
        expected = set(case["violations"])
        assert {rule for rule, _, _ in found} == expected, (case["name"], found)
        named |= expected
        positive += not expected
    assert positive and named == rules, ("every rule has a negative case", rules - named, named - rules)
    return len(corpus["cases"])


# ---------------------------------------------------------------------------
# The gate frame (§8.2): the port of ouro_jail::records::parse_release.
# ---------------------------------------------------------------------------


def parse_release(payload, expected, validator):
    if not payload:
        return "gate_closed"
    if len(payload) > 1024 or b"\r" in payload or not payload.endswith(b"\n") or b"\n" in payload[:-1]:
        return "gate_invalid"
    def no_duplicates(pairs):
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate object key")
        return dict(pairs)
    try:
        frame = json.loads(payload[:-1].decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, ValueError):
        return "gate_invalid"
    if list(validator.iter_errors(frame)):
        return "gate_invalid"
    if frame["attempt_id"] != expected["attempt_id"] or frame["policy_digest"] != expected["policy_digest"]:
        return "gate_invalid"
    return "release"


def check_gate_frames(validators):
    corpus = read("fixtures/gate-frames.json")
    for case in corpus["cases"]:
        if "frame" in case:
            payload = case["frame"].encode("utf-8")
        else:
            payload = base64.b64decode(case["frame_base64"], validate=True)
        result = parse_release(payload, corpus["expect"], validators["jail-gate"])
        assert result == case["result"], (case["name"], result)
    return len(corpus["cases"])


# ---------------------------------------------------------------------------
# The freeze (§13, §17): every wire schema's bytes are the frozen ones.
# ---------------------------------------------------------------------------


def check_loader_refuses_duplicate_ids():
    """The loader's own negative case: two files, one `$id`."""
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        for name in ["a.schema.json", "b.schema.json"]:
            (Path(directory) / name).write_text(json.dumps({"$id": "urn:ouro:schema:event:1"}))
        try:
            load_schemas(Path(directory))
        except AssertionError:
            return
        raise AssertionError("the schema loader accepted two files declaring one $id")


def check_frozen(schemas):
    manifest = tomllib.loads((ROOT / "frozen-schemas.toml").read_text())
    assert manifest["schema"] == "ouro.jail.frozen-schemas/1"
    frozen = {entry["file"]: entry for entry in manifest["frozen"]}
    unfrozen = {entry["file"] for entry in manifest.get("unfrozen", [])}
    for file in sorted(ROOT.glob("*.schema.json")):
        assert file.name in frozen or file.name in unfrozen, f"{file.name} is neither frozen nor unfrozen"
    for name, entry in frozen.items():
        raw = (ROOT / name).read_bytes()
        schema = json.loads(raw)
        actual = hashlib.sha256(raw).hexdigest()
        assert schema["$id"] == entry["id"], f"{name} declares {schema['$id']}, frozen as {entry['id']}"
        assert actual == entry["sha256"], (
            f"{name} changed under its frozen identifier {entry['id']} (sha256 {actual}); "
            "a breaking change needs a new identifier (jail-v1 §13)")
        assert "draft" not in schema["title"].lower(), f"{name} is frozen but titled {schema['title']!r}"
    return len(frozen)


def hash_bytes(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def policy_hash(snapshot):
    return hash_bytes(b"ouro.jail.policy/1\0" + rfc8785.dumps(snapshot))


def argv_frame(argv):
    raw = [native_bytes(value) for value in argv]
    return b"ouro.jail.argv/1\0" + struct.pack(">Q", len(raw)) + b"".join(
        struct.pack(">Q", len(value)) + value for value in raw
    )


def check_policy_sets(value):
    if isinstance(value, dict):
        for nested in value.values():
            check_policy_sets(nested)
    elif isinstance(value, list):
        encoded = [rfc8785.dumps(item) for item in value]
        assert encoded == sorted(set(encoded)), "noncanonical policy set"
        for item in value:
            check_policy_sets(item)


def check_canonical_fixtures(validators):
    snapshot = read("fixtures/policy-snapshot.json")
    validators["policy-snapshot"].validate(snapshot)
    check_byte_objects(snapshot)
    check_policy_sets(snapshot)
    for ceiling in snapshot["limits"].values():
        if ceiling is not None:
            assert 0 < int(ceiling["value"]) <= 2**64 - 1
    expected = read("fixtures/digests.json")
    canonical = (ROOT / "fixtures/policy.jcs").read_bytes()
    assert canonical == rfc8785.dumps(snapshot)
    assert not canonical.endswith(b"\n")
    assert policy_hash(snapshot) == expected["policy_digest"]
    assert argv_frame(expected["argv"]).hex() == expected["argv_preimage_hex"]
    assert hash_bytes(argv_frame(expected["argv"])) == expected["argv_digest"]
    assert hash_bytes(argv_frame(list(reversed(expected["argv"])))) != expected["argv_digest"]
    assert hash_bytes(argv_frame(["ab", "c"])) != hash_bytes(argv_frame(["a", "bc"]))
    assert hash_bytes(argv_frame([])) != hash_bytes(argv_frame([""]))
    changed = copy.deepcopy(snapshot)
    changed["limits"]["wall"]["value"] = "300001"
    assert policy_hash(changed) != expected["policy_digest"]
    changed = copy.deepcopy(snapshot)
    changed["environment"]["bindings"][0]["value"] = "changed"
    assert policy_hash(changed) != expected["policy_digest"]
    # This compares fixture declarations; it is not a production resolver.
    context = read("fixtures/canonical-context.json")
    for filename in ["canonical-input.toml", "canonical-equivalent.toml"]:
        config = tomllib.loads((ROOT / "fixtures" / filename).read_text())
        assert config["schema"] == "ouro.jail.policy/1"
        assert config["extends"] == snapshot["profile"]
        duration = re.fullmatch(r"([1-9][0-9]*)(ms|s|m|h)", config["limits"]["wall"])
        units = {"ms": 1, "s": 1000, "m": 60000, "h": 3600000}
        assert str(int(duration[1]) * units[duration[2]]) == snapshot["limits"]["wall"]["value"]
        assert str(config["limits"]["pids"]) == snapshot["limits"]["pids"]["value"]
        assert config["observation"] == snapshot["observation"]
        for key in ["read_only", "deny_read"]:
            declared = {
                posixpath.normpath(posixpath.join(context["profile_directory"], value))
                for value in config["filesystem"][key]
            }
            suffix = "fixtures" if key == "read_only" else "secrets"
            assert declared == {context["workspace"] + "/" + suffix}
            assert {"root": "workspace", "path": suffix} in snapshot["filesystem"][key]
    # Base64 validity, UTF-8 uniqueness and NUL are semantic codec constraints.
    for bad in [
        {"encoding": "base64", "data": "YWJj"},
        {"encoding": "base64", "data": "/w"},
        {"encoding": "base64", "data": "/x=="},
        {"encoding": "base64", "data": "AP8="},
        "bad\0path",
        "\ud800",
    ]:
        try:
            native_bytes(bad)
        except (AssertionError, ValueError, UnicodeError):
            continue
        raise AssertionError(f"invalid native value accepted: {bad!r}")


def check_network_fixtures():
    table = read("network-addresses.json")
    denied = {
        4: [ipaddress.ip_network(value) for value in table["ipv4_deny"]],
        6: [ipaddress.ip_network(value) for value in table["ipv6_deny"]],
    }
    public_v6 = ipaddress.ip_network(table["ipv6_default_public"])
    compatible = ipaddress.ip_network("::/96")
    cases = read("fixtures/network-cases.json")
    for case in cases:
        try:
            assert "%" not in case["input"]
            address = ipaddress.ip_address(case["input"])
            if address.version == 6 and address.ipv4_mapped:
                address = address.ipv4_mapped
            elif address.version == 6 and address in compatible and int(address) not in [0, 1]:
                raise ValueError("deprecated compatible address")
            result = "deny" if (
                any(address in prefix for prefix in denied[address.version])
                or (address.version == 6 and address not in public_v6)
            ) else "public"
            if "normalized" in case:
                assert str(address) == case["normalized"]
        except (ValueError, AssertionError):
            result = "reject"
        assert result == case["result"], (case, result)
    return len(cases)


def main():
    schemas = load_schemas(ROOT)
    check_loader_refuses_duplicate_ids()
    validators = build_validators(schemas)
    # J5-C: an example's schema is named by its file's prefix; checked-in
    # evidence receipts are product output and held to the same contract.
    prefixes = {"event-": "jail-event", "receipt-": "jail-receipt", "gate-": "jail-gate",
                "control-": "jail-control", "doctor-": "jail-doctor"}
    examples = sorted((ROOT / "examples").glob("*.json"))
    evidence = sorted((ROOT / "evidence").glob("*receipt*.json"))
    for file in examples + evidence:
        record = json.loads(file.read_text())
        kind = "jail-receipt" if file in evidence else next(
            schema for prefix, schema in prefixes.items() if file.name.startswith(prefix))
        errors = [e.message for e in validators[kind].iter_errors(record)]
        assert not errors, (file.name, errors)
        if kind == "jail-receipt":
            assert_clean(semantic_receipt(record), file.name)
        elif kind == "jail-event":
            assert_clean(semantic_event(record), file.name)
    cases = read("fixtures/validation-cases.json")
    for case in cases:
        record = read(case["base"])
        for change in case["changes"]:
            record = apply(record, change)
        errors = list(validators[case["schema"]].iter_errors(record))
        assert (not errors) == case["valid"], (case["name"], [e.message for e in errors])
        if not errors and case["schema"] == "jail-receipt":
            assert_clean(semantic_receipt(record), case["name"])
    semantic_count = check_semantic_corpus(validators)
    gate_count = check_gate_frames(validators)
    frozen_count = check_frozen(schemas)
    check_canonical_fixtures(validators)
    network_count = check_network_fixtures()
    print(f"PASS: {len(schemas)} schemas ({frozen_count} frozen), {len(examples)} examples, "
          f"{len(evidence)} evidence receipts, {len(cases)} validation cases,")
    print(f"      {semantic_count} semantic cases, {gate_count} gate frames, policy/argv golden bytes,")
    print(f"      native codec, and {network_count} address cases.")
    print("No live containment, observer, proxy, or platform execution was tested.")


if __name__ == "__main__":
    main()
