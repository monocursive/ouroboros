# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
"""Validate ledger schemas and canonical fixtures, never live durability.

Run: uv run docs/specs/ledger-v1/validate_contract.py
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import rfc8785

ROOT = Path(__file__).resolve().parent
JAIL = ROOT.parent / "jail-v1"
spec = importlib.util.spec_from_file_location("jail_contract", JAIL / "validate_contract.py")
jail = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jail)


def read(name):
    return json.loads((ROOT / "fixtures" / name).read_text())


def digest(record):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(record)).hexdigest()


def expect_invalid(validator, instance, label):
    assert not validator.is_valid(instance), f"invalid fixture accepted: {label}"


def main():
    jail_schemas = jail.load_schemas(JAIL)
    ledger_schemas = jail.load_schemas(ROOT)
    assert not set(jail_schemas) & set(ledger_schemas)
    validators = jail.build_validators(jail_schemas | ledger_schemas)
    request = read("request.json")
    source = read("source.json")
    canonical_source = read("canonical-source.json")
    prepared = read("prepared.json")
    owner = read("owner.json")
    run = read("run.json")
    for name, instance in [("request", request), ("jail-event", source),
                           ("source", canonical_source), ("record", prepared),
                           ("record", owner), ("record", canonical_source), ("run", run)]:
        validators[name].validate(instance)

    # Source composition preserves every value in the frozen producer envelope.
    writer_keys = {"run_id", "seq", "prev", "received_at", "provenance", "kind", "request_id"}
    recovered_source = {k: v for k, v in canonical_source.items() if k not in writer_keys}
    assert recovered_source == source
    validators["jail-event"].validate(recovered_source)
    assert ledger_schemas["source"]["$defs"] == jail_schemas["event"]["$defs"] | jail_schemas["jail-event"].get("$defs", {})
    for key, value in jail_schemas["event"]["properties"].items():
        assert ledger_schemas["source"]["properties"][key] == value, f"source property drift: {key}"
    assert ledger_schemas["source"]["allOf"] == jail_schemas["event"]["allOf"] + jail_schemas["jail-event"]["allOf"][1:]

    records = [prepared, owner, canonical_source]
    bytes_expected = b"".join(rfc8785.dumps(record) + b"\n" for record in records)
    assert (ROOT / "fixtures/records.ndjson").read_bytes() == bytes_expected
    previous = None
    for seq, record in enumerate(records, 1):
        assert record["seq"] == seq and record["prev"] == previous
        assert record["run_id"] == run["run_id"] and record["attempt_id"] == run["attempt_id"]
        previous = digest(record)
    assert run["chain"] == {"head_seq": len(records), "head_digest": previous}
    assert read("digests.json") == {"prepared": digest(prepared), "owner": digest(owner), "canonical_source": digest(canonical_source)}

    # Ledger admission can end in a proved native exec failure while preserving
    # the jail's refused phase. The run settles failure, never success or denial.
    failure = read("settled-exec-failure.json")
    failure_run = read("run-exec-failure.json")
    validators["record"].validate(failure)
    validators["run"].validate(failure_run)
    failure_records = [json.loads(line) for line in (ROOT / "fixtures/exec-failure-records.ndjson").read_text().splitlines()]
    assert (ROOT / "fixtures/exec-failure-records.ndjson").read_bytes() == b"".join(rfc8785.dumps(record) + b"\n" for record in failure_records)
    previous = None
    trace = []
    for seq, record in enumerate(failure_records, 1):
        validators["record"].validate(record)
        assert record["seq"] == seq and record["prev"] == previous
        assert record["run_id"] == failure_run["run_id"] and record["attempt_id"] == failure_run["attempt_id"]
        previous = digest(record)
        if record["kind"] == "source":
            trace.append({k: v for k, v in record.items() if k not in writer_keys})
    assert failure_records[-1] == failure
    assert failure_run["chain"] == {"head_seq": len(failure_records), "head_digest": previous}
    receipt = failure["body"]["receipt"]
    assert receipt["phase"] == "refused" and receipt["outcome"]["kind"] == "exec_error"
    assert failure_run["state"] == "settled" and failure_run["outcome"] == receipt["outcome"]
    assert failure["body"]["receipt_digest"] == digest(receipt)
    assert not jail.semantic_receipt(receipt)
    assert not jail.semantic_trace(trace)
    assert not jail.trace_ends_with(trace, receipt)
    for label, path, value in [
        ("generic admitted refusal", ["outcome", "kind"], "refused"),
        ("exec observed in refused receipt", ["exec_observed"], True),
        ("attempt tree not empty", ["lifetime", "tree_empty"], None),
        ("boundary integrity lost", ["lifetime", "integrity"], "lost"),
        ("only registered boundary verified", ["lifetime", "verification_scope"], "registered_boundary"),
    ]:
        altered = copy.deepcopy(failure)
        target = altered["body"]["receipt"]
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        expect_invalid(validators["record"], altered, label)

    altered = copy.deepcopy(request)
    altered["raw_argv"] = ["secret"]
    expect_invalid(validators["request"], altered, "raw argv in prepare")
    altered = copy.deepcopy(request)
    altered["io"]["actor"] = "owner"
    expect_invalid(validators["request"], altered, "identity in io plan")
    altered = copy.deepcopy(request)
    altered["capture"]["streams"] = ["stdout", "stdout"]
    expect_invalid(validators["request"], altered, "duplicate capture selection")
    altered = copy.deepcopy(canonical_source)
    altered["provenance"]["actor"] = "forged"
    expect_invalid(validators["source"], altered, "arbitrary actor")
    altered = copy.deepcopy(canonical_source)
    altered["operation"] = "intent.admitted"
    expect_invalid(validators["source"], altered, "producer intent forgery")
    altered = copy.deepcopy(canonical_source)
    altered["fields"]["raw_environment"] = "secret"
    expect_invalid(validators["source"], altered, "raw environment in source")
    altered = copy.deepcopy(prepared)
    altered["body"]["request_id"] = "x" * 128
    altered["request_id"] = "prepare:" + altered["body"]["request_id"]
    validators["record"].validate(altered)
    altered["request_id"] += "x"
    expect_invalid(validators["record"], altered, "overlong internal preparation namespace")
    altered = copy.deepcopy(prepared)
    altered["run_id"] = "../../escape"
    expect_invalid(validators["record"], altered, "path escape")
    altered = copy.deepcopy(canonical_source)
    altered["fields"]["transition"] = "changed"
    assert digest(altered) != digest(canonical_source)
    print("Ledger schemas, source preservation, canonical bytes, chain and privacy fixtures pass.")
    print("Document contract only; no live durability, launch or containment is tested.")


if __name__ == "__main__":
    main()
