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
freeze_spec = importlib.util.spec_from_file_location("ledger_freeze", ROOT / "freeze.py")
freeze = importlib.util.module_from_spec(freeze_spec)
freeze_spec.loader.exec_module(freeze)
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


def operator_tail_fixtures(validators):
    request = read("append-request.json")
    record = read("operator-intent.json")
    validators["append-request"].validate(request)
    validators["record"].validate(record)
    assert record["body"]["fields"] == request["intent"]["body"]
    for role in ["owner", "producer"]:
        altered = copy.deepcopy(record)
        altered["provenance"]["role"] = role
        expect_invalid(validators["record"], altered, "operator intent role forgery")
    for key in ["actor", "role", "provenance", "run_id", "attempt_id", "seq", "prev", "received_at", "token_id"]:
        altered = copy.deepcopy(request)
        altered["intent"]["body"][key] = "forged"
        expect_invalid(validators["append-request"], altered, "caller identity")
    for kind in ["admitted", "denied", "settled"]:
        altered = copy.deepcopy(request)
        altered["intent"].update(kind=kind, effect_id=None)
        expect_invalid(validators["append-request"], altered, "effect lifecycle without identity")
    for kind in ["owner_claimed", "source", "outcome_unknown", "hold"]:
        altered = copy.deepcopy(request)
        altered["intent"]["kind"] = kind
        expect_invalid(validators["append-request"], altered, "operator attempts owner mutation")
    page = read("tail-page.json")
    validators["tail"].validate(page)
    validators["tail-request"].validate({"run_id":page["run_id"], "cursor":page["next_cursor"]})
    assert len(page["ndjson"].encode()) <= 65536
    assert page["head"]["head_digest"] == digest(record)
    assert page["ndjson"].encode() == rfc8785.dumps(record) + b"\n"
    altered = copy.deepcopy(page)
    altered["next_cursor"] = None
    expect_invalid(validators["tail"], altered, "caught-up tail loses resume position")


def target_comparison_fixtures(validators):
    report = read("diff-target-page.json")
    validators["diff"].validate(report)
    assert report["mode"] == "target_counts" and report["total_changes"] == 2
    assert report["target_scope"]["exec"] == ["proc.exec"]
    assert report["classes"]["net"]["left_reason"] == "target_comparison_unsupported"
    assert json.loads(report["next_after"])["mode"] == "target_counts"
    assert report["changes"][0]["observation"]["target"]["path_basis"] == "argument_snapshot"
    for key in ["target_scope"]:
        altered = copy.deepcopy(report)
        del altered[key]
        expect_invalid(validators["diff"], altered, "missing target semantics")
    altered = copy.deepcopy(report)
    del altered["changes"][0]["observation"]["target"]
    expect_invalid(validators["diff"], altered, "target comparison without target")
    altered = copy.deepcopy(report)
    altered["mode"] = "event_counts"
    expect_invalid(validators["diff"], altered, "target comparison relabelled as count-only")
    altered = copy.deepcopy(report)
    altered["changes"][0]["observation"]["target"]["path"] = {"kind":"unavailable", "reason":"argument_not_read"}
    expect_invalid(validators["diff"], altered, "unknown path presented as comparable identity")
    altered = copy.deepcopy(report)
    altered["changes"][0]["observation"]["target"] = {"kind":"proxy_destination", "destination":"example.test:443"}
    validators["diff"].validate(altered)
    altered["changes"][0]["observation"]["target"]["destination"] = ""
    expect_invalid(validators["diff"], altered, "empty proxy identity")
    altered = copy.deepcopy(report)
    altered["right"]["unavailable_targets"] = {"exec":{"count":1,"first_record":{"seq":5,"provenance":report["changes"][0]["left_first_record"]["provenance"]}}}
    validators["diff"].validate(altered)
    altered["right"]["unavailable_targets"]["exec"]["count"] = 0
    expect_invalid(validators["diff"], altered, "zero missing-identity count")


def discovery_fixtures(validators):
    catalog = read("catalog-page.json")
    discovery = read("discovery-page.json")
    catalog_request = read("catalog-request.json")
    discovery_request = read("discovery-request.json")
    for name, instance in [("catalog", catalog), ("discovery", discovery),
                           ("catalog-request", catalog_request),
                           ("discovery-request", discovery_request)]:
        validators[name].validate(instance)
    assert catalog["snapshot"] == discovery["catalog_snapshot"]
    assert catalog["runs"][0] == discovery["run"]
    assert discovery["page"]["snapshot"] == discovery["run"]["chain"]
    assert discovery["page"]["run_id"] == discovery["run"]["run_id"]
    assert discovery["page"]["child_protection"] == discovery["run"]["child_protection"]
    assert discovery["page"]["records"][0]["provenance"]["role"] == "producer"
    assert json.loads(catalog["next_after"])["snapshot"] == catalog["snapshot"]
    assert json.loads(discovery["next_after"])["snapshot"] == catalog["snapshot"]
    for name, original, filter_key, maximum in [
            ("catalog-request", catalog_request, "filter", 100),
            ("discovery-request", discovery_request, "runs", 1000)]:
        for key, value in [("tags", ["blue", "blue"]), ("tags", ["x" * 65]),
                           ("tags", [str(i) for i in range(17)]),
                           ("launch", "../escape"), ("outcome", "success"),
                           ("since", "2026-02-30T00:00:00Z")]:
            altered = copy.deepcopy(original)
            altered[filter_key][key] = value
            expect_invalid(validators[name], altered, "invalid run filter")
        for key, value in [("limit", 0), ("limit", maximum + 1), ("after", "x" * 4097),
                           ("principal", "forged")]:
            altered = copy.deepcopy(original)
            altered[key] = value
            expect_invalid(validators[name], altered, "unbounded or attributed discovery")
    altered = copy.deepcopy(discovery_request)
    altered["filter"]["selector"] = "all"
    expect_invalid(validators["discovery-request"], altered, "discovery is not full export")
    request = read("request.json")
    request.update(launch="fixture-discovery", tags=["blue", "qa"])
    validators["request"].validate(request)
    for key, value in [("tags", ["blue", "blue"]), ("tags", ["x" * 65]),
                       ("launch", "../escape"), ("launch", None)]:
        altered = copy.deepcopy(request)
        altered[key] = value
        expect_invalid(validators["request"], altered, "invalid immutable metadata")
    altered = copy.deepcopy(catalog)
    altered["runs"] *= 101
    expect_invalid(validators["catalog"], altered, "unbounded summary count")
    altered = copy.deepcopy(catalog)
    altered["runs"][0]["child_protection"] = "probably_safe"
    expect_invalid(validators["catalog"], altered, "invented catalog protection")
    empty = {**discovery, "matched_runs": 0, "run": None, "page": None,
             "next_after": None, "done": True}
    validators["discovery"].validate(empty)


def reader_fixtures(validators, records, run):
    request = read("read-request.json")
    page = read("read-page.json")
    unobserved = read("read-page-unobserved.json")
    incomplete = read("read-page-incomplete.json")
    finished = read("export-finished.json")
    checkpoint = read("export-checkpoint.json")
    for name, instance in [("read-request", request), ("read", page),
                           ("read", unobserved), ("read", incomplete),
                           ("export", finished), ("export", checkpoint)]:
        validators[name].validate(instance)
    assert page["records"] == [records[4]], "reader altered stored source attribution"
    assert page["snapshot"] == finished["snapshot"] == checkpoint["snapshot"] == run["chain"]
    assert page["child_protection"] == run["child_protection"]
    assert len(page["ndjson"].encode("utf-8")) <= 65536
    assert sum(len(rfc8785.dumps(record)) + 1 for record in page["records"]) <= 131072
    canonical_bytes = (ROOT / "fixtures/exec-failure-records.ndjson").read_bytes()
    assert finished["bytes_written"] == len(canonical_bytes)
    assert checkpoint["bytes_written"] == len(canonical_bytes.splitlines(keepends=True)[0])
    assert unobserved["records"] == [] and unobserved["coverage"]["selection_status"] == "unobserved"
    assert unobserved["child_protection"] == "unprotected"
    assert incomplete["records"] == page["records"] and not incomplete["local_consistency"]
    assert incomplete["stream_status"] == "incomplete" and incomplete["problems"]

    for limit in [0, 1001]:
        altered = copy.deepcopy(request)
        altered["limit"] = limit
        expect_invalid(validators["read-request"], altered, "unbounded reader limit")
    for label, key, value in [("caller principal", "principal", "forged"),
                              ("cursor shape", "cursor", "arbitrary-token")]:
        altered = copy.deepcopy(request)
        altered[key] = value
        expect_invalid(validators["read-request"], altered, label)
    for label, key, value in [("decision is not a stage", "stage", "decision"),
                              ("filtered full export", "selector", "all"),
                              ("invalid calendar date", "since", "2026-02-30T12:00:00Z")]:
        altered = copy.deepcopy(request)
        altered["filter"][key] = value
        expect_invalid(validators["read-request"], altered, label)
    altered = copy.deepcopy(page)
    altered["records"][0]["inferred_action"] = "exec succeeded"
    expect_invalid(validators["read"], altered, "embellished source record")
    altered = copy.deepcopy(page)
    altered["ndjson"] = "{}\n"
    expect_invalid(validators["read"], altered, "mixed query and export payload")
    altered = copy.deepcopy(page)
    altered["coverage"]["classes"]["exec"]["observed_count"] = "unbounded payload"
    expect_invalid(validators["read"], altered, "non-numeric observed count")
    altered = copy.deepcopy(finished)
    altered["next_cursor"] = "f" * 64
    expect_invalid(validators["export"], altered, "finished status retains a cursor")
    altered = copy.deepcopy(checkpoint)
    altered["done"] = True
    expect_invalid(validators["export"], altered, "checkpoint claims completion")
    altered = copy.deepcopy(finished)
    altered["ndjson"] = canonical_bytes.decode()
    expect_invalid(validators["export"], altered, "record bytes in status metadata")


def pruning_fixtures(validators, run, records):
    """Synthetic retained metadata: shape and checksum checks, not deletion proof."""
    replay = {}
    replay_hash = hashlib.sha256()
    writer_keys = {"run_id", "seq", "prev", "received_at", "provenance", "kind", "request_id"}
    for record in records:
        if record["kind"] == "source":
            original = {"kind": "source", "request_id": record["request_id"],
                        "body": {k: v for k, v in record.items() if k not in writer_keys}}
        else:
            original = {k: v for k, v in record.items()
                        if k not in {"schema", "run_id", "attempt_id", "seq", "prev", "received_at", "provenance"}}
        receipt = {"seq": record["seq"], "digest": digest(record)}
        identity = rfc8785.dumps({"request_id": record["request_id"],
                                 "effect_id": record.get("effect_id"),
                                 "payload_digest": digest(original), **receipt})
        replay_hash.update(len(identity).to_bytes(8, "little"))
        replay_hash.update(identity)
        replay[record["request_id"]] = {"digest": digest(original), "receipt": receipt}
        if record.get("effect_id"):
            replay[f'effect:{record["kind"]}:{record["effect_id"]}'] = replay[record["request_id"]]
    data = b"".join(rfc8785.dumps(record) + b"\n" for record in records)
    segment = {"name": "events-0001.ndjson", "first_seq": 1, "last_seq": len(records),
               "bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
               "head_digest": run["chain"]["head_digest"]}
    manifest = {"schema": "ouro.ledger.segments/2", "run_id": run["run_id"],
                "attempt_id": run["attempt_id"], "segments": [segment],
                "replay_digest": "sha256:" + replay_hash.hexdigest()}
    retained = {"schema": "ouro.ledger.gc-anchor/1", "run": run, "manifest": manifest,
                "replay": replay, "strict_source_loss": False,
                "last_activity_at": max(record["received_at"] for record in records),
                "collected_at": "2026-10-05T12:00:00Z", "cutoff": "2026-10-04T12:00:00Z",
                "retain_days": 1, "operator": run["owner"],
                "files": [{"path": segment["name"], "bytes": len(data), "digest": segment["digest"],
                           "device": 1, "inode": 1}]}
    envelope = {"digest": digest(retained), "retained": retained}
    validators["gc-anchor"].validate(envelope)
    complete = {"schema": "ouro.ledger.gc-complete/1", "anchor_digest": envelope["digest"]}
    validators["gc-complete"].validate(complete)
    # Capture-only authority binds a terminal chain but never inventories events.
    capture = {"stdout": {"state": "captured", "stored_bytes": 0},
               "stderr": {"state": "not_captured"}}
    captured = {"schema": "ouro.ledger.capture-gc-anchor/1", "run_id": run["run_id"],
                "attempt_id": run["attempt_id"], "chain": run["chain"], "capture": capture,
                **{k: retained[k] for k in ["last_activity_at", "collected_at", "cutoff", "retain_days", "operator"]},
                "files": [{"path": "artifacts/stdout.bin", "bytes": 0,
                           "digest": "sha256:" + hashlib.sha256(b"").hexdigest(), "device": 1, "inode": 2}]}
    capture_envelope = {"digest": digest(captured), "retained": captured}
    validators["capture-gc-anchor"].validate(capture_envelope)
    validators["capture-gc-complete"].validate({"schema": "ouro.ledger.capture-gc-complete/1", "anchor_digest": digest(captured)})
    all_captures = copy.deepcopy(capture_envelope)
    all_captures["retained"]["files"] = [
        {**captured["files"][0], "path": f"artifacts/{name}.bin"}
        for name in ("stdout", "stderr", "argv")
    ]
    validators["capture-gc-anchor"].validate(all_captures)
    all_history = copy.deepcopy(envelope)
    all_history["retained"]["files"] += all_captures["retained"]["files"]
    validators["gc-anchor"].validate(all_history)
    for path in ["events-0001.ndjson", "../escape", "artifacts/vendor-state"]:
        altered = copy.deepcopy(capture_envelope)
        altered["retained"]["files"][0]["path"] = path
        expect_invalid(validators["capture-gc-anchor"], altered, "capture-only authority may not delete other files")
    history = {"state": "pruned", "anchor_digest": envelope["digest"],
               "collected_at": retained["collected_at"]}
    result = {"schema": "ouro.ledger.gc-result/1", "retain_days": 1,
              "pruned": [{"run_id": run["run_id"], "chain": run["chain"], "history": history,
                          "removed_files": 1, "removed_bytes": len(data)}],
              "kept": [], "failed": [], "next_after": None}
    validators["gc-result"].validate(result)
    capture_result = {**result, "pruned": [], "capture_retain_days": 1,
                      "captures_pruned": [{"run_id": run["run_id"], "chain": run["chain"],
                                           "capture_history": {**history, "anchor_digest": digest(captured)},
                                           "removed_files": 1, "removed_bytes": 0}]}
    validators["gc-result"].validate(capture_result)
    validators["run"].validate({**run, "capture_history": history})
    for state in ["pruning", "pruned"]:
        validators["run"].validate({**run, "history": {**history, "state": state}})
    for path in ["../escape", "artifacts/../stdout.bin", "artifacts/vendor-state", "run.json"]:
        altered = copy.deepcopy(envelope)
        altered["retained"]["files"][0]["path"] = path
        expect_invalid(validators["gc-anchor"], altered, "unsafe deletion inventory path")
    for key, value in [("holds", ["operator"]), ("history", history), ("state", "outcome_unknown")]:
        altered = copy.deepcopy(envelope)
        altered["retained"]["run"][key] = value
        expect_invalid(validators["gc-anchor"], altered, "ineligible retained run")
    altered = copy.deepcopy(envelope)
    altered["retained"]["files"][0].update(path="artifacts/stdout.bin", bytes=16777217)
    expect_invalid(validators["gc-anchor"], altered, "unbounded capture inventory")
    altered = copy.deepcopy(result)
    altered["pruned"][0]["history"]["state"] = "pruning"
    expect_invalid(validators["gc-result"], altered, "unfinished pruning claims a receipt")
    altered = {**complete, "anchor_digest": "sha256:invalid"}
    expect_invalid(validators["gc-complete"], altered, "invalid completion anchor")


def bundle_fixtures(validators):
    manifest = read("bundle.json")
    report = read("bundle-verification.json")
    validators["bundle"].validate(manifest)
    validators["bundle-verification"].validate(report)
    events = (ROOT / "fixtures" / "bundle-events.ndjson").read_bytes()
    members = {item["name"]: item for item in manifest["files"]}
    for name, data in [("events.ndjson", events), ("receipts.json", rfc8785.dumps(manifest["run"]["receipts"]) + b"\n")]:
        assert members[name]["bytes"] == len(data)
        assert members[name]["digest"] == "sha256:" + hashlib.sha256(data).hexdigest()
    for line in events.splitlines():
        record = json.loads(line)
        validators["record"].validate(record)
        assert rfc8785.dumps(record) == line
    assert report["snapshot"] == manifest["run"]["chain"]
    assert report["manifest_digest"] == "sha256:" + hashlib.sha256(rfc8785.dumps(manifest) + b"\n").hexdigest()
    for key, value in [("authenticity", "signed"), ("capture_digest_basis", "launch_time")]:
        altered = copy.deepcopy(manifest)
        altered[key] = value
        expect_invalid(validators["bundle"], altered, "unsupported authenticity claim")
    for name in ["../events.ndjson", "vendor-state", "environment.bin"]:
        altered = copy.deepcopy(manifest)
        altered["files"][0]["name"] = name
        expect_invalid(validators["bundle"], altered, "unsafe or unsupported member")
    altered = copy.deepcopy(manifest)
    altered["files"].append(altered["files"][0])
    expect_invalid(validators["bundle"], altered, "duplicate canonical member")
    altered = copy.deepcopy(manifest)
    altered["files"][0]["bytes"] = 67108865
    expect_invalid(validators["bundle"], altered, "oversized stream")
    for key, value in [("external_custody", True), ("authenticity", "signed"), ("local_consistency", False)]:
        altered = copy.deepcopy(report)
        altered[key] = value
        expect_invalid(validators["bundle-verification"], altered, "invalid successful verification claim")


def signed_bundle_fixtures(validators):
    manifest = read("bundle-v2.json")
    envelope = read("bundle-signature.json")
    public = read("signer.json")
    trusted = read("bundle-verification-v2.json")
    untrusted = read("bundle-verification-untrusted.json")
    for name, value in [("bundle-v2", manifest), ("bundle-signature", envelope),
                        ("signer", public), ("bundle-verification-v2", trusted),
                        ("bundle-verification-v2", untrusted)]:
        validators[name].validate(value)
    assert trusted["signature"]["trust"] == "pinned"
    assert untrusted["signature"]["trust"] == "untrusted"
    assert trusted["external_custody"] is False
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(manifest) + b"\n").hexdigest()
    assert envelope["manifest_digest"] == trusted["manifest_digest"] == expected
    assert envelope["public_key"] == public["public_key"] == trusted["signature"]["public_key"]
    assert envelope["key_id"] == public["key_id"] == "sha256:" + hashlib.sha256(bytes.fromhex(public["public_key"])).hexdigest()
    events = (ROOT / "fixtures" / "bundle-v2-events.ndjson").read_bytes()
    member = next(f for f in manifest["files"] if f["name"] == "events.ndjson")
    assert member["digest"] == "sha256:" + hashlib.sha256(events).hexdigest()
    for line in events.splitlines():
        validators["record"].validate(json.loads(line))
    altered = copy.deepcopy(manifest)
    altered["authenticity"] = "unsigned"
    expect_invalid(validators["bundle-v2"], altered, "v2 signature downgrade")
    for name, value in [("signer", public), ("bundle-signature", envelope)]:
        altered = copy.deepcopy(value)
        altered["algorithm"] = "rsa"
        expect_invalid(validators[name], altered, "unsupported signer algorithm")
        altered = copy.deepcopy(value)
        altered["public_key"] += "00"
        expect_invalid(validators[name], altered, "oversized public key")
    altered = copy.deepcopy(trusted)
    del altered["signature"]
    expect_invalid(validators["bundle-verification-v2"], altered, "signature status omitted")
    altered = copy.deepcopy(trusted)
    altered["external_custody"] = True
    expect_invalid(validators["bundle-verification-v2"], altered, "signature upgrades custody")


def transcript_fixtures(validators):
    absent = {"state": "not_captured", "displayed_bytes": 0, "display_truncated": False}
    report = {"schema": "ouro.ledger.show/1", "run": read("run.json"), "transcript": {
        "schema": "ouro.ledger.transcript/1", "limit_bytes_per_stream": 65536,
        "encoding": "escaped_bytes", "integrity": "unverified_local_artifact",
        "streams": {name: copy.deepcopy(absent) for name in ("stdout", "stderr", "argv")},
    }}
    validators["show"].validate(report)
    for state in ("captured", "truncated", "incomplete"):
        report["transcript"]["streams"]["stdout"] = {
            "state": state, "displayed_bytes": 4, "display_truncated": False,
            "stored_bytes": 4, "text": r"hi\n\xff",
        }
        report["transcript"]["streams"]["argv"] = copy.deepcopy(report["transcript"]["streams"]["stdout"])
        validators["show"].validate(report)
    for key, value in (("text", "\x1b[31m"), ("displayed_bytes", 65537), ("state", "pruned")):
        altered = copy.deepcopy(report)
        altered["transcript"]["streams"]["stdout"][key] = value
        expect_invalid(validators["show"], altered, "unsafe or unbounded transcript")
    altered = copy.deepcopy(report)
    altered["transcript"]["integrity"] = "verified"
    expect_invalid(validators["show"], altered, "transcript invents integrity")


def main():
    print(f"ledger milestone-2 contract freeze: {freeze.check()} files match")
    jail_schemas = jail.load_schemas(JAIL)
    ledger_schemas = jail.load_schemas(ROOT)
    assert not set(jail_schemas) & set(ledger_schemas)
    validators = jail.build_validators(jail_schemas | ledger_schemas)
    operator_tail_fixtures(validators)
    discovery_fixtures(validators)
    target_comparison_fixtures(validators)
    bundle_fixtures(validators)
    signed_bundle_fixtures(validators)
    transcript_fixtures(validators)
    for suffix in ("", "-v2"):
        manifest = read(f"bundle{suffix}.json")
        manifest["files"] = [f for f in manifest["files"] if f["name"] in ("events.ndjson", "receipts.json")]
        for name in ("stdout", "stderr", "argv"):
            manifest["files"].append({"name": f"{name}.bin", "bytes": 0, "digest": "sha256:" + hashlib.sha256(b"").hexdigest()})
        validators[f"bundle{suffix}"].validate(manifest)
        oversized = copy.deepcopy(manifest)
        oversized["files"][-1]["bytes"] = 16777217
        expect_invalid(validators[f"bundle{suffix}"], oversized, "unbounded argv capture")
        duplicate = copy.deepcopy(manifest)
        duplicate["files"][-2] = duplicate["files"][-1]
        expect_invalid(validators[f"bundle{suffix}"], duplicate, "duplicate argv capture")
        report = read(f"bundle-verification{suffix}.json")
        report["captures"] = ["stdout", "stderr", "argv"]
        validators[f"bundle-verification{suffix}"].validate(report)
    query = read("query-page.json")
    comparison = read("diff-page.json")
    validators["query"].validate(query)
    validators["diff"].validate(comparison)
    assert query["pages"][0]["run_id"] != query["pages"][1]["run_id"]
    assert comparison["mode"] == "event_counts" and comparison["total_changes"] == 2
    assert comparison["comparison_status"] == "partial"
    assert comparison["classes"]["proxy.net"]["left_reason"] == "unobserved"
    position = json.loads(comparison["next_after"])
    assert position["left_head"] == comparison["left"]["snapshot"]
    assert position["right_head"] == comparison["right"]["snapshot"]
    altered = copy.deepcopy(comparison)
    altered["right"]["child_protection"] = "unprotected"
    validators["diff"].validate(altered)
    altered["right"]["child_protection"] = "probably_safe"
    expect_invalid(validators["diff"], altered, "invented comparison protection")
    altered = copy.deepcopy(query)
    altered["pages"] *= 5
    expect_invalid(validators["query"], altered, "unbounded cross-run fanout")
    request = read("request.json")
    detached = copy.deepcopy(request)
    detached["owner_lifetime"] = "systemd_user_service"
    detached["io"]["mode"] = "batch"
    validators["request"].validate(detached)
    altered = copy.deepcopy(detached)
    altered["io"]["mode"] = "foreground"
    expect_invalid(validators["request"], altered, "detached foreground streams")
    altered = copy.deepcopy(detached)
    altered["owner_lifetime"] = "unchecked_double_fork"
    expect_invalid(validators["request"], altered, "unproved owner independence")
    source = read("source.json")
    canonical_source = read("canonical-source.json")
    prepared = read("prepared.json")
    owner = read("owner.json")
    run = read("run.json")
    for name, instance in [("request", request), ("jail-event", source),
                           ("source", canonical_source), ("record", prepared),
                           ("record", owner), ("record", canonical_source), ("run", run)]:
        validators[name].validate(instance)

    # Retention intents are canonical operator records, never owner observations.
    for kind in ["hold", "release"]:
        intent = copy.deepcopy(prepared)
        intent.update(kind=kind, request_id=f"retention-{kind}", body={})
        validators["record"].validate(intent)
        for key, value in [("body", {"actor": "operator"}), ("effect_id", "forged")]:
            altered = copy.deepcopy(intent)
            altered[key] = value
            expect_invalid(validators["record"], altered, "forged retention payload")
        for key, value in [("role", "owner"), ("token_id", "a" * 32)]:
            altered = copy.deepcopy(intent)
            altered["provenance"][key] = value
            expect_invalid(validators["record"], altered, "forged retention authority")
    held = copy.deepcopy(run)
    held["holds"] = ["operator"]
    validators["run"].validate(held)
    for holds in [["operator", "operator"], ["invented"]]:
        held["holds"] = holds
        expect_invalid(validators["run"], held, "invalid operator holds")
    gc = read("gc-plan.json")
    validators["gc-plan"].validate(gc)
    captured_gc = copy.deepcopy(gc)
    captured_gc.update(capture_retain_days=7, capture_cutoff=gc["cutoff"])
    for candidate in captured_gc["runs"]:
        candidate.update(captures_candidate=False, captures_keep_reasons=["operator_hold"])
    validators["gc-plan"].validate(captured_gc)
    captured_gc["runs"][0]["captures_candidate"] = True
    expect_invalid(validators["gc-plan"], captured_gc, "capture candidate has keep reasons")
    for key, value in [("dry_run", False), ("deletion_supported", False),
                       ("verification_required", False), ("retain_days", 0),
                       ("retain_days", 36501), ("next_after", "../escape"),
                       ("runs", gc["runs"] * 101)]:
        altered = copy.deepcopy(gc)
        altered[key] = value
        expect_invalid(validators["gc-plan"], altered, "unsafe retention preview")
    altered = copy.deepcopy(gc)
    altered["runs"][0]["candidate"] = True
    expect_invalid(validators["gc-plan"], altered, "candidate has keep reasons")
    altered["runs"][0]["keep_reasons"] = []
    validators["gc-plan"].validate(altered)

    # Redaction extends writer metadata, not the frozen Jail schema.
    redacted = copy.deepcopy(canonical_source)
    redacted.update(json.loads((JAIL / "examples/event-open.json").read_text()))
    redacted["fields"]["path"] = {"kind":"unavailable", "reason":"ledger_redacted"}
    redacted["redaction"] = {"schema":"ouro.ledger.redaction/1", "fields":["path"]}
    validators["record"].validate(redacted)
    for marker in [{"schema":"wrong", "fields":["path"]},
                   {"schema":"ouro.ledger.redaction/1", "fields":["outcome"]},
                   {"schema":"ouro.ledger.redaction/1", "fields":["path","path"]}]:
        redacted["redaction"] = marker
        expect_invalid(validators["record"], redacted, "invalid redaction marker")
    for selectors in [["paths"], ["destinations"], ["destinations","paths"]]:
        policy = read("request.json") | {"redact":selectors}
        validators["request"].validate(policy)
    for selectors in [[], ["paths","paths"], ["paths","destinations"], ["all"], None]:
        policy = read("request.json") | {"redact":selectors}
        expect_invalid(validators["request"], policy, "invalid redaction policy")

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

    # A manifest anchors canonical bytes and ordered immutable replay receipts.
    replay_hash = hashlib.sha256()
    for record in records:
        if record["kind"] == "source":
            original = {"kind": "source", "request_id": record["request_id"],
                        "body": {k: v for k, v in record.items() if k not in writer_keys}}
        else:
            original = {k: v for k, v in record.items()
                        if k not in {"schema", "run_id", "attempt_id", "seq", "prev", "received_at", "provenance"}}
        identity = rfc8785.dumps({"request_id": record["request_id"],
                                 "effect_id": record.get("effect_id"),
                                 "payload_digest": digest(original),
                                 "seq": record["seq"], "digest": digest(record)})
        replay_hash.update(len(identity).to_bytes(8, "little"))
        replay_hash.update(identity)
    manifest = {"schema": "ouro.ledger.segments/1", "run_id": run["run_id"],
                "attempt_id": run["attempt_id"],
                "segment": {"name": "events-0001.ndjson", "first_seq": 1,
                            "last_seq": len(records), "bytes": len(bytes_expected),
                            "digest": "sha256:" + hashlib.sha256(bytes_expected).hexdigest(),
                            "head_digest": previous},
                "replay_digest": "sha256:" + replay_hash.hexdigest()}
    validators["segments"].validate(manifest)
    for key, value in [("name", "../escape"), ("first_seq", 0),
                       ("digest", "sha256:invalid"), ("last_seq", 0)]:
        altered = copy.deepcopy(manifest)
        altered["segment"][key] = value
        expect_invalid(validators["segments"], altered, "unsafe segment anchor")

    # Version 2 preserves the legacy anchors and adds an ordered segment array.
    rotated = copy.deepcopy(manifest)
    rotated["schema"] = "ouro.ledger.segments/2"
    rotated["segments"] = [rotated.pop("segment")]
    validators["segments"].validate(rotated)
    for key, value in [("name", "../escape"), ("first_seq", 0),
                       ("digest", "sha256:invalid"), ("bytes", 0)]:
        altered = copy.deepcopy(rotated)
        altered["segments"][0][key] = value
        expect_invalid(validators["segments"], altered, "unsafe rotated segment")
    altered = copy.deepcopy(rotated)
    altered["segments"] = []
    expect_invalid(validators["segments"], altered, "empty rotated manifest")
    altered = copy.deepcopy(rotated)
    altered["segment"] = manifest["segment"]
    expect_invalid(validators["segments"], altered, "mixed manifest versions")

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
    pruning_fixtures(validators, failure_run, failure_records)
    assert failure_run["chain"] == {"head_seq": len(failure_records), "head_digest": previous}
    receipt = failure["body"]["receipt"]
    assert receipt["phase"] == "refused" and receipt["outcome"]["kind"] == "exec_error"
    assert failure_run["state"] == "settled" and failure_run["outcome"] == receipt["outcome"]
    assert failure["body"]["receipt_digest"] == digest(receipt)
    assert not jail.semantic_receipt(receipt)
    assert not jail.semantic_trace(trace)
    assert not jail.trace_ends_with(trace, receipt)
    reader_fixtures(validators, failure_records, failure_run)
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

    for names in (["argv"], ["stdout", "stderr", "argv"]):
        selected = copy.deepcopy(request)
        selected["capture"]["streams"] = names
        validators["request"].validate(selected)
    for mode in ("foreground", "batch"):
        control = copy.deepcopy(request)
        control["io"] = {"mode": mode, "pty": False, "control": "separate_fd"}
        validators["request"].validate(control)
    control["owner_lifetime"] = "systemd_user_service"
    expect_invalid(validators["request"], control, "detached owner cannot depend on client fd")
    for role in (3, None, "stdout", "separate"):
        control = copy.deepcopy(request)
        control["io"]["control"] = role
        expect_invalid(validators["request"], control, "control role must be separate fd without process-local number")
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
    recovered = copy.deepcopy(canonical_source)
    recovered["provenance"].update(role="recovery", token_id=None)
    validators["source"].validate(recovered)
    validators["record"].validate(recovered)
    recovered["provenance"]["token_id"] = "a" * 32
    expect_invalid(validators["source"], recovered, "recovery cannot claim a live producer token")
    gap = copy.deepcopy(prepared)
    gap.update(kind="evidence_gap", request_id="outage:1", body={"reason": "writer_outage", "episode": 1, "owner": owner["body"]["owner"]})
    gap["provenance"].update(role="recovery", token_id=None)
    validators["record"].validate(gap)
    gap["provenance"]["role"] = "owner"
    expect_invalid(validators["record"], gap, "outage marker requires recovery provenance")
    admission = copy.deepcopy(prepared)
    admission["provenance"].update(role="recovery", token_id=None)
    expect_invalid(validators["record"], admission, "recovery cannot prepare a run")
    print("Ledger schemas, bounded readers, source preservation, canonical bytes, chain and privacy fixtures pass.")
    print("Document contract only; no live durability, launch or containment is tested.")


if __name__ == "__main__":
    main()
