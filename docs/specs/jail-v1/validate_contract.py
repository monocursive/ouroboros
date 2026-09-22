# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc8785==0.1.4"]
# ///
"""Validate specification artifacts, not live jail/backend conformance.

Run: uv run docs/specs/jail-v1/validate_contract.py
The checked-in fixture corpus is also input to the future Rust P01/R01 suite.
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
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent


def read(path):
    return json.loads((ROOT / path).read_text())


def native_bytes(value):
    if isinstance(value, str):
        raw = value.encode("utf-8", errors="strict")
    else:
        assert set(value) == {"encoding", "data"}
        assert value["encoding"] == "base64"
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


def semantic_receipt(record):
    check_byte_objects(record)
    ids = [item["id"] for item in record["credentials"]]
    assert len(ids) == len(set(ids)), "duplicate credential id"
    limits = [item["key"] for item in record["applied"]["limits"]]
    assert len(limits) == len(set(limits)), "duplicate limit"
    for name, coverage in record["coverage"].items():
        if coverage["status"] != "unsupported":
            source = coverage["sources"][0]
            assert record["observer"]["sources"][source] != "unsupported", name


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
    schemas = {file.stem.removesuffix(".schema"): json.loads(file.read_text())
               for file in ROOT.glob("*.schema.json")}
    registry = Registry()
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    validators = {
        name: Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        for name, schema in schemas.items()
    }
    examples = list((ROOT / "examples").glob("*.json"))
    for file in examples:
        record = json.loads(file.read_text())
        kind = "jail-event" if file.name.startswith("event-") else "jail-receipt"
        validators[kind].validate(record)
        if kind == "jail-receipt":
            semantic_receipt(record)
    cases = read("fixtures/validation-cases.json")
    for case in cases:
        record = read(case["base"])
        for change in case["changes"]:
            node = record
            for part in change["path"][:-1]:
                node = node[part]
            node[change["path"][-1]] = change["value"]
        errors = list(validators[case["schema"]].iter_errors(record))
        assert (not errors) == case["valid"], (case["name"], [e.message for e in errors])
        if not errors and case["schema"] == "jail-receipt":
            semantic_receipt(record)
    check_canonical_fixtures(validators)
    network_count = check_network_fixtures()
    print(f"PASS: {len(schemas)} schemas, {len(examples)} examples, {len(cases)} validation cases,")
    print(f"      policy/argv golden bytes, native codec, and {network_count} address cases.")
    print("No live containment, observer, proxy, or platform execution was tested.")


if __name__ == "__main__":
    main()
