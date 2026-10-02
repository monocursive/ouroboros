#!/usr/bin/env python3
"""Validate measured custody evidence without opening the production gate."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics

CASES = ("wall", "cancel", "root_death", "guardian_death", "ward_death",
         "guardian_stop", "ward_stop", "guardian_gap", "ward_gap", "both_death")
ROLES = {"root", "plain", "stubborn", "setsid", "double-fork", "spawn-group", "spawn-session"}
SOURCES = {"macos_es_pair.c", "macos_es_pair.py", "macos_es.c", "macos_es.py", "macos_native.c", "macos_native.py"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def token_key(token):
    require(isinstance(token, list) and len(token) == 8 and
            all(type(value) is int and 0 <= value < 2**32 for value in token), "invalid audit token")
    return token[5], token[7]


def timing(values):
    require(values and all(type(value) in (int, float) and math.isfinite(value) and value >= 0 for value in values),
            "invalid timing sample")
    ordered = sorted(values)
    return {"p50_ms": statistics.median(ordered), "p95_ms": ordered[math.ceil(.95 * len(ordered)) - 1]}


def summarize(result, source_directory, after):
    require(result["status"] == "single_custodian_failures_measured_full_lifetime_gate_open", "incomplete experiment")
    require(result["lifetime_contract_verified"] is False and result["production_execution_enabled"] is False,
            "evidence must not claim the production gate passed")
    require(result["fixture_cleanup_verified"] is True, "runner cleanup not verified")
    require(set(result["source_sha256"]) == SOURCES, "source inventory mismatch")
    require(after["helper_sha256"] == result["binary_sha256"], "helper changed after measurement")
    for name, expected in result["source_sha256"].items():
        actual = hashlib.sha256((source_directory / name).read_bytes()).hexdigest()
        require(actual == expected == after["tested_sources_sha256"][name], "tested source mismatch: " + name)
    cases = result["cases"]
    samples = {row["sample"] for row in cases}
    require(samples and samples == set(range(1, max(samples) + 1)), "noncontiguous samples")
    expected = {(sample, case) for sample in samples for case in CASES}
    actual = [(row["sample"], row["case"]) for row in cases]
    require(len(actual) == len(set(actual)) and set(actual) == expected, "missing or duplicate trial")
    auth = result.get("auth_exec_fail_closed", False)
    for row in cases:
        case = row["case"]
        require(row["lifetime_contract_verified"] is False and row["expected_mechanism_outcome"] is True,
                "unexpected mechanism claim")
        members = row["fixture_processes"]
        require(len(members) == len(ROLES) and {member["role"] for member in members} == ROLES, "fixture membership mismatch")
        keys = {token_key(member["audit_token"]) for member in members}
        require(len(keys) == len(ROLES), "duplicate fixture identity")
        for member in members:
            require(token_key(member["audit_token"]) == (member["pid"], member["pidversion"]), "fixture token mismatch")
            require(member["custody_fds_open"] is False, "workload inherited custody descriptor")
        attacks = row["custodian_signal_attacks"]
        require(len(attacks) == 4 and all(attack["rc"] == -1 and attack["errno"] == 1 for attack in attacks),
                "custodian signal protection not established")
        require({attack["target"] for attack in attacks} == {member["pid"] for member in row["custodians"].values()},
                "signal probes missed a custodian")
        for name in ("guardian_events", "ward_events"):
            events = row[name]
            observed = {token_key(event["token"]) for event in events if "token" in event}
            require(keys <= observed, "each client must independently observe known fixture members")
            require(not any(event.get("kind") == "signal_error" for event in events), "audit-token signal error")
            if auth:
                require([event for event in events if event.get("kind") == "auth_config"] == [
                    {"kind": "auth_config", "fail_closed": True, "deadline_max_ms": 250, "cache": False}],
                    "fail-closed AUTH_EXEC setup missing")
        require(set(row["after"]) == ROLES, "independent snapshot membership mismatch")
        alive = [member["alive"] for member in row["after"].values()]
        require(all(type(value) is bool for value in alive), "invalid liveness result")
        if case == "both_death":
            require(all(alive) and row["fixture_tree_empty_before_runner_cleanup"] is False,
                    "simultaneous-death counterexample lost")
            require(all(row["heartbeat_after"][role] > value for role, value in row["heartbeat_before"].items()),
                    "survivor workload activity missing")
        else:
            require(not any(alive) and row["fixture_tree_empty_before_runner_cleanup"] is True,
                    "known fixture survived a single failure")
            if case != "guardian_gap":
                require(row["intact_custodian_settlement"] is True and any(
                    event.get("kind") == "settled" and event["observed_live_members"] == 0 and
                    event["gap"] is False and event["synced"] is True and event["root_reaped"] is True
                    for event in row["guardian_events"] + row["ward_events"]), "intact final drain absent")
        if case.endswith("_gap"):
            events = row["guardian_events"] if case.startswith("guardian") else row["ward_events"]
            require(any(event.get("reason") == "event_integrity" for event in events) and
                    any(event.get("kind") == "settled" and event["gap"] is True for event in events),
                    "synthetic integrity fault not retained")
        if auth and case in ("guardian_stop", "ward_stop", "both_death"):
            probe = row["exec_probe"]
            if case == "both_death":
                require(probe["spawn_errno"] == 0 and probe["reaped"] is True and probe["wait_status"] == 0 and
                        probe["marker_created"] is True, "completed post-loss exec counterexample missing")
            else:
                failed = probe["spawn_errno"] != 0 or (probe["reaped"] is True and probe["wait_status"] != 0)
                require(failed and probe["marker_created"] is False, "paused-client exec probe completed")
    grouped = {}
    for case in CASES:
        selected = [row for row in cases if row["case"] == case]
        grouped[case] = {
            "trials": len(selected),
            "known_fixture_empty": sum(row["fixture_tree_empty_before_runner_cleanup"] for row in selected),
            "ready": timing([row["ready_ms"] for row in selected]),
            "independent_observation": timing([row["observation_ms"] for row in selected]),
        }
        probes = [row["exec_probe"] for row in selected if row.get("exec_probe")]
        if probes:
            grouped[case]["exec_probe"] = {
                "trials": len(probes), "markers_created": sum(probe["marker_created"] for probe in probes),
                "observation": timing([probe["observation_ms"] for probe in probes])}
    return {"trials": len(cases), "auth_exec_fail_closed": auth, "cases": grouped,
            "scope": "known controlled fixture processes in a development VM",
            "lifetime_contract_verified": False, "native_execution_ready": False,
            "remaining_gates": ["simultaneous custodian loss", "unobserved forks and real event loss",
                                "complete final tree drain", "actual PID reuse", "normal SIP with Apple-approved signature",
                                "filesystem, Mach, descriptor and agent compatibility conformance"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--after-hashes", type=Path, required=True)
    parser.add_argument("--lane", choices=("notify", "auth"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw = args.results.read_bytes()
    result = summarize(json.loads(raw), args.results.parent / "tested-source",
                       json.loads(args.after_hashes.read_text())[args.lane])
    result["results_sha256"] = hashlib.sha256(raw).hexdigest()
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"trials": result["trials"], "native_execution_ready": False}))


if __name__ == "__main__":
    main()
