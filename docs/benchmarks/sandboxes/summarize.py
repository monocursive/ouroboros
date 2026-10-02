#!/usr/bin/env python3
"""Recompute only successful, complete, same-host comparisons from raw launches."""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import statistics

CASES = {"noop", "python", "git", "reads", "writes", "spawn", "cpu"}


def evaluate(metadata, status, complete, raw):
    problems = []
    if hashlib.sha256(raw).hexdigest() != complete["launches_sha256"]:
        problems.append("raw launch digest mismatch")
    if complete["binary_sha256_after"] != metadata["hashes"]["bin/ouro-jail"]:
        problems.append("ouro-jail binary changed")
    try:
        rows = [json.loads(line) for line in raw.splitlines()]
    except ValueError:
        return {"valid": False, "problems": problems + ["invalid launch JSON"], "available": status["available"], "rows": [], "comparisons": []}
    groups = defaultdict(list)
    sequences = set()
    for row in rows:
        if row["sequence"] in sequences: problems.append("duplicate sequence")
        sequences.add(row["sequence"])
        if row["phase"] != "measurement": continue
        tool, case = row["tool"], row["case"]
        groups[tool, case].append(row)
        records = row["records"]
        reference = status["reference"].get(case)
        if row["exit"] or row["timeout"] or len(records) != 1 or not reference or any(records[0].get(k) != v for k, v in reference.items()):
            problems.append("invalid completed work at sequence " + str(row["sequence"]))
        if tool == "ouro-jail":
            receipt = row.get("receipt", {})
            coverage = receipt.get("coverage", {})
            if not coverage or receipt.get("lifetime", {}).get("tree_empty") is not True or receipt.get("outcome", {}).get("kind") != "exited" or receipt.get("outcome", {}).get("code") != 0 or any(c["gaps"] for c in coverage.values()):
                problems.append("unsettled or incomplete ouro receipt at sequence " + str(row["sequence"]))
    expected = {(tool, case) for tool, available in status["available"].items() if available for case in CASES}
    if set(groups) != expected: problems.append("missing or unexpected comparison arms")
    summaries = []
    for (tool, case), group in sorted(groups.items()):
        rounds = [row["round"] for row in group]
        if len(group) != metadata["samples"] or set(rounds) != set(range(metadata["samples"])):
            problems.append("missing or duplicate rounds for " + tool + "/" + case)
        elapsed = sorted(row["elapsed_ms"] for row in group)
        payload = [row["records"][0]["payload_ns"] / 1e6 for row in group if len(row["records"]) == 1 and "payload_ns" in row["records"][0]]
        summaries.append({"tool": tool, "workload": case, "n": len(group), "median_ms": statistics.median(elapsed), "p95_ms": elapsed[math.ceil(0.95 * len(elapsed)) - 1], "payload_median_ms": statistics.median(payload) if payload else None, "load1_max": max(row["load"][0] for row in group)})
    if metadata["samples"] < 30 or metadata["warmup"] < 1: problems.append("insufficient samples or warmup")
    if status["invalid_sequences"] or complete["invalid_measurements"]: problems.append("runner reported invalid measurements")
    by_arm = {(r["tool"], r["workload"]): r for r in summaries}
    for row in summaries:
        baseline = by_arm.get(("direct", row["workload"]))
        row["over_direct"] = row["median_ms"] / baseline["median_ms"] if baseline else None
    comparisons = []
    if not problems:
        for competitor in ("greywall", "srt", "srt-unix-compat"):
            if not status["available"].get("ouro-jail") or not status["available"].get(competitor): continue
            for case in sorted(CASES):
                ouro, other = by_arm["ouro-jail", case], by_arm[competitor, case]
                comparisons.append({"competitor": competitor, "workload": case, "competitor_over_ouro_median": other["median_ms"] / ouro["median_ms"], "competitor_over_ouro_p95": other["p95_ms"] / ouro["p95_ms"]})
    return {"valid": not problems, "problems": problems, "available": status["available"], "rows": summaries, "comparisons": comparisons, "scope": "same-host CLI elapsed time; no cross-host speed comparison; unavailable arms are not wins"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    p = args.directory
    result = evaluate(json.loads((p / "metadata.json").read_text()), json.loads((p / "performance-status.json").read_text()), json.loads((p / "complete.json").read_text()), (p / "launches.ndjson").read_bytes())
    (p / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
