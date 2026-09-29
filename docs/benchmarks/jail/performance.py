#!/usr/bin/env python3
"""Apply K17's phase budgets to a summary recomputed by `xtask perf summarize`."""
import argparse
import hashlib
import json
from pathlib import Path


def evaluate(summary):
    problems = list(summary["integrity"])
    gate = summary["gate"]
    parameters = summary["parameters"]
    if parameters["fileops_rounds"] != 5000 or parameters["spawn_count"] != 200:
        problems.append("the measured workloads differ from K17's fixed fixtures")
    if parameters["warmup"] < 1:
        problems.append("no warm-up launches were recorded")
    if not gate["integrity_ok"]:
        problems.append("raw-data integrity was not established")
    if gate["max_load"] is None:
        problems.append("no quiet-host threshold was declared")
    expected = {(s, w) for s in ("plain", "scope") for w in ("noop", "spawn-tree", "fileops")}
    seen = set()
    rows = []
    for comparison in summary["comparisons"]:
        if comparison["profile"] != "tool" or comparison["kind"] != "off_vs_direct":
            continue
        cell = (comparison["session"], comparison["workload"])
        if cell in seen or cell not in expected:
            problems.append(f"duplicate or unexpected cell: {cell}")
        seen.add(cell)
        sufficient = (
            comparison["subject_valid"] >= 30
            and comparison["baseline_valid"] >= 30
            and comparison["subject_excluded"] == 0
            and comparison["baseline_excluded"] == 0
            and comparison["startup_verdict"] in ("pass", "fail")
            and gate["max_load"] is not None
            and comparison["load1_max"] is not None
            and comparison["load1_max"] <= gate["max_load"]
        )
        startup = comparison["added_startup_ms"]
        post = comparison["post_start_overhead_pct"]
        if not sufficient or startup is None or (cell[1] == "fileops" and post is None):
            problems.append(f"insufficient or loaded measurements: {cell}")
            continue
        rows.append({
            "session": cell[0], "workload": cell[1],
            "subject_valid": comparison["subject_valid"],
            "baseline_valid": comparison["baseline_valid"],
            "subject_flagged": comparison["subject_flagged"],
            "load1_max": comparison["load1_max"],
            "added_startup_p95_ms": startup["p95"],
            "startup_pass": startup["p95"] < 500,
            "post_start_overhead_median_pct": post["median"] if post else None,
            "post_start_pass": post["median"] <= 100 if cell[1] == "fileops" else None,
        })
    if seen != expected:
        problems.append(f"missing cells: {sorted(expected - seen)}")
    verdict = "unverified" if problems else (
        "pass" if all(r["startup_pass"] and r["post_start_pass"] is not False for r in rows) else "fail"
    )
    return {"gate": "K17", "verdict": verdict, "problems": problems, "rows": rows,
            "limits": {"startup_p95_ms_exclusive": 500, "fileops_post_start_overhead_pct_inclusive": 100}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw = args.summary.read_bytes()
    result = evaluate(json.loads(raw))
    result["summary_sha256"] = hashlib.sha256(raw).hexdigest()
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
