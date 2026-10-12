#!/usr/bin/env python3
"""Recompute medians/p95 from raw launches.ndjson; withhold failed work."""
import argparse
import json
from pathlib import Path
import statistics


def pct(values, q):
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q / 100 * (len(ordered) + 1)) - 1))
    return ordered[index]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in (args.results_dir / "launches.ndjson").read_text().splitlines()]
    measured = [r for r in rows if r.get("phase") == "measurement" and not r.get("timeout")]
    table = {}
    for tool in sorted({r["tool"] for r in measured}):
        for case in sorted({r["case"] for r in measured}):
            sample = [r for r in measured if r["tool"] == tool and r["case"] == case]
            ok = [r for r in sample if r["exit"] == 0 and len(r["records"]) == 1]
            work = [r["records"][0]["payload_ns"] / 1e6 for r in ok if r["records"][0].get("payload_ns") is not None]
            entry = {
                "samples": len(sample),
                "successful": len(ok),
                "elapsed_ms_median": round(statistics.median(r["elapsed_ms"] for r in ok), 2) if ok else None,
                "elapsed_ms_p95": round(pct([r["elapsed_ms"] for r in ok], 95), 2) if ok else None,
                "work_ms_median": round(statistics.median(work), 2) if work else None,
            }
            table.setdefault(tool, {})[case] = entry
    summary_path = args.results_dir / "summary.json"
    output = {"table": table}
    if summary_path.exists():
        summary = json.loads(summary_path.read_text())
        output["available"] = summary["performance"]["available"]
        output["invalid_sequences"] = summary["performance"]["invalid_sequences"]
        output["safety"] = [{"tool": s["tool"], "probe": s.get("probe"), "status": s["status"]} for s in summary["safety"]]
    (args.results_dir / "table.json").write_text(json.dumps(output, indent=2) + "\n")
    for tool, cases in table.items():
        print(tool)
        for case, e in cases.items():
            print("  %-8s n=%2d ok=%2d  wall %8.2f / %8.2f ms   work %8.2f ms" % (case, e["samples"], e["successful"], e["elapsed_ms_median"] or -1, e["elapsed_ms_p95"] or -1, e["work_ms_median"] or -1))


if __name__ == "__main__":
    raise SystemExit(main())
