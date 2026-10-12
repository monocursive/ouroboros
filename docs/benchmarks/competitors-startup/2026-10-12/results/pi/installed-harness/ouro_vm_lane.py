#!/usr/bin/env python3
"""ouro-vm disposable-VM lane on Apple Silicon (VM isolation class).

Each attempt boots an offline Linux ARM64 VM, runs a POSIX-shell workload,
and copies the workspace back. Boot cost dominates; this lane records VM
startup + in-guest work for a small battery, and is never mixed into the
per-command wrapper ratios of suite.py.

Workloads (POSIX sh, validated by returned file counts and markers):
  noop      one echo
  writes    100 file writes in the guest workspace
  reads     100 reads of staged input files
  spawn     50 child shell spawns
"""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

WORKLOADS = {
    "noop": "echo ok > marker-noop",
    "writes": "i=0; while [ $i -lt 100 ]; do echo x > w$i; i=$((i+1)); done",
    "reads": "i=0; while [ $i -lt 100 ]; do cat input/r$i > /dev/null; i=$((i+1)); done",
    "spawn": "i=0; while [ $i -lt 50 ]; do (/bin/true); i=$((i+1)); done; echo done > marker-spawn",
}
EXPECTED = {"noop": ("marker-noop", 1), "writes": ("w", 100), "reads": (None, 0), "spawn": ("marker-spawn", 1)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--vm", default="ouro-vm")
    args = parser.parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    inputs = root / "vm-inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    for i in range(100):
        (inputs / ("r%d" % i)).write_bytes(b"y" * 256)
    raw = (out / "vm-launches.ndjson").open("w")
    counter = 0
    table = {}
    for case, script in WORKLOADS.items():
        times = []
        ok_count = 0
        for sample in range(-args.warmup, args.samples):
            counter += 1
            result_dir = root / ("vm-run-%s-%d" % (case, counter))
            subprocess.run(["rm", "-rf", str(result_dir)], check=False)
            before = time.perf_counter_ns()
            process = subprocess.run([args.vm, "run", "--workspace", str(inputs), "--out", str(result_dir), "--profile", "build", "--wall", "120", "--", "/bin/sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
            elapsed = (time.perf_counter_ns() - before) / 1e6
            workspace = result_dir / "workspace"
            valid = process.returncode == 0
            if case == "writes" and workspace.exists():
                valid = valid and len([p for p in workspace.iterdir() if p.name.startswith("w")]) == 100
            if case == "reads":
                valid = valid  # exit 0 is the contract
            if case in ("noop", "spawn") and workspace.exists():
                valid = valid and (workspace / EXPECTED[case][0]).exists()
            row = {"sequence": counter, "case": case, "round": sample, "elapsed_ms": round(elapsed, 1), "exit": process.returncode, "valid": valid, "stdout": process.stdout.decode(errors="replace")[-500:], "stderr": process.stderr.decode(errors="replace")[-500:]}
            raw.write(json.dumps(row, separators=(",", ":")) + "\n")
            raw.flush()
            if sample >= 0:
                times.append(elapsed)
                ok_count += 1 if valid else 0
            print(case, sample, round(elapsed), "exit", process.returncode, "valid", valid, flush=True)
        table[case] = {"samples": args.samples, "valid": ok_count, "elapsed_ms_median": round(statistics.median(times), 1) if times else None, "elapsed_ms_min": round(min(times), 1) if times else None}
    raw.close()
    (out / "vm-summary.json").write_text(json.dumps({"schema": "ouro-vm-lane/1", "samples": args.samples, "table": table}, indent=2) + "\n")
    print(json.dumps(table, indent=1))


if __name__ == "__main__":
    raise SystemExit(main())
