#!/usr/bin/env python3
"""Measure Ouroboros ceilings; other products run identical bounded controls."""
import argparse
import json
from pathlib import Path
import shutil
from compare import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    suite = Suite(args.root.resolve(), args.out.resolve(), 0, 0)
    original_command = suite.command
    payload = suite.work / "resource_payload.py"
    shutil.copyfile(suite.root / "harness/resource_payload.py", payload)
    limits = {"wall": "wall=1s", "pids": "pids=16", "memory": "mem=64MiB"}
    active_limit = None

    def command(tool, argv):
        result = original_command(tool, argv)
        if tool == "ouro-jail" and active_limit:
            at = result.index("--")
            result[at:at] = ["--limit", active_limit]
        return result

    suite.command = command
    result = []
    try:
        for tool in suite.tools:
            preflight = suite.run(tool, suite.payload_command("noop"), "preflight", "noop")
            if preflight["exit"] or not preflight["records"]:
                result.append({"tool": tool, "status": "unavailable"}); continue
            for mode in limits:
                active_limit = limits[mode] if tool == "ouro-jail" else None
                row = suite.run(tool, [suite.python, str(payload), mode], "safety", mode)
                result.append({"tool": tool, "resource": mode, "requested_ceiling": active_limit, "sequence": row["sequence"], "exit": row["exit"], "elapsed_ms": row["elapsed_ms"], "records": row["records"], "receipt": row.get("receipt")})
            active_limit = None
            print(tool, "resources complete", flush=True)
        (suite.out / "resources.json").write_text(json.dumps(result, indent=2) + "\n")
    finally:
        suite.close()


if __name__ == "__main__":
    main()
