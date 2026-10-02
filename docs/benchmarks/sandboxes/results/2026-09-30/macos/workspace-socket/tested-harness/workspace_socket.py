#!/usr/bin/env python3
"""Can a granted workspace socket bridge to a host service? Owned echo only."""
import argparse
import json
from pathlib import Path
import platform
from compare import CanaryServer, Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    suite = Suite(args.root.resolve(), args.out.resolve(), 0, 0)
    path = suite.work / "host-service.sock"
    server = CanaryServer(path)
    result = []
    tools = suite.tools + (["srt-unix-compat"] if platform.system() == "Linux" else [])
    try:
        for tool in tools:
            if tool == "srt-unix-compat":
                config = json.loads(suite.srt_config.read_text())
                config["network"]["allowAllUnixSockets"] = True
                suite.srt_config.write_text(json.dumps(config, indent=2) + "\n")
            preflight = suite.run(tool, suite.payload_command("noop"), "preflight", "noop")
            if preflight["exit"] or not preflight["records"]:
                result.append({"tool": tool, "status": "unavailable"}); continue
            for repetition in range(3):
                before = server.hits
                row = suite.run(tool, [suite.python, str(suite.payload), "probe", "unix", str(path)], "safety", "visible_workspace_host_socket", repetition)
                record = next((r for r in row["records"] if r.get("probe") == "unix"), None)
                reached = record and record.get("allowed") is True and server.hits > before
                status = "allowed" if reached else ("denied" if row["exit"] == 0 and record and record.get("allowed") is False and server.hits == before else "inconclusive")
                result.append({"tool": tool, "repetition": repetition, "status": status, "sequence": row["sequence"], "detail": record, "host_accepts": server.hits - before})
        (suite.out / "workspace-socket.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    finally:
        server.close(); path.unlink(); suite.close()


if __name__ == "__main__":
    main()
