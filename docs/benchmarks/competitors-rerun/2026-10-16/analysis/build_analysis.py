#!/usr/bin/env python3
"""Aggregate the 2026-10-16 rerun raw results into tables and the selected dataset.

Inputs are the per-host result directories under raw/<host>/ (pulled from the
hosts unchanged). Stats follow summarize.py: successful measured samples only,
median of even counts averaged, p95 by nearest rank. A coding pass requires
client/wrapper exit 0, no timeout and all checker keys true.
"""
import csv
import hashlib
import json
import statistics
import sys
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent
RAW = CORPUS / "raw"
OUT = CORPUS / "analysis"
CASES = ["noop", "python", "git", "reads", "writes", "spawn", "cpu"]
HOSTS = ["vps", "pi", "mac"]
NATIVE_TOOL_LABEL = {"ouro-jail": "ukai", "ouro-obs-off": "ukai-obs-off", "direct": "direct", "greywall": "greywall", "mxc": "mxc"}
CONTAINER_TOOLS = {"docker-run": "docker-fresh", "docker-warm": "docker-warm", "openshell-ephemeral": "openshell-fresh", "openshell-warm": "openshell-warm"}


def pct(values, q):
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q / 100 * (len(ordered) + 1)) - 1))
    return ordered[index]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def perf_tables():
    native, container = {}, {}
    for host in HOSTS:
        table_json = RAW / host / ("%s-perf" % host) / "table.json"
        if table_json.exists():
            native[host] = json.loads(table_json.read_text())
        summary = RAW / host / ("mac-openshell" if host == "mac" else "%s-openshell" % host if host == "vps" else "pi-docker") / "openshell-summary.json"
        if summary.exists():
            container[host] = json.loads(summary.read_text())
    return native, container


def coding_rows():
    native_runs, container_runs, workflows = [], [], []
    for host in HOSTS:
        root = RAW / host
        for path in sorted(root.glob("v5-*-rerun/agent-runs.ndjson")):
            agent = path.parent.name.split("-")[1]
            for row in json.loads("[" + ",".join(path.read_text().splitlines()) + "]"):
                entry = {"host": host, "class": "native", "agent": agent, **{k: row[k] for k in ("agent_kind",) if False}}
                entry.update({k: row[k] for k in ("mode", "task", "repetition", "success", "exit", "timeout", "elapsed_ms") if k in row})
                if row.get("container_result"):
                    entry["inner_work_ms"] = row["container_result"].get("work_ms")
                native_runs.append((path, entry))
        for path in sorted(root.glob("os14-*/agent-runs.ndjson")):
            if "wf" in path.parent.name or path.parent.name == "os14-smoke":
                continue
            for row in json.loads("[" + ",".join(path.read_text().splitlines()) + "]"):
                container_runs.append((path, {"host": host, "class": "container", **{k: row[k] for k in ("agent", "mode", "task", "repetition", "success", "exit", "timeout", "elapsed_ms") if k in row}, "inner_work_ms": (row.get("container_result") or {}).get("work_ms")}))
        for path in sorted(root.glob("workflow-v2-rerun/agent-runs.ndjson")):
            for row in json.loads("[" + ",".join(path.read_text().splitlines()) + "]"):
                workflows.append((path, {"host": host, "class": "native", "task": "inventory-workflow", **{k: row[k] for k in ("agent", "mode", "success", "exit", "elapsed_ms") if k in row}}))
        for path in sorted(root.glob("os14-wf*/agent-runs.ndjson")) + sorted(root.glob("os14-docker-wf-*/agent-runs.ndjson")):
            for row in json.loads("[" + ",".join(path.read_text().splitlines()) + "]"):
                workflows.append((path, {"host": host, "class": "container", "task": "inventory-workflow", **{k: row[k] for k in ("agent", "mode", "success", "exit", "elapsed_ms") if k in row}}))
    return native_runs, container_runs, workflows


def main():
    OUT.mkdir(exist_ok=True)
    native_perf, container_perf = perf_tables()
    native_runs, container_runs, workflows = coding_rows()

    lines = ["# Rerun 2026-10-16 performance tables", "",
             "Median / p95 wall time in milliseconds over successful measured samples (30 per bucket after three discarded warmups; container lane 30/1). Failed or unconfirmed launches are excluded and counted.", ""]
    csv_rows = []
    for host in HOSTS:
        if host not in native_perf:
            continue
        lines += ["## %s native" % host, "", "| tool | case | n | ok | median | p95 | work median |", "|---|---|---:|---:|---:|---:|---:|"]
        table = native_perf[host]["table"]
        for tool in sorted(table):
            for case in CASES:
                e = table[tool].get(case)
                if not e:
                    continue
                lines.append("| %s | %s | %d | %d | %s | %s | %s |" % (NATIVE_TOOL_LABEL.get(tool, tool), case, e["samples"], e["successful"], e["elapsed_ms_median"], e["elapsed_ms_p95"], e["work_ms_median"]))
                csv_rows.append([host, "native", NATIVE_TOOL_LABEL.get(tool, tool), case, e["samples"], e["successful"], e["elapsed_ms_median"], e["elapsed_ms_p95"], e["work_ms_median"]])
        lines.append("")
    for host in HOSTS:
        if host not in container_perf:
            continue
        lines += ["## %s container" % host, "", "| tool | case | ok | median |", "|---|---|---:|---:|"]
        for tool, cases in container_perf[host]["table"].items():
            for case in CASES:
                e = cases.get(case)
                if not e:
                    continue
                lines.append("| %s | %s | %s | %s |" % (CONTAINER_TOOLS.get(tool, tool), case, e.get("successful"), e.get("elapsed_ms_median")))
                csv_rows.append([host, "container", CONTAINER_TOOLS.get(tool, tool), case, e.get("samples"), e.get("successful"), e.get("elapsed_ms_median"), None, e.get("work_ms_median")])
        lines.append("")
    (OUT / "performance-tables.md").write_text("\n".join(lines) + "\n")
    with (OUT / "performance.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "class", "tool", "case", "samples", "successful", "wall_ms_median", "wall_ms_p95", "work_ms_median"])
        writer.writerows(csv_rows)

    def bucket(rows, key_fields):
        grouped = {}
        for source, row in rows:
            grouped.setdefault(tuple(row[k] for k in key_fields), []).append(row)
        return grouped

    coding_lines = ["# Rerun 2026-10-16 coding compatibility", "", "| host | class | client | arm | attempted | passed | median success ms |", "|---|---|---|---|---:|---:|---:|"]
    selected = {"schema": "selected-rerun/1", "native_agents": [], "container_agents": [], "workflows": [], "selection": []}
    for key, rows in sorted(bucket(native_runs, ("host", "agent", "mode")).items()):
        ok = [r for r in rows if r["success"]]
        median = round(statistics.median([r["elapsed_ms"] for r in ok]), 1) if ok else None
        coding_lines.append("| %s | native | %s | %s | %d | %d | %s |" % (*key, len(rows), len(ok), median))
        selected["native_agents"].append({"host": key[0], "agent": key[1], "mode": key[2], "attempted": len(rows), "passed": len(ok), "median_success_ms": median})
    for key, rows in sorted(bucket(container_runs, ("host", "agent", "mode")).items()):
        ok = [r for r in rows if r["success"]]
        median = round(statistics.median([r["elapsed_ms"] for r in ok]), 1) if ok else None
        inner = round(statistics.median([r["inner_work_ms"] for r in ok if r.get("inner_work_ms") is not None]), 1) if ok else None
        coding_lines.append("| %s | container | %s | %s | %d | %d | %s |" % (*key, len(rows), len(ok), median))
        selected["container_agents"].append({"host": key[0], "agent": key[1], "mode": key[2], "attempted": len(rows), "passed": len(ok), "median_success_ms": median, "median_inner_ms": inner})
    coding_lines.append("")
    wf_lines = ["# Workflow (inventory CLI), one run per client/arm", "", "| host | class | client | arm | success | exit |", "|---|---|---|---|---|---:|"]
    for source, row in sorted(workflows, key=lambda item: (item[1]["host"], item[1]["class"], item[1]["agent"], item[1]["mode"])):
        wf_lines.append("| %s | %s | %s | %s | %s | %s |" % (row["host"], row["class"], row["agent"], row["mode"], row["success"], row["exit"]))
        selected["workflows"].append({"host": row["host"], "class": row["class"], "agent": row["agent"], "mode": row["mode"], "success": row["success"], "exit": row["exit"]})
    (OUT / "coding-tables.md").write_text("\n".join(coding_lines) + "\n\n" + "\n".join(wf_lines) + "\n")

    for source, _ in native_runs + container_runs + workflows:
        rel = str(source.relative_to(CORPUS))
        if all(item["source"] != rel for item in selected["selection"]):
            selected["selection"].append({"source": rel, "sha256": sha(source)})
    (OUT / "selected-results.json").write_text(json.dumps(selected, indent=2) + "\n")
    print("native buckets:", len(selected["native_agents"]), "container buckets:", len(selected["container_agents"]), "workflows:", len(selected["workflows"]))


if __name__ == "__main__":
    sys.exit(main())
