#!/usr/bin/env python3
"""OpenShell container-class lane: same seven workloads inside sandboxes.

OpenShell runs agents in container/VM sandboxes behind a gateway; it is a
different isolation class from per-command namespace wrappers, so its numbers
are never mixed into the wrapper ratios of suite.py. This lane measures, on
one host with one Docker daemon:

  docker-run         plain `docker run --rm` of the fixture image (baseline)
  openshell-ephemeral `sandbox create --no-keep` per command (full lifecycle)
  openshell-warm     `sandbox exec` into one retained sandbox (steady state)

Validation is by in-container completion records (count + checksum against
the docker-run reference): container writes are not host-visible by design.
Also probes container->host egress to a canary on the docker bridge.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import socket
import statistics
import subprocess
import threading
import time

CASES = ["noop", "python", "git", "reads", "writes", "spawn", "cpu"]
IMAGE = "bench-openshell:latest"
WARM = "bench-warm"


class Canary:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("0.0.0.0", 0))
        self.port = self.socket.getsockname()[1]
        self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.stop = threading.Event()
        self.hits = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, peer = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.hits.append(peer)
            with conn:
                try:
                    conn.recv(64)
                    conn.sendall(b"canary")
                except OSError:
                    pass

    def close(self):
        self.stop.set()
        self.socket.close()


def run(command, timeout=120, cwd=None):
    before = time.perf_counter_ns()
    process = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    elapsed = (time.perf_counter_ns() - before) / 1e6
    return {"argv": [str(c) for c in command], "elapsed_ms": elapsed, "exit": process.returncode, "stdout": process.stdout.decode(errors="replace"), "stderr": process.stderr.decode(errors="replace")}


def records(raw):
    out = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "workload" in value:
            out.append(value)
    return out


def build_image(root):
    context = root / "image"
    context.mkdir(parents=True, exist_ok=True)
    shutil_copy = __import__("shutil").copyfile
    shutil_copy(root / "harness/payload.py", context / "payload.py")
    shutil_copy(root / "harness/workload.c", context / "workload.c")
    (context / "Dockerfile").write_text(
        "FROM ubuntu:24.04\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev python3 git && rm -rf /var/lib/apt/lists/*\n"
        "WORKDIR /work\n"
        "COPY payload.py workload.c /work/\n"
        "RUN cc -O2 /work/workload.c -o /work/workload\n"
        "RUN python3 -c \"import pathlib; inputs = pathlib.Path('/work/inputs'); inputs.mkdir(parents=True, exist_ok=True); [ (inputs / ('f%04d' % i)).write_bytes(b'x' * 4096) for i in range(1000) ]\"\n"
        "RUN echo 'outputs/' > /work/.gitignore\n"
        "RUN git init -q /work && git -C /work add inputs payload.py workload .gitignore\n"
        "RUN mkdir -p /work/outputs && chown -R 1000:1000 /work && git config --system --add safe.directory /work\n"
        "CMD [\"/bin/true\"]\n"
    )
    return run(["docker", "build", "-t", IMAGE, str(context)], timeout=600)


def payload_argv(case):
    if case in ("python", "git"):
        return ["/usr/bin/python3", "/work/payload.py", case]
    return ["/work/workload", case]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--openshell", default="openshell")
    args = parser.parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    canary = Canary()
    raw = (out / "openshell-launches.ndjson").open("w")
    counter = 0

    def emit(row):
        nonlocal counter
        counter += 1
        row["sequence"] = counter
        row["records"] = records(row.pop("stdout"))
        raw.write(json.dumps(row, separators=(",", ":")) + "\n")
        raw.flush()
        return row

    build = build_image(root)
    (out / "build.json").write_text(json.dumps(build, indent=2)[:8000] + "\n")
    if build["exit"] != 0:
        raise SystemExit("image build failed: " + build["stderr"][-500:])
    probe = "import socket,sys,json\ntry:\n s=socket.create_connection((sys.argv[1],int(sys.argv[2])),2);s.sendall(b'probe');print(json.dumps({'probe':'tcp','allowed':s.recv(16)==b'canary'}))\nexcept OSError as e:\n print(json.dumps({'probe':'tcp','allowed':False,'error':str(e)}))"
    reference = {}
    for case in CASES:
        row = emit(dict(run(["docker", "run", "--rm", IMAGE, *payload_argv(case)]), phase="reference", case=case, tool="docker-run"))
        if row["exit"] or len(row["records"]) != 1:
            raise RuntimeError("broken container reference: " + case + " " + row["stderr"][-300:])
        reference[case] = {k: row["records"][0][k] for k in ("workload", "count", "checksum")}
    print("container reference established", flush=True)

    def openshell(argv, timeout=180):
        return run([args.openshell, *argv], timeout=timeout)

    # Warm sandbox for the exec lane.
    subprocess.run([args.openshell, "sandbox", "delete", WARM], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    warm = run([args.openshell, "sandbox", "create", "--name", WARM, "--detach", "--from", IMAGE, "--", "sleep", "3600"], timeout=180)
    emit(dict(warm, phase="setup", case="warm-create", tool="openshell-warm"))
    if warm["exit"] != 0:
        raise SystemExit("warm sandbox failed: " + warm["stderr"][-500:])

    lanes = {
        "docker-run": lambda case: run(["docker", "run", "--rm", IMAGE, *payload_argv(case)]),
        "openshell-ephemeral": lambda case: openshell(["sandbox", "create", "--no-keep", "--from", IMAGE, "--", *payload_argv(case)]),
        "openshell-warm": lambda case: openshell(["sandbox", "exec", WARM, "--workdir", "/work", "--", *payload_argv(case)]),
    }
    errors = []
    for round_id in range(-args.warmup, args.samples):
        for tool, lane in lanes.items():
            for case in CASES:
                row = emit(dict(lane(case), phase="warmup" if round_id < 0 else "measurement", case=case, tool=tool, round=round_id))
                valid = row["exit"] == 0 and len(row["records"]) == 1 and all(row["records"][0].get(k) == v for k, v in reference[case].items())
                if not valid:
                    errors.append(row["sequence"])
        print("round", round_id, "complete", flush=True)

    # Egress probe: container -> host canary via the docker bridge gateway.
    bridge = subprocess.run(["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"], stdout=subprocess.PIPE).stdout.decode().strip()
    probe = "import socket,sys,json\ntry:\n s=socket.create_connection((sys.argv[1],int(sys.argv[2])),2);s.sendall(b'probe');print(json.dumps({'probe':'tcp','allowed':s.recv(16)==b'canary'}))\nexcept OSError as e:\n print(json.dumps({'probe':'tcp','allowed':False,'error':str(e)}))"
    egress = []
    for tool in ("docker-run", "openshell-ephemeral", "openshell-warm"):
        before_hits = len(canary.hits)
        if tool == "docker-run":
            row = run(["docker", "run", "--rm", IMAGE, "/usr/bin/python3", "-c", probe, bridge, str(canary.port)])
        elif tool == "openshell-ephemeral":
            row = openshell(["sandbox", "create", "--no-keep", "--from", IMAGE, "--", "/usr/bin/python3", "-c", probe, bridge, str(canary.port)])
        else:
            row = openshell(["sandbox", "exec", WARM, "--", "/usr/bin/python3", "-c", probe, bridge, str(canary.port)])
        time.sleep(0.2)
        egress.append({"tool": tool, "exit": row["exit"], "stdout": row["stdout"][-400:], "stderr": row["stderr"][-400:], "host_accepts_during_probe": len(canary.hits) - before_hits, "bridge_gateway": bridge, "port": canary.port})
        emit(dict(row, phase="safety", case="host-egress", tool=tool))
    (out / "egress.json").write_text(json.dumps(egress, indent=2) + "\n")

    teardown = run([args.openshell, "sandbox", "delete", WARM], timeout=60)
    emit(dict(teardown, phase="teardown", case="warm-delete", tool="openshell-warm"))

    measured = [json.loads(line) for line in (out / "openshell-launches.ndjson").read_text().splitlines()]
    table = {}
    for tool in lanes:
        for case in CASES:
            ok = [r for r in measured if r["phase"] == "measurement" and r["tool"] == tool and r["case"] == case and r["exit"] == 0 and len(r["records"]) == 1]
            times = [r["elapsed_ms"] for r in ok]
            work = [r["records"][0]["payload_ns"] / 1e6 for r in ok if r["records"][0].get("payload_ns") is not None]
            table.setdefault(tool, {})[case] = {"samples": args.samples, "successful": len(ok), "elapsed_ms_median": round(statistics.median(times), 2) if times else None, "work_ms_median": round(statistics.median(work), 2) if work else None}
    summary = {"schema": "openshell-lane/1", "image": IMAGE, "samples": args.samples, "warmup": args.warmup, "reference": reference, "invalid_sequences": errors, "table": table, "egress": [{"tool": e["tool"], "host_accepts_during_probe": e["host_accepts_during_probe"]} for e in egress]}
    (out / "openshell-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary["table"], indent=1))
    print("egress:", json.dumps(summary["egress"]))
    canary.close()
    raw.close()
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
