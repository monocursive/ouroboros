#!/usr/bin/env python3
"""Excluded diagnostics: fixed write work, per-operation time and host counters.

No governor, filesystem, policy or observer settings are changed. The instrumented
payload is separate from the original scored workload.c.
"""
import argparse
import json
import random
import subprocess
import threading
import time
from pathlib import Path
from suite import Suite, SEED


def snapshot():
    files = ["/proc/meminfo", "/proc/vmstat", "/proc/stat", "/proc/diskstats",
             "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
             "/sys/class/thermal/thermal_zone0/temp"]
    result = {"monotonic_ns": time.monotonic_ns()}
    for name in files:
        try:
            result[name] = Path(name).read_text()
        except OSError as error:
            result[name] = {"unavailable": str(error)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=8)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    suite = Suite(args.root, args.out, 0, 0, ["direct", "ouro-before", "mxc"])
    source = (args.root / "harness/workload.c").read_text()
    source = source.replace("uint64_t start = now(), checksum = 0, count = 0;",
        "uint64_t start = now(), checksum = 0, count = 0; uint64_t opens=0, writes=0, closes=0, max_open=0, max_write=0;")
    source = source.replace("int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);",
        "uint64_t before=now(); int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600); uint64_t d=now()-before; opens+=d; if(d>max_open)max_open=d;")
    source = source.replace("if (fd < 0 || write(fd, bytes, sizeof(bytes)) != sizeof(bytes) || close(fd)) return 3;",
        "if(fd<0)return 3; before=now(); ssize_t written=write(fd,bytes,sizeof(bytes)); d=now()-before; writes+=d; if(d>max_write)max_write=d; if(written!=sizeof(bytes))return 3; before=now(); int closed=close(fd); closes+=now()-before; if(closed)return 3;")
    source = source.replace("return 0;", 'printf("{\\"probe\\":\\"write_operation_times\\",\\"open_ns\\":%llu,\\"write_ns\\":%llu,\\"close_ns\\":%llu,\\"max_open_ns\\":%llu,\\"max_write_ns\\":%llu}\\n",(unsigned long long)opens,(unsigned long long)writes,(unsigned long long)closes,(unsigned long long)max_open,(unsigned long long)max_write); return 0;')
    diagnostic = suite.work / "workload-diag.c"
    diagnostic.write_text(source)
    subprocess.run(["cc", "-O2", str(diagnostic), "-o", str(suite.work / "workload-diag")], check=True)
    rows = []
    try:
        # Direct traces may follow children; never attach to Ouro's tracees.
        for index in range(2):
            argv = ["strace", "-ttt", "-T", "-o", str(args.out / ("direct-%d.strace" % index)),
                    str(suite.work / "workload"), "writes"]
            before = snapshot()
            result = subprocess.run(argv, cwd=suite.work, env=suite.env, capture_output=True, timeout=40)
            rows.append({"kind": "direct-strace", "argv": argv, "before": before,
                         "after": snapshot(), "exit": result.returncode,
                         "stdout": result.stdout.decode(), "stderr": result.stderr.decode()})
        generator = random.Random(SEED)
        for round_id in range(args.rounds):
            tools = list(suite.tools)
            generator.shuffle(tools)
            for tool in tools:
                samples = []
                stop = threading.Event()
                def monitor():
                    while not stop.is_set():
                        samples.append(snapshot())
                        stop.wait(.02)
                thread = threading.Thread(target=monitor, daemon=True)
                thread.start()
                try:
                    row = suite.run(tool, [str(suite.work / "workload-diag"), "writes"],
                                    "excluded-write-diagnostic", "writes", round_id)
                finally:
                    stop.set()
                    thread.join()
                row["host_samples"] = samples
                rows.append(row)
                print(round_id, tool, round(row["elapsed_ms"], 1), row["exit"], flush=True)
        (args.out / "diagnostic.json").write_text(json.dumps(rows, indent=2) + "\n")
    finally:
        suite.close()


if __name__ == "__main__":
    main()
