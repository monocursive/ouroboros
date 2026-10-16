#!/bin/sh
# Rerun 2026-10-16 Pi: native suite + docker-only container controls (OpenShell
# 0.1.4 startup failure re-verified separately) + resource probes.
set -e
B=/home/monocursive/bench-ouro-rerun
R=$B/runs/pi-perf
mkdir -p "$B/results"
rm -rf "$R" "$B/results/pi-perf" "$B/results/pi-docker" "$B/results/pi-resources"
mkdir -p "$R/bin"
cp -r "$B/harness" "$R/harness"
cp /home/monocursive/ukai-src/target/release/ukai-jail /home/monocursive/bench-ouro/bin/greywall /home/monocursive/bench-ouro/bin/lxc-exec "$R/bin/"
cd "$R"
export PATH="/usr/sbin:/sbin:$PATH"
python3 harness/suite.py --root "$R" --out "$B/results/pi-perf" --samples 30 --warmup 3 > "$B/results/pi-perf.log" 2>&1
python3 harness/summarize.py "$B/results/pi-perf" > "$B/results/pi-perf-table.txt" 2>&1 || true
python3 harness/openshell_perf_v2.py --root "$R" --out "$B/results/pi-docker" --samples 30 --warmup 3 --docker-only --skip-build > "$B/results/pi-docker.log" 2>&1
python3 harness/resource_probes.py --root "$R" --out "$B/results/pi-resources" > "$B/results/pi-resources.log" 2>&1
echo PI-PERF-DONE
