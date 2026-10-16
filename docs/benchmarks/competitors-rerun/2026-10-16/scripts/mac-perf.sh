#!/bin/bash
# Rerun 2026-10-16 Mac: suite (ouro refusal + greywall syntax failure recorded
# as preflight unavailability, as in 2026-10-11) + openshell 0.1.4 container lane.
set -e
export PATH=/opt/homebrew/bin:/usr/local/bin:/Users/monocursive/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin
B=/Users/monocursive/bench-ouro-rerun
R=$B/runs/mac-perf
mkdir -p "$B/results"
rm -rf "$R" "$B/results/mac-perf" "$B/results/mac-openshell" "$B/results/mac-resources"
mkdir -p "$R/bin"
cp -r "$B/harness" "$R/harness"
cp /Users/monocursive/bench-ouro/bin/greywall /Users/monocursive/bench-ouro/bin/mxc-exec-mac "$R/bin/"
cd "$R"
python3 harness/suite.py --root "$R" --out "$B/results/mac-perf" --samples 30 --warmup 3 --tools direct,ouro-jail,greywall,mxc > "$B/results/mac-perf.log" 2>&1
python3 harness/summarize.py "$B/results/mac-perf" > "$B/results/mac-perf-table.txt" 2>&1 || true
B=/Users/monocursive/bench-ouro-rerun
export HOME=$B XDG_CONFIG_HOME=$B/openshell/config XDG_STATE_HOME=$B/openshell/state OPENSHELL_LOCAL_TLS_DIR=$B/openshell/tls
python3 harness/openshell_perf_v2.py --root "$R" --out "$B/results/mac-openshell" --samples 30 --warmup 3 --openshell /Users/monocursive/bench-ouro/bin-0.1.4/openshell --skip-build > "$B/results/mac-openshell.log" 2>&1
python3 harness/resource_probes.py --root "$R" --out "$B/results/mac-resources" > "$B/results/mac-resources.log" 2>&1
echo MAC-PERF-DONE
