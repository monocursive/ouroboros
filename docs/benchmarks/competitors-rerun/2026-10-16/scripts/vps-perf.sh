#!/bin/sh
# Rerun 2026-10-16 VPS: native four-way suite, openshell 0.1.4 container lane, resource probes.
# Recorded host policy: apparmor_restrict_unprivileged_userns set 0 for the
# native suite (both 2026-10-11 and this cohort), restored to 1 afterwards.
set -e
B=/home/ubuntu/bench-ouro-rerun
R=$B/runs/vps-perf
mkdir -p "$B/results"
rm -rf "$R" "$B/results/vps-perf" "$B/results/vps-openshell" "$B/results/vps-resources"
mkdir -p "$R/bin"
cp -r "$B/harness" "$R/harness"
cp /home/ubuntu/ukai-src/target/release/ukai-jail /home/ubuntu/bench-ouro/bin/greywall /home/ubuntu/bench-ouro/bin/lxc-exec "$R/bin/"
sysctl kernel.apparmor_restrict_unprivileged_userns > "$B/results/vps-userns-before.txt"
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >> "$B/results/vps-userns-before.txt"
cd "$R"
python3 harness/suite.py --root "$R" --out "$B/results/vps-perf" --samples 30 --warmup 3 > "$B/results/vps-perf.log" 2>&1
python3 harness/summarize.py "$B/results/vps-perf" > "$B/results/vps-perf-table.txt" 2>&1 || true
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1 > "$B/results/vps-userns-after.txt"
export HOME=$B XDG_CONFIG_HOME=$B/openshell/config XDG_STATE_HOME=$B/openshell/state OPENSHELL_LOCAL_TLS_DIR=$B/openshell/tls
python3 harness/openshell_perf_v2.py --root "$R" --out "$B/results/vps-openshell" --samples 30 --warmup 3 --openshell /home/ubuntu/bench-ouro/bin-0.1.4/openshell --skip-build > "$B/results/vps-openshell.log" 2>&1
python3 harness/resource_probes.py --root "$R" --out "$B/results/vps-resources" > "$B/results/vps-resources.log" 2>&1
echo VPS-PERF-DONE
