#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-final"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
python3 "$bench_root/harness/start_proxy.py"
for bench_run in file-denial perf-after resource-after backing-after; do
  mkdir -p "$bench_root/runs/$bench_run"
  ln -s "$bench_root/bin" "$bench_root/runs/$bench_run/bin"
  ln -s "$bench_root/harness" "$bench_root/runs/$bench_run/harness"
done
python3 "$bench_root/harness/file_denial_probe.py" --root "$bench_root/runs/file-denial" --out "$bench_root/results/file-denial" > "$bench_root/results/file-denial.log" 2>&1
python3 "$bench_root/harness/suite_paired.py" --root "$bench_root/runs/perf-after" --out "$bench_root/results/perf-after" --samples 30 --warmup 3 > "$bench_root/results/perf-after.log" 2>&1
python3 "$bench_root/harness/resource_probes.py" --root "$bench_root/runs/resource-after" --out "$bench_root/results/resource-after" > "$bench_root/results/resource-after.log" 2>&1
python3 "$bench_root/harness/backing_probe.py" --root "$bench_root/runs/backing-after" --out "$bench_root/results/backing-after" > "$bench_root/results/backing-after.log" 2>&1
python3 "$bench_root/harness/agentbench_v2.py" --root "$bench_root" --out "$bench_root/results/native-after" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --runs 2 > "$bench_root/results/native-after.log" 2>&1
python3 "$bench_root/harness/agentbench_workflow.py" --root "$bench_root" --out "$bench_root/results/workflow-after" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --tasks inventory-workflow --runs 1 > "$bench_root/results/workflow-after.log" 2>&1
python3 "$bench_root/harness/host_snapshot.py" --root "$bench_root"
echo LINUX-NATIVE-COMPLETE
