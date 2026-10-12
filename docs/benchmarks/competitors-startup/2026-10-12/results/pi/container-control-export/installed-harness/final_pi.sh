#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
for bench_run in perf-v3-folder-deny resource-v3-folder-deny; do
  mkdir -p "$bench_root/runs/$bench_run"
  ln -sfn "$bench_root/bin" "$bench_root/runs/$bench_run/bin"
  ln -sfn "$bench_root/harness" "$bench_root/runs/$bench_run/harness"
done
python3 "$bench_root/harness/suite.py" --root "$bench_root/runs/perf-v3-folder-deny" --out "$bench_root/results/perf-v3-folder-deny" --samples 30 --warmup 3 > "$bench_root/results/perf-v3-folder-deny.log" 2>&1
python3 "$bench_root/harness/resource_probes.py" --root "$bench_root/runs/resource-v3-folder-deny" --out "$bench_root/results/resource-v3-folder-deny" > "$bench_root/results/resource-v3-folder-deny.log" 2>&1
python3 -c 'import openshell_lane,json,pathlib; r=openshell_lane.build_image(pathlib.Path.home()/"bench-ouro"); (pathlib.Path.home()/"bench-ouro/results/container-base-build.json").write_text(json.dumps(r,indent=2)); assert r["exit"]==0'
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v2-smoke" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --tasks add-multiply --runs 1 > "$bench_root/results/openshell-v2-smoke.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v2-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --runs 2 --skip-build --skip-provider-setup > "$bench_root/results/openshell-v2-final.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-workflow-v2-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$bench_root/results/openshell-workflow-v2-final.log" 2>&1
python3 "$bench_root/harness/openshell_perf_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-perf-v2-final" --samples 30 --warmup 3 --skip-build > "$bench_root/results/openshell-perf-v2-final.log" 2>&1
echo PI-FINAL-COMPLETE
