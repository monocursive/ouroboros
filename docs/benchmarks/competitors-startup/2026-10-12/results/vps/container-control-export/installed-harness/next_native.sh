#!/bin/sh
# Serialize host measurements behind the active primary batch.
set -eu
bench_root="$HOME/bench-ouro"
primary_pid="$1"
primary_name="$2"
modes="$3"
auth_path="$4"
if [ "$primary_pid" != "done" ]; then
  while kill -0 "$primary_pid" 2>/dev/null; do sleep 10; done
fi
if ! python3 -c 'import pathlib,sys; sys.exit(0 if pathlib.Path(sys.argv[1]).read_text().splitlines()[-1] == "COMPLETE" else 1)' "$bench_root/results/$primary_name.log"; then
  echo 'Primary batch did not complete; dependent work withheld.'
  exit 1
fi
python3 "$bench_root/harness/agentbench_v2.py" --root "$bench_root" --out "$bench_root/results/v5-opencode" --key-file "$bench_root/anthropic.key" --auth-file "$auth_path" --agents opencode --tasks add-multiply,fix-offbyone,refactor-yaml-json --runs 2 --modes "$modes" --wall 180 > "$bench_root/results/v5-opencode.log" 2>&1
perf_root="$bench_root/runs/perf-v2-final"
mkdir -p "$perf_root"
ln -s "$bench_root/bin" "$perf_root/bin"
ln -s "$bench_root/harness" "$perf_root/harness"
if python3 "$bench_root/harness/suite.py" --root "$perf_root" --out "$bench_root/results/perf-v2-final" --samples 30 --warmup 3 > "$bench_root/results/perf-v2-final.log" 2>&1; then
  echo 'PERF-COMPLETE exit=0'
else
  echo "PERF-COMPLETE exit=$? (inspect results)"
fi
python3 "$bench_root/harness/agentbench_workflow.py" --root "$bench_root" --out "$bench_root/results/workflow-v2-final" --key-file "$bench_root/anthropic.key" --auth-file "$auth_path" --agents claude,opencode,codex --tasks inventory-workflow --runs 1 --modes "$modes" --wall 240 > "$bench_root/results/workflow-v2-final.log" 2>&1
resource_root="$bench_root/runs/resource-v2-final"
mkdir -p "$resource_root"
ln -s "$bench_root/bin" "$resource_root/bin"
ln -s "$bench_root/harness" "$resource_root/harness"
python3 "$bench_root/harness/resource_probes.py" --root "$resource_root" --out "$bench_root/results/resource-v2-final" > "$bench_root/results/resource-v2-final.log" 2>&1
echo 'NATIVE-PIPELINE-COMPLETE'
