#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
while kill -0 1610671 2>/dev/null; do sleep 10; done
mkdir -p "$bench_root/runs/resource-v3-folder-deny"
ln -sfn "$bench_root/bin" "$bench_root/runs/resource-v3-folder-deny/bin"
ln -sfn "$bench_root/harness" "$bench_root/runs/resource-v3-folder-deny/harness"
python3 "$bench_root/harness/resource_probes.py" --root "$bench_root/runs/resource-v3-folder-deny" --out "$bench_root/results/resource-v3-folder-deny" > "$bench_root/results/resource-v3-folder-deny.log" 2>&1
for bench_agent in claude opencode codex; do
  bench_build_flag=""
  if [ "$bench_agent" = claude ]; then bench_build_flag=--skip-build; fi
  python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v2-$bench_agent-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --agents "$bench_agent" --single-agent-image --runs 2 --skip-provider-setup $bench_build_flag > "$bench_root/results/openshell-v2-$bench_agent-final.log" 2>&1
  python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-workflow-v2-$bench_agent-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --agents "$bench_agent" --single-agent-image --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$bench_root/results/openshell-workflow-v2-$bench_agent-final.log" 2>&1
  docker image inspect "ouro-comparison-$bench_agent-v2:20261011" > "$bench_root/results/openshell-v2-$bench_agent-final/image-inspect.json"
  docker image rm "ouro-comparison-$bench_agent-v2:20261011" > "$bench_root/results/openshell-v2-$bench_agent-final/image-cache-removal.log" 2>&1
done
python3 "$bench_root/harness/openshell_perf_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-perf-v2-final" --samples 30 --warmup 3 --skip-build > "$bench_root/results/openshell-perf-v2-final.log" 2>&1
echo VPS-FINAL-COMPLETE
