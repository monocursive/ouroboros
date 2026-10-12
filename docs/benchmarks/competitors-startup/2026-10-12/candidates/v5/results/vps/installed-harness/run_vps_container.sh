#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-native-final"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
python3 "$bench_root/harness/start_gateway.py"
python3 "$bench_root/harness/refresh_codex_from_cache.py" --root "$bench_root" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --out "$bench_root/results/provider-after-setup" --fresh --provider-name benchmark-codex-after
for bench_agent in claude opencode codex; do
  python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-after-$bench_agent" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --agents "$bench_agent" --single-agent-image --codex-provider benchmark-codex-after --runs 2 --skip-provider-setup > "$bench_root/results/container-after-$bench_agent.log" 2>&1
  python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-workflow-after-$bench_agent" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --agents "$bench_agent" --single-agent-image --codex-provider benchmark-codex-after --tasks inventory-workflow --runs 1 --skip-provider-setup --skip-build > "$bench_root/results/container-workflow-after-$bench_agent.log" 2>&1
  docker image inspect "ouro-comparison-$bench_agent-after:20261011" > "$bench_root/results/container-after-$bench_agent/image-inspect.json"
  docker image rm "ouro-comparison-$bench_agent-after:20261011" > "$bench_root/results/container-after-$bench_agent/image-cache-removal.log" 2>&1
done
python3 "$bench_root/harness/openshell_perf_v2.py" --root "$bench_root" --out "$bench_root/results/container-perf-after" --samples 30 --warmup 3 --skip-build > "$bench_root/results/container-perf-after.log" 2>&1
python3 "$bench_root/harness/container_limits_probe.py" --out "$bench_root/results/container-limits-after" > "$bench_root/results/container-limits-after.log" 2>&1
python3 "$bench_root/harness/container_filesystem_probe.py" --out "$bench_root/results/container-filesystem-after" > "$bench_root/results/container-filesystem-after.log" 2>&1
python3 "$bench_root/harness/container_egress_probe.py" --out "$bench_root/results/container-egress-after" > "$bench_root/results/container-egress-after.log" 2>&1
echo VPS-CONTAINER-COMPLETE
