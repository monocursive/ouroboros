#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-native-final"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-after-codex" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --agents codex --single-agent-image --codex-provider benchmark-codex-after --runs 2 --skip-provider-setup > "$bench_root/results/container-after-codex.log" 2>&1
python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-workflow-after-codex" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --agents codex --single-agent-image --codex-provider benchmark-codex-after --tasks inventory-workflow --runs 1 --skip-provider-setup --skip-build > "$bench_root/results/container-workflow-after-codex.log" 2>&1
docker image inspect ouro-comparison-codex-after:20261011 > "$bench_root/results/container-after-codex/image-inspect.json"
docker image rm ouro-comparison-codex-after:20261011 > "$bench_root/results/container-after-codex/image-cache-removal.log" 2>&1
python3 "$bench_root/harness/openshell_perf_v2.py" --root "$bench_root" --out "$bench_root/results/container-perf-after" --samples 30 --warmup 3 --skip-build > "$bench_root/results/container-perf-after.log" 2>&1
python3 "$bench_root/harness/container_limits_probe.py" --out "$bench_root/results/container-limits-after" > "$bench_root/results/container-limits-after.log" 2>&1
python3 "$bench_root/harness/container_filesystem_probe.py" --out "$bench_root/results/container-filesystem-after" > "$bench_root/results/container-filesystem-after.log" 2>&1
python3 "$bench_root/harness/container_egress_probe.py" --out "$bench_root/results/container-egress-after" > "$bench_root/results/container-egress-after.log" 2>&1
sh "$bench_root/harness/finish_export.sh"
