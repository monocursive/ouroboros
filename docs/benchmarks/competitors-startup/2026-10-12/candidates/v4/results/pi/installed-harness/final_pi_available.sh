#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
python3 "$bench_root/harness/refresh_codex_from_cache.py" --root "$bench_root" --auth-file "$bench_root/auth/codex/auth.json" --out "$bench_root/results/codex-provider-fresh-recovery-v2" --fresh --provider-name benchmark-codex-v3 > "$bench_root/results/codex-provider-fresh-recovery-v2.log" 2>&1
python3 "$bench_root/harness/pi_warm_startup.py" --root "$bench_root" --out "$bench_root/results/openshell-warm-availability" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" > "$bench_root/results/openshell-warm-availability.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v2-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --modes docker,openshell-ephemeral --codex-provider benchmark-codex-v3 --runs 2 --skip-build --skip-provider-setup > "$bench_root/results/openshell-v2-final.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-workflow-v2-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --modes docker,openshell-ephemeral --codex-provider benchmark-codex-v3 --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$bench_root/results/openshell-workflow-v2-final.log" 2>&1
python3 "$bench_root/harness/openshell_perf_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-perf-v2-final" --samples 30 --warmup 3 --skip-build --docker-only > "$bench_root/results/openshell-perf-v2-final.log" 2>&1
python3 "$bench_root/harness/container_limits_probe.py" --out "$bench_root/results/container-limits-v4" > "$bench_root/results/container-limits-v4.log" 2>&1
python3 "$bench_root/harness/container_filesystem_probe.py" --out "$bench_root/results/container-filesystem-v4" > "$bench_root/results/container-filesystem-v4.log" 2>&1
python3 "$bench_root/harness/host_snapshot.py" --root "$bench_root" > "$bench_root/results/host-provenance.log" 2>&1
mkdir -p "$bench_root/results/container-image-harness"
bench_cid=$(docker create ouro-comparison-agents-v2:20261011)
docker cp "$bench_cid:/opt/bench/." "$bench_root/results/container-image-harness/"
docker image inspect ouro-comparison-agents-v2:20261011 --format '{{.Id}}' > "$bench_root/results/container-image-harness/image-id.txt"
docker rm "$bench_cid" >/dev/null
echo PI-AVAILABLE-FINAL-COMPLETE
