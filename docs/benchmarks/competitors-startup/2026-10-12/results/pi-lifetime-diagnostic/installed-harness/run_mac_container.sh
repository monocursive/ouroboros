#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup"
export PATH="$bench_root/bin:/opt/homebrew/bin:/usr/bin:/bin"
export PYTHONPATH="$bench_root/harness"
export DOCKER_HOST="unix://$HOME/.orbstack/run/docker.sock"
export DOCKER_CONFIG="$bench_root/openshell/docker-config"
export DOCKER_BUILDKIT=0
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-after-v2" --container-bins "$bench_root/linux-bin" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/.codex/auth.json" --codex-provider benchmark-codex-after --runs 2 --skip-provider-setup > "$bench_root/results/container-after-v2.log" 2>&1
python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-workflow-after" --container-bins "$bench_root/linux-bin" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/.codex/auth.json" --codex-provider benchmark-codex-after --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$bench_root/results/container-workflow-after.log" 2>&1
python3 "$bench_root/harness/openshell_perf_v2.py" --root "$bench_root" --out "$bench_root/results/container-perf-after" --samples 30 --warmup 3 --skip-build > "$bench_root/results/container-perf-after.log" 2>&1
python3 "$bench_root/harness/container_limits_probe.py" --out "$bench_root/results/container-limits-after" > "$bench_root/results/container-limits-after.log" 2>&1
python3 "$bench_root/harness/container_filesystem_probe.py" --out "$bench_root/results/container-filesystem-after" > "$bench_root/results/container-filesystem-after.log" 2>&1
python3 "$bench_root/harness/container_egress_probe.py" --out "$bench_root/results/container-egress-after" > "$bench_root/results/container-egress-after.log" 2>&1
python3 "$bench_root/harness/ouro_vm_lane.py" --root "$bench_root/runs/vm-after" --out "$bench_root/results/vm-after" --vm "$HOME/.local/bin/ouro-vm" --samples 3 --warmup 0 > "$bench_root/results/vm-after.log" 2>&1
echo MAC-CONTAINER-COMPLETE
