#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-after"
export PATH="$bench_root/bin:/opt/homebrew/bin:/usr/bin:/bin"
export PYTHONPATH="$bench_root/harness"
export DOCKER_HOST="unix://$HOME/.orbstack/run/docker.sock"
export DOCKER_CONFIG="$bench_root/openshell/docker-config"
export DOCKER_BUILDKIT=0
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
mkdir -p "$bench_root/runs/perf-after"
ln -s "$bench_root/bin" "$bench_root/runs/perf-after/bin"
ln -s "$bench_root/harness" "$bench_root/runs/perf-after/harness"
python3 "$bench_root/harness/suite.py" --root "$bench_root/runs/perf-after" --out "$bench_root/results/perf-after" --tools direct,mxc --samples 30 --warmup 3 > "$bench_root/results/perf-after.log" 2>&1
python3 "$bench_root/harness/agentbench_v2.py" --root "$bench_root" --out "$bench_root/results/native-after" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/.codex/auth.json" --modes direct,mxc,greywall --runs 2 > "$bench_root/results/native-after.log" 2>&1
python3 "$bench_root/harness/agentbench_workflow.py" --root "$bench_root" --out "$bench_root/results/workflow-after" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/.codex/auth.json" --modes direct,mxc,greywall --tasks inventory-workflow --runs 1 > "$bench_root/results/workflow-after.log" 2>&1
python3 "$bench_root/harness/host_snapshot.py" --root "$bench_root"
echo MAC-NATIVE-COMPLETE
