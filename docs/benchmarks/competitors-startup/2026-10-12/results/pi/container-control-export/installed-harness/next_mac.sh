#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro"
export PATH="$bench_root/bin:/opt/homebrew/bin:/usr/bin:/bin"
export DOCKER_HOST="unix://$HOME/.orbstack/run/docker.sock"
export DOCKER_CONFIG="$bench_root/openshell/docker-config"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
while kill -0 "$1" 2>/dev/null; do sleep 10; done
python3 -c 'import json,pathlib,sys; s=json.loads((pathlib.Path.home()/"bench-ouro/results/openshell-v2-codex-routing-smoke/agent-summary.json").read_text()); sys.exit(0 if len(s)==3 and all(v["success"]==v["runs"] for v in s.values()) else 1)'
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v2-final" --container-bins "$bench_root/linux-bin" --key-file "$bench_root/anthropic.key" --auth-file "$HOME/.codex/auth.json" --runs 2 --skip-build --skip-provider-setup > "$bench_root/results/openshell-v2-final.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-workflow-v2-final" --container-bins "$bench_root/linux-bin" --key-file "$bench_root/anthropic.key" --auth-file "$HOME/.codex/auth.json" --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$bench_root/results/openshell-workflow-v2-final.log" 2>&1
python3 "$bench_root/harness/openshell_perf_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-perf-v2-final" --samples 30 --warmup 3 --skip-build > "$bench_root/results/openshell-perf-v2-final.log" 2>&1
sh "$bench_root/harness/next_native.sh" done openshell-v2-final direct,mxc,greywall "$HOME/.codex/auth.json"
echo 'MAC-PIPELINE-COMPLETE'
