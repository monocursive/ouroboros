#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro"
export PATH="$bench_root/bin:/opt/homebrew/bin:/usr/bin:/bin"
export DOCKER_HOST="unix://$HOME/.orbstack/run/docker.sock"
export DOCKER_CONFIG="$bench_root/openshell/docker-config"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
while kill -0 4337 2>/dev/null; do sleep 10; done
python3 "$bench_root/harness/container_egress_probe.py" --out "$bench_root/results/container-egress-v3" > "$bench_root/results/container-egress-v3.log" 2>&1
mkdir -p "$bench_root/runs/backing-v3"
ln -s "$bench_root/bin" "$bench_root/runs/backing-v3/bin"
ln -s "$bench_root/harness" "$bench_root/runs/backing-v3/harness"
python3 "$bench_root/harness/backing_probe.py" --root "$bench_root/runs/backing-v3" --out "$bench_root/results/backing-v3" > "$bench_root/results/backing-v3.log" 2>&1
echo MAC-FINAL-COMPLETE
