#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-native-final"
export PATH="$bench_root/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
if [ "$(uname -s)" = Darwin ]; then
  export DOCKER_HOST="unix://$HOME/.orbstack/run/docker.sock"
  export DOCKER_CONFIG="$bench_root/openshell/docker-config"
  bench_auth="$HOME/.codex/auth.json"
else
  bench_auth="$HOME/bench-ouro/auth/codex/auth.json"
fi
python3 "$bench_root/harness/host_snapshot.py" --root "$bench_root" > "$bench_root/results/host-provenance-final.log" 2>&1
bench_gateway_pid=$(python3 - "$bench_root/results/gateway-start.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['pid'])
PY
)
python3 "$bench_root/harness/cleanup_services.py" --root "$bench_root" --gateway-pid "$bench_gateway_pid" > "$bench_root/results/service-cleanup.log" 2>&1
python3 "$bench_root/harness/export_results.py" --root "$bench_root" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$bench_auth" --output "$bench_root/after-evidence.tar.gz" > "$bench_root/export-after.log" 2>&1
echo EXPORT-COMPLETE
