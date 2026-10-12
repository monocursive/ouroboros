#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-native-final"
bench_pid="$1"
while kill -0 "$bench_pid" 2>/dev/null; do
  bench_stat=$(ps -p "$bench_pid" -o stat= || true)
  case "$bench_stat" in Z*) break;; esac
  sleep 10
done
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
for bench_file in gateway-start.json gateway-after.log service-cleanup.json service-cleanup.log host-provenance-final.json; do
  if [ -f "$bench_root/results/$bench_file" ]; then
    cp "$bench_root/results/$bench_file" "$bench_root/results/phase1-$bench_file"
  fi
done
if [ -f "$bench_root/after-evidence.tar.gz" ]; then
  mv "$bench_root/after-evidence.tar.gz" "$bench_root/after-evidence-initial.tar.gz"
fi
python3 "$bench_root/harness/start_gateway.py"
python3 "$bench_root/harness/pi_warm_after.py" --root "$bench_root" --out "$bench_root/results/container-warm-availability-v2" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" > "$bench_root/results/container-warm-availability-v2.log" 2>&1
for bench_agent in claude opencode codex; do
  bench_ready=$(python3 - "$bench_root/results/container-warm-availability-v2/availability.json" "$bench_agent" <<'PY'
import json,sys
print(int(next(r for r in json.load(open(sys.argv[1])) if r['agent']==sys.argv[2])['ready']))
PY
)
  if [ "$bench_ready" = 1 ]; then
    python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-warm-after-$bench_agent" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --agents "$bench_agent" --modes openshell-warm --codex-provider benchmark-codex-after --runs 2 --skip-provider-setup --skip-build > "$bench_root/results/container-warm-after-$bench_agent.log" 2>&1
    python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-warm-workflow-after-$bench_agent" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --agents "$bench_agent" --modes openshell-warm --codex-provider benchmark-codex-after --tasks inventory-workflow --runs 1 --skip-provider-setup --skip-build > "$bench_root/results/container-warm-workflow-after-$bench_agent.log" 2>&1
  fi
done
sh "$bench_root/harness/finish_export.sh"
echo CORRECTED-AVAILABILITY-COMPLETE
