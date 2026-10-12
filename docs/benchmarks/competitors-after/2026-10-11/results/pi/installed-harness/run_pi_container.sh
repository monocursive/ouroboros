#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-after"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
export OPENSHELL_LOCAL_TLS_DIR="$bench_root/openshell/tls"
export XDG_STATE_HOME="$bench_root/openshell/state"
python3 "$bench_root/harness/link_container_tools.py"
python3 "$bench_root/harness/start_gateway.py"
python3 "$bench_root/harness/refresh_codex_from_cache.py" --root "$bench_root" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --out "$bench_root/results/provider-after-setup" --fresh --provider-name benchmark-codex-after
python3 - <<'PY'
from pathlib import Path
from types import SimpleNamespace
from openshell_agent_after import build
root = Path.home() / 'bench-ouro-after'
out = root / 'results/container-image-after'
out.mkdir(parents=True, exist_ok=True)
build(SimpleNamespace(root=root, out=out, container_bins=root/'bin', single_agent_image=False, agents='claude,opencode,codex'))
PY
python3 "$bench_root/harness/pi_warm_after.py" --root "$bench_root" --out "$bench_root/results/container-warm-availability" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" > "$bench_root/results/container-warm-availability.log" 2>&1
for bench_agent in claude opencode codex; do
  bench_modes=$(python3 - "$bench_root/results/container-warm-availability/availability.json" "$bench_agent" <<'PY'
import json,sys
r = next(r for r in json.load(open(sys.argv[1])) if r['agent'] == sys.argv[2])
print('docker,openshell-ephemeral,openshell-warm' if r['ready'] else 'docker,openshell-ephemeral')
PY
)
  python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-after-$bench_agent" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --agents "$bench_agent" --modes "$bench_modes" --codex-provider benchmark-codex-after --runs 2 --skip-provider-setup --skip-build > "$bench_root/results/container-after-$bench_agent.log" 2>&1
  python3 "$bench_root/harness/openshell_agent_after.py" --root "$bench_root" --out "$bench_root/results/container-workflow-after-$bench_agent" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --agents "$bench_agent" --modes "$bench_modes" --codex-provider benchmark-codex-after --tasks inventory-workflow --runs 1 --skip-provider-setup --skip-build > "$bench_root/results/container-workflow-after-$bench_agent.log" 2>&1
done
python3 "$bench_root/harness/pi_perf_after.py" > "$bench_root/results/container-perf-after.log" 2>&1
python3 "$bench_root/harness/container_limits_probe.py" --out "$bench_root/results/container-limits-after" > "$bench_root/results/container-limits-after.log" 2>&1
python3 "$bench_root/harness/container_filesystem_probe.py" --out "$bench_root/results/container-filesystem-after" > "$bench_root/results/container-filesystem-after.log" 2>&1
python3 "$bench_root/harness/container_egress_probe.py" --out "$bench_root/results/container-egress-after" > "$bench_root/results/container-egress-after.log" 2>&1
echo PI-CONTAINER-COMPLETE
