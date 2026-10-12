#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
while kill -0 1806664 2>/dev/null; do sleep 10; done
python3 "$bench_root/harness/refresh_codex_from_cache.py" --root "$bench_root" --auth-file "$bench_root/auth/codex/auth.json" --out "$bench_root/results/codex-provider-fresh-recovery" --fresh --provider-name benchmark-codex-v3 > "$bench_root/results/codex-provider-fresh-recovery.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v3-codex-smoke" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --agents codex --codex-provider benchmark-codex-v3 --single-agent-image --tasks add-multiply --runs 1 --skip-provider-setup > "$bench_root/results/openshell-v3-codex-smoke.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v3-codex-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --agents codex --codex-provider benchmark-codex-v3 --single-agent-image --runs 2 --skip-build --skip-provider-setup > "$bench_root/results/openshell-v3-codex-final.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-workflow-v3-codex-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --agents codex --codex-provider benchmark-codex-v3 --single-agent-image --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$bench_root/results/openshell-workflow-v3-codex-final.log" 2>&1
python3 "$bench_root/harness/container_limits_probe.py" --out "$bench_root/results/container-limits-v4" > "$bench_root/results/container-limits-v4.log" 2>&1
python3 "$bench_root/harness/container_filesystem_probe.py" --out "$bench_root/results/container-filesystem-v4" > "$bench_root/results/container-filesystem-v4.log" 2>&1
python3 "$bench_root/harness/host_snapshot.py" --root "$bench_root" > "$bench_root/results/host-provenance.log" 2>&1
echo VPS-CODEX-RECOVERY-COMPLETE
