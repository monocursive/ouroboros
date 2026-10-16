#!/bin/bash
# Rerun 2026-10-16 Mac container coding lanes: build agent image once (the
# prior corpus' dated tag does not exist for 20261016), then small+workflow.
set -eu
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
B=/Users/monocursive/bench-ouro-rerun
export HOME=$B XDG_CONFIG_HOME=$B/openshell/config XDG_STATE_HOME=$B/openshell/state OPENSHELL_LOCAL_TLS_DIR=$B/openshell/tls
OS=/Users/monocursive/bench-ouro/bin-0.1.4/openshell
export PYTHONPATH="$B/harness"
mkdir -p "$B/results"
python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-smoke" --container-bins /Users/monocursive/bench-ouro/linux-bin --key-file /Users/monocursive/bench-ouro/anthropic.key --auth-file /Users/monocursive/.codex/auth.json --openshell "$OS" --tasks add-multiply --runs 1 --skip-provider-setup > "$B/results/os14-smoke.log" 2>&1
python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-agents" --container-bins /Users/monocursive/bench-ouro/linux-bin --key-file /Users/monocursive/bench-ouro/anthropic.key --auth-file /Users/monocursive/.codex/auth.json --openshell "$OS" --runs 2 --skip-build --skip-provider-setup > "$B/results/os14-agents.log" 2>&1
python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-wf" --container-bins /Users/monocursive/bench-ouro/linux-bin --key-file /Users/monocursive/bench-ouro/anthropic.key --auth-file /Users/monocursive/.codex/auth.json --openshell "$OS" --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$B/results/os14-wf.log" 2>&1
echo MAC-CONTAINER-DONE
