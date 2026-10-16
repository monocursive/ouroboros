#!/bin/bash
# Rerun 2026-10-16 Mac coding battery: native direct/greywall/mxc (ouro native
# unsupported), container docker + openshell fresh/warm with all three clients.
set -eu
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
B=/Users/monocursive/bench-ouro-rerun
while ! grep -q MAC-PERF-DONE "$B/perf-run.log" 2>/dev/null; do sleep 30; done
mkdir -p "$B/bin"
for n in greywall greyproxy mxc-exec-mac claude opencode codex codex-code-mode-host; do ln -sf "/Users/monocursive/bench-ouro/bin/$n" "$B/bin/$n"; done
export PATH="$B/bin:/Users/monocursive/.local/bin:/opt/homebrew/bin:/usr/bin:/bin"
export PYTHONPATH="$B/harness"
mkdir -p "$B/results"
for agent in claude opencode codex; do
  python3 "$B/harness/agentbench_v2.py" --root "$B" --out "$B/results/v5-$agent-rerun" --key-file /Users/monocursive/bench-ouro/anthropic.key --auth-file /Users/monocursive/.codex/auth.json --agents "$agent" --tasks add-multiply,fix-offbyone,refactor-yaml-json --runs 2 --modes direct,greywall,mxc --wall 180 > "$B/results/v5-$agent-rerun.log" 2>&1
done
python3 "$B/harness/agentbench_workflow.py" --root "$B" --out "$B/results/workflow-v2-rerun" --key-file /Users/monocursive/bench-ouro/anthropic.key --auth-file /Users/monocursive/.codex/auth.json --agents claude,opencode,codex --tasks inventory-workflow --runs 1 --modes direct,greywall,mxc --wall 240 > "$B/results/workflow-v2-rerun.log" 2>&1
B=/Users/monocursive/bench-ouro-rerun
export HOME=$B XDG_CONFIG_HOME=$B/openshell/config XDG_STATE_HOME=$B/openshell/state OPENSHELL_LOCAL_TLS_DIR=$B/openshell/tls
OS=/Users/monocursive/bench-ouro/bin-0.1.4/openshell
python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-smoke" --container-bins /Users/monocursive/bench-ouro/linux-bin --key-file /Users/monocursive/bench-ouro/anthropic.key --auth-file /Users/monocursive/.codex/auth.json --openshell "$OS" --tasks add-multiply --runs 1 --skip-build > "$B/results/os14-smoke.log" 2>&1
python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-agents" --container-bins /Users/monocursive/bench-ouro/linux-bin --key-file /Users/monocursive/bench-ouro/anthropic.key --auth-file /Users/monocursive/.codex/auth.json --openshell "$OS" --runs 2 --skip-build > "$B/results/os14-agents.log" 2>&1
python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-wf" --container-bins /Users/monocursive/bench-ouro/linux-bin --key-file /Users/monocursive/bench-ouro/anthropic.key --auth-file /Users/monocursive/.codex/auth.json --openshell "$OS" --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$B/results/os14-wf.log" 2>&1
echo MAC-AGENTS-DONE
