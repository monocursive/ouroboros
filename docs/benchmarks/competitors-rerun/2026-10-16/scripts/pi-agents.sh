#!/bin/sh
# Rerun 2026-10-16 Pi coding battery: native small+workflow; container docker controls only.
set -eu
B=/home/monocursive/bench-ouro-rerun
while ! grep -q PI-PERF-DONE "$B/perf-run.log" 2>/dev/null; do sleep 30; done
mkdir -p "$B/bin"
for n in greywall greyproxy lxc-exec claude opencode codex codex-code-mode-host; do cp -L "/home/monocursive/bench-ouro/bin/$n" "$B/bin/$n"; done
cp /home/monocursive/ukai-src/target/release/ukai-jail "$B/bin/ukai-jail"
export PATH="$B/bin:/home/monocursive/.opencode/bin:/usr/sbin:/sbin:/usr/bin:/bin"
export PYTHONPATH="$B/harness"
mkdir -p "$B/results"
for agent in claude opencode codex; do
  python3 "$B/harness/agentbench_v2.py" --root "$B" --out "$B/results/v5-$agent-rerun" --key-file /home/monocursive/bench-ouro/anthropic.key --auth-file "$B/auth/codex/auth.json" --agents "$agent" --tasks add-multiply,fix-offbyone,refactor-yaml-json --runs 2 --modes direct,ouro,greywall,mxc --wall 180 > "$B/results/v5-$agent-rerun.log" 2>&1
done
python3 "$B/harness/agentbench_workflow.py" --root "$B" --out "$B/results/workflow-v2-rerun" --key-file /home/monocursive/bench-ouro/anthropic.key --auth-file "$B/auth/codex/auth.json" --agents claude,opencode,codex --tasks inventory-workflow --runs 1 --modes direct,ouro,greywall,mxc --wall 240 > "$B/results/workflow-v2-rerun.log" 2>&1
OS=/home/monocursive/bench-ouro/bin-0.1.4/openshell
for agent in claude opencode codex; do
  python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-docker-$agent" --key-file /home/monocursive/bench-ouro/anthropic.key --auth-file "$B/auth/codex/auth.json" --openshell "$OS" --agents "$agent" --single-agent-image --runs 2 --modes docker --skip-provider-setup > "$B/results/os14-docker-$agent.log" 2>&1
  python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-docker-wf-$agent" --key-file /home/monocursive/bench-ouro/anthropic.key --auth-file "$B/auth/codex/auth.json" --openshell "$OS" --agents "$agent" --single-agent-image --tasks inventory-workflow --runs 1 --modes docker --skip-build --skip-provider-setup > "$B/results/os14-docker-wf-$agent.log" 2>&1
  docker image inspect "ouro-comparison-$agent-v2:20261016" > "$B/results/os14-docker-$agent/image-inspect.json"
  docker image rm "ouro-comparison-$agent-v2:20261016" > "$B/results/os14-docker-$agent/image-cache-removal.log" 2>&1
done
echo PI-AGENTS-DONE
