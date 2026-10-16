#!/bin/sh
# Rerun 2026-10-16 VPS coding battery: native small+workflow, container small+workflow.
# Waits for the perf run to finish so phases stay serialized on this host.
set -eu
B=/home/ubuntu/bench-ouro-rerun
while ! grep -q VPS-PERF-DONE "$B/perf-run.log" 2>/dev/null; do sleep 30; done
# The coding lanes need the same userns setting as the 2026-10-11 cohort.
sysctl kernel.apparmor_restrict_unprivileged_userns > "$B/results/vps-agents-userns-before.txt"
sudo -n sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >> "$B/results/vps-agents-userns-before.txt"
[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = "0" ] || { echo USERNS-STILL-RESTRICTED; exit 1; }
mkdir -p "$B/bin"
for n in greywall greyproxy lxc-exec claude opencode codex codex-code-mode-host; do cp -L "/home/ubuntu/bench-ouro/bin/$n" "$B/bin/$n"; done
cp /home/ubuntu/ukai-src/target/release/ukai-jail "$B/bin/ukai-jail"
export PATH="$B/bin:/home/ubuntu/.opencode/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$B/harness"
mkdir -p "$B/results"
for agent in claude opencode codex; do
  python3 "$B/harness/agentbench_v2.py" --root "$B" --out "$B/results/v5-$agent-rerun" --key-file /home/ubuntu/bench-ouro/anthropic.key --auth-file "$B/auth/codex/auth.json" --agents "$agent" --tasks add-multiply,fix-offbyone,refactor-yaml-json --runs 2 --modes direct,ouro,greywall,mxc --wall 180 > "$B/results/v5-$agent-rerun.log" 2>&1
done
python3 "$B/harness/agentbench_workflow.py" --root "$B" --out "$B/results/workflow-v2-rerun" --key-file /home/ubuntu/bench-ouro/anthropic.key --auth-file "$B/auth/codex/auth.json" --agents claude,opencode,codex --tasks inventory-workflow --runs 1 --modes direct,ouro,greywall,mxc --wall 240 > "$B/results/workflow-v2-rerun.log" 2>&1
export HOME=$B XDG_CONFIG_HOME=$B/openshell/config XDG_STATE_HOME=$B/openshell/state OPENSHELL_LOCAL_TLS_DIR=$B/openshell/tls
OS=/home/ubuntu/bench-ouro/bin-0.1.4/openshell
for agent in claude opencode codex; do
  if [ "$agent" = claude ]; then pskip=""; else pskip=--skip-provider-setup; fi
  python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-$agent" --key-file /home/ubuntu/bench-ouro/anthropic.key --auth-file "$B/auth/codex/auth.json" --openshell "$OS" --agents "$agent" --single-agent-image --runs 2 $pskip > "$B/results/os14-$agent.log" 2>&1
  python3 "$B/harness/openshell_agent_v2.py" --root "$B" --out "$B/results/os14-wf-$agent" --key-file /home/ubuntu/bench-ouro/anthropic.key --auth-file "$B/auth/codex/auth.json" --openshell "$OS" --agents "$agent" --single-agent-image --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$B/results/os14-wf-$agent.log" 2>&1
  docker image inspect "ouro-comparison-$agent-v2:20261016" > "$B/results/os14-$agent/image-inspect.json"
  docker image rm "ouro-comparison-$agent-v2:20261016" > "$B/results/os14-$agent/image-cache-removal.log" 2>&1
done
sysctl -w kernel.apparmor_restrict_unprivileged_userns=1 > "$B/results/vps-agents-userns-after.txt" 2>/dev/null || sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1 > "$B/results/vps-agents-userns-after.txt"
echo VPS-AGENTS-DONE
