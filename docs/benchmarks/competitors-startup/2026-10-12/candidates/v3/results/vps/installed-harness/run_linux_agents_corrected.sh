#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
python3 "$bench_root/harness/agentbench_v2.py" --root "$bench_root" --out "$bench_root/results/native-after-v2" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --runs 2 > "$bench_root/results/native-after-v2.log" 2>&1
python3 "$bench_root/harness/agentbench_workflow.py" --root "$bench_root" --out "$bench_root/results/workflow-after-v2" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --tasks inventory-workflow --runs 1 > "$bench_root/results/workflow-after-v2.log" 2>&1
echo CORRECTED-NATIVE-COMPLETE
