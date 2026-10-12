#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
if [ "$1" != done ]; then
  while kill -0 "$1" 2>/dev/null; do sleep 10; done
fi
python3 -c 'import pathlib,sys; sys.exit(0 if (pathlib.Path.home()/"bench-ouro/results/next-native.log").read_text().splitlines()[-1] == "NATIVE-PIPELINE-COMPLETE" else 1)'
openshell status > "$bench_root/results/openshell-v2-status.log" 2>&1
docker info --format '{{json .}}' > "$bench_root/results/docker-v2-info.json"
python3 -c 'import openshell_lane,json,pathlib; r=openshell_lane.build_image(pathlib.Path.home()/"bench-ouro"); (pathlib.Path.home()/"bench-ouro/results/container-base-build.json").write_text(json.dumps(r,indent=2)); assert r["exit"]==0' 
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v2-smoke" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --tasks add-multiply --runs 1 > "$bench_root/results/openshell-v2-smoke.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-v2-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --runs 2 --skip-build --skip-provider-setup > "$bench_root/results/openshell-v2-final.log" 2>&1
python3 "$bench_root/harness/openshell_agent_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-workflow-v2-final" --key-file "$bench_root/anthropic.key" --auth-file "$bench_root/auth/codex/auth.json" --tasks inventory-workflow --runs 1 --skip-build --skip-provider-setup > "$bench_root/results/openshell-workflow-v2-final.log" 2>&1
python3 "$bench_root/harness/openshell_perf_v2.py" --root "$bench_root" --out "$bench_root/results/openshell-perf-v2-final" --samples 30 --warmup 3 --skip-build > "$bench_root/results/openshell-perf-v2-final.log" 2>&1
echo 'CONTAINER-PIPELINE-COMPLETE'
