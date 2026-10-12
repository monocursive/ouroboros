#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-native-final"
export PATH="$bench_root/bin:/opt/homebrew/bin:/usr/bin:/bin"
export PYTHONPATH="$bench_root/harness"
for bench_probe in resource-after backing-after grey-rules-after; do
  mkdir -p "$bench_root/runs/$bench_probe"
  ln -s "$bench_root/bin" "$bench_root/runs/$bench_probe/bin"
  ln -s "$bench_root/harness" "$bench_root/runs/$bench_probe/harness"
done
python3 "$bench_root/harness/resource_probes.py" --root "$bench_root/runs/resource-after" --out "$bench_root/results/resource-after" > "$bench_root/results/resource-after.log" 2>&1
python3 "$bench_root/harness/backing_probe.py" --root "$bench_root/runs/backing-after" --out "$bench_root/results/backing-after" > "$bench_root/results/backing-after.log" 2>&1
python3 "$bench_root/harness/grey_rule_probe.py" --root "$bench_root/runs/grey-rules-after" --out "$bench_root/results/grey-rules-after" > "$bench_root/results/grey-rules-after.log" 2>&1
sh "$bench_root/harness/finish_export.sh"
