#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
while kill -0 "$1" 2>/dev/null; do sleep 10; done
for bench_probe in backing-v3 grey-rules-v3; do
  mkdir -p "$bench_root/runs/$bench_probe"
  ln -s "$bench_root/bin" "$bench_root/runs/$bench_probe/bin"
  ln -s "$bench_root/harness" "$bench_root/runs/$bench_probe/harness"
done
python3 "$bench_root/harness/backing_probe.py" --root "$bench_root/runs/backing-v3" --out "$bench_root/results/backing-v3" > "$bench_root/results/backing-v3.log" 2>&1
python3 "$bench_root/harness/grey_rule_probe.py" --root "$bench_root/runs/grey-rules-v3" --out "$bench_root/results/grey-rules-v3" > "$bench_root/results/grey-rules-v3.log" 2>&1
echo POST-LINUX-COMPLETE
