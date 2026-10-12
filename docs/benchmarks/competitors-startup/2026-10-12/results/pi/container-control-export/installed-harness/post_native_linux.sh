#!/bin/sh
set -eu
bench_host="$1"
bench_pid="$2"
bench_root="$HOME/bench-ouro-startup-final"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
while kill -0 "$bench_pid" 2>/dev/null; do
  bench_stat=$(ps -p "$bench_pid" -o stat= || true)
  case "$bench_stat" in Z*) break;; esac
  sleep 10
done
if [ "$bench_host" = pi ]; then
  sh "$bench_root/harness/run_pi_opencode_corrected.sh"
fi
mkdir -p "$bench_root/runs/grey-rules-after"
ln -s "$bench_root/bin" "$bench_root/runs/grey-rules-after/bin"
ln -s "$bench_root/harness" "$bench_root/runs/grey-rules-after/harness"
python3 "$bench_root/harness/grey_rule_probe.py" --root "$bench_root/runs/grey-rules-after" --out "$bench_root/results/grey-rules-after" > "$bench_root/results/grey-rules-after.log" 2>&1
if [ "$bench_host" = vps ]; then
  python3 "$bench_root/harness/compress_proxy_store.py"
  sh "$bench_root/harness/run_vps_container.sh"
else
  sh "$bench_root/harness/run_pi_container.sh"
fi
sh "$bench_root/harness/finish_export.sh"
