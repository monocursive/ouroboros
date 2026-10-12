#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-native-final"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$bench_root/harness"
while kill -0 "$1" 2>/dev/null; do
 bench_state=$(ps -o stat= -p "$1" || true)
 case "$bench_state" in Z*) break;; esac
 sleep 10
done
grep -q PROFILE-NATIVE-COMPLETE "$bench_root/results/native-full.log"
mkdir -p "$bench_root/runs/grey-rules-after"
ln -s "$bench_root/bin" "$bench_root/runs/grey-rules-after/bin"
ln -s "$bench_root/harness" "$bench_root/runs/grey-rules-after/harness"
python3 "$bench_root/harness/grey_rule_probe.py" --root "$bench_root/runs/grey-rules-after" --out "$bench_root/results/grey-rules-after" > "$bench_root/results/grey-rules-after.log" 2>&1
if [ "$2" = vps ]; then
 python3 "$bench_root/harness/compress_proxy_store.py"
 sh "$bench_root/harness/run_vps_container_startup.sh"
else
 sh "$bench_root/harness/run_pi_container_startup.sh"
fi
sh "$bench_root/harness/finish_export.sh"
echo LINUX-FULL-COMPLETE
