#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-native-final"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
mkdir -p "$bench_root/runs/grey-rules-after"
ln -s "$bench_root/bin" "$bench_root/runs/grey-rules-after/bin"
ln -s "$bench_root/harness" "$bench_root/runs/grey-rules-after/harness"
python3 "$bench_root/harness/grey_rule_probe.py" --root "$bench_root/runs/grey-rules-after" --out "$bench_root/results/grey-rules-after" > "$bench_root/results/grey-rules-after.log" 2>&1
python3 "$bench_root/harness/host_snapshot.py" --root "$bench_root" > "$bench_root/results/host-provenance-final.log" 2>&1
python3 "$bench_root/harness/cleanup_services.py" --root "$bench_root" --gateway-pid 0 > "$bench_root/results/service-cleanup.log" 2>&1
python3 "$bench_root/harness/export_results.py" --root "$bench_root" --key-file "$HOME/bench-ouro/anthropic.key" --auth-file "$HOME/bench-ouro/auth/codex/auth.json" --output "$bench_root/native-evidence.tar.gz" > "$bench_root/export-native.log" 2>&1
echo FINAL-NATIVE-EXPORT-COMPLETE
