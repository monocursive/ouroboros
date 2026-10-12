#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
python3 "$bench_root/harness/finalize_linux_validation.py" "$bench_root" "$1"
mkdir -p "$bench_root/runs/profile-v3" "$bench_root/results/profile-v3"
ln -s "$bench_root/bin" "$bench_root/runs/profile-v3/bin"
ln -s "$bench_root/harness" "$bench_root/runs/profile-v3/harness"
ln -s "$bench_root/results/profile-v3" "$bench_root/runs/profile-v3/results"
python3 "$bench_root/harness/profile_startup.py" --root "$bench_root/runs/profile-v3" > "$bench_root/results/profile-v3.log" 2>&1
sh "$bench_root/harness/run_linux_native.sh"
echo PROFILE-NATIVE-COMPLETE
