#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-final"
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
python3 "$bench_root/harness/finalize_linux_validation.py" "$bench_root" "$1"
mkdir -p "$bench_root/runs/profile-final" "$bench_root/results/profile-final"
ln -s "$bench_root/bin" "$bench_root/runs/profile-final/bin"
ln -s "$bench_root/harness" "$bench_root/runs/profile-final/harness"
ln -s "$bench_root/results/profile-final" "$bench_root/runs/profile-final/results"
python3 "$bench_root/harness/profile_startup.py" --root "$bench_root/runs/profile-final" > "$bench_root/results/profile-final.log" 2>&1
sh "$bench_root/harness/run_linux_native.sh"
echo PROFILE-NATIVE-COMPLETE
