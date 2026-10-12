#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-native-final"
while kill -0 "$1" 2>/dev/null; do
 bench_state=$(ps -o stat= -p "$1" || true)
 case "$bench_state" in Z*) break;; esac
 sleep 10
done
grep -q FINAL-PI-NATIVE-COMPLETE "$bench_root/results/native-resume.log"
cat "$bench_root/results/native-resume.log" >> "$bench_root/results/native-full.log"
sh "$bench_root/harness/linux_post_startup.sh" "$1" pi
