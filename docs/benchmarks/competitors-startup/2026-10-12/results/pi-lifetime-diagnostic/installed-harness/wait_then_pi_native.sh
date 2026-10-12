#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup"
while kill -0 "$1" 2>/dev/null; do
 bench_state=$(ps -o stat= -p "$1" || true)
 case "$bench_state" in Z*) break;; esac
 sleep 10
done
grep -q r13_current_confirmation "$bench_root/results/validation-baseline.log"
python3 - "$bench_root" <<'PY_CHECK'
from pathlib import Path
import json,sys
root=Path(sys.argv[1]);v=json.loads((root/'results/validation/baseline-failure-comparison.json').read_text());assert v['current_source_restored']
PY_CHECK
export PATH="$bench_root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
mkdir -p "$bench_root/runs/write-matrix-after"
ln -s "$bench_root/bin" "$bench_root/runs/write-matrix-after/bin"
ln -s "$bench_root/harness" "$bench_root/runs/write-matrix-after/harness"
python3 "$bench_root/harness/write_matrix_after.py" --root "$bench_root/runs/write-matrix-after" --out "$bench_root/results/write-matrix-after" --instrumented-source "$bench_root/runs/write-diagnostic-before/work/workload-diag.c" --rounds 6 > "$bench_root/results/write-matrix-after.log" 2>&1
sh "$bench_root/harness/profile_and_native.sh" "$bench_root/src"
