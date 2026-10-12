#!/bin/sh
set -eu
bench_root="$HOME/bench-ouro-startup-final"
while kill -0 "$1" 2>/dev/null; do
 bench_state=$(ps -o stat= -p "$1" || true)
 case "$bench_state" in Z*) break;; esac
 sleep 10
done
grep -q precision_current_confirmation "$bench_root/results/validation-baseline-precision.log"
python3 - "$bench_root" <<'PY_CHECK'
from pathlib import Path
import json,sys,re
root=Path(sys.argv[1]);v=json.loads((root/'results/validation/baseline-precision-comparison.json').read_text());assert v['current_source_restored']
s=(root/'results/validation/j4_tracer_precision_linux-baseline-race.log').read_text();assert 'test result: FAILED' in s and 'QueueFull' in s
PY_CHECK
python3 "$bench_root/harness/check_final_validation.py" "$bench_root" pi
"$bench_root/bin/ouro-jail" doctor --json > "$bench_root/results/validation/doctor-after.json" 2> "$bench_root/results/validation/doctor-after.stderr.log"
sh "$bench_root/harness/profile_and_native.sh" "$HOME/bench-ouro-startup/src"
echo FINAL-PI-NATIVE-COMPLETE
