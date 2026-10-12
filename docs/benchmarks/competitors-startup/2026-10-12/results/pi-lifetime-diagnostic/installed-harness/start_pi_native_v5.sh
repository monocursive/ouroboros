#!/bin/sh
set -eu
bench_old="$HOME/bench-ouro-startup-final"
while kill -0 "$1" 2>/dev/null; do
 bench_state=$(ps -o stat= -p "$1" || true)
 case "$bench_state" in Z*) break;; esac
 sleep 10
done
grep -q LINUX-FULL-COMPLETE "$bench_old/results/full-followup-resume.log"
cp "$bench_old/probe-v5.rs" "$HOME/bench-ouro-startup/src/crates/ouro-jail/src/platform/linux/probe.rs"
python3 - <<'PY_PREP'
from pathlib import Path
import shutil,tarfile
old=Path.home()/'bench-ouro-startup-final';new=Path.home()/'bench-ouro-startup-stable-final';assert not new.exists();new.mkdir(mode=0o700);shutil.copytree(old/'bin',new/'bin',symlinks=True)
for name in ['harness','results','runs','data','config']:(new/name).mkdir(mode=0o700)
with tarfile.open(old/'native-final-harness.tar.gz') as tar:tar.extractall(new/'harness',filter='data')
shutil.copyfile(old/'results/doctor-before.json',new/'results/doctor-before.json')
PY_PREP
sh "$HOME/bench-ouro-startup-stable-final/harness/validate_native_final.sh" "$HOME/bench-ouro-startup/src" pi > "$HOME/bench-ouro-startup-stable-final/results/native-full.log" 2>&1
