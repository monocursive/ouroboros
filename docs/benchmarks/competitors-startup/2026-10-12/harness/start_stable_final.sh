#!/bin/sh
set -eu
bench_source="$1"
bench_host="$2"
bench_old="$HOME/bench-ouro-startup-native-final"
bench_root="$HOME/bench-ouro-startup-stable-final"
bench_log=native-full.log
if [ "$bench_host" = pi ]; then bench_log=native-resume.log; fi
while kill -0 "$3" 2>/dev/null; do
 bench_state=$(ps -o stat= -p "$3" || true)
 case "$bench_state" in Z*) break;; esac
 sleep 10
done
grep -q FINAL-NATIVE-EXPORT-COMPLETE "$bench_old/results/$bench_log"
cp "$bench_old/fs-stable.rs" "$bench_source/crates/ouro-jail/src/platform/linux/fs.rs"
python3 - <<'PY_PREP'
from pathlib import Path
import os,shutil,tarfile
old=Path.home()/'bench-ouro-startup-native-final';new=Path.home()/'bench-ouro-startup-stable-final';assert not new.exists();new.mkdir(mode=0o700)
shutil.copytree(old/'bin',new/'bin',symlinks=True,copy_function=os.link)
# Only frozen tools are shared. New Ouro artifacts receive new inodes.
(new/'bin/ouro-jail').unlink();(new/'bin/ouro-fixture').unlink()
for name in ['harness','results','runs','data','config']:(new/name).mkdir(mode=0o700)
with tarfile.open(old/'stable-harness.tar.gz') as tar:tar.extractall(new/'harness',filter='data')
shutil.copyfile(old/'results/doctor-before.json',new/'results/doctor-before.json')
PY_PREP
sh "$bench_root/harness/validate_native_final.sh" "$bench_source" "$bench_host" > "$bench_root/results/native-full.log" 2>&1
