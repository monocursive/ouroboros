#!/bin/sh
# ouro-jail vs greywall vs baseline — hyperfine suite, reference host.
export PATH=$HOME/.local/bin:$PATH
cd "$HOME/benchws" || exit 1
mkdir -p fsdir
OUT=/tmp/bench-results
mkdir -p "$OUT"

# The grep workload reads dir0..dir4 (1000 files with one needle); stage
# them once so `grep -rq needle` finds its match and exits zero.
if [ ! -d dir0 ]; then
  i=0
  while [ $i -lt 5 ]; do
    d=dir$i
    mkdir -p "$d"
    j=0
    while [ $j -lt 200 ]; do
      echo "filler text without the mark" > "$d/file$j"
      j=$((j+1))
    done
    echo "needle" > "$d/needle-file"
    i=$((i+1))
  done
fi

FAILED=0

run_bench () {
  name="$1"; shift
  log="$OUT/$name.log"
  if hyperfine -N --warmup 2 --min-runs 30 --style basic \
      -n baseline -n ouro-obs-on -n ouro-obs-off -n greywall \
      --export-json "$OUT/$name.json" "$@" >"$log" 2>&1
  then
    tail -12 "$log"
    echo "=== $name done ==="
  else
    status=$?
    tail -12 "$log" >&2
    echo "=== $name FAILED (hyperfine exit $status) ===" >&2
    FAILED=$status
  fi
}

# 1. spawn-only
run_bench true \
  'true' \
  'ouro-jail run --profile tool -- true' \
  'ouro-jail run --profile tool --observe off -- true' \
  'greywall -- true'

# 2. interpreter
run_bench python \
  'python3 -c pass' \
  'ouro-jail run --profile tool -- python3 -c pass' \
  'ouro-jail run --profile tool --observe off -- python3 -c pass' \
  'greywall -- python3 -c pass'

# 3. real tool
run_bench gitstatus \
  'git status' \
  'ouro-jail run --profile tool -- git status' \
  'ouro-jail run --profile tool --observe off -- git status' \
  'greywall -- git status'

# 4. fs-heavy writes (100 files)
run_bench fswrite \
  'sh -c "cd fsdir && i=0; while [ \$i -lt 100 ]; do echo x > f\$i; i=\$((i+1)); done"' \
  'ouro-jail run --profile tool -- sh -c "cd fsdir && i=0; while [ \$i -lt 100 ]; do echo x > f\$i; i=\$((i+1)); done"' \
  'ouro-jail run --profile tool --observe off -- sh -c "cd fsdir && i=0; while [ \$i -lt 100 ]; do echo x > f\$i; i=\$((i+1)); done"' \
  'greywall -- sh -c "cd fsdir && i=0; while [ \$i -lt 100 ]; do echo x > f\$i; i=\$((i+1)); done"'

# 5. fs-heavy read (grep over 1000 files)
run_bench grep \
  'grep -rq needle dir0 dir1 dir2 dir3 dir4' \
  'ouro-jail run --profile tool -- grep -rq needle dir0 dir1 dir2 dir3 dir4' \
  'ouro-jail run --profile tool --observe off -- grep -rq needle dir0 dir1 dir2 dir3 dir4' \
  'greywall -- grep -rq needle dir0 dir1 dir2 dir3 dir4'

if [ "$FAILED" -ne 0 ]; then
  echo "BENCH-FAILED (hyperfine exit $FAILED); a workload summary is missing" >&2
  exit "$FAILED"
fi
echo ALL-DONE
