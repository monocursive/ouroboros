#!/bin/sh
# ouro-jail vs greywall vs baseline — hyperfine suite, reference host.
export PATH=$HOME/.local/bin:$PATH
cd "$HOME/benchws" || exit 1
mkdir -p fsdir
OUT=/tmp/bench-results
mkdir -p "$OUT"

run_bench () {
  name="$1"; shift
  hyperfine -N --warmup 2 --min-runs 30 --style basic \
    -n baseline -n ouro-obs-on -n ouro-obs-off -n greywall \
    --export-json "$OUT/$name.json" \
    "$@" 2>&1 | tail -12
  echo "=== $name done ==="
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

echo ALL-DONE
