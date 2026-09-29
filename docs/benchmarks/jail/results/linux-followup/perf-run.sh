#!/bin/bash
set -eu
cd /home/ubuntu/ouroboros
RUN_DIR=$PWD/target/regression-20260929/final
trap 'echo $? > "$RUN_DIR/perf-exit-code"' EXIT
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
date -u +%FT%TZ > "$RUN_DIR/perf-started-at"
target/release/xtask perf run --launches 30 --warmup 5 --profiles tool --sessions plain,scope --workloads noop,spawn-tree,fileops --fileops-rounds 5000 --spawn-count 200 --max-load 3 --seed 20260929 --out "$RUN_DIR/perf" --jail "$PWD/target/release/ouro-jail" --fixture "$PWD/target/release/ouro-fixture" --revision 2c8f28dcda4bc60b2e5ba51b2f8f9d7c93bf5bfa+dirty > "$RUN_DIR/perf.log" 2>&1
target/release/xtask perf summarize --dir "$RUN_DIR/perf" > "$RUN_DIR/perf-recompute.log" 2>&1
python3 docs/benchmarks/jail/performance.py --summary "$RUN_DIR/perf/summary.json" --out "$RUN_DIR/k17.json" > "$RUN_DIR/k17.log" 2>&1
date -u +%FT%TZ > "$RUN_DIR/perf-finished-at"
