#!/bin/sh
# The old boot corpus remains untouched; this is the additional pre-J2 corpus gate.
set -eu
J2_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$J2_ROOT"
J2_OUT=${J2_BOOT_GATE_OUT:-"$J2_ROOT/_build/j2-boot-gate"}
J2_RUNS=${BOOT_GATE_RUNS:-10}
mkdir -p "$J2_OUT"
for mode in plain preload; do
  i=1
  while [ "$i" -le "$J2_RUNS" ]; do
    copy=$(mktemp -d "$J2_OUT/copy-$mode-$i.XXXXXX")
    cp -R test/support/j2_fixture/data/. "$copy/"
    flags="--no-start"
    if [ "$mode" = preload ]; then flags="--no-start --preload-modules"; fi
    log="$J2_OUT/boot-$mode-$i.log"
    # Fresh node name prevents adoption of the writer's nonode@nohost records.
    if J2_FIXTURE_COPY="$copy" MIX_ENV=test \
      elixir --sname "j2-boot-$mode-$i" -S mix run $flags scripts/fixture/j2_boot_check.exs >"$log" 2>&1; then
      cat "$log" | grep '^J2 BOOT:'
    else
      echo "J2 boot failed: $log" >&2
      exit 1
    fi
    i=$((i + 1))
  done
done
