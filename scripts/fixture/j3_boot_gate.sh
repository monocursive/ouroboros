#!/bin/sh
set -eu
J3_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$J3_ROOT"
J3_OUT=${J3_BOOT_GATE_OUT:-"$J3_ROOT/_build/j3-boot-gate"}
J3_RUNS=${BOOT_GATE_RUNS:-10}
mkdir -p "$J3_OUT"
for mode in plain preload; do
  i=1
  while [ "$i" -le "$J3_RUNS" ]; do
    copy=$(mktemp -d "$J3_OUT/copy-$mode-$i.XXXXXX")
    cp -R test/support/j3_fixture/data/. "$copy/"
    flags="--no-start"
    if [ "$mode" = preload ]; then flags="--no-start --preload-modules"; fi
    log="$J3_OUT/boot-$mode-$i.log"
    if J3_FIXTURE_COPY="$copy" MIX_ENV=test elixir --sname "j3-boot-$mode-$i" -S mix run $flags scripts/fixture/j3_boot_check.exs >"$log" 2>&1; then
      grep '^J3 BOOT:' "$log"
    else
      echo "J3 boot failed: $log" >&2
      cat "$log" >&2
      exit 1
    fi
    i=$((i + 1))
  done
done
