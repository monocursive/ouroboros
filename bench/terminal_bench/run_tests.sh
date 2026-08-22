#!/bin/sh
# The adapter's unit tests. No docker, no model key, no Linux dist, no `harbor` install.
#
#     bench/terminal_bench/run_tests.sh          quiet
#     bench/terminal_bench/run_tests.sh -v       per-test names
#
# `-t` matters: it makes `bench/terminal_bench` the import root, so `tests` is a package
# and `ouroboros_agent` is importable. Without it, discovery finds the files and then
# cannot import what they are testing.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v python3 > /dev/null 2>&1; then
  echo "bench/terminal_bench: python3 is not on PATH" >&2
  exit 64
fi

exec python3 -m unittest discover -s "$here/tests" -t "$here" "$@"
