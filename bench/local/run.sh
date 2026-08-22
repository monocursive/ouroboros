#!/bin/sh
# The local eval corpus. No model key, no network, no docker, no spend.
#
#     bench/local/run.sh                    every task
#     bench/local/run.sh --filter bash      only tasks whose id contains "bash"
#     bench/local/run.sh --keep             leave the scratch dir for inspection
#     bench/local/run.sh --ouro PATH        grade a particular client binary
#
# Exits non-zero if any task fails. See docs/BENCHMARKS.md for what this does and does
# not measure.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../.." && pwd)

cd "$repo"

if ! command -v elixir > /dev/null 2>&1; then
  echo "bench.local: elixir is not on PATH" >&2
  exit 64
fi

# The corpus grades the client and the runtime in this checkout, so both have to be
# built before it can say anything. `mix compile` is cheap when it is a no-op; a missing
# client is a message rather than a build, because building it is minutes and the caller
# should choose to spend them.
mix compile

if [ -z "${OURO_BIN:-}" ] &&
   [ ! -f "$repo/tui/target/release/ouro" ] &&
   [ ! -f "$repo/tui/target/debug/ouro" ]; then
  echo "bench.local: no ouro binary; run 'cd tui && cargo build' first" >&2
  exit 64
fi

exec elixir "$here/run.exs" "$@"
