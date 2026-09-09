#!/bin/sh
# The self corpus: Ouroboros, graded on changes to Ouroboros.
#
#     bench/self/run.sh --oracle --spend 1        the $0 proof of the grader
#     bench/self/run.sh --spend 5.00              a paid run over the whole corpus
#     bench/self/run.sh --spend 5.00 --filter 03  one task
#     bench/self/run.sh --spend 5.00 --model anthropic/claude-...   a named model
#     bench/self/run.sh --spend 5.00 --keep       leave the scratch worktrees behind
#     bench/self/run.sh --spend 5.00 --no-approve-all   the unattended posture: every
#                                                 approval answered deny/once
#     bench/self/run.sh --repo /path/to/checkout  the runtime under test lives elsewhere
#     bench/self/run.sh --history /path/to/repo   the corpus's commits live elsewhere
#
# `--repo` is the improve loop's contract: it compiles and boots the runtime from that
# checkout while the corpus's workspaces and hidden tests still come from the history.
# `--history` is the other half, and the selftest points it at a fixture repository.
#
# `--spend` is required: this runs a real model against real credentials. Exit status is
# 0 when every task ran and passed, 1 when one failed, 3 when the run stopped at the cap
# with tasks still to run, 64 for a refusal or a turn nobody could price, and 1 for a
# failure. See bench/self/README.md.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../.." && pwd)

# `--repo <path>` names the checkout whose runtime is under test, so it is the one to
# compile and the one whose `tui/target` holds the client. Read here as well as in
# run.exs, because this script builds before it hands over.
previous=""

for argument in "$@"; do
  case "$previous" in
    --repo) repo=$argument ;;
  esac

  case "$argument" in
    --repo=*) repo=${argument#--repo=} ;;
  esac

  previous=$argument
done

if [ ! -d "$repo" ]; then
  echo "bench.self: --repo $repo is not a directory" >&2
  exit 64
fi

repo=$(CDPATH= cd -- "$repo" && pwd)

cd "$repo"

if ! command -v elixir > /dev/null 2>&1; then
  echo "bench.self: elixir is not on PATH" >&2
  exit 64
fi

if ! command -v git > /dev/null 2>&1; then
  echo "bench.self: git is not on PATH" >&2
  exit 64
fi

# The corpus grades the runtime and the client in this checkout, so both have to be built
# before it can say anything. `mix compile` is cheap when it is a no-op; a missing client
# is a message rather than a build, because building it is minutes and the caller should
# choose to spend them.
mix compile

# The client this checkout builds, not one on PATH: a corpus that silently graded a
# different binary than the code under test would be worse than no corpus. A linked git
# worktree has no `tui/target` of its own, so there OURO_BIN is how you name one — and
# naming it is the operator saying which binary they mean.
if [ -z "${OURO_BIN:-}" ] &&
   [ ! -f "$repo/tui/target/release/ouro" ] &&
   [ ! -f "$repo/tui/target/debug/ouro" ]; then
  echo "bench.self: no ouro binary under $repo/tui/target." >&2
  echo "bench.self: run 'cd tui && cargo build', or set OURO_BIN=/path/to/ouro." >&2
  exit 64
fi

exec elixir "$here/run.exs" "$@"
