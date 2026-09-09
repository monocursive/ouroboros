#!/bin/sh
# What one gate step's log says, as opposed to what its exit status says.
#
#     bench/self/lib/improve/gate-verdict.sh <kind> <exit-status> <log>
#
# Prints one line: `<verdict><TAB><note>`, verdict 0 for green and 1 for red. `improve.sh`
# records the verdict as the step's rc and the note beside it.
#
# The reason this exists as its own file rather than as a function inside `improve.sh` is
# that it is the one place where a *green* answer is a decision: `mix test`'s exit status
# is a number a session can set (one `System.at_exit(fn _ -> System.halt(0) end)` in
# `test/test_helper.exs` compiles, formats, and makes every suite exit 0), so the gate
# reads what ExUnit reported and not only how the process ended. A file can be fed a
# crafted log by the selftest in milliseconds; `make test` and `mix dialyzer` cannot be
# run there at all.
#
# Kinds:
#   rc         green iff the command exited 0 (mix format, mix compile)
#   mix-test   green iff it exited 0, reported at least one `Result:` line, every one of
#              them is a clean pass, there is no `Failed:` line, and at least one test ran
#   make-test  the same rule over every `Result:` line the whole `make test` log carries
#   dialyzer   green iff it exited 0 and said `done (passed successfully)`
#
# This repository runs Elixir 1.20, whose ExUnit prints `Result: 6 passed`,
# `Result: 1 passed, 1 skipped, 1 excluded`, `Result: 1/2 passed` + `Failed: 1 test`, and
# `Result: 0 tests, 3 excluded`. Only the first two shapes are a pass. `grep -a` because
# `mix test` output carries NUL bytes; `^` because ExUnit writes these at column 0 and a
# test that prints its own summary line should have to work for it — and cannot help
# itself either way, since an extra line can only add a `Result:` that must also be a pass.

set -eu

kind=${1:-}
rc=${2:-0}
log=${3:-}

tab=$(printf '\t')

verdict=0
note=''

summary=''
results=0
passes=0
failed=0
passed=0

if [ -n "$log" ] && [ -f "$log" ]; then
  summary=$(
    grep -a -e '^Result:' -e '^Failed:' "$log" 2> /dev/null |
      tail -n 4 | tr '\n\t' '  ' | sed -e 's/  */ /g' -e 's/ *$//' || true
  )
  set -- $(
    grep -a -e '^Result:' -e '^Failed:' "$log" 2> /dev/null | awk '
      /^Failed:/ { failed++; next }
      /^Result:/ {
        results++
        # `Result: <n> passed…` is a pass. `Result: <m>/<n> passed` is a failure summary
        # and `Result: 0 tests, …` is a suite that ran nothing; neither is.
        if ($2 ~ /^[0-9]+$/ && $3 ~ /^passed/) { passes++; passed += $2 }
      }
      END { printf "%d %d %d %d\n", results + 0, passes + 0, failed + 0, passed + 0 }
    ' || printf '0 0 0 0\n'
  )
  results=$1
  passes=$2
  failed=$3
  passed=$4
fi

case $kind in
  rc)
    if [ "$rc" -ne 0 ]; then
      verdict=1
      note="exit $rc"
    fi
    ;;

  dialyzer)
    if [ "$rc" -ne 0 ]; then
      verdict=1
      note="exit $rc"
    elif [ -z "$log" ] || [ ! -f "$log" ]; then
      verdict=1
      note='exit 0 but there is no log to read'
    elif grep -a -q -F 'done (passed successfully)' "$log"; then
      note='done (passed successfully)'
    else
      verdict=1
      note='exit 0 but no "done (passed successfully)" line: dialyzer did not report a pass'
    fi
    ;;

  mix-test | make-test)
    if [ "$rc" -ne 0 ]; then
      verdict=1
      note="exit $rc${summary:+: $summary}"
    elif [ "$results" -eq 0 ]; then
      verdict=1
      note='exit 0 but no result line: the suite did not report'
    elif [ "$failed" -gt 0 ]; then
      verdict=1
      note="exit 0 but the suite reported a failure: $summary"
    elif [ "$passes" -ne "$results" ]; then
      verdict=1
      note="exit 0 but a result line is not a pass: $summary"
    elif [ "$passed" -eq 0 ]; then
      verdict=1
      note="exit 0 but no test ran: $summary"
    else
      note="$summary"
    fi
    ;;

  *)
    printf 'gate-verdict: unknown kind %s\n' "$kind" >&2
    exit 64
    ;;
esac

printf '%s%s%s\n' "$verdict" "$tab" "$note"
