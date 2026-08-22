#!/bin/sh
# "Bounded everything" has to be observable or it is a slogan. The command asks to sleep
# 45s inside a 2s budget: the tool must terminate it, say so, report it as an error the
# model can read, and let the turn finish well inside the task's own 90s deadline.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool bash
expect_tool_error bash
expect_trajectory_contains "timed out after"
expect_file_missing overran.txt

# The whole run, daemon round-trip included, must be nearer the 2s budget than the 45s
# sleep. 30s is a generous ceiling that still fails loudly if the kill never happens.
[ "$BENCH_DURATION_MS" -lt 30000 ] ||
  fail "the turn took ${BENCH_DURATION_MS}ms; the command was not killed at its budget"

bench_done
