#!/bin/sh
# A hallucinated tool name is the commonest way for a corpus to lie to itself: if the
# call were dropped, every scripted task would still "pass" while doing nothing. The
# loop must name the tool, list what does exist, mark the result an error, and carry on.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool ripgrep_all
expect_tool_error ripgrep_all
expect_tool read
expect_trajectory_contains "is not a tool in this session"
expect_trajectory_contains "def value, do: 7"

bench_done
