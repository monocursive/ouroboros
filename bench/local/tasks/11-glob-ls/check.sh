#!/bin/sh
# Both search tools are :read, so neither is gated. Two tool calls in one turn also
# proves the loop iterates rather than stopping at the first result.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool glob
expect_tool ls
expect_no_tool_errors
expect_approvals 0 0
expect_files_changed_count 0
expect_trajectory_contains "one.ex"
expect_trajectory_contains "two.ex"
expect_trajectory_contains "docs"
expect_trajectory_lacks "notes.md.ex"

bench_done
