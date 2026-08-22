#!/bin/sh
# grep prefers ripgrep and falls back to a built-in walker when `rg` is not on PATH.
# The corpus must pass either way, so it asserts on the matches, never on the engine.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool grep
expect_no_tool_errors
expect_approvals 0 0
expect_files_changed_count 0
expect_trajectory_contains "lib/parser.ex"
expect_trajectory_contains "lib/writer.ex"
expect_trajectory_contains "handle the escaped-quote case"

bench_done
