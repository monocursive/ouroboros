#!/bin/sh
# A read is never gated: it runs in every approval mode and asks nobody.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_no_error
expect_tool read
expect_no_tool_errors
expect_approvals 0 0
expect_min_tokens 1
expect_files_changed_count 0
expect_event tool_result
expect_trajectory_contains "defmodule Calc do"

bench_done
