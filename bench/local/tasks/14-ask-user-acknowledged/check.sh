#!/bin/sh
# Two things are pinned here. First, ask_user is asked even under auto_approve — the
# mode governs permissions, and a question is not a permission. Second, an `approve`
# carrying no text is reported as an acknowledgement rather than being dressed up as an
# answer the operator never gave.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool ask_user
expect_no_tool_errors
expect_approvals 1 1
expect_trajectory_contains "Keep the legacy /v1 endpoint?"
expect_trajectory_contains "acknowledged the question without giving an answer"
expect_trajectory_lacks "The operator declined to answer"

bench_done
