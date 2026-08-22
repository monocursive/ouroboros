#!/bin/sh
# ask_user rides the approval channel, so a headless run answers it like any other
# approval — deny/once with a stated reason. The contract is that a declined question is
# NOT an error: the tool returns prose telling the model to proceed and say which way it
# went, and the turn completes.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool ask_user
expect_no_tool_errors
expect_approvals 1 1
expect_files_changed_count 0
expect_trajectory_contains "Should the export be JSON or CSV?"
expect_trajectory_contains "The operator declined to answer"
expect_trajectory_contains "ouro run: headless, no approver"

bench_done
