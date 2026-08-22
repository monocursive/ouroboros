#!/bin/sh
# `plan` is the one tool whose value is entirely in the event it publishes. If
# plan_updated does not reach `ouro run --stream-json`, no client can draw a plan.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool plan
expect_no_tool_errors
expect_approvals 0 0
expect_files_changed_count 0
expect_event plan_updated
expect_trajectory_contains "extract the tokenizer"
expect_trajectory_contains "in_progress"

bench_done
