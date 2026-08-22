#!/bin/sh
# `ouro run` without --approve-all answers every approval deny/once with a stated
# reason, and the run is still a *completed* turn: a refused tool is an in-band error
# the agent is told about, not a crash. The file must not exist.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool write
expect_tool_error write
expect_approvals 1 1
expect_files_changed_count 0
expect_file_missing lib/intruder.ex
expect_trajectory_contains "ouro run: headless, no approver"

bench_done
