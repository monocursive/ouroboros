#!/bin/sh
# bash is classified :execute, so it is gated even under auto_edit; only --approve-all
# or auto_approve runs it. Its effects are deliberately not checkpointed, so
# files_changed stays empty even though a file appeared — that asymmetry is the thing
# worth pinning.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool bash
expect_no_tool_errors
expect_approvals 1 1
expect_file_exists data/count.txt
expect_file_contains data/count.txt "4"
expect_files_changed_count 0

bench_done
