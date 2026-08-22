#!/bin/sh
# auto_edit is not "yes to everything". A write inside the workspace runs unasked; a
# shell command is :execute and is still gated. Exactly one approval — the bash call —
# is the whole assertion, and it is what separates auto_edit from auto_approve.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool write
expect_tool bash
expect_no_tool_errors
expect_approvals 1 1
expect_files_changed_include "STAMP"
expect_file_contains STAMP "build-42"
expect_trajectory_contains "build-42"

bench_done
