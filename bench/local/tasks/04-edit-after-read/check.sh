#!/bin/sh
# approval_mode: auto_edit lets an in-workspace write through without asking, which is
# what makes the zero-approval assertion here meaningful rather than incidental.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool read
expect_tool edit
expect_no_tool_errors
expect_approvals 0 0
expect_files_changed_include "version.ex"
expect_file_contains lib/version.ex '"2.0.0"'
expect_file_lacks lib/version.ex '"1.0.0"'
expect_file_line_count lib/version.ex 3

bench_done
