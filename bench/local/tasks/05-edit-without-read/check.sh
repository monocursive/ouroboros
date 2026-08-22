#!/bin/sh
# The read-before-edit guard is the difference between an agent that edits and one that
# guesses. It must refuse in-band — telling the model what to do next — and leave the
# file byte-identical.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool edit
expect_tool_error edit
expect_files_changed_count 0
expect_file_contains lib/config.ex "5000"
expect_file_lacks lib/config.ex "9000"
expect_trajectory_contains "has not been read in this session"

bench_done
