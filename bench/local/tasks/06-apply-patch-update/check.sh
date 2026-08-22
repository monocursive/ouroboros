#!/bin/sh
# apply_patch carries the same read-before-write guard as edit; this is the path where
# it is satisfied. The whole patch is planned before anything is written, so a success
# means every section landed.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool read
expect_tool apply_patch
expect_no_tool_errors
expect_files_changed_include "math.ex"
expect_file_contains lib/math.ex "def total(list)"
expect_file_lacks lib/math.ex "def sum(list)"

bench_done
