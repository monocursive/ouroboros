#!/bin/sh
# `*** Add File:` needs no prior read — it requires the opposite, that the path is
# absent. Under prompt it is still a write, so the approval count is the proof that the
# gate saw it.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool apply_patch
expect_no_tool_errors
expect_approvals 1 1
expect_files_changed_include "logger.ex"
expect_file_exists lib/logger.ex
expect_file_contains lib/logger.ex "defmodule Logger do"
expect_file_contains lib/logger.ex "def info(message)"

bench_done
