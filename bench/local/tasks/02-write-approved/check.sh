#!/bin/sh
# Under approval_mode: prompt a write is gated; --approve-all is the answer, and the
# file is on disk afterwards. The pair with 03 is the whole point: same script, same
# mode, one flag apart, opposite outcome.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool write
expect_no_tool_errors
expect_approvals 1 1
# `files_changed` names one file once even though the payload carries it twice — the
# absolute `path` and the workspace-relative path in the unified diff header. The runner
# folds the two; this task pins that fold.
expect_files_changed_count 1
expect_files_changed_include "greeter.ex"
expect_file_exists lib/greeter.ex
expect_file_contains lib/greeter.ex "defmodule Greeter do"
expect_file_contains lib/greeter.ex "def hello(name)"

bench_done
