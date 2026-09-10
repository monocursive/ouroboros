#!/bin/sh
# A tool that cannot answer must say so in band, and the point of this task is that the
# turn survives it: the failure is a tool result the model reads, not a raise, a hang, or
# the end of the turn. The agent then routes around it with `read`, which is the
# behaviour that keeps a benchmark run alive.
#
# `grep` is the subject because its refusal is a property of the *arguments* and not of
# the host: an unbalanced group does not compile on any machine, so the outcome is the
# same everywhere without installing or configuring anything.
#
# The assertions pin the CONTRACT (in-band, bounded, non-fatal) and the two strings this
# runtime writes itself, not the regex engine's own words for what it did not like.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool grep
expect_tool_error grep
expect_tool read
expect_approvals 0 0
expect_files_changed_count 0
expect_trajectory_contains "grep failed:"
expect_trajectory_contains "is not a usable regular expression"
expect_trajectory_contains "Plain prose"

# Bounded: a failure explains itself in a line, it does not paste the workspace back.
expect_trajectory_under_bytes 65536

bench_done
