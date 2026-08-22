#!/bin/sh
# code_intel cannot answer on a default runtime, and the point of this task is that it
# says so instead of raising, hanging, or ending the turn. The agent then routes around
# it with `read`, which is the behaviour that keeps a benchmark run alive.
#
# Two independent reasons it cannot answer here, both worth knowing:
#
#   1. `Ouroboros.CodeIntel.Registry.resolve/2` takes the workspace root from the node's
#      `:workspace_allowed_roots`, which is EMPTY on a default runtime and is not
#      populated by admitting a session's workspace. So every path is judged
#      `{:outside_workspace, …}` before a language is ever considered. That is what this
#      corpus observes today, and it means code_intel is unreachable for an ordinary
#      `ouro run --workspace …` session regardless of what is installed.
#   2. Even past that, there is no LSP pool in this build and no tree-sitter fallback,
#      and `.txt` is claimed by no server in the registry.
#
# The assertions below therefore pin the CONTRACT (in-band, bounded, non-fatal) and not
# the message, so that fixing either reason above does not turn this task red for the
# wrong cause. The specific string is recorded in the comment instead.
. "$BENCH_LIB/assert.sh"

expect_status completed
expect_exit 0
expect_tool code_intel
expect_tool_error code_intel
expect_tool read
expect_approvals 0 0
expect_files_changed_count 0
expect_trajectory_contains "code_intel failed:"
expect_trajectory_contains "Plain prose"

# Bounded: a failure explains itself in a line, it does not paste the workspace back.
expect_trajectory_under_bytes 65536

bench_done
