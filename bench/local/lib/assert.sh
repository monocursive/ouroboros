# Assertions for a task's check.sh. POSIX sh; no jq, no python, no dependency at all.
#
# The runner has already parsed the run into $BENCH_FACTS — a file of single-quoted
# BENCH_* assignments — so a check reads shell variables rather than JSON. The raw
# result object ($BENCH_RESULT) and the whole event stream ($BENCH_TRAJECTORY) are on
# disk beside it for a check that wants to look at something this file does not name.
#
# Every assertion records a failure and keeps going, so one run reports every broken
# expectation instead of only the first. `bench_done` is what sets the exit status.
#
# Usage:
#     #!/bin/sh
#     . "$BENCH_LIB/assert.sh"
#     expect_status completed
#     expect_tool read
#     bench_done

set -u

if [ -z "${BENCH_FACTS:-}" ] || [ ! -f "$BENCH_FACTS" ]; then
  echo "assert.sh: BENCH_FACTS is unset or missing; this script is run by bench/local/run.exs" >&2
  exit 64
fi

# shellcheck disable=SC1090
. "$BENCH_FACTS"

BENCH_FAILURES=0

fail() {
  echo "  - $*"
  BENCH_FAILURES=$((BENCH_FAILURES + 1))
}

bench_done() {
  [ "$BENCH_FAILURES" -eq 0 ] && exit 0
  echo "  ($BENCH_FAILURES expectation(s) unmet; status=$BENCH_STATUS exit=$BENCH_EXIT tools=[$BENCH_TOOLS])"
  exit 1
}

# --- the run itself ----------------------------------------------------------

expect_status() {
  [ "$BENCH_STATUS" = "$1" ] || fail "status: wanted '$1', got '$BENCH_STATUS' (error: ${BENCH_ERROR:-none})"
}

expect_exit() {
  [ "$BENCH_EXIT" = "$1" ] || fail "exit code: wanted '$1', got '$BENCH_EXIT'"
}

expect_no_error() {
  [ -z "$BENCH_ERROR" ] || fail "result carried an error: $BENCH_ERROR"
}

expect_error_contains() {
  case "$BENCH_ERROR" in
    *"$1"*) ;;
    *) fail "result error did not contain '$1' (got: '${BENCH_ERROR:-none}')" ;;
  esac
}

# --- tools -------------------------------------------------------------------

_in_list() {
  # _in_list <needle> <space-separated haystack>
  case " $2 " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

expect_tool() {
  _in_list "$1" "$BENCH_TOOLS" || fail "tool '$1' was never called (called: [$BENCH_TOOLS])"
}

expect_no_tool() {
  _in_list "$1" "$BENCH_TOOLS" && fail "tool '$1' was called and should not have been"
  return 0
}

expect_tool_count() {
  # expect_tool_count <name> <n>
  _count=0
  for _t in $BENCH_TOOLS; do
    [ "$_t" = "$1" ] && _count=$((_count + 1))
  done
  [ "$_count" -eq "$2" ] || fail "tool '$1' ran $_count time(s), wanted $2"
}

expect_tool_error() {
  _in_list "$1" "$BENCH_TOOL_ERRORS" ||
    fail "tool '$1' did not report an error (errors: [$BENCH_TOOL_ERRORS])"
}

expect_no_tool_errors() {
  [ -z "$BENCH_TOOL_ERRORS" ] || fail "tools reported errors: [$BENCH_TOOL_ERRORS]"
}

expect_event() {
  _in_list "$1" "$BENCH_EVENTS" || fail "event '$1' never arrived (saw: [$BENCH_EVENTS])"
}

# --- approvals, usage, files -------------------------------------------------

expect_approvals() {
  # expect_approvals <requested> <answered>
  [ "$BENCH_APPROVALS_REQUESTED" = "$1" ] ||
    fail "approvals requested: wanted $1, got $BENCH_APPROVALS_REQUESTED"
  [ "$BENCH_APPROVALS_ANSWERED" = "$2" ] ||
    fail "approvals answered: wanted $2, got $BENCH_APPROVALS_ANSWERED"
}

expect_min_tokens() {
  [ "$BENCH_TOTAL_TOKENS" -ge "$1" ] ||
    fail "total_tokens: wanted at least $1, got $BENCH_TOTAL_TOKENS"
}

expect_files_changed_count() {
  [ "$BENCH_FILES_CHANGED_COUNT" = "$1" ] ||
    fail "files_changed: wanted $1 path(s), got $BENCH_FILES_CHANGED_COUNT [$BENCH_FILES_CHANGED]"
}

expect_files_changed_include() {
  case " $BENCH_FILES_CHANGED " in
    *"$1"*) ;;
    *) fail "files_changed did not mention '$1' (got: [$BENCH_FILES_CHANGED])" ;;
  esac
}

# --- the workspace on disk ---------------------------------------------------

expect_file_exists() {
  [ -f "$BENCH_WORKSPACE/$1" ] || fail "workspace file '$1' does not exist"
}

expect_file_missing() {
  [ -f "$BENCH_WORKSPACE/$1" ] && fail "workspace file '$1' exists and should not"
  return 0
}

expect_file_contains() {
  # expect_file_contains <relative path> <fixed string>
  if [ ! -f "$BENCH_WORKSPACE/$1" ]; then
    fail "workspace file '$1' does not exist, so it cannot contain '$2'"
    return 0
  fi
  grep -qF -- "$2" "$BENCH_WORKSPACE/$1" || fail "workspace file '$1' does not contain '$2'"
}

expect_file_lacks() {
  if [ ! -f "$BENCH_WORKSPACE/$1" ]; then
    fail "workspace file '$1' does not exist, so '$2' cannot be checked"
    return 0
  fi
  grep -qF -- "$2" "$BENCH_WORKSPACE/$1" && fail "workspace file '$1' still contains '$2'"
  return 0
}

expect_file_line_count() {
  if [ ! -f "$BENCH_WORKSPACE/$1" ]; then
    fail "workspace file '$1' does not exist"
    return 0
  fi
  _lines=$(wc -l < "$BENCH_WORKSPACE/$1" | tr -d ' ')
  [ "$_lines" = "$2" ] || fail "workspace file '$1' has $_lines line(s), wanted $2"
}

# --- the event stream --------------------------------------------------------

expect_trajectory_contains() {
  grep -qF -- "$1" "$BENCH_TRAJECTORY" ||
    fail "the event stream never mentioned '$1'"
}

expect_trajectory_lacks() {
  grep -qF -- "$1" "$BENCH_TRAJECTORY" && fail "the event stream mentioned '$1' and should not"
  return 0
}

# The trajectory is the contract `ouro run --stream-json` publishes; a task that cares
# about output size should say so rather than assume.
expect_trajectory_under_bytes() {
  _bytes=$(wc -c < "$BENCH_TRAJECTORY" | tr -d ' ')
  [ "$_bytes" -le "$1" ] || fail "the event stream is $_bytes bytes, over the $1-byte cap"
}
