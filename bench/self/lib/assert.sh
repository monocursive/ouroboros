# Assertions for bench/self/selftest.sh. POSIX sh; no jq, no python, no dependency.
#
# The runner writes compact JSON (`JSON.encode!/1`), so a field is `"name":value` with no
# whitespace around the colon. That is a fact about the writer in this repository, not a
# general JSON reader, and `json_field` says so rather than pretending to parse.
#
# Every assertion records a failure and keeps going, so one selftest run reports every
# broken expectation instead of only the first. `assert_done` sets the exit status.

set -u

SELFTEST_FAILURES=0

fail() {
  echo "  FAIL $*" >&2
  SELFTEST_FAILURES=$((SELFTEST_FAILURES + 1))
}

ok() {
  echo "  ok   $*"
}

assert_done() {
  if [ "$SELFTEST_FAILURES" -eq 0 ]; then
    echo ""
    echo "bench/self/selftest.sh: green"
    exit 0
  fi

  echo ""
  echo "bench/self/selftest.sh: $SELFTEST_FAILURES expectation(s) unmet" >&2
  exit 1
}

SELFTEST_STEP=0

# Runs a command, captures its output, and checks its exit status. The output is left in
# $LAST_OUTPUT (a file path) so a later assertion can read it.
run_expect() {
  wanted="$1"
  label="$2"
  shift 2

  SELFTEST_STEP=$((SELFTEST_STEP + 1))
  LAST_OUTPUT="$SELFTEST_SCRATCH/step-$SELFTEST_STEP.log"

  set +e
  "$@" > "$LAST_OUTPUT" 2>&1
  got=$?
  set -e

  if [ "$got" = "$wanted" ]; then
    ok "$label (exit $got)"
  else
    fail "$label: wanted exit $wanted, got $got"
    tail -n 30 "$LAST_OUTPUT" >&2
  fi
}

expect_file() {
  if [ -f "$1" ]; then ok "$2"; else fail "$2: $1 does not exist"; fi
}

expect_contains() {
  if grep -q -F -e "$2" "$1" 2>/dev/null; then
    ok "$3"
  else
    fail "$3: $1 does not contain '$2'"
  fi
}

expect_not_contains() {
  if grep -q -F -e "$2" "$1" 2>/dev/null; then
    fail "$3: $1 unexpectedly contains '$2'"
  else
    ok "$3"
  fi
}

# One field of the `run` object in a runner `result.json`.
#
# Not a JSON parser. `JSON.encode!/1` writes compact output and the `run` object is flat,
# so `"run":{` up to the first `}` is exactly that object and a field in it is
# `"name":value` up to the next `,` or `}`. Isolating the object first matters: `tasks`
# is a key in both the run object and the document, and a reader that took the last match
# would answer with the task array.
run_field() {
  sed -n 's/.*"run":{\([^}]*\)}.*/\1/p' "$1" 2>/dev/null |
    grep -o "\"$2\":[^,}]*" |
    head -1 |
    sed 's/^"[^"]*"://' |
    tr -d '"'
}

expect_json() {
  got=$(run_field "$1" "$2")

  if [ "$got" = "$3" ]; then
    ok "$4"
  else
    fail "$4: run.$2 is '$got', wanted '$3'"
  fi
}
