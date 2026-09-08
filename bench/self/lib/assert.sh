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
# Not a JSON parser. `JSON.encode!/1` writes compact output, and the `run` object runs from
# `"run":{` to the `},"tasks":[` that starts the task array — the one place a nested object
# ends and a named array begins. Isolating it first matters: `tasks` is a key in both the
# run object and the document, and a reader that took the last match would answer with the
# task array.
#
# `run.flags` is the one object nested inside it, and it is deleted before the search
# rather than searched: it carries a `model`, an `oracle`, a `timeout` and a `history` of
# its own — every one of them a name the run object also uses — so a reader that did not
# remove it would sometimes answer with the flag instead of the result.
run_field() {
  sed -n 's/.*"run":{\(.*\)},"tasks":\[.*/\1/p' "$1" 2> /dev/null |
    sed 's/"flags":{[^}]*}//' |
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

# Every task's `reason` in a runner `result.json`, one per line.
#
# The `run` object has no `reason` key, so every match is a task's. No reason this corpus
# produces contains a quote or a comma, which is what makes a grep enough here — the same
# bargain `run_field` makes, and stated for the same reason.
task_reasons() {
  grep -o '"reason":"[^"]*"' "$1" 2> /dev/null | sed -e 's/^"reason":"//' -e 's/"$//'
}

# Asserts that EVERY task has the given reason. `expect_contains` over the whole file was
# what this replaces, and it could not tell "every task failed for this reason" from
# "the word appears once" — nor from a field name in the run object, which is how the
# spend-cap assertion managed to hold whatever happened.
expect_every_reason() {
  got=$(task_reasons "$1" | sort -u | tr '\n' ' ' | sed 's/ *$//')

  if [ "$got" = "$2" ]; then
    ok "$3"
  else
    fail "$3: the task reasons are '$got', wanted every one to be '$2'"
  fi
}

# Asserts that at least one task has the given reason.
expect_reason() {
  if task_reasons "$1" | grep -q -x -F -e "$2"; then
    ok "$3"
  else
    fail "$3: no task's reason is '$2' (they are: $(task_reasons "$1" | tr '\n' ' '))"
  fi
}
