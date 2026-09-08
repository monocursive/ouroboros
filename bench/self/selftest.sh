#!/bin/sh
# The $0 gate for bench/self: extraction, the oracle, the spend guard, and two negative
# controls that make the grader's two enforcement points falsifiable.
#
#     bench/self/selftest.sh
#
# No model key, no network beyond git and the local hex cache, no spend. Takes a few
# minutes: every step builds real worktrees at real commits and compiles them.
#
# What it proves, step by step:
#
#   1  two named commits extract, and each verifies (hidden tests fail at the parent,
#      pass at the commit) — so the corpus format and the extractor agree.
#   2  the oracle grades both tasks `pass` at $0 — so the worktree, the hidden-test
#      restore, the modified-test check and the budget arithmetic all work.
#   3  a run without `--spend`, and one with `--spend 0`, are refused.
#   4  the two test seams are refused outside `--oracle`.
#   5  the running total stops the run at the cap, and the task that did not run says so.
#   6  `--oracle-cheat no-solution` fails every task `tests_failed`. This is the control
#      for the hidden-test restore: the parent's copy of each test PASSES, so a runner
#      that skipped the restore would grade doing nothing as a full pass.
#   7  `--oracle-cheat blank-tests` fails every task `modified_tests`. This is the control
#      for the modified-test check: the solution is written correctly, so without that
#      check the restore would put the real test back and the task would pass.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../.." && pwd)

# Two small Elixir fix commits, verified by hand and by `extract.exs --commits` before
# they were pinned here. Both change one file under `lib/` and one test file that already
# existed, which is what step 7 needs. Named in bench/self/README.md.
COMMIT_A=7f9d816676f67528ca854cc52628d6ccb1f42457
COMMIT_B=2d5a0ea6dfa92029cac7d732ac20b3afbc1a582a

# In a linked git worktree there is no `tui/target`, so the client has to be named. The
# message run.sh prints says the same thing; saying it here too means the gate fails with
# an instruction rather than seven identical refusals.
if [ -z "${OURO_BIN:-}" ] &&
   [ ! -f "$repo/tui/target/release/ouro" ] &&
   [ ! -f "$repo/tui/target/debug/ouro" ]; then
  echo "bench/self/selftest.sh: no ouro binary under $repo/tui/target." >&2
  echo "bench/self/selftest.sh: run 'cd tui && cargo build', or set OURO_BIN=/path/to/ouro." >&2
  exit 64
fi

SELFTEST_SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/ouroboros-bench-self-selftest.XXXXXX")
export SELFTEST_SCRATCH

cleanup() {
  rm -rf "$SELFTEST_SCRATCH"
}

trap cleanup EXIT INT TERM

# shellcheck disable=SC1091
. "$here/lib/assert.sh"

tasks="$SELFTEST_SCRATCH/tasks"

echo "bench/self/selftest.sh"
echo "  repo    $repo"
echo "  scratch $SELFTEST_SCRATCH"
echo ""

# --- 1. extraction ----------------------------------------------------------

echo "1. extraction of two named commits"

run_expect 0 "extract.exs --commits verifies both" \
  elixir "$here/extract.exs" --commits "$COMMIT_A,$COMMIT_B" --out "$tasks" --replace --jobs 2

first=$(ls "$tasks" 2>/dev/null | sed -n 1p)
second=$(ls "$tasks" 2>/dev/null | sed -n 2p)

if [ -n "$first" ] && [ -n "$second" ]; then
  ok "two tasks were written ($first, $second)"
else
  fail "two tasks were written: got '$first' '$second'"
fi

expect_file "$tasks/$first/task.json" "the first task has a task.json"
expect_contains "$tasks/$first/task.json" "$COMMIT_A" "the first task pins $COMMIT_A"
expect_contains "$tasks/$first/task.json" '"hidden_tests"' "the first task names its hidden tests"
expect_contains "$tasks/$first/task.json" '"solution_files"' "the first task names its solution files"
expect_contains "$tasks/$first/task.json" 'Acceptance.' "the instruction carries an acceptance list"
expect_contains "$tasks/$second/task.json" "$COMMIT_B" "the second task pins $COMMIT_B"

# The corpus is a list of pins: no test content may be sitting in it.
expect_not_contains "$tasks/$first/task.json" 'use ExUnit.Case' "no test body is copied into the corpus"

# --- 2. the oracle ----------------------------------------------------------

echo ""
echo "2. the oracle"

run_expect 0 "the oracle grades every task" \
  sh "$here/run.sh" --oracle --spend 1 --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/oracle"

oracle="$SELFTEST_SCRATCH/oracle/result.json"
expect_file "$oracle" "the oracle wrote result.json"
expect_json "$oracle" "tasks" "2" "the oracle saw two tasks"
expect_json "$oracle" "ran" "2" "the oracle ran both"
expect_json "$oracle" "passed" "2" "the oracle graded both pass"
expect_json "$oracle" "spent" "0.0" "the oracle spent nothing"
expect_json "$oracle" "oracle" "true" "the result object says it was an oracle run"

# --- 3. the spend guard refuses ---------------------------------------------

echo ""
echo "3. --spend is required"

run_expect 64 "a run without --spend is refused" \
  sh "$here/run.sh" --oracle --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/nospend"
expect_contains "$LAST_OUTPUT" "--spend <usd> is required" "the refusal says why"

run_expect 64 "a run with --spend 0 is refused" \
  sh "$here/run.sh" --oracle --spend 0 --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/zerospend"

# --- 4. the seams are refused outside the oracle ----------------------------

echo ""
echo "4. the test seams are oracle-only"

run_expect 64 "--fake-cost-usd is refused without --oracle" \
  sh "$here/run.sh" --spend 1 --fake-cost-usd 0.01 --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/seam1"

run_expect 64 "--oracle-cheat is refused without --oracle" \
  sh "$here/run.sh" --spend 1 --oracle-cheat no-solution --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/seam2"

# --- 5. the cap stops the run -----------------------------------------------

echo ""
echo "5. the running total stops the run at the cap"

run_expect 3 "a run that reaches the cap stops and says which tasks did not run" \
  sh "$here/run.sh" --oracle --spend 0.03 --fake-cost-usd 0.04 \
  --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/cap"

cap="$SELFTEST_SCRATCH/cap/result.json"
expect_file "$cap" "the capped run wrote result.json"
expect_json "$cap" "tasks" "2" "the capped run saw two tasks"
expect_json "$cap" "ran" "1" "the capped run ran one"
expect_json "$cap" "passed" "1" "the one that ran passed"
expect_contains "$cap" "spend_cap" "the task that did not run says spend_cap"
expect_contains "$LAST_OUTPUT" "did not run" "the report names the tasks that did not run"

# --- 6. control: the hidden tests really are restored ------------------------

echo ""
echo "6. negative control: no solution must fail, which proves the restore"

run_expect 1 "an agent that changes nothing fails every task" \
  sh "$here/run.sh" --oracle --spend 1 --oracle-cheat no-solution \
  --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/nosolution"

nosolution="$SELFTEST_SCRATCH/nosolution/result.json"
expect_file "$nosolution" "the control wrote result.json"
expect_json "$nosolution" "ran" "2" "the control ran both"
expect_json "$nosolution" "passed" "0" "the control passed nothing"
expect_contains "$nosolution" "tests_failed" "the reason is tests_failed, not a pass"
expect_not_contains "$nosolution" "modified_tests" "and not modified_tests: nothing was touched"

# --- 7. control: a blanked test is caught ------------------------------------

echo ""
echo "7. negative control: blanking a test must fail, which proves the check"

run_expect 1 "an agent that blanks a pre-existing test fails every task" \
  sh "$here/run.sh" --oracle --spend 1 --oracle-cheat blank-tests \
  --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/blanked"

blanked="$SELFTEST_SCRATCH/blanked/result.json"
expect_file "$blanked" "the control wrote result.json"
expect_json "$blanked" "ran" "2" "the control ran both"
expect_json "$blanked" "passed" "0" "the control passed nothing"
expect_contains "$blanked" "modified_tests" "the reason is modified_tests"

assert_done
