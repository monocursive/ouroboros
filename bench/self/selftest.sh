#!/bin/sh
# The $0 gate for bench/self: the grader's rules, its refusals, and every way anybody has
# managed to make it say `pass` without doing the work.
#
#     bench/self/selftest.sh
#
# No model key, no network beyond git and the local hex cache, no spend. Twelve minutes on
# the machine this was written on: most of it is this repository's own trees being built
# and compiled twice per task — once for the agent, once for the grade — and the cheap half
# runs first so that a broken rule fails in seconds rather than in ten minutes.
#
# The order is deliberate. Phases 1 to 6 need nothing of this repository's history and run
# against a two-file fixture project (`lib/fixture.sh`), which compiles in a second; every
# claim they make is about the runner's own logic. Phases 7 to 11 make the same claims
# against real commits, where a build is minutes, and are the ones that would notice if the
# fixture were lying about the shape of a real tree.
#
# What it proves, phase by phase:
#
#   1  the verdict rule: what `mix test` REPORTED, not how its process ended.
#   2  the refusals that come before anything is built — `--spend`, the four test seams,
#      and an `OURO_BIN` that names nothing — and that none of them starts a daemon.
#   3  the oracle's environment carries no secret, asserted by spawning `env` through the
#      runner's own environment builder.
#   4  the extractor's two gates, against a fixture history built to trip them: a commit
#      whose hidden test already passes at its parent, and one whose own test does not
#      pass. And a merge, which is not a task.
#   5  four corpora that are not corpora: pins that disagree with the history, a task
#      naming no `_test.exs`, a directory with no `task.json`, and two tasks with one id.
#   6  the fixture corpus: the oracle passes it, and eight scripted agents do not. Six of
#      them are the ways the adversarial review made the previous grader say `pass`.
#   7  two named commits of THIS repository extract, and each verifies.
#   8  the oracle grades both `pass` at $0.
#   9  the running total stops the run at the cap.
#  10  the two original controls, against real commits.
#  11  the three proved exploits, against real commits: a new `test/support/*.ex` that
#      rewrites the restored tests at compile time, a `mix.exs` alias that makes `mix test`
#      exit 0, and one `git log --all --grep` for the task's own subject.
#  12  no worktree and no ref of this corpus's is left behind.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../.." && pwd)

# Two small Elixir fix commits, verified by hand and by `extract.exs --commits` before
# they were pinned here. Both change one file under `lib/` and one test file that already
# existed, which is what the blanking controls need. Named in bench/self/README.md.
COMMIT_A=7f9d816676f67528ca854cc52628d6ccb1f42457
COMMIT_B=2d5a0ea6dfa92029cac7d732ac20b3afbc1a582a

# A model this node prices, so that a seam refusal is provably the seam's and not the
# pricing pre-flight's. Checked on 2026-09-08 against this checkout's own
# `Provider.Native.Cost.cost_usd/5`.
PRICED_MODEL=anthropic:claude-sonnet-4-5

# In a linked git worktree there is no `tui/target`, so the client has to be named. The
# message run.sh prints says the same thing; saying it here too means the gate fails with
# an instruction rather than a dozen identical refusals.
if [ -z "${OURO_BIN:-}" ] &&
   [ ! -f "$repo/tui/target/release/ouro" ] &&
   [ ! -f "$repo/tui/target/debug/ouro" ]; then
  echo "bench/self/selftest.sh: no ouro binary under $repo/tui/target." >&2
  echo "bench/self/selftest.sh: run 'cd tui && cargo build', or set OURO_BIN=/path/to/ouro." >&2
  exit 64
fi

SELFTEST_SCRATCH=$(mktemp -d "${BENCH_SELF_TMPDIR:-${TMPDIR:-/tmp}}/ouroboros-bench-self-selftest.XXXXXX")
export SELFTEST_SCRATCH

cleanup() {
  rm -rf "$SELFTEST_SCRATCH"
}

trap cleanup EXIT INT TERM

# shellcheck disable=SC1091
. "$here/lib/assert.sh"

fixture="$SELFTEST_SCRATCH/fixture"
fixture_tasks="$SELFTEST_SCRATCH/fixture-tasks"
tasks="$SELFTEST_SCRATCH/tasks"

echo "bench/self/selftest.sh"
echo "  repo    $repo"
echo "  scratch $SELFTEST_SCRATCH"
echo ""

# --- 1. the verdict rule ----------------------------------------------------

echo "1. the verdict is what ExUnit reported, not how the process ended"

# `mix test`'s exit status is a number the code under test can set, so the grade is read
# out of the summary line instead. The rule is `lib/improve/gate-verdict.sh`'s, which the
# improve loop's gate applies to the same suites: same shapes, same answers.
verdict() {
  printf '%s\n' "$2" > "$SELFTEST_SCRATCH/verdict.log"

  got=$(
    elixir -e "
      Code.require_file(\"$here/lib/support.exs\")

      case Bench.Self.Verdict.of(File.read!(\"$SELFTEST_SCRATCH/verdict.log\"), $3, $4) do
        {:ok, _summary} -> IO.puts(\"green\")
        {:error, _note} -> IO.puts(\"red\")
      end
    " 2>/dev/null
  )

  if [ "$got" = "$1" ]; then
    ok "$5"
  else
    fail "$5: the rule answered '$got', wanted '$1'"
  fi
}

verdict green "Result: 3 passed" 0 2 "3 passed over 2 files is green"
verdict red "Result: 3 passed" 2 2 "a non-zero exit is red even with a passing summary"
verdict red "Result: 1/2 passed
Failed: 1 test" 0 1 "a Failed: line is red even at exit 0"
verdict red "" 0 1 "exit 0 and no Result: line is red — the suite did not report"
verdict red "Result: 1 passed" 0 2 "fewer passing tests than hidden files is red"
verdict red "Result: 0 tests, 3 excluded" 0 1 "a suite that ran nothing is red"
verdict green "Result: 1 passed, 1 skipped, 1 excluded" 0 1 "skips and exclusions beside a pass are green"

# --- 2. the refusals that come first ----------------------------------------

echo ""
echo "2. what is refused before anything is built"

run_expect 64 "a run without --spend is refused" \
  sh "$here/run.sh" --oracle --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/nospend"
expect_contains "$LAST_OUTPUT" "--spend <usd> is required" "the refusal says why"

run_expect 64 "a run with --spend 0 is refused" \
  sh "$here/run.sh" --oracle --spend 0 --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/zerospend"

# Each seam is refused on a run whose model this node CAN price, so that the refusal is
# provably the seam guard's and not the pricing pre-flight's — which is the hole the
# review found in the previous version of these four assertions. Nothing may start a
# daemon: the guard runs before the client is even resolved.
seam() {
  run_expect 64 "$1 is refused without --oracle, on a priced model" \
    sh "$here/run.sh" --spend 1 --model "$PRICED_MODEL" "$@" \
    --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/seam"

  expect_contains "$LAST_OUTPUT" "$1 is a test seam and is only accepted with --oracle" \
    "the refusal names $1 and says it is a seam"
  expect_not_contains "$LAST_OUTPUT" "daemon  starting" "no daemon was started for $1"
  expect_not_contains "$LAST_OUTPUT" "cannot price" "the refusal is the seam guard's, not the pricing pre-flight's"
}

seam --fake-cost-usd 0.01
seam --oracle-cheat no-solution
seam --fake-status failed
seam --oracle-as-paid

run_expect 64 "OURO_BIN naming a file that is not there is refused" \
  env OURO_BIN="$SELFTEST_SCRATCH/no-such-ouro" \
  sh "$here/run.sh" --oracle --spend 1 --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/nobin"
expect_contains "$LAST_OUTPUT" "OURO_BIN names" "the refusal names the path"
expect_not_contains "$LAST_OUTPUT" "daemon  starting" "no daemon was started for a missing client"

# --- 3. the oracle's environment --------------------------------------------

echo ""
echo "3. the oracle's environment carries no secret"

# Asserted by spawning `env` through the runner's own builder, because the mistake this
# catches is invisible by inspection: a port's `env` option *extends* the caller's
# environment, so a list that merely omits a key removes nothing at all.
run_expect 0 "a planted key does not reach a child of the oracle's environment" \
  elixir -e "
    Code.require_file(\"$here/lib/support.exs\")
    System.put_env(\"ANTHROPIC_API_KEY\", \"planted-by-the-selftest\")
    System.put_env(\"GITHUB_TOKEN\", \"planted-by-the-selftest\")

    {:ok, 0, out} =
      Bench.Self.Exec.run(System.find_executable(\"env\"), [],
        cd: \"/\",
        stderr: :stdout,
        env: Bench.Self.Env.build(%{\"OUROBOROS_DATA_DIR\" => \"/tmp/bench-self-probe\"}, Bench.Self.Env.secrets())
      )

    if String.contains?(out, \"planted-by-the-selftest\"),
      do: (IO.puts(\"LEAKED\"); System.halt(1)),
      else: IO.puts(\"clean\")

    unless String.contains?(out, \"OUROBOROS_DATA_DIR=/tmp/bench-self-probe\"),
      do: (IO.puts(\"the override did not reach the child either\"); System.halt(1))
  "
expect_contains "$LAST_OUTPUT" "clean" "the child saw neither planted secret"

# --- 4. the extractor's gates, against a history built to trip them ----------

echo ""
echo "4. the extractor's gates"

shas=$(sh "$here/lib/fixture.sh" "$fixture")
fixture_task=$(echo "$shas" | sed -n 1p)
fixture_passes=$(echo "$shas" | sed -n 2p)
fixture_broken=$(echo "$shas" | sed -n 3p)
fixture_merge=$(echo "$shas" | sed -n 4p)

run_expect 0 "four fixture commits are examined and one is accepted" \
  elixir "$here/extract.exs" --history "$fixture" \
  --commits "$fixture_task,$fixture_passes,$fixture_broken,$fixture_merge" \
  --out "$fixture_tasks" --replace --jobs 1

expect_contains "$LAST_OUTPUT" "extracted 1 tasks" "exactly one of the four is a task"
expect_contains "$LAST_OUTPUT" "parent_already_passes" \
  "a commit whose hidden test already passes at its parent is dropped"
expect_contains "$LAST_OUTPUT" "commit_does_not_pass" \
  "a commit whose hidden test does not pass at the commit is dropped"
expect_contains "$LAST_OUTPUT" "merge_commit" "a merge is not a task"

fixture_id=$(ls "$fixture_tasks" | sed -n 1p)
expect_contains "$fixture_tasks/$fixture_id/task.json" '"instruction_kind": "full"' \
  "the task records which instruction it carries"

run_expect 0 "--instruction subject-only rewrites the corpus's instructions" \
  elixir "$here/extract.exs" --history "$fixture" --instruction subject-only --reinstruct "$fixture_tasks"
expect_contains "$fixture_tasks/$fixture_id/task.json" '"instruction_kind": "subject-only"' \
  "and records that it did"

run_expect 0 "--instruction full puts them back" \
  elixir "$here/extract.exs" --history "$fixture" --instruction full --reinstruct "$fixture_tasks"

# --- 5. four corpora that are not corpora -----------------------------------

echo ""
echo "5. corpora the runner refuses, and the one it survives"

doctored="$SELFTEST_SCRATCH/doctored"
rm -rf "$doctored"
cp -R "$fixture_tasks" "$doctored"

# One hidden test path dropped from the pins: git says the commit touched two, the corpus
# claims one. The weaker grade would look exactly like a pass, so it is not graded at all.
sed '/"test\/existing_test.exs",/d' "$doctored/$fixture_id/task.json" > "$doctored/$fixture_id/task.json.new"
mv "$doctored/$fixture_id/task.json.new" "$doctored/$fixture_id/task.json"

run_expect 1 "a corpus whose pins disagree with the history is not graded" \
  sh "$here/run.sh" --oracle --spend 1 --history "$fixture" \
  --tasks-dir "$doctored" --out "$SELFTEST_SCRATCH/pins"
expect_contains "$SELFTEST_SCRATCH/pins/result.json" "disagrees with the history" \
  "the reason names the disagreement"

notests="$SELFTEST_SCRATCH/no-test-file"
rm -rf "$notests"
cp -R "$fixture_tasks" "$notests"
sed -e '/"test\/existing_test.exs",/d' -e 's|"test/greet_test.exs"|"test/support/nothing.ex"|' \
  "$notests/$fixture_id/task.json" > "$notests/$fixture_id/task.json.new"
mv "$notests/$fixture_id/task.json.new" "$notests/$fixture_id/task.json"

run_expect 1 "a task naming no _test.exs is not graded" \
  sh "$here/run.sh" --oracle --spend 1 --history "$fixture" \
  --tasks-dir "$notests" --out "$SELFTEST_SCRATCH/notests"
expect_contains "$SELFTEST_SCRATCH/notests/result.json" "names no" \
  "the reason is the missing test file, not the pins"

duplicate="$SELFTEST_SCRATCH/duplicate-id"
rm -rf "$duplicate"
cp -R "$fixture_tasks" "$duplicate"
cp -R "$duplicate/$fixture_id" "$duplicate/99-a-second-directory-one-id"

run_expect 64 "a corpus with two tasks under one id is refused" \
  sh "$here/run.sh" --oracle --spend 1 --history "$fixture" \
  --tasks-dir "$duplicate" --out "$SELFTEST_SCRATCH/duplicate"
expect_contains "$LAST_OUTPUT" "share the id" "the refusal says which id"

stray="$SELFTEST_SCRATCH/stray-directory"
rm -rf "$stray"
cp -R "$fixture_tasks" "$stray"
mkdir -p "$stray/00-not-a-task"

run_expect 0 "a directory holding no task.json is reported and skipped, not fatal" \
  sh "$here/run.sh" --oracle --spend 1 --history "$fixture" \
  --tasks-dir "$stray" --out "$SELFTEST_SCRATCH/stray-out"
expect_contains "$LAST_OUTPUT" "holds no task.json" "the skip is reported"

# --- 6. the fixture corpus: one oracle and eight agents that must not score ---

echo ""
echo "6. the grader, against the fixture corpus"

cheat() {
  wanted_exit=$1
  wanted_reason=$2
  label=$3
  shift 3

  run_expect "$wanted_exit" "$label" \
    sh "$here/run.sh" --oracle --spend 1 --history "$fixture" \
    --tasks-dir "$fixture_tasks" --out "$SELFTEST_SCRATCH/cheat" "$@"

  expect_every_reason "$SELFTEST_SCRATCH/cheat/result.json" "$wanted_reason" \
    "  and every task's reason is $wanted_reason"
}

# `--repo` is the improve loop's contract: the runtime under test comes from the named
# checkout while the corpus's commits still come from the history.
run_expect 0 "the oracle passes the fixture task, through --repo" \
  sh "$here/run.sh" --oracle --spend 1 --repo "$repo" --history "$fixture" \
  --tasks-dir "$fixture_tasks" --out "$SELFTEST_SCRATCH/fixture-oracle"
expect_json "$SELFTEST_SCRATCH/fixture-oracle/result.json" "passed" "1" "the oracle graded it pass"
expect_json "$SELFTEST_SCRATCH/fixture-oracle/result.json" "spent" "0.0" "at \$0"
expect_contains "$SELFTEST_SCRATCH/fixture-oracle/result.json" '"corpus_sha256"' \
  "result.json carries a digest of the corpus it was graded against"
expect_contains "$SELFTEST_SCRATCH/fixture-oracle/result.json" '"ouro_bin_sha256"' \
  "and of the client binary"

cheat 1 tests_failed "an agent that changes nothing fails, which proves the restore" \
  --oracle-cheat no-solution
cheat 1 modified_tests "an agent that blanks a pre-existing test fails" \
  --oracle-cheat blank-tests
cheat 1 modified_tests "and so does one that COMMITS the same edit" \
  --oracle-cheat commit-tests
cheat 1 modified_tests "and one that hides it with git update-index --assume-unchanged" \
  --oracle-cheat hide-tests
cheat 1 modified_tests "and one that deletes it outright" \
  --oracle-cheat delete-tests
cheat 0 - "a new test of the agent's own, staged and then edited, is not a modification" \
  --oracle-cheat stage-new-test
cheat 1 tests_failed "a new test/support file that rewrites the tests at compile time fails" \
  --oracle-cheat game-support
cheat 0 - "a lib/ file that rewrites them at compile time changes nothing, because the restore is after the compile" \
  --oracle-cheat lib-rewrite
cheat 1 refused "a mix.exs carrying a test alias is refused, not graded" \
  --oracle-cheat mixexs-alias
cheat 1 tests_failed "looking the answer up in the workspace's history finds nothing" \
  --oracle-cheat history-cheat
cheat 1 not_completed "a turn whose result is not completed cannot pass" \
  --fake-status failed
cheat 64 setup_failed "a completed turn with no cost stops a priced run" \
  --oracle-as-paid
expect_contains "$SELFTEST_SCRATCH/cheat/result.json" "unpriced_turn" "and says it was unpriced"

# --- 7. extraction, against this repository ---------------------------------

echo ""
echo "7. extraction of two named commits of this repository"

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

# --- 8. the oracle ----------------------------------------------------------

echo ""
echo "8. the oracle, against this repository"

run_expect 0 "the oracle grades every task" \
  sh "$here/run.sh" --oracle --spend 1 --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/oracle"

oracle="$SELFTEST_SCRATCH/oracle/result.json"
expect_file "$oracle" "the oracle wrote result.json"
expect_json "$oracle" "tasks" "2" "the oracle saw two tasks"
expect_json "$oracle" "ran" "2" "the oracle ran both"
expect_json "$oracle" "passed" "2" "the oracle graded both pass"
expect_json "$oracle" "spent" "0.0" "the oracle spent nothing"
expect_json "$oracle" "oracle" "true" "the result object says it was an oracle run"

# --- 9. the cap stops the run -----------------------------------------------

echo ""
echo "9. the running total stops the run at the cap"

run_expect 3 "a run that reaches the cap stops and says which tasks did not run" \
  sh "$here/run.sh" --oracle --spend 0.03 --fake-cost-usd 0.04 \
  --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/cap"

cap="$SELFTEST_SCRATCH/cap/result.json"
expect_file "$cap" "the capped run wrote result.json"
expect_json "$cap" "tasks" "2" "the capped run saw two tasks"
expect_json "$cap" "ran" "1" "the capped run ran one"
expect_json "$cap" "passed" "1" "the one that ran passed"
expect_reason "$cap" "spend_cap" "the task that did not run gives spend_cap as its reason"
expect_contains "$LAST_OUTPUT" "did not run" "the report names the tasks that did not run"

# --- 10. the two original controls, against real commits ---------------------

echo ""
echo "10. the negative controls, against this repository"

run_expect 1 "an agent that changes nothing fails every task" \
  sh "$here/run.sh" --oracle --spend 1 --oracle-cheat no-solution \
  --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/nosolution"

nosolution="$SELFTEST_SCRATCH/nosolution/result.json"
expect_json "$nosolution" "ran" "2" "the control ran both"
expect_json "$nosolution" "passed" "0" "the control passed nothing"
expect_every_reason "$nosolution" "tests_failed" "the reason is tests_failed, not a pass"

run_expect 1 "an agent that blanks a pre-existing test fails every task" \
  sh "$here/run.sh" --oracle --spend 1 --oracle-cheat blank-tests \
  --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/blanked"

blanked="$SELFTEST_SCRATCH/blanked/result.json"
expect_json "$blanked" "ran" "2" "the control ran both"
expect_json "$blanked" "passed" "0" "the control passed nothing"
expect_every_reason "$blanked" "modified_tests" "the reason is modified_tests"

# --- 11. the three proved exploits, against real commits --------------------

echo ""
echo "11. the review's three exploits, against this repository"

# One task each: these are the same code paths phase 6 covers, run here against a real
# tree so that nothing rests on the fixture being shaped like one.
exploit() {
  wanted_reason=$1
  label=$2
  shift 2

  run_expect 1 "$label" \
    sh "$here/run.sh" --oracle --spend 1 --filter "$first" \
    --tasks-dir "$tasks" --out "$SELFTEST_SCRATCH/exploit" "$@"

  expect_every_reason "$SELFTEST_SCRATCH/exploit/result.json" "$wanted_reason" \
    "  and the reason is $wanted_reason"
}

exploit tests_failed "a new test/support file rewriting the restored tests scores nothing" \
  --oracle-cheat game-support
exploit refused "a doctored mix.exs is refused rather than graded" \
  --oracle-cheat mixexs-alias
exploit tests_failed "the answer is not in the workspace's history to be found" \
  --oracle-cheat history-cheat

# --- 12. nothing left behind ------------------------------------------------

echo ""
echo "12. what the run left in the repository"

left=$(git -C "$repo" worktree list | grep -c bench-self || true)

if [ "$left" = "0" ]; then
  ok "no bench-self worktree is registered"
else
  fail "no bench-self worktree is registered: $left left behind"
  git -C "$repo" worktree list | grep bench-self >&2 || true
fi

for where in "$repo" "$fixture"; do
  refs=$(git -C "$where" for-each-ref refs/bench-self | wc -l | tr -d ' ')

  if [ "$refs" = "0" ]; then
    ok "no temporary ref is left in $where"
  else
    fail "no temporary ref is left in $where: $refs left behind"
  fi
done

assert_done
