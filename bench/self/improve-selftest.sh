#!/bin/sh
# The gate on `bench/self/improve.sh`. No model, no key, no network, no spend.
#
#     bench/self/improve-selftest.sh
#
# It runs the whole outer loop twice against a shim client
# (`bench/self/lib/improve/shim-ouro.sh`): once with `--dry-run`, which must print every
# command and touch nothing, and once for real with `--quick --no-bench --no-pr`, which
# must produce a worktree branched from `dev`, two gates that actually ran, a review, a
# body that carries the review and the protected-namespace hunk, and one commit carrying
# the session trailer — with nothing pushed.
#
# What it proves is the plumbing. It says nothing about whether a model can do the work:
# the shim's "change" is a comment and a test that cannot fail. See bench/self/IMPROVE.md.
#
# The worktree it makes is registered in this checkout's git directory and is removed at
# the end, on failure and on interrupt as well as on success.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo=$(CDPATH= cd -- "$here/../.." && pwd -P)

improve="$here/improve.sh"
shim="$here/lib/improve/shim-ouro.sh"

[ -x "$improve" ] || {
  printf 'improve-selftest: %s is missing or not executable\n' "$improve" >&2
  exit 1
}
[ -x "$shim" ] || {
  printf 'improve-selftest: %s is missing or not executable\n' "$shim" >&2
  exit 1
}

scratch=$(mktemp -d "${TMPDIR:-/tmp}/ouroboros-improve-selftest.XXXXXX")
scratch=$(CDPATH= cd -- "$scratch" && pwd -P)

# The task title decides the slug, the branch and the worktree name, so both titles carry
# the pid: two selftests at once must not fight over one branch.
worktrees="$scratch/worktrees"

slug_of() {
  printf '%s' "$1" | tr 'A-Z' 'a-z' |
    sed -e 's/[^a-z0-9]\{1,\}/-/g' -e 's/^-*//' -e 's/-*$//' | cut -c 1-48 | sed -e 's/-*$//'
}

title="selftest $$ the shim change"
slug=$(slug_of "$title")
branch="self/improve-$slug"
wt="$worktrees/improve-$slug"

red_title="selftest $$ the shim change that breaks the suite"
red_slug=$(slug_of "$red_title")
red_branch="self/improve-$red_slug"
red_wt="$worktrees/improve-$red_slug"

noop_title="selftest $$ the shim change that changes nothing"
noop_slug=$(slug_of "$noop_title")
noop_branch="self/improve-$noop_slug"
noop_wt="$worktrees/improve-$noop_slug"

own_title="selftest $$ the shim change that commits itself"
own_slug=$(slug_of "$own_title")
own_branch="self/improve-$own_slug"
own_wt="$worktrees/improve-$own_slug"

failures=0
phase=setup

# `git worktree add` writes into this checkout's git directory, so removing the directory
# is not enough: the registration and the branch have to go too, or the next run of this
# script inherits both. The red phase deliberately leaves its worktree behind, which is
# what improve.sh is supposed to do, so this has two to clear.
drop_worktree() {
  if git -C "$repo" worktree list --porcelain 2> /dev/null | grep -qx "worktree $1"; then
    git -C "$repo" worktree remove --force "$1" > /dev/null 2>&1 || true
  fi
  if git -C "$repo" show-ref --verify --quiet "refs/heads/$2"; then
    git -C "$repo" branch -D "$2" > /dev/null 2>&1 || true
  fi
}

cleanup() {
  _exit=$?
  trap - EXIT
  drop_worktree "$wt" "$branch"
  drop_worktree "$red_wt" "$red_branch"
  drop_worktree "$noop_wt" "$noop_branch"
  drop_worktree "$own_wt" "$own_branch"
  git -C "$repo" worktree prune > /dev/null 2>&1 || true
  # Kept when something went wrong: the logs are the only thing that says what.
  if [ "$_exit" -eq 0 ] && [ "$failures" -eq 0 ]; then
    rm -rf "$scratch"
  else
    printf 'improve-selftest: scratch kept at %s\n' "$scratch" >&2
  fi
  exit "$_exit"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ok() {
  printf '  ok    %s\n' "$*"
}

bad() {
  printf '  FAIL  %s\n' "$*"
  failures=$((failures + 1))
}

check() {
  _what=$1
  shift
  if "$@"; then ok "$_what"; else bad "$_what"; fi
}

refute() {
  _what=$1
  shift
  if "$@"; then bad "$_what"; else ok "$_what"; fi
}

has() {
  grep -q -- "$2" "$1"
}

# `grep -F` for text that is a fixed string, so a `.` or a `[` in a heading is a `.` or a
# `[` and not a pattern that happens to match.
hasf() {
  grep -qF -- "$2" "$1"
}

printf '==> improve-selftest\n'
printf '  repo      %s\n' "$repo"
printf '  scratch   %s\n' "$scratch"
printf '  branch    %s\n' "$branch"
printf '  worktree  %s\n' "$wt"

task="$scratch/task.md"
cat > "$task" << TASK
$title

A shim stands in for the model here, so this task is never read by one. It exists so the
loop has a title to slug, a body to quote and a commit message to write.
TASK

export OUROBOROS_IMPROVE_WORKTREES="$worktrees"
export OURO_SHIM_STATE="$scratch/shim-state"
mkdir -p "$OURO_SHIM_STATE"

dev_sha=$(git -C "$repo" rev-parse dev)

# ------------------------------------------------------------------ 1. the dry run

phase=dry-run
printf '\n==> phase: --dry-run prints and does nothing\n'

dry_log="$scratch/dry-run.log"
dry_rc=0
OUROBOROS_IMPROVE_RUN_DIR="$scratch/dry-run" \
  "$improve" "$task" --ouro "$shim" --quick --no-bench --no-pr --dry-run \
  > "$dry_log" 2>&1 || dry_rc=$?

check "--dry-run exits 0 (rc=$dry_rc)" test "$dry_rc" -eq 0
check "--dry-run prints the worktree command" hasf "$dry_log" "worktree add -b $branch"
check "--dry-run prints the daemon command" hasf "$dry_log" '--dev daemon'
check "--dry-run prints the implementer run" hasf "$dry_log" 'implementer-prompt.txt'
check "--dry-run prints the resolved client path" hasf "$dry_log" "$shim"
check "--dry-run says it executed nothing" hasf "$dry_log" '(dry run: not executed)'
refute "--dry-run made no worktree" test -e "$wt"
refute "--dry-run made no run dir" test -e "$scratch/dry-run"
refute "--dry-run created no branch" git -C "$repo" show-ref --verify --quiet "refs/heads/$branch"

# ------------------------------------------------------------------ 2. the real pass

phase=run
printf '\n==> phase: the loop, against the shim\n'

run_log="$scratch/run.log"
run_rc=0
OUROBOROS_IMPROVE_RUN_DIR="$scratch/run" \
  "$improve" "$task" --ouro "$shim" --quick --no-bench --no-pr \
  > "$run_log" 2>&1 || run_rc=$?

if [ "$run_rc" -ne 0 ]; then
  printf '\n  improve.sh exited %s; last 60 lines:\n\n' "$run_rc"
  tail -n 60 "$run_log" | sed 's/^/  | /'
  printf '\n'
fi
check "improve.sh exits 0 (rc=$run_rc)" test "$run_rc" -eq 0

# --- the worktree

check "the worktree exists" test -d "$wt"
check "improve.sh names its base" hasf "$run_log" "from dev at $dev_sha on branch $branch"
if [ -d "$wt" ]; then
  check "the worktree descends from dev" \
    git -C "$wt" merge-base --is-ancestor "$dev_sha" HEAD
  check "the worktree is on the branch" \
    test "$(git -C "$wt" rev-parse --abbrev-ref HEAD)" = "$branch"
fi

# --- the sessions

check "the implementer session ran" hasf "$run_log" 'implementer rc=0 (session shim-impl'
check "the reviewer session ran" hasf "$run_log" 'reviewer rc=0 (session shim-review'
check "the fix wave resumed the implementer" hasf "$run_log" 'fix-wave rc=0 (session shim-impl'

# Both halves of the shim's edit are present, so the fix wave really did run in the same
# worktree as the implementer rather than in a fresh one.
if [ -f "$wt/lib/ouroboros/control/grants.ex" ]; then
  markers=$(grep -c 'improve-selftest: shim marker' "$wt/lib/ouroboros/control/grants.ex" || true)
  check "both shim markers are in grants.ex (found $markers)" test "$markers" -eq 2
fi

# --- the gates

for g in gate-1 gate-2; do
  check "$g ran mix format" hasf "$run_log" "$g.format rc=0"
  check "$g ran mix compile" hasf "$run_log" "$g.compile rc=0"
  # The ExUnit result, not just an rc: `$g.test rc=0 (skipped: …)` is also rc=0, and a
  # gate that skipped the suite is exactly the thing this check is here to catch.
  check "$g really ran the touched suite" hasf "$run_log" "$g.test rc=0 (Result: 1 passed)"
  check "$g reports green" hasf "$run_log" "$g rc=0"
  check "$g skipped the slow half under --quick" hasf "$run_log" "$g.make-test rc=0 (skipped: --quick)"
done
check "the gate ran the test the shim wrote" hasf "$run_log" 'mix test test/self_improve_shim_test.exs'

# The gate has to grade the worktree, not the checkout the script lives in. The shim's
# edits exist only in the worktree, so a gate that ran in the wrong tree could not have
# found the test file — and nothing the sessions did may have leaked back here.
refute "the shim's test did not leak into the checkout" test -e "$repo/test/self_improve_shim_test.exs"
refute "the shim's marker did not leak into the checkout" \
  hasf "$repo/lib/ouroboros/control/grants.ex" 'improve-selftest: shim marker'

# --- the review

check "REVIEW.md exists" test -f "$wt/REVIEW.md"

# --- the protected-namespace scan and the body

check "the protected scan ran" hasf "$run_log" 'protected-scan rc=0 (1 hunk(s)'
check "PR_BODY.md exists" test -f "$wt/PR_BODY.md"
# The body writer checks its own output before anything can be pushed. Take the section
# out of the writer and this line, not only the one below it, goes red.
check "the body writer verified its own section" hasf "$run_log" \
  'pr-body rc=0 (human review section present)'
if [ -f "$wt/PR_BODY.md" ]; then
  check "the body has the human-review section" hasf "$wt/PR_BODY.md" '## Human review required'
  # Anchored: the review quotes `lib/ouroboros/control/grants.ex:2` in prose and the
  # section preamble names the namespace, so an unanchored match would pass with the scan
  # gone. Only the scan writes the path on a line of its own.
  check "the body names the grants.ex hunk" has "$wt/PR_BODY.md" '^lib/ouroboros/control/grants\.ex$'
  check "the body carries a hunk header" has "$wt/PR_BODY.md" '^  @@'
  check "the body quotes the review" hasf "$wt/PR_BODY.md" 'Mutation table'
  check "the body carries the task" hasf "$wt/PR_BODY.md" 'A shim stands in for the model here'
  check "the body names both sessions" hasf "$wt/PR_BODY.md" \
    'Generated by bench/self/improve.sh (Ouroboros native sessions shim-impl, shim-review)'
  check "the body says the slow gate was skipped" hasf "$wt/PR_BODY.md" 'did **not** run'
  check "the body says why the corpus did not run" hasf "$wt/PR_BODY.md" 'not run: --no-bench'
fi

# --- the commit

if [ -d "$wt" ]; then
  git -C "$wt" log -1 --format=%B > "$scratch/commit-msg.txt" 2> /dev/null || true
  check "the commit subject is the task title" \
    test "$(git -C "$wt" log -1 --format=%s)" = "$title"
  check "the commit carries the session trailer" hasf "$scratch/commit-msg.txt" \
    'Co-Authored-By: Ouroboros native session shim-impl'
  git -C "$wt" show --stat --format= HEAD > "$scratch/commit-stat.txt" 2> /dev/null || true
  check "the commit carries the shim's change" hasf "$scratch/commit-stat.txt" \
    'lib/ouroboros/control/grants.ex'
  check "the commit carries the shim's test" hasf "$scratch/commit-stat.txt" \
    'test/self_improve_shim_test.exs'
  # The script's own paperwork is evidence, not the change.
  refute "the commit excludes REVIEW.md" hasf "$scratch/commit-stat.txt" 'REVIEW.md'
  refute "the commit excludes PR_BODY.md" hasf "$scratch/commit-stat.txt" 'PR_BODY.md'
  check "exactly one commit is on the branch" \
    test "$(git -C "$wt" rev-list --count "$dev_sha..HEAD")" = 1
fi

# --- nothing was pushed

refute "--no-pr pushed nothing (no remote-tracking ref)" \
  git -C "$repo" show-ref --verify --quiet "refs/remotes/origin/$branch"
refute "--no-pr ran no push step" hasf "$run_log" '==> push'
refute "--no-pr called no gh" hasf "$run_log" 'gh pr create'
check "--no-pr says so" hasf "$run_log" 'pr rc=0 (skipped: --no-pr (nothing pushed))'

# ------------------------------------------------------------------ 3. a red gate 2

# The decisive gate. A session that leaves the suite failing must not reach a commit, and
# the only way to know the refusal works is to watch it happen.
phase=red-gate
printf '\n==> phase: gate 2 red stops the loop before the commit\n'

red_task="$scratch/red-task.md"
cat > "$red_task" << TASK
$red_title

The shim is told to leave a failing test behind. Nothing should be committed.
TASK

red_log="$scratch/red.log"
red_rc=0
OURO_SHIM_BREAK=1 OUROBOROS_IMPROVE_RUN_DIR="$scratch/red" \
  "$improve" "$red_task" --ouro "$shim" --quick --no-bench --no-pr \
  > "$red_log" 2>&1 || red_rc=$?

check "improve.sh exits non-zero on a red gate 2 (rc=$red_rc)" test "$red_rc" -ne 0
# A non-zero rc *and* the ExUnit line: `mix test` exits 2 on a failing test, and a step
# that failed for some other reason would not have counted one.
check "gate 1 saw the failure" has "$red_log" '^gate-1\.test rc=[1-9].*Failed: 1 test'
check "gate 2 saw the failure" has "$red_log" '^gate-2\.test rc=[1-9].*Failed: 1 test'
check "gate 2 reports red" hasf "$red_log" 'gate-2 rc=1'
check "the loop says why it stopped" hasf "$red_log" \
  'gate 2 failed after the fix wave; nothing is committed and nothing is pushed'
refute "a red gate 2 makes no commit step" hasf "$red_log" '==> commit'
refute "a red gate 2 makes no body" test -f "$red_wt/PR_BODY.md"
if [ -d "$red_wt" ]; then
  check "the red branch carries no commit" \
    test "$(git -C "$red_wt" rev-list --count "$dev_sha..HEAD")" = 0
fi
refute "a red gate 2 pushed nothing" \
  git -C "$repo" show-ref --verify --quiet "refs/remotes/origin/$red_branch"
check "the worktree is left behind to look at" test -d "$red_wt"

# ------------------------------------------------------------------ 4. a no-op session

# A session that reports `completed` and changed nothing is not a change. It must not
# reach a review, a gate or a pull request.
phase=no-op
printf '\n==> phase: a session that changed nothing stops the loop\n'

noop_task="$scratch/noop-task.md"
cat > "$noop_task" << TASK
$noop_title

The shim is told to change nothing. The loop should refuse before it reviews anything.
TASK

noop_log="$scratch/noop.log"
noop_rc=0
OURO_SHIM_NOOP=1 OUROBOROS_IMPROVE_RUN_DIR="$scratch/noop" \
  "$improve" "$noop_task" --ouro "$shim" --quick --no-bench --no-pr \
  > "$noop_log" 2>&1 || noop_rc=$?

check "improve.sh exits non-zero on an empty change (rc=$noop_rc)" test "$noop_rc" -ne 0
check "the implementer session still reported completed" hasf "$noop_log" \
  'implementer rc=0 (session shim-impl, status completed)'
check "the loop says the change was empty" hasf "$noop_log" 'changed nothing in'
refute "an empty change gates nothing" hasf "$noop_log" '==> gate-1.format'
refute "an empty change reviews nothing" hasf "$noop_log" '==> reviewer'
refute "an empty change commits nothing" hasf "$noop_log" '==> commit'
if [ -d "$noop_wt" ]; then
  check "the empty branch carries no commit" \
    test "$(git -C "$noop_wt" rev-list --count "$dev_sha..HEAD")" = 0
fi

# ------------------------------------------------------------ 5. a self-committing session

# The implementer brief tells the session not to commit. One that does anyway leaves a
# branch whose commits carry neither the task title nor the `Co-Authored-By` trailer, and
# the loop must say so rather than making an empty commit or an amend — or, worse,
# reporting it as "the sessions changed nothing", which is a different thing entirely.
phase=self-commit
printf '\n==> phase: a session that commits its own work stops the loop\n'

own_task="$scratch/own-task.md"
cat > "$own_task" << TASK
$own_title

The shim is told to commit its own work. The loop should refuse to commit over it.
TASK

own_log="$scratch/own.log"
own_rc=0
OURO_SHIM_COMMIT=1 OUROBOROS_IMPROVE_RUN_DIR="$scratch/own" \
  "$improve" "$own_task" --ouro "$shim" --quick --no-bench --no-pr \
  > "$own_log" 2>&1 || own_rc=$?

check "improve.sh exits non-zero on a self-committed change (rc=$own_rc)" test "$own_rc" -ne 0
check "the gates still ran" hasf "$own_log" 'gate-2 rc=0'
check "the loop names the reason" hasf "$own_log" \
  'the session committed its own work, so this commit would carry neither the task title nor the session trailer'
refute "it is not reported as an empty change" hasf "$own_log" 'there is no commit to make'
refute "no body was written" test -f "$own_wt/PR_BODY.md"
if [ -d "$own_wt" ]; then
  check "only the session's own commits are on the branch" \
    test "$(git -C "$own_wt" rev-list --count "$dev_sha..HEAD")" = 2
  git -C "$own_wt" log --format=%B "$dev_sha..HEAD" > "$scratch/own-msg.txt" 2> /dev/null || true
  refute "the loop attached its trailer to none of them" hasf "$scratch/own-msg.txt" \
    'Co-Authored-By: Ouroboros native session'
fi

# ------------------------------------------------------------------ verdict

printf '\n'
if [ "$failures" -eq 0 ]; then
  printf 'improve-selftest: green\n'
  exit 0
fi

printf 'improve-selftest: %s check(s) failed (phase %s)\n' "$failures" "$phase" >&2
printf 'improve.sh log: %s\n' "$run_log" >&2
exit 1
