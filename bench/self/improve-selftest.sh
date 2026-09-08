#!/bin/sh
# The gate on `bench/self/improve.sh`. No model, no key, no network, no spend.
#
#     bench/self/improve-selftest.sh
#
# It drives the whole outer loop against a shim client
# (`bench/self/lib/improve/shim-ouro.sh`) over sixteen phases: the dry run, the argument
# handling, the gate verdict on its own, one green pass, and then one phase per refusal the
# loop is supposed to make — a red suite, an empty change, a self-committing session, a
# session that turns the decisive gate green with an exit status, a session that edits the
# build definitions the gates run, a diff that hides itself from `git diff`, a file left
# where a change may not land, a client that prints two result objects, the push and the
# pull request, a gate that must hold no model credentials, a client that ignores its own
# timeout, and a worktree that is already there. It ends by counting the watchdog sleeps
# the run left behind, which must be none.
#
# `improve-selftest.sh 4 9` runs those phases and nothing else, which is what a mutation
# harness wants: one phase is minutes, and sixteen of them are most of an hour.
#
# Every phase declares how many checks it expects to run, and a phase that runs a different
# number fails: a check deleted along with the thing it covered would otherwise leave the
# suite green and shorter.
#
# What it proves is the plumbing. It says nothing about whether a model can do the work:
# the shim's "change" is a comment and a test that cannot fail. See bench/self/IMPROVE.md.
#
# The worktrees it makes are registered in this checkout's git directory and are removed at
# the end, on failure and on interrupt as well as on success. Expect eight to ten minutes.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo=$(CDPATH= cd -- "$here/../.." && pwd -P)

improve="$here/improve.sh"
shim="$here/lib/improve/shim-ouro.sh"
verdict="$here/lib/improve/gate-verdict.sh"

for _f in "$improve" "$shim" "$verdict"; do
  [ -x "$_f" ] || {
    printf 'improve-selftest: %s is missing or not executable\n' "$_f" >&2
    exit 1
  }
done

scratch=$(mktemp -d "${TMPDIR:-/tmp}/ouroboros-improve-selftest.XXXXXX")
scratch=$(CDPATH= cd -- "$scratch" && pwd -P)

worktrees="$scratch/worktrees"
wt_list="$scratch/worktrees.tsv"
: > "$wt_list"

tab=$(printf '\t')

# Unique per run, so the orphan sweep at the end counts only this run's watchdog sleeps and
# two selftests at once do not read each other's.
impl_to=$((70000 + $$ % 1000))
rev_to=$((impl_to + 1))
impl_watchdog=$((impl_to + 120))
rev_watchdog=$((rev_to + 120))

slug_of() {
  printf '%s' "$1" | tr 'A-Z' 'a-z' |
    sed -e 's/[^a-z0-9]\{1,\}/-/g' -e 's/^-*//' -e 's/-*$//' | cut -c 1-48 | sed -e 's/-*$//'
}

# The title decides the slug, the branch and the worktree name, so every title carries the
# pid: two selftests at once must not fight over one branch.
case_title=''
case_slug=''
case_branch=''
case_wt=''
case_task=''

mk_case() {
  case_title="selftest $$ $1"
  case_slug=$(slug_of "$case_title")
  case_branch="self/improve-$case_slug"
  case_wt="$worktrees/improve-$case_slug"
  case_task="$scratch/task-$(printf '%s' "$1" | tr ' /' '--').md"
  printf '%s\n\n%s\n' "$case_title" "$2" > "$case_task"
  printf '%s\t%s\n' "$case_wt" "$case_branch" >> "$wt_list"
}

failures=0
checks=0
phase=setup
phase_expected=0
phase_at=0

# Which phases to run, by number, or all of them when no number is given:
#
#     bench/self/improve-selftest.sh 4 9
#
# One phase is a worktree, two gates and minutes; a mutation is caught by one of them, and
# a harness that had to run all sixteen to see it go red would be an hour per mutation. The
# phase bodies below are deliberately not indented inside their guard, so that the text of
# a task file written across two lines stays the text it was.
wanted=$*
want() {
  if [ -z "$wanted" ]; then
    return 0
  fi
  for _w in $wanted; do
    if [ "$_w" = "$1" ]; then
      return 0
    fi
  done
  return 1
}

# `git worktree add` writes into this checkout's git directory, so removing the directory
# is not enough: the registration and the branch have to go too, or the next run of this
# script inherits both. Several phases deliberately leave their worktree behind, which is
# what improve.sh is supposed to do, so this has a list to clear.
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
  while IFS="$tab" read -r _w _b; do
    [ -n "$_w" ] || continue
    drop_worktree "$_w" "$_b"
  done < "$wt_list"
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
  checks=$((checks + 1))
  printf '  ok    %s\n' "$*"
}

bad() {
  checks=$((checks + 1))
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

valid_utf8() {
  iconv -f UTF-8 -t UTF-8 "$1" > /dev/null 2>&1
}

count_of() {
  _c=$(grep -c -- "$2" "$1" 2> /dev/null || true)
  [ -n "$_c" ] || _c=0
  printf '%s\n' "$_c"
}

# What the protected-namespace scan printed, and only that: a run that also refused where
# the change landed prints a list of paths of its own, and a check that matched either of
# them would not be a check on the scan.
protected_block() {
  sed -n '/^==> protected-scan$/,/^protected-scan rc=/p' "$1" | sed -n 's/^    //p'
}

phase_start() {
  phase=$1
  phase_expected=$2
  phase_at=$checks
  printf '\n==> phase: %s (%s checks)\n' "$phase" "$phase_expected"
}

# A phase that ran a different number of checks than it says it does is a phase somebody
# edited without editing its count — which is how a check disappears with the thing it was
# there to cover.
phase_end() {
  _n=$((checks - phase_at))
  if [ "$_n" -ne "$phase_expected" ]; then
    printf '  FAIL  phase %s ran %s checks, not the %s it declares\n' "$phase" "$_n" "$phase_expected"
    failures=$((failures + 1))
  fi
}

printf '==> improve-selftest\n'
printf '  repo      %s\n' "$repo"
printf '  scratch   %s\n' "$scratch"
printf '  timeouts  implementer %s, reviewer %s\n' "$impl_to" "$rev_to"

export OUROBOROS_IMPROVE_WORKTREES="$worktrees"
export OURO_SHIM_STATE="$scratch/shim-state"
mkdir -p "$OURO_SHIM_STATE"

dev_sha=$(git -C "$repo" rev-parse dev)

# One `improve.sh` run. The run directory and the shim state go under this script's own
# scratch, which is what OUROBOROS_IMPROVE_RUN_DIR and OURO_SHIM_STATE are documented for.
#
# A phase's payload goes in `run_env` as `NAME=value` words (no whitespace in a value) and
# in `run_path`, both cleared after every run: a `VAR=x some_function` prefix persists in
# the shell after the call in POSIX sh, so one phase's shim payload would otherwise be
# every later phase's payload too.
run_env=''
run_path=''

run_improve() {
  _name=$1
  shift
  _log="$scratch/$_name.log"
  _rc=0
  env PATH="${run_path:-$PATH}" OUROBOROS_IMPROVE_RUN_DIR="$scratch/run-$_name" $run_env \
    "$improve" "$case_task" --ouro "$shim" \
    --implementer-timeout "$impl_to" --reviewer-timeout "$rev_to" "$@" \
    > "$_log" 2>&1 || _rc=$?
  run_env=''
  run_path=''
  printf '%s\n' "$_rc" > "$scratch/$_name.rc"
  return 0
}

rc_of() {
  cat "$scratch/$1.rc"
}

# ------------------------------------------------------------------ stubs on PATH
#
# Three programs the loop calls that a selftest must not let reach the world: `mix`, which
# would otherwise run the real gates when a phase is about something else entirely; `git`,
# whose `push` must never leave this machine; and `gh`, which opens pull requests.
# Each records what it was asked to do and answers the way the real one would.

stub_dir="$scratch/stub-bin"
mkdir -p "$stub_dir"
STUB_REAL_GIT=$(command -v git)
export STUB_REAL_GIT

cat > "$stub_dir/mix" << 'STUB'
#!/bin/sh
# A stub `mix`: it does not compile or test anything, it records the environment it was
# handed, and it answers `test` with the one line ExUnit would print for a green suite.
if [ -n "${STUB_MIX_ENV:-}" ]; then
  {
    printf '=== mix %s\n' "$*"
    env
  } >> "$STUB_MIX_ENV"
fi
case "${1:-}" in
  test) printf 'Result: 1 passed\n' ;;
  *) : ;;
esac
exit 0
STUB

cat > "$stub_dir/git" << 'STUB'
#!/bin/sh
# A stub `git` that intercepts exactly one subcommand — `push` — and delegates every other
# invocation to the real one. STUB_BREAK_BODY, when set, names a file to strip the pull
# request body's own section out of, the moment `improve.sh` asks about the remote — which
# is the step before the check that has to catch it.
find_sub() {
  while [ $# -gt 0 ]; do
    case $1 in
      -C | -c | --git-dir | --work-tree | --namespace)
        shift 2
        ;;
      -*) shift ;;
      *)
        printf '%s\n' "$1"
        return 0
        ;;
    esac
  done
  return 0
}
sub=$(find_sub "$@")
if [ "$sub" = push ]; then
  _rec=''
  for _a in "$@"; do _rec="$_rec[$_a]"; done
  printf '%s\n' "$_rec" >> "$STUB_GIT_PUSH"
  printf 'stub git: refused to push\n'
  exit 0
fi
if [ "$sub" = remote ] && [ -n "${STUB_BREAK_BODY:-}" ] && [ -f "$STUB_BREAK_BODY" ]; then
  grep -v '^## Human review required$' "$STUB_BREAK_BODY" > "$STUB_BREAK_BODY.cut" &&
    mv "$STUB_BREAK_BODY.cut" "$STUB_BREAK_BODY"
fi
exec "$STUB_REAL_GIT" "$@"
STUB

cat > "$stub_dir/gh" << 'STUB'
#!/bin/sh
_rec=''
for _a in "$@"; do _rec="$_rec[$_a]"; done
printf '%s\n' "$_rec" >> "$STUB_GH_CALLS"
printf 'https://example.invalid/pull/1\n'
exit 0
STUB

chmod +x "$stub_dir/mix" "$stub_dir/git" "$stub_dir/gh"

# The stub git records its argv after the leading options, so what a phase asserts on is
# `[push][-u][origin][<branch>]` — the arguments the push itself is made of.

# The case two phases share: the dry run walks it and the green pass runs it.
mk_case 'the shim change' 'A shim stands in for the model here, so this task is never read by
one. It exists so the loop has a title to slug, a body to quote and a commit message to
write.'
main_title=$case_title
main_branch=$case_branch
main_wt=$case_wt
main_task=$case_task

# ------------------------------------------------------------------ 1. the dry run

if want 1; then
phase_start '--dry-run prints and does nothing' 13

run_improve dry-run --quick --no-bench --no-pr --dry-run
dry_log="$scratch/dry-run.log"

check "--dry-run exits 0 (rc=$(rc_of dry-run))" test "$(rc_of dry-run)" -eq 0
check "--dry-run prints the worktree command" hasf "$dry_log" "worktree add -b $main_branch"
check "--dry-run prints the daemon command" hasf "$dry_log" '--dev daemon'
check "--dry-run prints the implementer run" hasf "$dry_log" 'implementer-prompt.txt'
check "--dry-run prints the resolved client path" hasf "$dry_log" "$shim"
check "--dry-run says it executed nothing" hasf "$dry_log" '(dry run: not executed)'
refute "--dry-run made no worktree" test -e "$main_wt"
refute "--dry-run made no run dir" test -e "$scratch/run-dry-run"
refute "--dry-run created no branch" git -C "$repo" show-ref --verify --quiet "refs/heads/$main_branch"

# S-D38: a dry run asked about a client that is not built names the path it would have
# taken rather than refusing to answer. A real run refuses.
missing_ouro="$scratch/no-such-client"
miss_rc=0
OUROBOROS_IMPROVE_RUN_DIR="$scratch/run-missing" "$improve" "$main_task" \
  --ouro "$missing_ouro" --quick --no-bench --no-pr --dry-run \
  > "$scratch/missing-dry.log" 2>&1 || miss_rc=$?
check "--dry-run with a missing --ouro exits 0 (rc=$miss_rc)" test "$miss_rc" -eq 0
check "--dry-run with a missing --ouro names the path" hasf "$scratch/missing-dry.log" "$missing_ouro"

real_rc=0
OUROBOROS_IMPROVE_RUN_DIR="$scratch/run-missing2" "$improve" "$main_task" \
  --ouro "$missing_ouro" --quick --no-bench --no-pr \
  > "$scratch/missing-real.log" 2>&1 || real_rc=$?
check "a real run with a missing --ouro refuses (rc=$real_rc)" test "$real_rc" -ne 0
check "a real run with a missing --ouro says which path" hasf "$scratch/missing-real.log" \
  "is not an executable file"

phase_end
fi

# ------------------------------------------------------------------ 2. the argument surface

if want 2; then
phase_start 'the argument surface' 12

arg_run() {
  _n=$1
  shift
  _rc=0
  OUROBOROS_IMPROVE_RUN_DIR="$scratch/run-arg-$_n" "$improve" "$@" \
    > "$scratch/arg-$_n.log" 2>&1 || _rc=$?
  printf '%s\n' "$_rc" > "$scratch/arg-$_n.rc"
  return 0
}

arg_run spend-bad "$main_task" --ouro "$shim" --dry-run --spend abc
check "--spend abc exits 64 (rc=$(cat "$scratch/arg-spend-bad.rc"))" \
  test "$(cat "$scratch/arg-spend-bad.rc")" -eq 64
check "--spend abc says what it takes" hasf "$scratch/arg-spend-bad.log" \
  '--spend takes a number of US dollars'
arg_run spend-ok "$main_task" --ouro "$shim" --dry-run --quick --no-pr --spend 12.50
check "--spend 12.50 is accepted (rc=$(cat "$scratch/arg-spend-ok.rc"))" \
  test "$(cat "$scratch/arg-spend-ok.rc")" -eq 0
arg_run timeout-frac "$main_task" --ouro "$shim" --dry-run --implementer-timeout 1.5
check "--implementer-timeout 1.5 exits 64" test "$(cat "$scratch/arg-timeout-frac.rc")" -eq 64
arg_run ddash --dry-run -- "$main_task"
check "-- takes what follows as the task (rc=$(cat "$scratch/arg-ddash.rc"))" \
  test "$(cat "$scratch/arg-ddash.rc")" -eq 0
check "-- reached the same title" hasf "$scratch/arg-ddash.log" "improve: $main_title"

printf '%s\n\nbody\n' 'ソースだけ' > "$scratch/task-unicode.md"
arg_run unicode "$scratch/task-unicode.md" --ouro "$shim" --dry-run
check "a title that slugifies to nothing refuses" test "$(cat "$scratch/arg-unicode.rc")" -ne 0
check "...and says why" hasf "$scratch/arg-unicode.log" 'slugifies to nothing'

arg_run two-tasks "$main_task" "$main_task" --dry-run
check "two task files exit 64" test "$(cat "$scratch/arg-two-tasks.rc")" -eq 64
arg_run unknown "$main_task" --nonesuch
check "an unknown option exits 64" test "$(cat "$scratch/arg-unknown.rc")" -eq 64

# The subject line is bounded in characters. Seventy ASCII bytes and then six two-byte ones
# puts the 72nd BYTE inside a character: a byte-wise cut would hand `gh pr create --title` a
# broken UTF-8 sequence.
utf8_head=$(awk 'BEGIN { s = ""; while (length(s) < 70) s = s "a"; print substr(s, 1, 70) }')
printf '%séééééé\n\nbody\n' "$utf8_head" > "$scratch/task-utf8.md"
arg_run utf8 "$scratch/task-utf8.md" --ouro "$shim" --dry-run
sed -n 's/^improve: //p' "$scratch/arg-utf8.log" | head -1 | tr -d '\n' > "$scratch/utf8-title.txt"
check "a title cut at 72 characters is still valid UTF-8" valid_utf8 "$scratch/utf8-title.txt"
check "...and is 72 characters, not 72 bytes" \
  test "$(LC_ALL=en_US.UTF-8 wc -m < "$scratch/utf8-title.txt" | tr -d ' ')" -eq 72

phase_end
fi

# ------------------------------------------------------------------ 3. the gate verdict

# The decisive gate is not an exit status. This phase feeds `gate-verdict.sh` the logs the
# four kinds of gate step produce, including the ones no selftest could produce for real:
# `make test` and `mix dialyzer` are minutes each and neither runs under --quick.
if want 3; then
phase_start 'the verdict on a gate log' 11

gv="$scratch/gv"
mkdir -p "$gv"
printf 'Result: 6 passed\n' > "$gv/pass.log"
printf 'Result: 1 passed, 1 skipped, 1 excluded\n' > "$gv/skip.log"
printf 'Result: 1/2 passed\nFailed: 1 test\n' > "$gv/fail.log"
printf 'compiled, said nothing else\n' > "$gv/silent.log"
printf 'Result: 0 tests, 3 excluded\n' > "$gv/none.log"
printf 'Result: 6 passed\nResult: 1/2 passed\nFailed: 1 test\n' > "$gv/two.log"
printf 'done (passed successfully)\n' > "$gv/dial.log"
printf 'Total errors: 3\n' > "$gv/dialbad.log"

verdict_is() {
  _want=$1
  shift
  [ "$("$verdict" "$@" | cut -f1)" = "$_want" ]
}
verdict_note_has() {
  _want=$1
  shift
  "$verdict" "$@" | cut -f2- | grep -qF -- "$_want"
}

check "rc green on exit 0" verdict_is 0 rc 0 "$gv/pass.log"
check "rc red on exit 2" verdict_is 1 rc 2 "$gv/pass.log"
check "mix test green on a clean pass" verdict_is 0 mix-test 0 "$gv/pass.log"
check "mix test green with skips and exclusions" verdict_is 0 mix-test 0 "$gv/skip.log"
check "mix test RED at exit 0 when ExUnit reported a failure" verdict_is 1 mix-test 0 "$gv/fail.log"
check "mix test RED at exit 0 with no result line" verdict_is 1 mix-test 0 "$gv/silent.log"
check "...and says the suite did not report" verdict_note_has 'no result line' mix-test 0 "$gv/silent.log"
check "mix test RED when no test ran" verdict_is 1 mix-test 0 "$gv/none.log"
check "make test RED when one of two result lines is a failure" verdict_is 1 make-test 0 "$gv/two.log"
check "dialyzer green only with its own line" verdict_is 0 dialyzer 0 "$gv/dial.log"
check "dialyzer RED at exit 0 without it" verdict_is 1 dialyzer 0 "$gv/dialbad.log"

phase_end
fi

# ------------------------------------------------------------------ 4. the real pass

if want 4; then
phase_start 'the loop, against the shim' 66

case_title=$main_title
case_branch=$main_branch
case_wt=$main_wt
case_task=$main_task
run_improve run --quick --no-bench --no-pr
run_log="$scratch/run.log"
run_rc=$(rc_of run)
wt=$main_wt
branch=$main_branch
title=$main_title

if [ "$run_rc" -ne 0 ]; then
  printf '\n  improve.sh exited %s; last 60 lines:\n\n' "$run_rc"
  tail -n 60 "$run_log" | sed 's/^/  | /'
  printf '\n'
fi
check "improve.sh exits 0 (rc=$run_rc)" test "$run_rc" -eq 0

# --- the worktree

check "the worktree exists" test -d "$wt"
check "improve.sh names its base" hasf "$run_log" "from dev at $dev_sha on branch $branch"
check "the worktree descends from dev" \
  git -C "$wt" merge-base --is-ancestor "$dev_sha" HEAD
check "the worktree is on the branch" \
  test "$(git -C "$wt" rev-parse --abbrev-ref HEAD 2> /dev/null || printf none)" = "$branch"

# --- where the loop keeps its own paperwork (M6)

run_data="$scratch/run-run/data"
check "the data dir is private (0700)" \
  test "$(ls -ld "$run_data" | cut -c 1-10)" = 'drwx------'
check "steps.tsv is under the data dir" test -f "$run_data/improve/steps.tsv"
check "the logs are under the data dir" test -f "$run_data/improve/logs/implementer-prompt.txt"
check "the reviewer scratch exists" test -d "$scratch/run-run/review-scratch"
check "the reviewer scratch is private (0700)" \
  test "$(ls -ld "$scratch/run-run/review-scratch" | cut -c 1-10)" = 'drwx------'
check "the reviewer prompt names it" hasf "$run_data/improve/logs/reviewer-prompt.txt" \
  "$scratch/run-run/review-scratch"
# `ouro run` takes the prompt as one argv element and Linux caps one at 128 KiB.
check "the reviewer prompt is inside the argv bound" \
  test "$(wc -c < "$run_data/improve/logs/reviewer-prompt.txt" | tr -d ' ')" -le 122880
check "...and says how much of the diff it carries" \
  hasf "$run_data/improve/logs/reviewer-prompt.txt" 'That is the whole diff'

# --- the sessions

check "the implementer session ran" hasf "$run_log" 'implementer rc=0 (session shim-impl'
check "the reviewer session ran" hasf "$run_log" 'reviewer rc=0 (session shim-review'
check "the fix wave resumed the implementer" hasf "$run_log" 'fix-wave rc=0 (session shim-impl'

# The fix-wave prompt carries a review that plants a role marker of its own. Quoted, it is
# one line of a blockquote; unquoted it would be a second instruction in the same message.
fix_prompt="$run_data/improve/logs/fix-wave-prompt.txt"
check "the fix-wave prompt has exactly one unquoted role marker" \
  test "$(count_of "$fix_prompt" '^OUROBOROS-IMPROVE-ROLE:')" -eq 1
check "the review's own role marker is quoted" hasf "$fix_prompt" '> OUROBOROS-IMPROVE-ROLE: fix-wave'
check "the fix-wave prompt says the quote is untrusted" hasf "$fix_prompt" \
  'UNTRUSTED TEXT WRITTEN'

# Both halves of the shim's edit are present, so the fix wave really did run in the same
# worktree as the implementer rather than in a fresh one.
check "both shim markers are in grants.ex" \
  test "$(count_of "$wt/lib/ouroboros/control/grants.ex" 'improve-selftest: shim marker')" -eq 2

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
check "the build scan ran after the implementer" hasf "$run_log" \
  'build-scan.implementer rc=0 (no build definition touched)'
check "the build scan ran again after the fix wave" hasf "$run_log" \
  'build-scan.fix-wave rc=0 (no build definition touched)'

# The gate has to grade the worktree, not the checkout the script lives in. The shim's
# edits exist only in the worktree, so a gate that ran in the wrong tree could not have
# found the test file — and nothing the sessions did may have leaked back here.
refute "the shim's test did not leak into the checkout" test -e "$repo/test/self_improve_shim_test.exs"
refute "the shim's marker did not leak into the checkout" \
  hasf "$repo/lib/ouroboros/control/grants.ex" 'improve-selftest: shim marker'

# --- the review

check "REVIEW.md exists" test -f "$wt/REVIEW.md"

# --- the protected-namespace scan and the body

check "the protected scan ran" hasf "$run_log" 'protected-scan rc=0 (1 path(s)'
check "PR_BODY.md exists" test -f "$wt/PR_BODY.md"
# The body writer checks its own output before anything can be pushed. Take the section
# out of the writer and this line, not only the one below it, goes red.
check "the body writer verified its own section" hasf "$run_log" \
  'pr-body rc=0 (human review section present)'
check "the body has the human-review section" hasf "$wt/PR_BODY.md" '## Human review required'
# The review the shim writes carries a `## Human review required` heading of its own at
# column 0. Quoted, it cannot be this section; unquoted, there would be two.
check "exactly one Human review required heading is at column 0" \
  test "$(count_of "$wt/PR_BODY.md" '^## Human review required$')" -eq 1
check "the review's own heading is inside the quote" hasf "$wt/PR_BODY.md" \
  '> ## Human review required'
check "the review's fence lines are quoted too" hasf "$wt/PR_BODY.md" '> ``````'
refute "no bare six-backtick line escaped into the body" has "$wt/PR_BODY.md" \
  '^ \{0,3\}`\{6,\}[[:space:]]*$'
# Anchored on the status and the path the scan writes, so an unanchored match somewhere in
# the quoted review cannot stand in for the scan.
check "the body names the grants.ex change" has "$wt/PR_BODY.md" \
  "^M${tab}lib/ouroboros/control/grants\\.ex\$"
check "the body carries a hunk header" has "$wt/PR_BODY.md" '^  @@'
check "the body quotes the review" hasf "$wt/PR_BODY.md" '> ## Mutation table'
check "the body bounds the review" hasf "$wt/PR_BODY.md" 'the first 200 are quoted'
refute "the body does not carry the review's tail" hasf "$wt/PR_BODY.md" 'SHIM-REVIEW-TAIL-SENTINEL'
check "the body carries the task" hasf "$wt/PR_BODY.md" 'A shim stands in for the model here'
check "the preamble is assembled from what happened" hasf "$wt/PR_BODY.md" \
  '- implementer session `shim-impl`: rc 0, status completed.'
check "the sessions table carries the rc" hasf "$wt/PR_BODY.md" \
  '| implementer | `shim-impl` | 0 | completed |'
check "the body names both sessions" hasf "$wt/PR_BODY.md" \
  'Generated by bench/self/improve.sh (Ouroboros native sessions shim-impl, shim-review)'
check "the body says the slow gate was skipped" hasf "$wt/PR_BODY.md" 'did **not** run'
check "the body says why the corpus did not run" hasf "$wt/PR_BODY.md" 'not run: --no-bench'

# --- the commit

git -C "$wt" log -1 --format=%B > "$scratch/commit-msg.txt" 2> /dev/null || true
check "the commit subject is the task title" \
  test "$(git -C "$wt" log -1 --format=%s)" = "$title"
check "the commit carries the session trailer" hasf "$scratch/commit-msg.txt" \
  'Co-Authored-By: Ouroboros native session shim-impl <noreply+shim-impl@ouroboros.local>'
check "git reads it as a trailer" \
  test -n "$(git -C "$repo" interpret-trailers --parse < "$scratch/commit-msg.txt")"
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

# --- nothing was pushed

refute "--no-pr pushed nothing (no remote-tracking ref)" \
  git -C "$repo" show-ref --verify --quiet "refs/remotes/origin/$branch"
refute "--no-pr ran no push step" hasf "$run_log" '==> push'
check "--no-pr says so" hasf "$run_log" 'pr rc=0 (skipped: --no-pr (nothing pushed))'

phase_end
fi

# ------------------------------------------------------------------ 5. a red gate 2

# The decisive gate. A session that leaves the suite failing must not reach a commit, and
# the only way to know the refusal works is to watch it happen.
if want 5; then
phase_start 'gate 2 red stops the loop before the commit' 9

mk_case 'the shim change that breaks the suite' \
  'The shim is told to leave a failing test behind. Nothing should be committed.'
red_wt=$case_wt
red_branch=$case_branch
red_task=$case_task
red_title=$case_title
run_env='OURO_SHIM_BREAK=1'
run_improve red --quick --no-bench --no-pr
red_log="$scratch/red.log"

check "improve.sh exits non-zero on a red gate 2 (rc=$(rc_of red))" test "$(rc_of red)" -ne 0
# A non-zero rc *and* the ExUnit line: `mix test` exits 2 on a failing test, and a step
# that failed for some other reason would not have counted one.
check "gate 1 saw the failure" has "$red_log" '^gate-1\.test rc=[1-9].*Failed: 1 test'
check "gate 2 saw the failure" has "$red_log" '^gate-2\.test rc=[1-9].*Failed: 1 test'
check "gate 2 reports red" hasf "$red_log" 'gate-2 rc=1'
check "the loop says why it stopped" hasf "$red_log" \
  'gate 2 failed after the fix wave; nothing is committed and nothing is pushed'
refute "a red gate 2 makes no commit step" hasf "$red_log" '==> commit'
refute "a red gate 2 makes no body" test -f "$red_wt/PR_BODY.md"
check "the red branch carries no commit" \
  test "$(git -C "$red_wt" rev-list --count "$dev_sha..HEAD" 2> /dev/null || printf 9)" = 0
check "the worktree is left behind to look at" test -d "$red_wt"

phase_end
fi

# ------------------------------------------------------------------ 6. an existing worktree

if want 6; then
phase_start 'a worktree that is already there' 2

case_wt=$red_wt
case_branch=$red_branch
case_task=$red_task
case_title=$red_title
run_improve again --quick --no-bench --no-pr
check "a second run over the same worktree refuses (rc=$(rc_of again))" test "$(rc_of again)" -ne 0
check "...and names the worktree" hasf "$scratch/again.log" \
  'already exists; remove it or give the task a different title'

phase_end
fi

# ------------------------------------------------------------------ 7. a no-op session

# A session that reports `completed` and changed nothing is not a change. It must not
# reach a review, a gate or a pull request.
if want 7; then
phase_start 'a session that changed nothing stops the loop' 7

mk_case 'the shim change that changes nothing' \
  'The shim is told to change nothing. The loop should refuse before it reviews anything.'
noop_wt=$case_wt
run_env='OURO_SHIM_NOOP=1'
run_improve noop --quick --no-bench --no-pr
noop_log="$scratch/noop.log"

check "improve.sh exits non-zero on an empty change (rc=$(rc_of noop))" test "$(rc_of noop)" -ne 0
check "the implementer session still reported completed" hasf "$noop_log" \
  'implementer rc=0 (session shim-impl, status completed)'
check "the loop says the change was empty" hasf "$noop_log" 'changed nothing in'
refute "an empty change gates nothing" hasf "$noop_log" '==> gate-1.format'
refute "an empty change reviews nothing" hasf "$noop_log" '==> reviewer'
refute "an empty change commits nothing" hasf "$noop_log" '==> commit'
check "the empty branch carries no commit" \
  test "$(git -C "$noop_wt" rev-list --count "$dev_sha..HEAD" 2> /dev/null || printf 9)" = 0

phase_end
fi

# ------------------------------------------------------------ 8. a self-committing session

# The implementer brief tells the session not to commit. One that does anyway leaves a
# branch whose commits carry neither the task title nor the `Co-Authored-By` trailer, and
# the loop must say so rather than making an empty commit or an amend — or, worse,
# reporting it as "the sessions changed nothing", which is a different thing entirely.
if want 8; then
phase_start 'a session that commits its own work stops the loop' 7

mk_case 'the shim change that commits itself' \
  'The shim is told to commit its own work. The loop should refuse to commit over it.'
own_wt=$case_wt
run_env='OURO_SHIM_COMMIT=1'
run_improve own --quick --no-bench --no-pr
own_log="$scratch/own.log"

check "improve.sh exits non-zero on a self-committed change (rc=$(rc_of own))" test "$(rc_of own)" -ne 0
check "the gates still ran" hasf "$own_log" 'gate-2 rc=0'
check "the loop names the reason" hasf "$own_log" \
  'the session committed its own work, so this commit would carry neither the task title nor the session trailer'
refute "it is not reported as an empty change" hasf "$own_log" 'there is no commit to make'
refute "no body was written" test -f "$own_wt/PR_BODY.md"
check "only the session's own commits are on the branch" \
  test "$(git -C "$own_wt" rev-list --count "$dev_sha..HEAD" 2> /dev/null || printf 9)" = 2
git -C "$own_wt" log --format=%B "$dev_sha..HEAD" > "$scratch/own-msg.txt" 2> /dev/null || true
refute "the loop attached its trailer to none of them" hasf "$scratch/own-msg.txt" \
  'Co-Authored-By: Ouroboros native session'

phase_end
fi

# --------------------------------------------------- 9. the gate that a session turned green

# One formatted, compiling line in `test/test_helper.exs` makes `mix test` exit 0 whatever
# ExUnit reports. Two things have to stop it: the build-definition scan, which refuses the
# change before any gate runs at all, and — if an operator allowed the build change — the
# gate reading the result line instead of the exit status.
if want 9; then
phase_start 'a session that turns the decisive gate green' 12

mk_case 'the shim change that halts the test helper' \
  'The shim edits test/test_helper.exs so mix test exits 0 whatever ExUnit says.'
halt_wt=$case_wt
run_env='OURO_SHIM_HALT_HELPER=1 OURO_SHIM_BREAK=1'
run_improve halt --quick --no-bench --no-pr
halt_log="$scratch/halt.log"

check "the loop refuses a changed build definition (rc=$(rc_of halt))" test "$(rc_of halt)" -eq 2
check "...naming the file" hasf "$halt_log" 'test/test_helper.exs'
check "...before any gate ran" test "$(count_of "$halt_log" '^==> gate-1\.format')" -eq 0
check "...and says the gates would have run it" hasf "$halt_log" \
  "the gates would have run the model's own build definition"
check "the refusal writes a body" test -f "$halt_wt/PR_BODY.md"
check "the body carries the refusal section" hasf "$halt_wt/PR_BODY.md" \
  '## Refused: build definition changed'
check "the refusal commits nothing" \
  test "$(git -C "$halt_wt" rev-list --count "$dev_sha..HEAD" 2> /dev/null || printf 9)" = 0

mk_case 'the shim change that halts the helper and is allowed' \
  'The same change, with --allow-build-changes, so the gate itself has to catch it.'
halt2_wt=$case_wt
run_env='OURO_SHIM_HALT_HELPER=1 OURO_SHIM_BREAK=1'
run_improve halt2 --quick --no-bench --no-pr --allow-build-changes
halt2_log="$scratch/halt2.log"

check "with --allow-build-changes the gates run (rc=$(rc_of halt2))" test "$(rc_of halt2)" -ne 0
check "mix test exited 0" hasf "$halt2_log" 'gate-2.test rc=1 (exit 0 but the suite reported a failure'
check "the gate is red anyway" hasf "$halt2_log" 'gate-2 rc=1'
check "the loop stops before the commit" hasf "$halt2_log" \
  'gate 2 failed after the fix wave; nothing is committed and nothing is pushed'
refute "nothing was committed" test -f "$halt2_wt/PR_BODY.md"

phase_end
fi

# ------------------------------------------------ 10. a diff that hides itself from git diff

# `lib/ouroboros/control/** -diff` in `.gitattributes` renders every hunk in the namespace
# as a binary difference; a rename, a mode change and a binary produce no `@@` line at all;
# and an added line beginning `++ ` is rendered `+++ …`, which a scan that read the diff
# body would take for a file header. The scan reads `--name-status`, which none of that
# touches.
if want 10; then
phase_start 'a change that hides itself from git diff' 13

mk_case 'the shim change that hides from the diff' \
  'The shim renames, chmods, adds a binary, adds a path with a space, plants a ++ line and
turns the namespace binary in .gitattributes.'
hide_wt=$case_wt
run_env='OURO_SHIM_HIDE=1 OURO_SHIM_RENAME=1 OURO_SHIM_MODE=1 OURO_SHIM_BINARY=1
OURO_SHIM_SPACEPATH=1 OURO_SHIM_PLUSPLUS=1'
run_improve hide --quick --no-bench --no-pr --allow-build-changes
hide_log="$scratch/hide.log"
hide_body="$hide_wt/PR_BODY.md"
hide_scan="$scratch/hide-protected.txt"
protected_block "$hide_log" > "$hide_scan"

check "the run finishes (rc=$(rc_of hide))" test "$(rc_of hide)" -eq 0
check "the build scan named .gitattributes" hasf "$hide_log" '.gitattributes'
check "the body lists the build change first" hasf "$hide_body" \
  "**The gates ran this change's own build definitions.**"
check "the scan still sees grants.ex through -diff" has "$hide_scan" \
  "^M${tab}lib/ouroboros/control/grants\\.ex\$"
check "the scan sees the renamed file's new name" has "$hide_scan" \
  "^R[0-9]*${tab}lib/ouroboros/control/planner_renamed\\.ex\$"
check "the scan sees the renamed file's old name" has "$hide_scan" \
  "^R[0-9]*${tab}lib/ouroboros/control/planner\\.ex\$"
check "the scan sees the mode change" has "$hide_scan" \
  "^M${tab}lib/ouroboros/control/store\\.ex\$"
check "the scan sees the binary" has "$hide_scan" \
  "^A${tab}lib/ouroboros/control/shim_blob\\.bin\$"
check "the scan sees the path with a space" has "$hide_scan" \
  "^A${tab}lib/ouroboros/control/sub dir/a b\\.ex\$"
check "the scan sees the ++ file under its own name" has "$hide_scan" \
  "^A${tab}lib/ouroboros/control/shim_plus_plus\\.ex\$"
refute "the ++ line did not become a path" hasf "$hide_scan" \
  'lib/ouroboros/agent/harmless_helper.ex'
check "the scan counts seven paths" hasf "$hide_log" 'protected-scan rc=0 (7 path(s)'
check "one commit was made" \
  test "$(git -C "$hide_wt" rev-list --count "$dev_sha..HEAD" 2> /dev/null || printf 9)" = 1

phase_end
fi

# ------------------------------------------------ 11. a file left where a change may not land

# `git add -A` is what makes a new module part of the change. It is also what sweeps in the
# script a reviewer session left behind, which is why the reviewer gets a scratch directory
# and why the commit step checks where the change landed.
if want 11; then
phase_start 'a file left where a change may not land' 8

mk_case 'the shim change that leaves a script behind' \
  'The shim leaves a script in the workspace root, which nothing asked for. It also writes
notes/from-the-task.md, which this line asks for by name.'
stray_wt=$case_wt
run_env='OURO_SHIM_STRAY=exploit-e9.sh OURO_SHIM_STRAY2=notes/from-the-task.md'
run_path="$stub_dir:$PATH"
run_improve stray --quick --no-bench --no-pr
stray_log="$scratch/stray.log"

check "the loop refuses to commit it (rc=$(rc_of stray))" test "$(rc_of stray)" -eq 2
check "...naming the file" hasf "$stray_log" 'exploit-e9.sh'
check "...and the allow-list" hasf "$stray_log" 'outside lib/* test/* docs/*'
refute "...but not the path the task file named" hasf "$stray_log" 'notes/from-the-task.md'
check "the refusal writes a body" test -f "$stray_wt/PR_BODY.md"
check "the body carries the refusal section" hasf "$stray_wt/PR_BODY.md" \
  '## Refused: the change landed outside the allowed paths'
check "nothing was committed" \
  test "$(git -C "$stray_wt" rev-list --count "$dev_sha..HEAD" 2> /dev/null || printf 9)" = 0
check "the file is still in the worktree to look at" test -f "$stray_wt/exploit-e9.sh"

phase_end
fi

# ------------------------------------------------ 12. a client that prints two result objects

# The result object is the LAST `"type":"result"` line, and what the loop read is what the
# loop reports: a session id it could not resume, a fix wave that exited non-zero, and a
# note that says so instead of claiming the implementer's own session was resumed.
if want 12; then
phase_start 'a client that prints two result objects' 8

mk_case 'the shim change with a second result object' \
  'The shim prints a subagent result after the real one.'
two_wt=$case_wt
run_env='OURO_SHIM_TWO_RESULTS=1'
run_path="$stub_dir:$PATH"
run_improve two --quick --no-bench --no-pr
two_log="$scratch/two.log"

check "the loop reads the last result object" hasf "$two_log" \
  'implementer rc=0 (session shim-SUBAGENT, status failed)'
check "the fix wave could not resume it" has "$two_log" '^fix-wave rc=64'
check "the run still finished (rc=$(rc_of two))" test "$(rc_of two)" -eq 0
check "the body says the client refused to resume" hasf "$two_wt/PR_BODY.md" \
  'the client refused to resume: rc 64'
refute "the body does not claim the session was resumed" hasf "$two_wt/PR_BODY.md" \
  "resumed from the implementer's own session"
check "the sessions table carries the failed status" hasf "$two_wt/PR_BODY.md" \
  '| implementer | `shim-SUBAGENT` | 0 | failed |'
check "the fix wave row carries its rc" hasf "$two_wt/PR_BODY.md" '| fix wave | `unknown` | 64 |'
git -C "$two_wt" log -1 --format=%B > "$scratch/two-msg.txt" 2> /dev/null || true
check "the trailer carries the id the loop actually read" hasf "$scratch/two-msg.txt" \
  'Co-Authored-By: Ouroboros native session shim-SUBAGENT'

phase_end
fi

# ------------------------------------------------------------ 13. the push and the pull request

if want 13; then
phase_start 'the push and the pull request' 9

mk_case 'the shim change that opens a pull request' \
  'A stub gh and a stub git stand in for the remote. Nothing leaves this machine.'
pr_wt=$case_wt
pr_branch=$case_branch
pr_title=$case_title
STUB_GIT_PUSH="$scratch/push-argv.txt"
STUB_GH_CALLS="$scratch/gh-argv.txt"
: > "$STUB_GIT_PUSH"
: > "$STUB_GH_CALLS"
export STUB_GIT_PUSH STUB_GH_CALLS
run_path="$stub_dir:$PATH"
run_improve pr --quick --no-bench
pr_log="$scratch/pr.log"

check "the run finishes (rc=$(rc_of pr))" test "$(rc_of pr)" -eq 0
check "the body was checked before the push" has "$pr_log" \
  '^pr-body rc=0 .*human review section present'
check "the push argv is exactly what it should be" hasf "$STUB_GIT_PUSH" \
  "[-C][$pr_wt][push][-u][origin][$pr_branch]"
check "the push step reports green" hasf "$pr_log" 'push rc=0'
check "gh pr create argv is exactly what it should be" hasf "$STUB_GH_CALLS" \
  "[pr][create][--base][dev][--head][$pr_branch][--title][$pr_title][--body-file][$pr_wt/PR_BODY.md]"
check "the pr step reports green" hasf "$pr_log" 'pr rc=0'

# The same run with the body's own section removed the step before the push. Nothing may
# reach `git push`.
mk_case 'the shim change whose body loses its section' \
  'The stub git strips the section out of PR_BODY.md just before the push check.'
brk_wt=$case_wt
: > "$STUB_GIT_PUSH"
: > "$STUB_GH_CALLS"
run_path="$stub_dir:$PATH"
run_env="STUB_BREAK_BODY=$brk_wt/PR_BODY.md"
run_improve prbreak --quick --no-bench
prbreak_log="$scratch/prbreak.log"

check "a body without the section refuses (rc=$(rc_of prbreak))" test "$(rc_of prbreak)" -ne 0
check "...at the pr step, before the push" hasf "$prbreak_log" \
  "pr rc=1 (the body has no '## Human review required' section)"
refute "...and nothing was pushed" test -s "$STUB_GIT_PUSH"

phase_end
fi

# ------------------------------------------------ 14. the gate holds no model credentials

# A gate runs the operator's commands over a tree a model wrote. The sessions keep the
# keys — they have to authenticate — and the gate steps do not.
if want 14; then
phase_start 'the gate holds no model credentials' 4

mk_case 'the shim change that watches the gate environment' \
  'A stub mix records the environment each gate step was handed.'
env_wt=$case_wt
STUB_MIX_ENV="$scratch/gate-env.txt"
: > "$STUB_MIX_ENV"
export STUB_MIX_ENV
OURO_SHIM_ENV="$scratch/session-env.txt"
: > "$OURO_SHIM_ENV"
export OURO_SHIM_ENV
canary="selftest-canary-$$"
run_path="$stub_dir:$PATH"
run_env="ANTHROPIC_API_KEY=$canary OUROBOROS_NATIVE_MODEL=canary-model-$$"
run_improve gateenv --quick --no-bench --no-pr

check "the gate ran through the stub mix" test -s "$STUB_MIX_ENV"
refute "no model key reached a gate step" hasf "$STUB_MIX_ENV" "$canary"
refute "no scripted-model variable reached a gate step" hasf "$STUB_MIX_ENV" "canary-model-$$"
check "the sessions still had the key" hasf "$OURO_SHIM_ENV" "$canary"

unset STUB_MIX_ENV OURO_SHIM_ENV
phase_end
fi

# ------------------------------------------------------------ 15. a client that never returns

# A client that ignores its own --timeout must not hang the loop. When the deadline passes
# the runtime is told to stop first — an abandoned turn keeps spending — and only then is
# the client killed.
if want 15; then
phase_start 'a client that will not return, and a loop that is interrupted' 8

mk_case 'the shim change that never returns' \
  'The shim sleeps past the deadline. The watchdog has to stop the runtime and kill it.'
slow_wt=$case_wt
slow_rc=0
OUROBOROS_IMPROVE_RUN_DIR="$scratch/run-slow" OURO_SHIM_SLEEP=40 \
  "$improve" "$case_task" --ouro "$shim" --quick --no-bench --no-pr \
  --implementer-timeout 3 --reviewer-timeout 3 \
  > "$scratch/slow.log" 2>&1 || slow_rc=$?
slow_log="$scratch/slow.log"

check "the loop did not hang (rc=$slow_rc)" test "$slow_rc" -ne 0
check "the deadline fired" hasf "$slow_log" 'killed at the deadline'
check "the implementer session reports a non-zero rc" has "$slow_log" '^implementer rc=[1-9]'
check "the runtime was told to stop first" \
  hasf "$scratch/run-slow/data/improve/logs/implementer.ndjson.deadline-stop" 'shim runtime stopped'
check "the loop says the change was empty" hasf "$slow_log" 'changed nothing in'

# A supervisor stops the loop mid-session. The status a shell reports for a signalled
# process is 128+n, and the EXIT trap still has to reach `ouro stop` and leave nothing
# behind. The trap runs when the session subshell returns, not the instant the signal
# lands, which is why the shim's sleep here is seconds rather than minutes.
mk_case 'the shim change that gets interrupted' \
  'The shim takes a moment; a supervisor sends SIGTERM while it is in flight.'
int_log="$scratch/interrupt.log"
env OUROBOROS_IMPROVE_RUN_DIR="$scratch/run-interrupt" OURO_SHIM_SLEEP=8 \
  "$improve" "$case_task" --ouro "$shim" --quick --no-bench --no-pr \
  --implementer-timeout "$impl_to" --reviewer-timeout "$rev_to" \
  > "$int_log" 2>&1 &
int_pid=$!
int_i=0
while [ "$int_i" -lt 60 ]; do
  if grep -q '^==> implementer' "$int_log" 2> /dev/null; then break; fi
  int_i=$((int_i + 1))
  sleep 0.5
done
kill -TERM "$int_pid" 2> /dev/null || true
int_rc=0
wait "$int_pid" || int_rc=$?

check "SIGTERM exits 143 (rc=$int_rc)" test "$int_rc" -eq 143
check "the loop says which signal it was" hasf "$int_log" 'improve: interrupted (TERM)'
check "the EXIT trap still stopped the runtime" hasf "$int_log" 'stop rc=0'

phase_end
fi

# ------------------------------------------------------------ 16. nothing was left running

# Every `with_deadline` call forks a `sleep`; killing the subshell that forked it would
# leave it counting down to a `kill -9` on whatever holds that pid an hour later. The
# timeouts this run used are unique to it, so what this counts is only its own.
if want 16; then
phase_start 'no watchdog outlived the run' 2

sleepers_named() {
  if command -v pgrep > /dev/null 2>&1; then
    pgrep -f "sleep $1" > /dev/null 2>&1 && return 0
    return 1
  fi
  ps -Ao command 2> /dev/null | grep -q "sleep $1"
}

refute "no implementer watchdog is still sleeping ($impl_watchdog)" sleepers_named "$impl_watchdog"
refute "no reviewer watchdog is still sleeping ($rev_watchdog)" sleepers_named "$rev_watchdog"

phase_end
fi

# ------------------------------------------------------------------ verdict

printf '\n'
printf 'improve-selftest: %s check(s)\n' "$checks"
if [ "$failures" -eq 0 ]; then
  printf 'improve-selftest: green\n'
  exit 0
fi

printf 'improve-selftest: %s check(s) failed (last phase %s)\n' "$failures" "$phase" >&2
printf 'improve.sh log: %s\n' "$scratch/run.log" >&2
exit 1
