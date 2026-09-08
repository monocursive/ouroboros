#!/bin/sh
# A TEST SHIM. This is not a client and it never talks to a runtime.
#
# `bench/self/improve-selftest.sh` passes it to `improve.sh --ouro` so the outer loop can
# be walked end to end with no model, no key, no network and no spend: it answers the four
# invocations improve.sh makes of `ouro` — `--dev daemon`, `stop`, `run`, `run --resume` —
# with the same shapes the real client produces (`tui/src/run.rs`, `Report::to_json`), and
# it edits the workspace the way a session would.
#
# It fails loudly on any flag it does not know, so that a flag added to improve.sh and not
# taught here shows up as a red selftest rather than as a silently skipped argument.
#
# Nothing outside the selftest should run this, and nothing in `improve.sh` knows it
# exists.

set -eu

marker_text='improve-selftest: shim marker'
grants=lib/ouroboros/control/grants.ex
shim_test=test/self_improve_shim_test.exs

# Where the shim remembers which workspace a session it started belongs to, so that a
# later `--resume` can find it. The selftest points this at its own scratch directory.
state_dir=${OURO_SHIM_STATE:-${TMPDIR:-/tmp}}

die() {
  printf 'shim-ouro: %s\n' "$*" >&2
  exit 64
}

# One `{"type":"result", …}` line, the shape `Report::to_json` writes. Status `completed`
# is exit 0 (`Status::code`), which is the only status this shim produces.
emit_result() {
  _session=$1
  shift
  printf '{"type":"agent_message","text":"shim %s"}\n' "$_session"
  printf '{"type":"result","session_id":"%s","turn_id":"%s-turn","status":"completed",' \
    "$_session" "$_session"
  printf '"provider":"native","usage":{},"files_changed":['
  _sep=''
  for _f in "$@"; do
    printf '%s"%s"' "$_sep" "$_f"
    _sep=','
  done
  printf '],"approvals":{"requested":0,"answered":0},"duration_ms":1}\n'
}

# Insert one comment line into a protected-namespace file, so improve.sh's
# protected-namespace scan and the "Human review required" section of the body have
# something real to find. Written through a temp file outside the workspace: a stray
# `.tmp` left inside a git worktree would be swept into the commit by `git add -A`.
insert_marker() {
  _file=$1
  _after=$2
  _n=$3
  [ -f "$_file" ] || die "$_file is not in the workspace"
  _tmp=$(mktemp "${TMPDIR:-/tmp}/shim-ouro.XXXXXX")
  awk -v after="$_after" -v line="  # $marker_text $_n" \
    '{ print } NR == after { print line }' "$_file" > "$_tmp"
  cat "$_tmp" > "$_file"
  rm -f "$_tmp"
}

write_shim_test() {
  # OURO_SHIM_BREAK is how the selftest sees a red gate: a session that leaves the suite
  # failing must not reach a commit, and a loop nobody ever watched refuse is a loop
  # nobody has evidence about. The failure is an assertion, not a compile error, so the
  # format and compile steps stay green and only the test step goes red.
  if [ -n "${OURO_SHIM_BREAK:-}" ]; then
    cat > "$shim_test" << 'ELIXIR'
defmodule Ouroboros.SelfImproveShimTest do
  @moduledoc false
  use ExUnit.Case, async: true

  test "the improve selftest shim left a test that fails on purpose" do
    assert Ouroboros.Control.Grants.__info__(:module) == :this_is_not_the_module
  end
end
ELIXIR
    return 0
  fi
  cat > "$shim_test" << 'ELIXIR'
defmodule Ouroboros.SelfImproveShimTest do
  @moduledoc false
  use ExUnit.Case, async: true

  test "the improve selftest shim left a test that passes" do
    assert Ouroboros.Control.Grants.__info__(:module) == Ouroboros.Control.Grants
  end
end
ELIXIR
}

# OURO_SHIM_COMMIT is a session that commits its own work, which the implementer brief
# tells it not to do. Both the implementer turn and the fix wave do it, so the tree is
# clean by the time the loop reaches its commit step and the loop has to refuse rather
# than make a commit carrying neither the task title nor the session trailer.
commit_own_work() {
  [ -n "${OURO_SHIM_COMMIT:-}" ] || return 0
  git add -A > /dev/null 2>&1 || true
  git -c user.name='Shim' -c user.email='shim@example.invalid' \
    commit -q -m 'a commit the session made for itself' > /dev/null 2>&1 || true
  return 0
}

write_review() {
  cat > REVIEW.md << 'REVIEW'
# Review

## Threat model

A change under `lib/ouroboros/control/` can widen what an agent is allowed to do without
any test noticing, because the enforcement point and the test that covers it are in
different files. The question is whether this diff moves an authority boundary.

## Findings

1. PLAUSIBLE — `lib/ouroboros/control/grants.ex:2`. The change is a comment. It moves no
   boundary and reaches no call site, so there is nothing to exploit; it is recorded here
   only so the mutation table below has a row and the count is not zero.

## Mutation table

| enforcement point | mutation | result |
|---|---|---|
| `Grants` module attributes | delete the inserted comment | no test goes red (a comment is not an enforcement point) |

## Verdict

No finding is PROVED. The diff is inert. This review was written by a test shim, not by a
model.
REVIEW
}

# ------------------------------------------------------------------------- argv

case "${1:-}" in
  --dev)
    shift
    [ "${1:-}" = daemon ] || die "unsupported --dev subcommand: ${1:-<none>}"
    printf 'shim runtime ready on port 0\n'
    exit 0
    ;;
  stop)
    printf 'shim runtime stopped\n'
    exit 0
    ;;
  run)
    shift
    ;;
  *)
    die "unsupported argv: $*"
    ;;
esac

prompt=''
workspace=''
resume=''

while [ $# -gt 0 ]; do
  case $1 in
    --workspace)
      workspace=$2
      shift 2
      ;;
    --resume)
      resume=$2
      shift 2
      ;;
    --provider | --model | --approval-mode | --sandbox-mode | --machine | --timeout)
      shift 2
      ;;
    --approve-all | --stream-json | --json | --plan | --verbose | -v)
      shift
      ;;
    -*)
      die "unknown flag $1 — teach the shim about it or improve.sh is passing something the real client would reject"
      ;;
    *)
      [ -n "$prompt" ] || prompt=$1
      shift
      ;;
  esac
done

[ -n "$prompt" ] || die "no prompt"

if [ -n "$resume" ]; then
  # The fix wave. `--resume` conflicts with `--workspace` in the real client, because the
  # resumed session already has one — so the shim has to remember. It writes the workspace
  # beside its state when the session starts and reads it back here. This is the shim's
  # own bookkeeping: `improve.sh` neither writes nor knows about it, which is the point.
  case $prompt in
    *"OUROBOROS-IMPROVE-ROLE: fix-wave"*) ;;
    *) die "--resume without the fix-wave role marker" ;;
  esac
  _state="$state_dir/session-$resume.workspace"
  [ -f "$_state" ] || die "no session $resume was started by this shim ($_state is missing)"
  workspace=$(cat "$_state")
  cd "$workspace" || die "no such workspace: $workspace"
  insert_marker "$grants" 2 2
  commit_own_work
  emit_result "$resume" "$grants"
  exit 0
fi

[ -n "$workspace" ] || die "run without --workspace"
cd "$workspace" || die "no such workspace: $workspace"

case $prompt in
  *"OUROBOROS-IMPROVE-ROLE: reviewer"*)
    write_review
    emit_result shim-review REVIEW.md
    ;;
  *"OUROBOROS-IMPROVE-ROLE: implementer"*)
    # OURO_SHIM_NOOP is a session that reports `completed` and changed nothing. The loop
    # has to refuse that rather than open an empty pull request.
    if [ -n "${OURO_SHIM_NOOP:-}" ]; then
      mkdir -p "$state_dir"
      printf '%s\n' "$workspace" > "$state_dir/session-shim-impl.workspace"
      emit_result shim-impl
      exit 0
    fi
    insert_marker "$grants" 1 1
    write_shim_test
    commit_own_work
    mkdir -p "$state_dir"
    printf '%s\n' "$workspace" > "$state_dir/session-shim-impl.workspace"
    emit_result shim-impl "$grants" "$shim_test"
    ;;
  *)
    die "the prompt carries no OUROBOROS-IMPROVE-ROLE marker"
    ;;
esac

exit 0
