#!/bin/sh
# Ouroboros works on Ouroboros: implement, review, fix, gate, pull request.
#
#     bench/self/improve.sh TASK.md [options]
#
# One task file in, one pull request out. The script owns the mechanism — a worktree, a
# runtime, the gates, the body, the push — and none of the judgement: an Ouroboros native
# session writes the change, a second one reviews it adversarially, the first one fixes
# what the review found, and gates a model cannot pass for itself decide whether any of
# it reaches a branch. A human merges. Nothing here merges itself.
#
# Options:
#   --model SPEC              the model every session runs on (default: the runtime's)
#   --spend USD               corpus budget; without it the corpus does not run
#   --no-bench                never run the corpus, whatever the diff touches
#   --no-pr                   commit locally and write the body; push nothing
#   --quick                   gate is format + compile + the touched suites, no more
#   --dry-run                 print every command with its paths resolved and run none
#   --ouro PATH               the client binary (default: OURO_BIN, then the newest build)
#   --implementer-timeout S   seconds for the implementer and the fix wave (default 3600)
#   --reviewer-timeout S      seconds for the reviewer (default 1800)
#
# Environment:
#   OURO_BIN                     the client, when --ouro is absent
#   OUROBOROS_IMPROVE_WORKTREES  where the worktree is made (default .claude/worktrees)
#   OUROBOROS_IMPROVE_RUN_DIR    daemon data dir and logs (default a fresh mktemp -d)
#   BENCH_SELF_BASELINE          an earlier bench/self result.json, for the corpus delta
#
# Every step prints `==> <step>`, the command it ran, and `<step> rc=<n>`. A step with no
# rc line did not run. Nothing is piped into anything before its exit status is read.
#
# See bench/self/IMPROVE.md for what this proves and what it does not.

set -eu

# ------------------------------------------------------------------------- constants

# The three namespaces whose modules make the runtime's guarantees enforceable — the
# loader's authorizer, the journal writer, the thing that decides what gets patched
# (docs/ARCHITECTURE.md, "Policy protects the modules that make these guarantees
# enforceable"). A hunk in any of them is listed under "Human review required" in the
# body whatever the reviewer concluded, because the reviewer is the same kind of thing
# as the implementer and a model's verdict on its own change is not a gate.
protected_paths='lib/ouroboros/control lib/ouroboros/upgrade lib/ouroboros/storage'

# The one path that makes the corpus worth its spend: a change to the native provider
# changes how every session behaves, so the number before and after means something.
corpus_trigger='lib/ouroboros/provider/native/'

review_file=REVIEW.md
body_file=PR_BODY.md
review_body_lines=200
diff_prompt_lines=1200
daemon_boot_secs=300
stop_secs=120
# Six, so a model that fences its own review in three or four cannot close ours early.
fence='``````'
fence_re='^`\{6,\}$'
role_marker='OUROBOROS-IMPROVE-ROLE'
body_required_heading='## Human review required'

# ------------------------------------------------------------------------- arguments

task_arg=''
model=''
spend=''
no_bench=0
no_pr=0
quick=0
dry_run=0
ouro_opt=''
implementer_timeout=3600
reviewer_timeout=1800

usage() {
  cat << 'USAGE'
bench/self/improve.sh TASK.md [options]

  --model SPEC              the model every session runs on (default: the runtime's)
  --spend USD               corpus budget; without it the corpus does not run
  --no-bench                never run the corpus, whatever the diff touches
  --no-pr                   commit locally and write the body; push nothing
  --quick                   gate is format + compile + the touched suites, no more
  --dry-run                 print every command with its paths resolved and run none
  --ouro PATH               the client binary (default: OURO_BIN, then the newest build)
  --implementer-timeout S   seconds for the implementer and the fix wave (default 3600)
  --reviewer-timeout S      seconds for the reviewer (default 1800)
  -h, --help                this

Environment: OURO_BIN, OUROBOROS_IMPROVE_WORKTREES, OUROBOROS_IMPROVE_RUN_DIR,
BENCH_SELF_BASELINE. See bench/self/IMPROVE.md.
USAGE
}

usage_die() {
  printf 'improve: %s\n\n' "$*" >&2
  usage >&2
  exit 64
}

need_value() {
  [ "$2" -ge 2 ] || usage_die "$1 needs a value"
}

is_number() {
  case $1 in
    '' | *[!0-9.]* | *.*.*) return 1 ;;
    *) return 0 ;;
  esac
}

while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      usage
      exit 0
      ;;
    --model)
      need_value "$1" $#
      model=$2
      shift 2
      ;;
    --spend)
      need_value "$1" $#
      spend=$2
      is_number "$spend" || usage_die "--spend takes a number of US dollars, not '$spend'"
      shift 2
      ;;
    --no-bench)
      no_bench=1
      shift
      ;;
    --no-pr)
      no_pr=1
      shift
      ;;
    --quick)
      quick=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --ouro)
      need_value "$1" $#
      ouro_opt=$2
      shift 2
      ;;
    --implementer-timeout)
      need_value "$1" $#
      implementer_timeout=$2
      is_number "$implementer_timeout" || usage_die "--implementer-timeout takes seconds"
      shift 2
      ;;
    --reviewer-timeout)
      need_value "$1" $#
      reviewer_timeout=$2
      is_number "$reviewer_timeout" || usage_die "--reviewer-timeout takes seconds"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      usage_die "unknown option $1"
      ;;
    *)
      [ -z "$task_arg" ] || usage_die "one task file, not two ($task_arg and $1)"
      task_arg=$1
      shift
      ;;
  esac
done

[ -n "$task_arg" ] || usage_die "a task file is the one required argument"

# ------------------------------------------------------------------------- helpers

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'improve: %s\n' "$*" >&2
  exit 1
}

# Quote one argument the way a reader could paste it back. Only for display: nothing is
# ever re-parsed out of this.
shquote() {
  case $1 in
    '' | *[!A-Za-z0-9_/.:=@%+,^-]*)
      printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
      ;;
    *) printf '%s' "$1" ;;
  esac
}

print_cmd() {
  printf '    $'
  for _arg in "$@"; do
    printf ' %s' "$(shquote "$_arg")"
  done
  printf '\n'
  [ "$dry_run" = 1 ] && printf '    (dry run: not executed)\n'
  return 0
}

abs() {
  _dir=$(dirname -- "$1")
  _base=$(basename -- "$1")
  _dir=$(CDPATH= cd -- "$_dir" 2> /dev/null && pwd -P) || die "no such directory: $(dirname -- "$1")"
  printf '%s/%s\n' "$_dir" "$_base"
}

# `<step> rc=<n>`, the line a reader and improve-selftest.sh both grep for. Every step
# prints one, the skipped ones included with the reason: a step that leaves no line
# behind is a step nobody can tell ran.
note() {
  if [ -n "${3:-}" ]; then
    printf '%s rc=%s (%s)\n' "$1" "$2" "$3"
  else
    printf '%s rc=%s\n' "$1" "$2"
  fi
  [ "$dry_run" = 1 ] && return 0
  printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$steps_file"
  return 0
}

# macOS ships no timeout(1), and a client that ignored its own --timeout still must not
# hang the loop: the command in the background, a sleeper that kills it, whichever
# finishes first. Only the ouro invocations get one — the gates are the operator's own
# commands and a hanging `make test` is a thing they should see hanging.
with_deadline() {
  _secs=$1
  _out=$2
  _err=$3
  shift 3
  "$@" > "$_out" 2> "$_err" &
  _pid=$!
  (
    sleep "$_secs"
    kill -9 "$_pid"
  ) > /dev/null 2>&1 &
  _watch=$!
  _rc=0
  wait "$_pid" || _rc=$?
  kill "$_watch" > /dev/null 2>&1 || true
  wait "$_watch" > /dev/null 2>&1 || true
  return "$_rc"
}

tail_log() {
  [ -f "$1" ] || return 0
  printf '    log: %s\n' "$1"
  # `mix test` writes NUL bytes; a terminal that meets one stops rendering the rest.
  tail -n 20 "$1" | tr -d '\000' | sed 's/^/    | /'
  return 0
}

# The first occurrence of a scalar key in a compact JSON document. No jq and no python3:
# this has to run wherever `ouro` and `git` do, and bench/local reads its own JSON the
# same way. A value carrying an escaped quote would defeat it; session ids, statuses,
# rates and totals do not carry one.
json_scalar() {
  [ -f "$1" ] || return 0
  awk -v key="$2" '
    { s = s $0 }
    END {
      pat = "\"" key "\"[ \t]*:[ \t]*"
      if (!match(s, pat)) exit 0
      rest = substr(s, RSTART + RLENGTH)
      if (substr(rest, 1, 1) == "\"") {
        rest = substr(rest, 2)
        q = index(rest, "\"")
        if (q > 0) print substr(rest, 1, q - 1)
      } else {
        n = match(rest, /[^-+.0-9eE]/)
        print (n > 0 ? substr(rest, 1, n - 1) : rest)
      }
    }
  ' "$1"
}

# The result object is the last `{"type":"result", …}` line of --stream-json, not the
# last line: a client is free to say something after it and one day will.
result_object() {
  sed -n '/"type"[ 	]*:[ 	]*"result"/p' "$1" | tail -n 1
}

slugify() {
  printf '%s' "$1" |
    tr 'A-Z' 'a-z' |
    sed -e 's/[^a-z0-9]\{1,\}/-/g' -e 's/^-\{1,\}//' -e 's/-\{1,\}$//' |
    cut -c 1-48 |
    sed -e 's/-\{1,\}$//'
}

# The first line of the task with a Markdown heading marker taken off, bounded to the 72
# columns a subject line gets — at the last word boundary inside them, not mid-word. The
# whole task is in the commit body either way.
task_title() {
  _line=$(sed -n '/[^[:space:]]/{s/^[[:space:]]*//;s/^#\{1,6\}[[:space:]]*//;s/[[:space:]]*$//;p;q;}' "$1")
  if [ "${#_line}" -le 72 ]; then
    printf '%s\n' "$_line"
    return 0
  fi
  _cut=$(printf '%s' "$_line" | cut -c 1-72)
  case $_cut in
    *' '*) printf '%s\n' "${_cut% *}" ;;
    *) printf '%s\n' "$_cut" ;;
  esac
}

# ------------------------------------------------------------------------- resolution

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo=$(CDPATH= cd -- "$here/../.." && pwd -P)
briefs="$repo/docs/self/briefs"

task_file=$(abs "$task_arg")
[ -f "$task_file" ] || die "$task_file is not a file"

for _brief in implementer reviewer fix-wave; do
  [ -f "$briefs/$_brief.md" ] || die "$briefs/$_brief.md is missing"
done

command -v git > /dev/null 2>&1 || die "git is not on PATH"
command -v awk > /dev/null 2>&1 || die "awk is not on PATH"
if [ "$dry_run" != 1 ]; then
  command -v mix > /dev/null 2>&1 || die "mix is not on PATH; the gates are mix commands"
fi

git -C "$repo" rev-parse --git-dir > /dev/null 2>&1 || die "$repo is not a git checkout"

# The client this checkout builds, not one on PATH, and between the release and debug
# builds the NEWEST — a stale release build once graded every task as "unrecognized
# subcommand". bench/local/run.exs makes the same choice for the same reason.
resolve_ouro() {
  if [ -n "$ouro_opt" ]; then
    [ -x "$ouro_opt" ] || die "--ouro $ouro_opt is not an executable file"
    abs "$ouro_opt"
    return 0
  fi
  if [ -n "${OURO_BIN:-}" ]; then
    [ -x "$OURO_BIN" ] || die "OURO_BIN=$OURO_BIN is not an executable file"
    abs "$OURO_BIN"
    return 0
  fi
  _newest=$(ls -t "$repo/tui/target/release/ouro" "$repo/tui/target/debug/ouro" 2> /dev/null | head -n 1)
  if [ -n "$_newest" ] && [ -x "$_newest" ]; then
    printf '%s\n' "$_newest"
    return 0
  fi
  # A dry run is asked what it *would* do, and answering "nothing, build a client first"
  # is not that. It names the path it would have taken and says the path is not there.
  if [ "$dry_run" = 1 ]; then
    printf '%s\n' "$repo/tui/target/release/ouro"
    return 0
  fi
  die "no ouro binary: build one with 'cd tui && cargo build', or pass --ouro PATH or OURO_BIN"
}

ouro=$(resolve_ouro)
if [ "$dry_run" = 1 ] && [ ! -x "$ouro" ]; then
  say "improve: note — $ouro does not exist yet; a real run needs 'cd tui && cargo build'"
fi

base_sha=$(git -C "$repo" rev-parse dev 2> /dev/null) ||
  die "this checkout has no 'dev' branch; the outer loop branches from dev (CONTRIBUTING.md)"

title=$(task_title "$task_file")
[ -n "$title" ] || die "$task_file has no first line to take a title from"
slug=$(slugify "$title")
[ -n "$slug" ] || die "the task title '$title' slugifies to nothing"

worktrees_root=${OUROBOROS_IMPROVE_WORKTREES:-$repo/.claude/worktrees}
wt="$worktrees_root/improve-$slug"
branch="self/improve-$slug"

tmp_root=${TMPDIR:-/tmp}
case $tmp_root in
  */) tmp_root=${tmp_root%/} ;;
esac

run_dir=${OUROBOROS_IMPROVE_RUN_DIR:-}
if [ "$dry_run" = 1 ]; then
  # Named so the printed commands carry a real path, and not created: --dry-run makes no
  # directory, no worktree, no branch and no runtime.
  [ -n "$run_dir" ] || run_dir="$tmp_root/ouroboros-improve.DRY-RUN"
else
  if [ -n "$run_dir" ]; then
    mkdir -p "$run_dir"
  else
    run_dir=$(mktemp -d "$tmp_root/ouroboros-improve.XXXXXX")
  fi
  chmod 700 "$run_dir"
  run_dir=$(CDPATH= cd -- "$run_dir" && pwd -P)
fi

logs="$run_dir/logs"
data_dir="$run_dir/data"
bench_out="$run_dir/bench"
steps_file="$run_dir/steps.tsv"

daemon_started=0
impl_session=''
impl_status=''
review_session=''
review_status=''
fix_session=''
fix_status=''
fix_note='not run'
gate1_rc=0
gate2_rc=0
corpus_note='not run: the corpus step did not run'
commit_sha=''
protected_file="$run_dir/protected.txt"

# ------------------------------------------------------------------------- teardown

cleanup() {
  _exit=$?
  trap - EXIT
  if [ "$daemon_started" = 1 ]; then
    printf '\n==> stop\n'
    print_cmd env OUROBOROS_DATA_DIR="$data_dir" "$ouro" stop
    _stop_rc=0
    (
      export OUROBOROS_DATA_DIR="$data_dir"
      cd "$repo" && with_deadline "$stop_secs" "$logs/stop.log" "$logs/stop.stderr" "$ouro" stop
    ) || _stop_rc=$?
    printf 'stop rc=%s\n' "$_stop_rc"
  fi
  if [ "$dry_run" != 1 ]; then
    printf '\nworktree  %s\n' "$wt"
    printf 'branch    %s\n' "$branch"
    printf 'run dir   %s\n' "$run_dir"
    printf '\nNeither is removed: the worktree is the change and the run dir is the evidence.\n'
    printf 'Drop them with: git -C %s worktree remove --force %s && git -C %s branch -D %s && rm -rf %s\n' \
      "$(shquote "$repo")" "$(shquote "$wt")" "$(shquote "$repo")" "$(shquote "$branch")" "$(shquote "$run_dir")"
  fi
  exit "$_exit"
}

on_signal() {
  printf '\nimprove: interrupted (%s)\n' "$1" >&2
  exit 130
}

trap cleanup EXIT
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP' HUP

# ------------------------------------------------------------------------- the steps

say "improve: $title"
say "  task      $task_file"
say "  repo      $repo"
say "  base      dev at $base_sha"
say "  worktree  $wt"
say "  branch    $branch"
say "  client    $ouro"
say "  run dir   $run_dir"
[ -n "$model" ] && say "  model     $model"
[ "$quick" = 1 ] && say "  gate      quick (no 'make test', no dialyzer)"
[ "$dry_run" = 1 ] && say "  dry run   every command is printed; none is executed"

if [ "$dry_run" != 1 ]; then
  mkdir -p "$logs" "$data_dir"
  chmod 700 "$data_dir"
  : > "$steps_file"
fi

# --- 1. the worktree ------------------------------------------------------------------

step_worktree() {
  printf '\n==> worktree\n'
  _rc=0
  if [ "$dry_run" != 1 ] && [ -e "$wt" ]; then
    die "$wt already exists; remove it or give the task a different title"
  fi
  print_cmd mkdir -p "$worktrees_root"
  print_cmd git -C "$repo" worktree add -b "$branch" "$wt" "$base_sha"
  if [ "$dry_run" != 1 ]; then
    mkdir -p "$worktrees_root"
    git -C "$repo" worktree add -b "$branch" "$wt" "$base_sha" > "$logs/worktree.log" 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
      tail_log "$logs/worktree.log"
      note worktree "$_rc"
      die "could not make the worktree"
    fi
  fi

  # deps/ and _build/ are the difference between a gate that runs in seconds and one that
  # rebuilds the world. `cp -Rc` clones on APFS and is free; everywhere else it is a copy.
  for _dir in deps _build; do
    if [ -d "$repo/$_dir" ]; then
      print_cmd cp -Rc "$repo/$_dir" "$wt/$_dir"
      if [ "$dry_run" != 1 ]; then
        cp -Rc "$repo/$_dir" "$wt/$_dir" 2> /dev/null ||
          cp -R "$repo/$_dir" "$wt/$_dir" ||
          die "could not clone $_dir into the worktree"
      fi
    fi
  done

  # The sealed helpers. A worktree finds them at priv/, never by walking a cwd: a path
  # derived from a cwd that reaches a Cargo.toml is code execution.
  for _dir in priv/wasm priv/sandbox; do
    if [ -d "$repo/$_dir" ]; then
      print_cmd cp -R "$repo/$_dir" "$wt/$_dir"
      if [ "$dry_run" != 1 ]; then
        mkdir -p "$(dirname "$wt/$_dir")"
        cp -R "$repo/$_dir" "$wt/$_dir" || die "could not copy $_dir into the worktree"
      fi
    fi
  done

  say "worktree $wt from dev at $base_sha on branch $branch"
  note worktree 0
}

# --- 2. the runtime -------------------------------------------------------------------

step_daemon() {
  printf '\n==> daemon\n'
  print_cmd env OUROBOROS_DATA_DIR="$data_dir" "$ouro" --dev daemon
  if [ "$dry_run" = 1 ]; then
    note daemon 0 'dry run'
    return 0
  fi
  _rc=0
  (
    # Only the data dir is scratch. XDG_CONFIG_HOME and every key stay: the model has to
    # authenticate, and an unattended run that silently used no key would be a run that
    # proved nothing. bench/local drops the keys because its model is scripted; this one
    # is not.
    export OUROBOROS_DATA_DIR="$data_dir"
    cd "$repo" &&
      with_deadline "$daemon_boot_secs" "$logs/daemon.log" "$logs/daemon.stderr" \
        "$ouro" --dev daemon
  ) || _rc=$?
  if [ "$_rc" -ne 0 ]; then
    tail_log "$logs/daemon.log"
    tail_log "$logs/daemon.stderr"
    note daemon "$_rc"
    die "the runtime did not come up"
  fi
  daemon_started=1
  _port=$(sed -n 's/.*port[ ]\{1,\}\([0-9]\{1,\}\).*/\1/p' "$logs/daemon.log" | tail -n 1)
  say "daemon ready on port ${_port:-?} with OUROBOROS_DATA_DIR=$data_dir"
  note daemon 0
}

# --- sessions -------------------------------------------------------------------------

# One `ouro run`. The exit status is read before anything is piped anywhere; the session
# id and the status come out of the result object in the stdout log, which is why stdout
# and stderr go to separate files.
ouro_session() {
  _name=$1
  _timeout=$2
  _prompt_file=$3
  shift 3
  _out="$logs/$_name.ndjson"
  _err="$logs/$_name.stderr"
  printf '\n==> %s\n' "$_name"
  print_cmd "$ouro" run "<contents of $_prompt_file>" "$@" \
    --approve-all --stream-json --timeout "$_timeout"
  if [ "$dry_run" = 1 ]; then
    session_id="DRY-$_name"
    session_status=completed
    note "$_name" 0 'dry run'
    return 0
  fi
  _rc=0
  (
    export OUROBOROS_DATA_DIR="$data_dir"
    cd "$repo" &&
      with_deadline "$((_timeout + 120))" "$_out" "$_err" \
        "$ouro" run "$(cat "$_prompt_file")" "$@" \
        --approve-all --stream-json --timeout "$_timeout"
  ) || _rc=$?
  result_object "$_out" > "$logs/$_name.result.json"
  session_id=$(json_scalar "$logs/$_name.result.json" session_id)
  session_status=$(json_scalar "$logs/$_name.result.json" status)
  [ -n "$session_status" ] || session_status='no-result'
  [ -n "$session_id" ] || session_id='unknown'
  say "session $session_id status $session_status"
  if [ "$_rc" -ne 0 ]; then
    tail_log "$_err"
  fi
  note "$_name" "$_rc" "session $session_id, status $session_status"
  return 0
}

write_prompt() {
  _path=$1
  _role=$2
  _brief=$3
  {
    printf '%s: %s\n\n' "$role_marker" "$_role"
    cat "$briefs/$_brief.md"
    printf '\n'
  } > "$_path"
}

# --- diffs ----------------------------------------------------------------------------

# `git add -N` is what makes a file the session created show up in `git diff` at all:
# without it a whole new module is invisible to every gate and to the review. REVIEW.md
# and PR_BODY.md are this script's own paperwork and are kept out of both the diff and
# the commit — a model-written file in the history is not the change.
refresh_index() {
  git -C "$wt" add -A -N -- . ":(exclude)$review_file" ":(exclude)$body_file" > /dev/null 2>&1 || true
}

touched_paths() {
  refresh_index
  git -C "$wt" diff --name-only "$base_sha" -- . \
    ":(exclude)$review_file" ":(exclude)$body_file"
}

# Deletions are dropped here and only here: `mix test` on a path the session deleted is a
# crash, not a gate. They are still a change, so `touched_paths` keeps them.
touched_test_files() {
  refresh_index
  git -C "$wt" diff --name-only --diff-filter=d "$base_sha" -- . \
    ":(exclude)$review_file" ":(exclude)$body_file" |
    sed -n '\#^test/.*_test\.exs$#p'
}

# --- gates ----------------------------------------------------------------------------

gate_step() {
  _name=$1
  shift
  _log="$logs/$_name.log"
  printf '\n==> %s\n' "$_name"
  print_cmd "$@"
  if [ "$dry_run" = 1 ]; then
    note "$_name" 0 'dry run'
    return 0
  fi
  _rc=0
  (cd "$wt" && "$@") > "$_log" 2>&1 || _rc=$?
  # This repository's ExUnit formatter prints `Result: N passed` / `Failed: N tests`, and
  # the surrounding output carries NUL bytes; `-a` is what makes grep read it at all.
  _result=$(grep -a -e 'Result:' -e 'Failed:' "$_log" 2> /dev/null | tail -n 2 | tr '\n' ' ' | sed 's/ *$//' || true)
  if [ "$_rc" -ne 0 ]; then
    gate_rc=1
    tail_log "$_log"
  fi
  note "$_name" "$_rc" "$_result"
  return 0
}

run_gate() {
  _gate=$1
  gate_rc=0
  gate_step "$_gate.format" mix format --check-formatted
  gate_step "$_gate.compile" mix compile --warnings-as-errors

  # `mix test` with no files is the whole suite, which is minutes and is not this gate.
  # Nothing to run is a fact the body reports, not a pass this step invents.
  _tests=''
  [ "$dry_run" = 1 ] || _tests=$(touched_test_files)
  if [ -z "$_tests" ]; then
    note "$_gate.test" 0 'skipped: the diff touches no test/**/*_test.exs'
  else
    set --
    while IFS= read -r _t; do
      if [ -n "$_t" ]; then set -- "$@" "$_t"; fi
    done << TESTS
$_tests
TESTS
    gate_step "$_gate.test" mix test "$@"
  fi

  if [ "$quick" = 1 ]; then
    note "$_gate.make-test" 0 'skipped: --quick'
    note "$_gate.dialyzer" 0 'skipped: --quick'
  else
    gate_step "$_gate.make-test" make test
    gate_step "$_gate.dialyzer" mix dialyzer
  fi

  printf '\n'
  note "$_gate" "$gate_rc"
}

# --- 8. the corpus --------------------------------------------------------------------

step_corpus() {
  printf '\n==> corpus\n'
  _runner="$wt/bench/self/run.sh"
  if [ "$no_bench" = 1 ]; then
    corpus_note='not run: --no-bench'
  elif [ -z "$spend" ]; then
    corpus_note='not run: no --spend, and the corpus costs money'
  elif [ "$dry_run" = 1 ]; then
    corpus_note='not run: --dry-run'
    print_cmd "$_runner" --spend "$spend" --out "$bench_out"
  elif [ ! -x "$_runner" ]; then
    corpus_note="not run: $_runner does not exist in the worktree"
  elif ! touched_paths | grep -q "^$corpus_trigger"; then
    corpus_note="not run: the diff touches nothing under $corpus_trigger"
  else
    set -- --spend "$spend" --out "$bench_out"
    [ -n "$model" ] && set -- "$@" --model "$model"
    print_cmd "$_runner" "$@"
    _rc=0
    (cd "$wt" && "$_runner" "$@") > "$logs/corpus.log" 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
      tail_log "$logs/corpus.log"
      corpus_note="ran and exited $_rc; see $logs/corpus.log"
    else
      _rate=$(json_scalar "$bench_out/result.json" pass_rate)
      _spent=$(json_scalar "$bench_out/result.json" spent)
      corpus_note="after: pass_rate ${_rate:-?}, spent \$${_spent:-?}"
      _base_json=${BENCH_SELF_BASELINE:-}
      if [ -n "$_base_json" ] && [ -f "$_base_json" ]; then
        _brate=$(json_scalar "$_base_json" pass_rate)
        _bspent=$(json_scalar "$_base_json" spent)
        corpus_note="before: pass_rate ${_brate:-?}, spent \$${_bspent:-?} ($_base_json); $corpus_note"
      else
        corpus_note="before: not run (set BENCH_SELF_BASELINE to an earlier result.json); $corpus_note"
      fi
    fi
    note corpus "$_rc" "$corpus_note"
    return 0
  fi
  note corpus 0 "$corpus_note"
}

# --- 9. the protected-namespace scan --------------------------------------------------

# File then hunk headers, one scan, written once and read by both the console and the
# body so the two cannot disagree. `+++ /dev/null` is a deletion, whose path is on the
# `---` line; taking the path from there instead of from `diff --git` also survives a
# name with a space in it.
step_protected() {
  printf '\n==> protected-scan\n'
  set -- diff "$base_sha..HEAD" --
  for _p in $protected_paths; do set -- "$@" "$_p"; done
  print_cmd git -C "$wt" "$@"
  if [ "$dry_run" = 1 ]; then
    note protected-scan 0 'dry run'
    return 0
  fi
  git -C "$wt" "$@" | awk '
    /^--- / { old = substr($0, 5); next }
    /^\+\+\+ / {
      path = substr($0, 5)
      if (path == "/dev/null") { path = old; sub(/^a\//, "", path) }
      else { sub(/^b\//, "", path) }
      print path
      next
    }
    /^@@ / { print "  " $0 }
  ' > "$protected_file"
  _hunks=$(grep -c '^  @@' "$protected_file" 2> /dev/null || true)
  [ -n "$_hunks" ] || _hunks=0
  if [ "$_hunks" -gt 0 ]; then
    sed 's/^/    /' "$protected_file"
  else
    say "    none"
  fi
  note protected-scan 0 "$_hunks hunk(s) under $protected_paths"
}

# --- 10. the commit -------------------------------------------------------------------

step_commit() {
  printf '\n==> commit\n'
  _msg="$logs/commit-msg.txt"
  print_cmd git -C "$wt" add -A -- . ":(exclude)$review_file" ":(exclude)$body_file"
  print_cmd git -C "$wt" commit -F "$_msg"
  if [ "$dry_run" = 1 ]; then
    note commit 0 'dry run'
    return 0
  fi
  {
    printf '%s\n\n' "$title"
    cat "$task_file"
    printf '\nCo-Authored-By: Ouroboros native session %s\n' "$impl_session"
  } > "$_msg"
  git -C "$wt" add -A -- . ":(exclude)$review_file" ":(exclude)$body_file"
  if git -C "$wt" diff --cached --quiet; then
    # Two different nothings. A session that committed its own work — which the
    # implementer brief tells it not to do — leaves a branch whose commits carry neither
    # the task title nor the session trailer, and the loop will not paper over that with
    # an empty commit or an amend. Both end the run; only one of them means the sessions
    # did nothing.
    if [ "$(git -C "$wt" rev-list --count "$base_sha..HEAD")" -gt 0 ]; then
      note commit 1 'the session made its own commit(s); nothing left for the loop to commit'
      say "the branch is $branch in $wt; commit or amend it by hand, or re-run the task"
      die "the session committed its own work, so this commit would carry neither the task title nor the session trailer"
    fi
    note commit 1 'nothing staged'
    die "the sessions changed nothing; there is no commit to make"
  fi
  _rc=0
  git -C "$wt" commit -q -F "$_msg" > "$logs/commit.log" 2>&1 || _rc=$?
  if [ "$_rc" -ne 0 ]; then
    tail_log "$logs/commit.log"
    note commit "$_rc"
    die "the commit failed"
  fi
  commit_sha=$(git -C "$wt" rev-parse HEAD)
  say "commit $commit_sha $title"
  note commit 0 "$commit_sha"
}

# --- 11. the body ---------------------------------------------------------------------

session_row() {
  printf '| %s | `%s` | %s |\n' "$1" "${2:-none}" "${3:-not run}"
}

step_body() {
  printf '\n==> pr-body\n'
  printf '    (writes %s)\n' "$wt/$body_file"
  if [ "$dry_run" = 1 ]; then
    note pr-body 0 'dry run'
    return 0
  fi
  {
    printf '# %s\n\n' "$title"
    printf 'Written by `bench/self/improve.sh`: an Ouroboros native session made this change,\n'
    printf 'a second one reviewed it, the first one answered the review, and the gates below\n'
    printf 'ran outside all of them. Nothing here merged itself.\n\n'

    printf '## The task\n\n'
    cat "$task_file"
    printf '\n\n'

    printf '## Sessions\n\n'
    printf '| role | session | status |\n|---|---|---|\n'
    session_row implementer "$impl_session" "$impl_status"
    session_row reviewer "$review_session" "$review_status"
    session_row 'fix wave' "$fix_session" "$fix_status"
    printf '\n'

    printf '## The review\n\n'
    if [ -f "$wt/$review_file" ]; then
      _lines=$(wc -l < "$wt/$review_file" | tr -d ' ')
      printf 'The reviewer session wrote `%s` in the worktree. It is quoted verbatim and\n' "$review_file"
      printf 'fenced: it is the model'"'"'s own words about its own repository, evidence of what was\n'
      printf 'looked at and not evidence that the change is sound.\n\n'
      printf '%s\n' "$fence"
      # The review is the only untrusted text in this body: a model that wrote its own
      # `## Human review required` heading would otherwise be writing our sections for us.
      # Fenced, and any line that could close the fence early is replaced.
      head -n "$review_body_lines" "$wt/$review_file" | sed "s/$fence_re/[fence replaced by improve.sh]/"
      printf '\n%s\n\n' "$fence"
      if [ "$_lines" -gt "$review_body_lines" ]; then
        printf 'The review is %s lines; the first %s are quoted. The whole file is at `%s`.\n\n' \
          "$_lines" "$review_body_lines" "$wt/$review_file"
      fi
    else
      printf 'The reviewer session wrote no `%s`. Nothing was reviewed.\n\n' "$review_file"
    fi

    printf '## Fix wave\n\n'
    printf '%s\n\n' "$fix_note"

    printf '## Gates\n\n'
    printf '| step | rc | note |\n|---|---|---|\n'
    while IFS="$(printf '\t')" read -r _n _r _c; do
      if [ -n "$_n" ]; then printf '| `%s` | %s | %s |\n' "$_n" "$_r" "$_c"; fi
    done < "$steps_file"
    printf '\n'
    if [ "$quick" = 1 ]; then
      printf 'Run with `--quick`: `make test` and `mix dialyzer` did **not** run. CONTRIBUTING.md\n'
      printf 'calls `make test` the local gate; this pull request has not passed it.\n\n'
    fi

    printf '## The corpus\n\n'
    printf '%s\n\n' "$corpus_note"

    printf '%s\n\n' "$body_required_heading"
    printf 'Hunks under `lib/ouroboros/control/`, `lib/ouroboros/upgrade/` and\n'
    printf '`lib/ouroboros/storage/` — the namespaces whose modules make the runtime'"'"'s\n'
    printf 'guarantees enforceable. Listed whatever the review concluded, because the reviewer\n'
    printf 'is the same kind of thing as the implementer.\n\n'
    if [ -s "$protected_file" ]; then
      printf '```\n'
      cat "$protected_file"
      printf '```\n\n'
    else
      printf 'none\n\n'
    fi

    printf '%s\n\n' '---'
    printf 'Generated by bench/self/improve.sh (Ouroboros native sessions %s, %s)\n' \
      "${impl_session:-none}" "${review_session:-none}"
  } > "$wt/$body_file"
  say "body $wt/$body_file"

  # The body writer checks its own output, on every run and not only on the path that
  # opens a pull request: the run stops here rather than reaching a push with a body that
  # never told anyone to look at the protected namespaces. `step_pr` checks again — the
  # same claim, one step closer to the irreversible thing.
  if ! grep -q "^$body_required_heading\$" "$wt/$body_file"; then
    note pr-body 1 "the body has no '$body_required_heading' section"
    die "the body is missing its protected-namespace section; stopping before the push"
  fi
  note pr-body 0 'human review section present'
}

# --- 12/13. push and pull request -----------------------------------------------------

step_pr() {
  printf '\n==> pr\n'
  if [ "$no_pr" = 1 ]; then
    note pr 0 'skipped: --no-pr (nothing pushed)'
    return 0
  fi
  if [ "$dry_run" = 1 ]; then
    print_cmd git -C "$wt" push -u origin "$branch"
    print_cmd gh pr create --base dev --head "$branch" --title "$title" \
      --body-file "$wt/$body_file"
    note pr 0 'dry run'
    return 0
  fi

  # The last thing between a model's change and a pull request. A body without the
  # section is a body nobody was told to look at the protected namespaces in.
  if ! grep -q "^$body_required_heading\$" "$wt/$body_file"; then
    note pr 1 "the body has no '$body_required_heading' section"
    die "refusing to open a pull request without the protected-namespace section"
  fi

  command -v gh > /dev/null 2>&1 || die "gh is not on PATH; re-run with --no-pr"

  _push_url=$(git -C "$repo" remote get-url --push origin 2> /dev/null || printf '')
  case $_push_url in
    git@* | ssh://*)
      say "    note: origin pushes over SSH ($_push_url). If SSH is not configured on this"
      say "          machine the push below fails. This script never edits a remote: give"
      say "          your own checkout an HTTPS push URL, or re-run with --no-pr."
      ;;
  esac

  printf '\n==> push\n'
  print_cmd git -C "$wt" push -u origin "$branch"
  _rc=0
  git -C "$wt" push -u origin "$branch" > "$logs/push.log" 2>&1 || _rc=$?
  if [ "$_rc" -ne 0 ]; then
    tail_log "$logs/push.log"
    note push "$_rc"
    die "the push failed; the commit is on $branch in $wt and --no-pr does the rest"
  fi
  note push 0

  print_cmd gh pr create --base dev --head "$branch" --title "$title" --body-file "$wt/$body_file"
  _rc=0
  (cd "$wt" && gh pr create --base dev --head "$branch" --title "$title" \
    --body-file "$wt/$body_file") > "$logs/pr.log" 2>&1 || _rc=$?
  tail_log "$logs/pr.log"
  note pr "$_rc"
  [ "$_rc" -eq 0 ] || die "gh pr create failed"
}

# ------------------------------------------------------------------------- the run

step_worktree
step_daemon

# 3. the implementer.
impl_prompt="$logs/implementer-prompt.txt"
if [ "$dry_run" != 1 ]; then
  write_prompt "$impl_prompt" implementer implementer
  {
    printf '%s\n\n# The task\n\n' '---'
    cat "$task_file"
    printf '\n\nThe worktree is %s, branched from dev at %s. Commit nothing: the loop that\n' "$wt" "$base_sha"
    printf 'started you gates the change and makes the commit.\n'
  } >> "$impl_prompt"
fi
set -- --provider native --workspace "$wt"
[ -n "$model" ] && set -- "$@" --model "$model"
ouro_session implementer "$implementer_timeout" "$impl_prompt" "$@"
impl_session=$session_id
impl_status=$session_status

if [ "$dry_run" != 1 ] && [ -z "$(touched_paths)" ]; then
  die "the implementer session changed nothing in $wt; there is nothing to review"
fi

# 4. gate 1. A red gate here is not fatal: the review and the fix wave exist to answer it,
# and a body that shows gate 1 red and gate 2 green shows the loop working.
run_gate gate-1
gate1_rc=$gate_rc

# 5. the reviewer.
review_prompt="$logs/reviewer-prompt.txt"
if [ "$dry_run" != 1 ]; then
  write_prompt "$review_prompt" reviewer reviewer
  {
    printf '%s\n\n# What to review\n\n' '---'
    printf 'The workspace is %s, a git worktree branched from dev at %s. The change under\n' "$wt" "$base_sha"
    printf 'review is uncommitted; see all of it with:\n\n    git diff %s\n\n' "$base_sha"
    printf 'Write your review to %s/%s. The task the implementer was given:\n\n' "$wt" "$review_file"
    cat "$task_file"
    printf '\n\n## The diff, first %s lines\n\n' "$diff_prompt_lines"
    git -C "$wt" diff --stat "$base_sha" -- | sed 's/^/    /'
    printf '\n'
    git -C "$wt" diff "$base_sha" -- | head -n "$diff_prompt_lines"
    printf '\n(Truncated at %s lines if it ended mid-hunk. Run the command above for the rest.)\n' \
      "$diff_prompt_lines"
  } >> "$review_prompt"
fi
set -- --provider native --workspace "$wt"
[ -n "$model" ] && set -- "$@" --model "$model"
ouro_session reviewer "$reviewer_timeout" "$review_prompt" "$@"
review_session=$session_id
review_status=$session_status

# 6. the fix wave, back into the implementer's own session so its context is intact.
fix_prompt="$logs/fix-wave-prompt.txt"
if [ "$dry_run" = 1 ]; then
  ouro_session fix-wave "$implementer_timeout" "$fix_prompt" --resume DRY-implementer
  fix_session=$session_id
  fix_status=$session_status
  fix_note='dry run'
elif [ ! -f "$wt/$review_file" ]; then
  fix_note="not run: the reviewer session wrote no $review_file"
  note fix-wave 0 "$fix_note"
elif [ "$impl_session" = unknown ]; then
  fix_note='not run: the implementer session id is unknown, so there is no session to resume'
  note fix-wave 0 "$fix_note"
else
  write_prompt "$fix_prompt" fix-wave fix-wave
  {
    printf '%s\n\n# The review to answer\n\n' '---'
    printf 'A reviewer session read your change and wrote this. It is another model'"'"'s claim,\n'
    printf 'not a verdict: check each finding before you act on it, and say plainly which ones\n'
    printf 'you did not fix and why.\n\n'
    cat "$wt/$review_file"
  } >> "$fix_prompt"
  ouro_session fix-wave "$implementer_timeout" "$fix_prompt" --resume "$impl_session"
  fix_session=$session_id
  fix_status=$session_status
  fix_note="session \`$fix_session\`, status $fix_status, resumed from the implementer's own session"
fi

# 7. gate 2. This one decides.
run_gate gate-2
gate2_rc=$gate_rc

# The decision, before the corpus rather than after it: the corpus costs real money, and a
# change that could not pass its own gate has not earned a measurement.
if [ "$gate2_rc" -ne 0 ]; then
  printf '\n'
  note decision 1 'gate 2 is red; stopping before the corpus and the commit'
  say "logs: $logs"
  die "gate 2 failed after the fix wave; nothing is committed and nothing is pushed"
fi

step_corpus
step_commit
step_protected
step_body
step_pr

# ------------------------------------------------------------------------- summary

printf '\n==> summary\n'
if [ "$dry_run" != 1 ]; then
  while IFS="$(printf '\t')" read -r _n _r _c; do
    if [ -n "$_n" ]; then printf '  %-20s rc=%-3s %s\n' "$_n" "$_r" "$_c"; fi
  done < "$steps_file"
fi
say ""
say "gate 1 rc=$gate1_rc, gate 2 rc=$gate2_rc"
[ "$no_pr" = 1 ] && say "--no-pr: the commit is local, the body is at $wt/$body_file, nothing was pushed"
say "A human reviews and merges. improve.sh never merges."
exit 0
