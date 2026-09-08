# The self corpus

Ouroboros, graded on changes to Ouroboros. Each task is a commit from this repository's
own history: the agent is given the commit message and the titles of the tests that commit
added, works in a detached worktree at the commit's parent, and is graded by restoring
those tests from the history and running them.

```sh
make bench-self                                  # the $0 gate: selftest.sh
bench/self/selftest.sh                           # the same, directly
bench/self/run.sh --oracle --spend 1             # the oracle over the whole corpus
bench/self/run.sh --spend 5.00                   # a paid run
bench/self/run.sh --spend 5.00 --filter 03       # one task
bench/self/run.sh --spend 5.00 --no-approve-all # the unattended posture
elixir bench/self/extract.exs --replace          # rebuild the corpus from the history
```

Prerequisites: Elixir, git, a built client (`cd tui && cargo build`), and — for a paid run
— a model key and a model this node can price. `run.sh` runs `mix compile` for you and
refuses with a message if the client is missing.

Two environment variables. `OURO_BIN` names the client, which is how you run this from a
linked git worktree: a worktree has no `tui/target` of its own, and the runner will not
reach outside the checkout to find one — grading a binary built from another commit is the
failure this refusal exists to prevent. `BENCH_SELF_TMPDIR` overrides where the worktrees
and the runtime's data directory are built, for a machine whose `$TMPDIR` is small; a task
worktree is `deps/` plus `_build/` plus the checkout, so budget half a gigabyte per
concurrent task (much less on APFS, where the clone shares blocks).

This is **not** [`bench/local`](../local/README.md). That corpus scripts the model and
measures whether the plumbing holds. This one drives a real model and measures whether the
agent can do the work, on tasks whose answer is already in the history and whose grade
nobody wrote by hand.

| | `bench/local` | `bench/self` |
|---|---|---|
| Model | scripted, free | real, paid (or the oracle) |
| Workspace | a fixture directory | a git worktree of this repository |
| Grade | a hand-written `check.sh` per task | the commit's own tests, restored |
| Runtime | seconds | minutes per task |
| Keys | removed from the environment | passed through, on purpose |

## What a run does

1. Loads `tasks/`, refusing a corpus in which one instruction contains another (the
   scripted model matches by containment; see `bench/local/README.md`) or in which an
   instruction carries a reserved prompt delimiter (the runtime would refuse it before the
   agent saw it; the list is asked of the runtime).
2. On the paid path, asks the runtime whether it can price the model
   (`Ouroboros.Provider.Native.Cost.cost_usd/5` through `mix run --no-start`). An unpriced
   model is a refusal, because a spend total that is permanently zero would sail past any
   cap.
3. Starts one `ouro --dev daemon` on a scratch `OUROBOROS_DATA_DIR` (mode 0700).
4. Per task, and only while the running total is under `--spend`:
   1. `git worktree add --detach <scratch>/work/<id> <base_sha>`, with `deps/`, `_build/`,
      `priv/wasm/` and `priv/sandbox/` cloned in from this checkout (`cp -Rc` on macOS, so
      APFS shares the blocks and a 300 MB `_build` costs metadata);
   2. `mix deps.get` when the commit's `mix.lock` is not the one those `deps/` were
      fetched for, then `mix compile` in `dev` and `test` — `test` alone under `--oracle`,
      where no agent will run a command. This is **setup**, timed and reported separately:
      a benchmark that charged the agent for a cold build would be measuring this machine;
   3. `ouro run "<instruction>" --provider native --workspace <worktree> --approval-mode
      prompt --approve-all --stream-json --timeout <secs> --model <spec>`. `--approve-all`
      answers every ask `approve`/`once` and the ask is still **counted**, which is what
      makes "approvals per task" a number this corpus can report;
      `--no-approve-all` runs the unattended posture instead, where a headless run answers
      `deny`/`once`;
   4. grading, below;
   5. `git worktree remove --force`, on every path including failure.
5. Writes `result.json` and every trajectory under `--out`, prints a table, stops the
   daemon, removes the scratch directory.

`--keep` skips step 4.5 and the last part of step 5, so the worktrees stay on disk *and*
registered with git. `git worktree list` shows them; `git worktree remove --force <dir>`,
or `git worktree prune` once they are deleted, is how they go away.

Exit status: `0` when every task ran and passed, `1` when one failed, `3` when the run
stopped at the spend cap with tasks still to run, `64` for a refusal.

## Grading

In order. The first thing that is not true is the reason.

1. **`completed`.** The result object says `completed`. `timeout` is its own reason;
   anything else is `not_completed`.
2. **The tests were not touched.** No file that already existed under `test/` was modified
   or deleted — `modified_tests`. Checked two ways: `git status --porcelain -- test`, and
   `git diff --name-status <base_sha> -- test`, which compares the working tree against
   the commit the task started from. The second is the one that matters: an agent that
   *commits* its edit to a test leaves `git status` clean. New files are allowed and are
   left in place, so writing your own tests is fine.
3. **The hidden tests pass.** Every path under `test/` the commit touched is written into
   the worktree from `commit_sha` — `test/support/**` included, because a commit whose
   fixture and test moved together is only gradable with both — and `mix test <the
   _test.exs paths>` must pass under a wall clock. Otherwise `tests_failed`.

A worktree or compile that does not come up is `setup_failed`, and so is a `task.json`
whose `hidden_tests` disagree with what the history says the commit touched: git is the
authority for the pins, and a weaker grade would look exactly like a pass.

## The corpus is a list of pins

`tasks/<nn>-<slug>/task.json`:

```json
{
  "id": "01-…",
  "base_sha": "…",           the parent: where the agent starts
  "commit_sha": "…",         the answer: where the hidden tests come from
  "subject": "…",
  "instruction": "…",        subject, body, acceptance list, rules
  "hidden_tests": ["test/…"],
  "solution_files": ["lib/…"],
  "timeout_secs": 600,
  "measured": {"compile_ms": …, "test_ms": …, "diff_lines": …}
}
```

No test content is stored. It is read from git at run time, so the number is reproducible
for as long as `dev`'s history is, and a corpus file cannot quietly weaken a task by
carrying a doctored copy of its test.

The `instruction` is the commit subject, the body with its trailers and any pasted diff
removed, an **Acceptance** list of the `test "…"` titles the commit *adds* (at most
twelve, never a test body), and a rules paragraph stating the two grading conditions.
Saying the rules does not make gaming easier — the grader enforces them either way — and
not saying them would be measuring a rule nobody was told.

## Extraction

`elixir bench/self/extract.exs [--replace] [--max-tasks 30] [--max-diff-lines 300]
[--task-ceiling-secs 600] [--max-solution-bytes 393216] [--max-candidates 90]
[--commit-checks 2] [--jobs 3] [--commits SHA,SHA] [--out DIR] [--verify <task-dir>]`

Candidates are commits reachable from `dev` that touch `lib/`, add or modify at least one
`test/**/*_test.exs`, are not merges, and stay out of `tui/`, `assets/`, `.github/`,
`scripts/` and `bench/`. Ranked `fix` first, then smaller non-test diff first.

Dropped, each reported with a count:

| class | why |
|---|---|
| `no_lib_change`, `no_test_added_or_modified` | not a change to behaviour with a test |
| `excluded_tree` | the change is Rust, assets, CI, a script, or this corpus itself |
| `build_files_changed` | `mix.exs` or `mix.lock`: the dependency set is not the one the cloned `_build` was compiled against |
| `non_test_deletion` | the oracle answers with `write` calls and cannot express a removal |
| `diff_too_large` | over `--max-diff-lines` |
| `solution_not_utf8`, `solution_too_large` | the oracle's script has to hold the file's bytes |
| `instruction_reserved_delimiter` | the instruction quotes one of the prompt assembler's own block tags, and `Runtime.Exposure` refuses such a prompt before the agent sees it. The list is asked of the runtime, not copied |
| `parent_already_passes` | the hidden tests pass without the change: nothing to do |
| `commit_does_not_pass` | the hidden tests do not pass *at the commit* on this machine |
| `over_task_ceiling`, `*_timeout` | compile plus test at the parent over `--task-ceiling-secs` |
| `setup_failed` | worktree, `mix deps.get` or `mix compile` at the parent |

Every accepted task was proved: in a detached worktree at the parent, built exactly the
way the runner builds one, the hidden tests **fail**; at the commit they **pass**.
`--verify <task-dir>` re-checks one existing task without re-extracting.

At the commit the tests are run `--commit-checks` times (default 2, different ExUnit seeds)
and every run must pass. This repository has load-sensitive suites and `--jobs` worktrees
compile and test at once, so a task whose *reference answer* passes only sometimes is noise
in the measurement rather than a task. Two runs is the cheapest screen that catches that
class; it is not a proof of determinism and does not claim to be. The extractor errs in the
safe direction throughout — a commit whose tests do not pass at the commit is never
accepted — so the cost of the variance is a smaller corpus, never a wrong one.

Extraction creates and removes git worktrees of this repository. It removes each one on
every path, including failure; after an interrupted run, `git worktree prune` cleans up
what is left.

## The budget

`--spend <usd>` is required, including for the oracle. The running total of the result
object's `usage.cost_usd` is checked **before** each task; at or over the cap the run stops
and the report names the tasks that did not run.

Before the first task, the runner asks this checkout's own
`Ouroboros.Provider.Native.Cost.cost_usd/5` — through `mix run --no-start`, so the answer is
the runtime's rather than a copy — whether it can price the model, and refuses if it cannot.
An unpriced model reports no `cost_usd`, a running total of nothing never reaches a cap, and
`--spend` would be decoration. The packaged default `openai_codex:gpt-5.6-sol` is **not**
priced, so a paid run has to name a model that is: `--model anthropic:claude-sonnet-4-5` and
`--model openai:gpt-4o` both price, and `OUROBOROS_NATIVE_MODEL` does the same job.

**One task can overshoot the cap by its own cost.** The check is between tasks because
there is no cost ceiling inside a turn: `ouro run` has no spend flag, and the runtime
reports cost only when the turn ends. What bounds a single task is `--timeout` (the task's
own `timeout_secs` by default). Budget accordingly: the worst case is the cap plus one
task's cost.

## The oracle, and the two controls

`--oracle` answers every task with the commit's own non-test files, through
[`bench/local`'s scripted model](../local/README.md#the-scripted-model-seam) — the same
file, compiled into the project's own `ebin` the same way, not a copy. One `write` per
changed file with that file's bytes at `commit_sha`, then a closing turn. It must grade
every task `pass` at $0, and the runner fails the run if it reports anything else.

That proves the grader accepts a correct answer. Two seams prove it *rejects* the two
things it exists to reject. Both are refused outside `--oracle`:

| seam | what it does | what must happen | the mutation it kills |
|---|---|---|---|
| `--oracle-cheat no-solution` | answers with nothing at all | every task `tests_failed` | skipping the hidden-test restore. The **parent's** copy of each test passes, so a runner that did not restore would grade doing nothing as a full pass |
| `--oracle-cheat blank-tests` | writes the real solution **and** overwrites a pre-existing hidden test with a file that asserts nothing | every task `modified_tests` | skipping the modified-test check. The solution is correct, so without that check the restore would put the real test back and the task would pass |
| `--fake-cost-usd <usd>` | charges each task that cost instead of its real one | the cap stops the run | a spend total that ignores a task |

## The selftest

`bench/self/selftest.sh` (`make bench-self`) is the $0 gate. It extracts two pinned
commits, runs the oracle over them, checks both spend refusals, checks that the seams are
oracle-only, drives the cap, and runs the two controls above. A few minutes; no key, no
network beyond git and the local hex cache, no spend.

The two commits it pins:

| sha | subject |
|---|---|
| `7f9d8166` | `fix(interactive): let a turn id reach the session's rewind, not only an ordinal` |
| `2d5a0ea6` | `fix(replay): a boundary keeps the record's own name for it` |

Both change one file under `lib/` and one test file that already existed — which is what
the `blank-tests` control needs.

## What is different from `bench/local`, and why

- **Real credentials.** The environment is passed through and `XDG_CONFIG_HOME` is kept:
  the packaged default model authenticates through it. Only `OUROBOROS_DATA_DIR` is
  scratch, so the run cannot touch the operator's sessions and `ouro stop` can only ever
  mean this run's runtime. Under `--oracle` the posture is `bench/local`'s exactly — a
  scratch config home and every provider key removed from the environment.
- **A real repository as the workspace.** Which is why setup is timed separately, why the
  worktree is removed on every path, and why `--keep` exists.
- **No `check.sh`.** The grade is the commit's own tests. Nobody writes an assertion.

## What this does not measure

The same list as [docs/BENCHMARKS.md](../../docs/BENCHMARKS.md) §1, plus two of its own:

- **Generalisation.** Every task is a change someone already made to *this* code base,
  ranked toward small fixes. A number here says the agent can re-derive a small fix in a
  code base it has the whole of; it does not say it can do the same anywhere else.
- **Whether the answer is the commit's answer.** Only that the hidden tests pass and no
  pre-existing test was touched. A different fix that passes them is a pass, which is the
  intent.
