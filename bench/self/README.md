# The self corpus

Ouroboros, graded on changes to Ouroboros. Each task is a commit from this repository's
own history: the agent is given the commit message and the titles of the tests that commit
added, works in a clone whose history stops at the commit's parent, and is graded by
taking its change as a diff, applying that diff to a fresh tree at the parent, restoring
those tests from the history, and running them.

```sh
make bench-self                                  # the $0 gate: selftest.sh
bench/self/selftest.sh                           # the same, directly
bench/self/run.sh --oracle --spend 1             # the oracle over the whole corpus
bench/self/run.sh --spend 5.00                   # a paid run
bench/self/run.sh --spend 5.00 --filter 03       # one task
bench/self/run.sh --spend 5.00 --no-approve-all # the unattended posture
elixir bench/self/extract.exs --replace          # rebuild the corpus from the history
bench/self/run.sh --spend 5.00 --repo /path/to/checkout    # grade another checkout's runtime
```

Prerequisites: Elixir, git, a built client (`cd tui && cargo build`), and — for a paid run
— a model key and a model this node can price. `run.sh` runs `mix compile` for you and
refuses with a message if the client is missing.

Two environment variables. `OURO_BIN` names the client, which is how you run this from a
linked git worktree: a worktree has no `tui/target` of its own, and the runner will not
reach outside the checkout to find one — grading a binary built from another commit is the
failure this refusal exists to prevent. Naming a path that is not there is a *refusal*, not
a fallback: a typo used to mean the corpus silently graded whatever `tui/target` happened
to hold. `BENCH_SELF_TMPDIR` overrides where the trees and the runtime's data directory are
built, for a machine whose `$TMPDIR` is small; a task costs two of them — one for the
agent, one for the grade — each `deps/` plus `_build/` plus the checkout, so budget a
gigabyte per task (much less on APFS, where the clone shares blocks).

Two flags say *which* repository is which, and they are different questions.
`--repo <checkout>` names the checkout whose runtime is under test: it is compiled, its
client is used, its `deps/` and `_build/` are cloned into every tree. `--history <repo>`
names the repository the corpus's commits live in. Both default to this checkout. The
improve loop passes `--repo` at its own worktree while the corpus keeps grading against
this history; `selftest.sh` passes `--history` at a two-file fixture project so the
grader's rules can be proved in seconds.

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
   1. the workspace: a temporary ref `refs/bench-self/<run>/<id>` at `base_sha`, then a
      **clone** of that ref alone through the `file://` transport into
      `<scratch>/work/<id>`, then the ref is deleted. The `file://` transport packs only
      what the asked-for ref reaches, so the commit that is the answer — and every commit
      after it — is not in the workspace at all; that this is so is asserted per task
      rather than assumed, and it costs 0.50 s and 4.3 MiB. The history *up to* the base is
      all there. `deps/`, `_build/`,
      `priv/wasm/` and `priv/sandbox/` are cloned in from the checkout (`cp -Rc` on macOS,
      so APFS shares the blocks and a 300 MB `_build` costs metadata);
   2. `mix deps.get` when the commit's `mix.lock` is not the one those `deps/` were
      fetched for, then `mix compile` in `dev` and `test` — `test` alone under `--oracle`,
      where no agent will run a command. This is **setup**, timed and reported separately:
      a benchmark that charged the agent for a cold build would be measuring this machine;
   3. `ouro run "<instruction>" --workspace <worktree> --approval-mode
      prompt --approve-all --stream-json --timeout <secs> --model <spec>`. `--approve-all`
      answers every ask `approve`/`once` and the ask is still **counted**, which is what
      makes "approvals per task" a number this corpus can report;
      `--no-approve-all` runs the unattended posture instead, where a headless run answers
      `deny`/`once`;
   4. grading, below;
   5. the workspace and the grading tree are removed, on every path including failure.
5. Writes `result.json` and every trajectory under `--out`, prints a table, stops the
   daemon, sweeps any temporary ref the run left, removes the scratch directory.

`--keep` skips step 4.5 and the last part of step 5, so the trees stay on disk. The
grading trees are registered worktrees — `git worktree list` shows them and
`git worktree remove --force <dir>` is how they go away; the workspaces are ordinary
clones, so `rm -rf` is all they need. A finished run leaves neither, and leaves no ref
under `refs/bench-self`; `selftest.sh` asserts both.

Exit status: `0` when every task ran and passed, `1` when one failed, `3` when the run
stopped at the spend cap with tasks still to run, and `64` for a refusal — including a
completed turn nobody could price, which stops the run because a running total that
cannot move is not a cap.

## Grading

**The grade is a diff on a pristine tree, not the tree the agent worked in.** It used to be
the tree, and an adversarial review took that apart twice over: one new file under
`test/support/` — allowed, because writing your own tests is part of the work — is on
`elixirc_paths(:test)`, so `mix test` compiled it into the grading VM, its module body ran
*after* both checks had passed, and it rewrote every restored hidden test. Score: 2/2. One
`test: ["cmd true"]` line in `mix.exs` made `mix test` exit 0 over a suite asserting
`1 == 2`. Score: 1/1.

So, in order. The first thing that is not true is the reason.

1. **`completed`.** The result object says `completed`. `timeout` is its own reason;
   anything else is `not_completed`. A completed turn that reported no `usage.cost_usd` on
   a paid run is `setup_failed: unpriced_turn`, and the run stops there.
2. **The task is gradable.** It names at least one `_test.exs`, or `setup_failed`:
   `mix test` with no paths runs the whole suite.
3. **The tests were not touched.** For every path that existed under `test/` at
   `base_sha`, the file on disk is hashed and compared with the base's blob — by content,
   never through the index, because `git update-index --assume-unchanged` makes `git
   status` *and* `git diff` forget a file that is sitting there modified. A missing file is
   a deletion. Either is `modified_tests`. A path that did not exist at the base is not in
   this list at all, so a new test of your own — staged, edited, committed, whatever — is
   not a modification of anything.
4. **The change stays in the source roots.** The agent's change is collected as
   `git diff --binary <base_sha>` (after `git add -N`, so new files count) over `lib/`,
   `assets/`, `priv/`, `config/`, `docs/` and `README.md` — the roots the thirty tasks
   actually use. A diff touching anything else is `refused`, not filtered: an agent that
   rewrote `mix.exs` did not do the task, and grading the rest of its diff would report a
   number for work nobody checked.
5. **The pins agree with the history.** Else `setup_failed`: git is the authority for what
   a task's `task.json` claims, and a weaker grade would look exactly like a pass.
6. **The hidden tests pass in a tree the agent never touched.** A fresh
   `git worktree add --detach <base_sha>`, with `deps/` and `_build/` cloned from the
   *checkout* — never from the agent's workspace. The diff is applied there and compiled;
   *then* every path under `test/` the commit touched is written in from `commit_sha`
   (`test/support/**` included, because a commit whose fixture and test moved together is
   only gradable with both); then `mix test <the _test.exs paths>` runs under a wall clock.
   Compiling before restoring is what makes a compile-time rewrite pointless: whatever a
   module body writes into `test/` is overwritten by the restore that follows it.
7. **The suite reported a pass, and the tests it ran were the real ones.** Not the exit
   status — that is a number the code under test can set. `Result: <n> passed` with no
   `Failed:` line, `n` at least the number of hidden test files, an uncut capture, and
   process exit 0. This is `bench/self/lib/improve/gate-verdict.sh`'s rule, which the
   improve loop applies to the same suites; the two agree by construction rather than by
   coincidence. Afterwards the restored files are hashed again and must still be
   `commit_sha`'s, so a rewrite at any point during the run is caught rather than believed.

A tree or compile that does not come up is `setup_failed`.

**What this still cannot do.** The grading tree compiles and runs the agent's own `lib/`
code, and Elixir runs module bodies at compile time. The ordering above and the hash check
after remove every way of *rewriting a test*; nothing here can tell ExUnit's summary from
one the graded code printed itself, and nothing that parses the output of a VM the graded
code runs in ever could. It is stated here rather than defended.

## The corpus is a list of pins

`tasks/<nn>-<slug>/task.json`:

```json
{
  "id": "01-…",
  "base_sha": "…",           the parent: where the agent starts
  "commit_sha": "…",         the answer: where the hidden tests come from
  "subject": "…",
  "instruction": "…",        subject, body, acceptance list, rules
  "instruction_kind": "full",   or "subject-only"
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
twelve, never a test body), and a rules paragraph stating the grading conditions. Saying
the rules does not make gaming easier — the grader enforces them either way — and not
saying them would be measuring a rule nobody was told.

**The body frequently describes the change.** It is a commit message written by the person
who made it, so it often names the function, the file, or the exact behaviour: of the
thirty tasks, 28 carry a body at all and **14 name a file the solution changes** by path or
by name (16 if a module name derived from that path counts). What the number measures is
therefore *executing a described change* against tests nobody showed the agent, in a
repository whose history stops at the base — not discovering what to change.

`--instruction subject-only` builds the harder corpus: the subject, the acceptance list and
the rules, with the body dropped. `--reinstruct <dir>` rewrites an existing corpus's
instructions in place from the same history, which is how the second corpus is made from
the first without re-extracting — same thirty commits, one variable changed. Neither has
been run against a model; the committed corpus is `full`.

## Extraction

`elixir bench/self/extract.exs [--replace] [--max-tasks 30] [--max-diff-lines 300]
[--task-ceiling-secs 600] [--max-solution-bytes 393216] [--max-candidates 90]
[--commit-checks 2] [--jobs 3] [--commits SHA,SHA] [--out DIR] [--verify <task-dir>]
[--history <repo>] [--instruction full|subject-only] [--reinstruct <dir>]`

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
| `merge_commit` | `--commits` named a merge: the diff against its first parent is the other branch's work |
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

## What a `result.json` says about itself

A number is only quotable if the file it came from can show what produced it. `run` carries
every flag as given (`filter`, `oracle`, `oracle_cheat`, `fake_cost_usd`, `fake_status`,
`oracle_as_paid`, `approve_all`/`no_approve_all`, `timeout`, `tasks_dir`, `repo`,
`history`, `model`, `keep`), a `corpus_sha256` over the sorted `task.json` bytes, the
client binary's `ouro_bin_sha256`, an `ouro_sha` with a `-dirty` suffix when the checkout
has uncommitted changes, both repository paths, and what the grader runs. A run with
`--oracle-cheat` sets `run.cheat` and the report says in words that no number from it is
quotable. Per task, `grade_command` is the exact `mix test` line, `grade_setup_ms` is the
grading tree's own build, and `unpriced` says whether the turn reported a cost.

Quote a number with its `ouro_sha`, its `corpus_sha256`, its `model`, and `run.cheat` being
absent. Without those four it is a number from somewhere.

## The oracle, and the controls

`--oracle` answers every task with the commit's own non-test files, through
[`bench/local`'s scripted model](../local/README.md#the-scripted-model-seam) — the same
file, compiled into the project's own `ebin` the same way, not a copy. One `write` per
changed file with that file's bytes at `commit_sha`, then a closing turn. It must grade
every task `pass` at $0, and the runner fails the run if it reports anything else.

That proves the grader accepts a correct answer. Two seams prove it *rejects* the two
things it exists to reject. Both are refused outside `--oracle`:

| seam | what it does | what must happen | what it kills |
|---|---|---|---|
| `--oracle-cheat no-solution` | answers with nothing at all | every task `tests_failed` | skipping the hidden-test restore. The **parent's** copy of each test passes, so a runner that did not restore would grade doing nothing as a full pass |
| `--oracle-cheat blank-tests` | writes the real solution **and** overwrites a pre-existing hidden test with a file that asserts nothing | every task `modified_tests` | skipping the modified-test check. The solution is correct, so without it the restore would put the real test back and the task would pass |
| `--oracle-cheat commit-tests` | the same, then `git commit`s it, so `git status` is clean | every task `modified_tests` | a check that reads `git status` |
| `--oracle-cheat hide-tests` | the same, then `git update-index --assume-unchanged`es it, so `git status` *and* `git diff` report a clean tree | every task `modified_tests` | a check that asks git rather than the file. **Proved against the previous version** |
| `--oracle-cheat stage-new-test` | writes the real solution and adds a test of its own, staged and then edited (`AM`) | every task **passes** | a check that reads the `M` and fails a file that did not exist at the base. **Proved against the previous version** |
| `--oracle-cheat game-support` | writes no solution and one new `test/support/*.ex` whose module body rewrites every restored hidden test at compile time | every task `tests_failed` | grading the agent's tree. **Scored 2/2 against the previous version** |
| `--oracle-cheat mixexs-alias` | writes the real solution and a `mix.exs` carrying a `test:` alias that makes `mix test` exit 0 | every task `refused` | grading a diff that reaches outside the source roots, and reading the exit status. **Proved against the previous version** |
| `--oracle-cheat history-cheat` | one `bash` call: `git log --all --grep "<its own subject>"`, then `git show "$sha:$f"` for every non-test file | every task `tests_failed` | a workspace that shares the repository's object store. **Scored 1/1 against the previous version** |
| `--fake-cost-usd <usd>` | charges each task that cost instead of its real one | the cap stops the run | a spend total that ignores a task |
| `--fake-status <status>` | replaces the result object's `status` | every task `not_completed` | a grade that ignores whether the turn finished |
| `--oracle-as-paid` | applies the paid path's unpriced-turn rule to an oracle run | the run stops, exit 64 | a turn with no `cost_usd` counting as $0 against the cap |

## The selftest

`bench/self/selftest.sh` (`make bench-self`) is the $0 gate: twelve phases, 118
assertions, no key, no network beyond git and the local hex cache, no spend. Eleven minutes
and forty seconds on the machine it was written on, most of it real trees being compiled
twice per task.

The cheap half runs first, and it runs against a **fixture repository** — a two-file Mix
project `lib/fixture.sh` builds in a second, with a history shaped to contain one of each
thing the extractor and the grader have to tell apart: a real fix, a commit whose hidden
test already passes at its parent, one whose own test does not pass, and a merge. Two of
those have no example in the corpus by construction, since a commit that trips either gate
is dropped before it becomes a task; proving them against this repository would mean
hunting for a commit that happens to trip them, which is a fact about the history rather
than about the code.

The phases: the verdict rule; the refusals that come before anything is built (`--spend`,
the four seams on a model this node *can* price, and an `OURO_BIN` that names nothing —
none of which may start a daemon); the oracle's environment, asserted by spawning `env`
through the runner's own builder; the extractor's two gates and the merge; four corpora
that are not corpora; the fixture corpus against the oracle and eight scripted agents that
must not score; then the same claims against real commits — extraction, the oracle at $0,
the cap, the two original controls, and the three proved exploits; and finally that no
worktree and no `refs/bench-self` ref is left behind.

The two commits it pins:

| sha | subject |
|---|---|
| `7f9d8166` | `fix(interactive): let a turn id reach the session's rewind, not only an ordinal` |
| `2d5a0ea6` | `fix(replay): a boundary keeps the record's own name for it` |

Both change one file under `lib/` and one test file that already existed — which is what
the blanking controls need.

## What is different from `bench/local`, and why

- **Real credentials.** The environment is passed through and `XDG_CONFIG_HOME` is kept:
  the packaged default model authenticates through it. Only `OUROBOROS_DATA_DIR` is
  scratch, so the run cannot touch the operator's sessions and `ouro stop` can only ever
  mean this run's runtime. Under `--oracle` the posture is `bench/local`'s exactly — a
  scratch config home, and every provider key plus `GITHUB_TOKEN` and the runtime's own
  three secrets removed from the environment, because the oracle runs no model and no
  operator tool and a variable it cannot use is one it should not carry.
- **A real repository as the workspace.** Which is why setup is timed separately, why the
  workspace and the grading tree are removed on every path, and why `--keep` exists.
- **No `check.sh`.** The grade is the commit's own tests. Nobody writes an assertion.

## What this does not measure

The same list as [docs/BENCHMARKS.md](../../docs/BENCHMARKS.md) §1, plus two of its own:

- **Generalisation.** Every task is a change someone already made to *this* code base,
  ranked toward small fixes. A number here says the agent can re-derive a small fix in a
  code base it has the whole of; it does not say it can do the same anywhere else.
- **Whether the answer is the commit's answer.** Only that the hidden tests pass and no
  pre-existing test was touched. A different fix that passes them is a pass, which is the
  intent.
