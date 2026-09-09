# Benchmarks

Status: written 2026-08-23, revised 2026-09-08. Three things live here, and they measure
different things.

> **There is no Terminal-Bench number for Ouroboros.** Not a bad one, not a provisional
> one — none. The adapter that would produce one is written and its decidable half is
> tested; the run needs a Linux build, a model key, and docker, and has not happened.
> When it happens the number goes in [§4](#4-the-number-when-there-is-one) whatever it
> is. That is the commitment `AGENT_EXPERIENCE.md` §10 makes, and this file is where it
> is kept.

| | [Terminal-Bench 2.1](#2-terminal-bench-21) | [The local corpus](#3-the-local-corpus) | [The self corpus](#5-the-self-corpus) |
|---|---|---|---|
| Question | can the agent solve real terminal work? | does the agent's plumbing hold? | can the agent make a change to *this* code base that tests it was never shown accept? |
| Model | a real one, paid for | a scripted one, free | a real one, paid for — or the oracle, free |
| Needs | docker, a key, a Linux `ouro` | Elixir and a built client | Elixir, git, a built client, and a model this node can price |
| Runtime | hours | ~5 seconds | 28 minutes for the $0 oracle over 30 tasks |
| Comparable to other agents | yes, that is the point | no, and it never will be | no: every task is a commit from this repository |
| Run it | `bench/terminal_bench/README.md` | `make bench-local` | `make bench-self`, then `bench/self/run.sh --spend <usd>` |
| Status here | never run | **17/17 green** on macOS 15 / Elixir 1.20.2 / OTP 29 | **oracle 30/30 at $0**; no paid run has happened |

---

## 1. What is measured, and what is not

**Measured by Terminal-Bench.** Whether the agent, driving a real model, completes tasks
in a container that a task author's own tests then grade. It ranks *harness plus model*,
which is the only axis on which a harness can be compared at all: the same model scores
about three points differently depending on the loop around it
([AGENT_EXPERIENCE.md §2.1](AGENT_EXPERIENCE.md)).

**Measured by the local corpus.** Whether an instruction reaches the native loop, the
tools dispatch, the permission gate answers, the guards refuse what they should, the
bounds bind, the events reach a client, and the numbers come back — end to end, through
the real `ouro run` client against a real spawned runtime, with a scripted model standing
in for a paid one.

**Measured by the self corpus.** Whether the agent, driving a real model, can make a change
to *this* code base that a commit's own tests then accept, without touching the tests it was
given, in a workspace whose history stops at the commit before the answer. The instruction is
that commit's message, which frequently describes the change — see [§5](#5-the-self-corpus)
for what that does and does not measure.

**Measured by none of them.**

- **Model quality.** The corpus scripts the model's answers; it cannot tell you whether a
  model would have chosen them.
- **Prompt engineering.** The system prompt, the `AGENTS.md` hierarchy, compaction quality
  and context packing all sit upstream of what the corpus asserts. Terminal-Bench measures
  their *effect*, mixed with everything else, and gives you one number for the mixture.
- **Latency or throughput under load.** Both suites are correctness harnesses. Neither
  runs concurrent sessions, and neither is a profiler.
- **Anything about the nine vendor providers.** Both are `--provider native`. Ouroboros
  running `claude` scores whatever `claude` scores; that is the vendor's number, not this
  project's, and publishing it as ours would be borrowing a result.
- **Cost, by the corpus.** It spends nothing, on purpose. Its token column is scripted
  arithmetic, not billing.

---

## 2. Terminal-Bench 2.1

Terminal-Bench 2.x runs on **Harbor** (`harbor-framework/harbor`), not on the
`terminal-bench` package, whose last release predates 2.0. The 2.1 set is 89 tasks — 2.0
with 26 of them repaired for bugs, timeouts, and reward-hacking robustness — and the board
ranks harness + model as shipped.

The adapter is [`bench/terminal_bench/`](../bench/terminal_bench/README.md):
`OuroborosAgent`, a `harbor.agents.installed.base.BaseInstalledAgent` that uploads a
prebuilt Linux `ouro`, starts the packaged daemon, and runs one headless turn.

```sh
export OURO_LINUX_DIST=/path/to/ouro   # `make ouro` on a Linux host
export ANTHROPIC_API_KEY=...

cd bench/terminal_bench
harbor run -d terminal-bench/terminal-bench-2-1 \
  --agent ouroboros_agent.agent:OuroborosAgent \
  -m anthropic/claude-opus-4-1 \
  -k 5 -n 8
```

Its own tests need none of that:

```sh
bench/terminal_bench/run_tests.sh     # 64 tests: no docker, no key, no harbor install
```

### What it will take to get a number

Three things this repository does not have on the machine where the adapter was written:

1. **A Linux `ouro`.** ERTS does not cross-compile. `make ouro` produces a client for the
   host that built it, so a Linux artifact is built on a Linux host or in CI. This is the
   hard prerequisite, and it is the same one `AGENT_EXPERIENCE.md` §10 names for releases.
2. **A model key, and a budget.** 89 tasks × 5 attempts is 445 transcripts against a
   frontier model. Published leaderboard rows carry costs in the low hundreds of dollars
   at that shape. Start with one task.
3. **docker.** Harbor runs each task in a container; the hosted `daytona` sandbox is the
   alternative.

Then: read the number, put it in §4, and only then consider submitting. Note that
community submissions to 2.1 were closed when the adapter was written — maintainer-run
only — so publishing the number here is the commitment, and a leaderboard row is a
separate thing that depends on someone else's queue.

### What the adapter reports, and what it refuses to

Harbor scores a trial by running the task's own `tests/test.sh` after the agent stops. The
adapter never reports pass or fail. It reports tokens (`n_input_tokens`,
`n_output_tokens`, `n_cache_tokens`), `cost_usd` computed by `Native.Cost` from `llm_db`
pricing, and metadata — status, tools used, approvals, iterations, files changed. A turn
that ends `failed` or `timeout` is a measurement the task's tests are there to grade; only
`lost`, `refused` and an unparseable run count as the client itself crashing.

Trajectories: the raw `ouro run --stream-json` NDJSON is the record; a summary is written
beside it. ATIF is deliberately **not** claimed — see the adapter README for why.

### What has actually been verified

The adapter README carries the full split. In one line: everything that does not need a
container has been run (64 tests, including the install script executed by `sh` and the
result mapping against a stream captured from a real `ouro run`), and **`agent.py` itself
has never been imported, let alone executed**, because `harbor` was not installed.

---

## 3. The local corpus

```sh
make bench-local              # or bench/local/run.sh, --filter / --keep / --ouro
```

Seventeen deterministic tasks. Each is a fixture workspace, an instruction, a scripted
model response, and a check command; each runs through the real `ouro run` against a real
`ouro --dev daemon` on a scratch data directory at mode 0700, with the operator's config
and every model API key removed from the environment. Full detail, including how to add a
task, is in [`bench/local/README.md`](../bench/local/README.md).

The scripted model is the same seam the native unit tests use —
`Ouroboros.Provider.Native.Model` behind `config :ouroboros, :native_model_module` — with
the script in a file rather than in a pid, because the corpus drives a separate BEAM.

### The run, as it stands today

macOS 15.5, Elixir 1.20.2, OTP 29, `tui/target/debug/ouro`, 2026-08-23:

```
task                      chk   run         duration  tokens  exercises
--------------------------------------------------------------------------------------------
01-read                   ok    completed    1333 ms     138  read
02-write-approved         ok    completed      77 ms     180  write,approval
03-write-denied           ok    completed      53 ms     172  write,approval
04-edit-after-read        ok    completed      45 ms     244  read,edit
05-edit-without-read      ok    completed      50 ms     186  edit,read-before-write guard
06-apply-patch-update     ok    completed      45 ms     295  read,apply_patch
07-apply-patch-add        ok    completed      75 ms     224  apply_patch,approval
08-bash                   ok    completed      75 ms     230  bash,approval
09-bash-timeout           ok    completed    2544 ms     218  bash,bounded output
10-grep                   ok    completed      50 ms     199  grep
11-glob-ls                ok    completed      54 ms     261  glob,ls
12-code-intel-no-server   ok    completed      52 ms     296  code_intel
13-ask-user-declined      ok    completed      36 ms     237  ask_user,approval
14-ask-user-acknowledged  ok    completed      33 ms     240  ask_user,approval
15-plan                   ok    completed      32 ms     234  plan
16-unknown-tool           ok    completed      50 ms     283  tool dispatch
17-auto-edit-boundary     ok    completed      73 ms     283  write,bash,approval

17/17 passed in 4677 ms, 3920 scripted tokens, $0.00 spent
```

The token column is scripted arithmetic and the `$0.00` is literal: nothing was bought.
The first task carries the daemon's first-session cost; the rest are tens of milliseconds.

**This is a regression suite that happens to print a table. It is not a score.** Nothing
about it is comparable to another agent, and a "17/17" next to somebody's 83.8% would be
comparing a passing test suite to a benchmark result.

### Two things it found

The corpus pins both behaviours so they cannot regress silently.

- **`ouro run` names one changed file twice** in `files_changed`: the `file_change`
  payload's absolute `path`, and the relative path parsed out of the unified diff header
  ([`tui/src/run.rs` `collect_paths`](../tui/src/run.rs)). `02-write-approved` pins the
  count at 2 and says why; the Terminal-Bench adapter deduplicates before telling Harbor,
  because Harbor only ever sees a count and reporting two files would be reporting a file
  that does not exist.
- **`code_intel` without a language server is a bounded in-band refusal.**
  `Ouroboros.CodeIntel.Registry.resolve/2` admits a path under configured
  `:workspace_allowed_roots` **or** the workspace of an interactive or coding session
  this node holds. A default install with no roots and no live session still judges
  every path `{:outside_workspace, …}` before a language is considered. With a
  session (or configured roots) and no server installed, the answer is
  `{:server_unavailable, …}` — in band, bounded, non-fatal. `12-code-intel-no-server`
  asserts that contract, not the message.

### Where it runs

`make bench-local` locally, and `.github/workflows/bench-local.yml` as a manual
`workflow_dispatch` job — never on push. It spawns a real runtime and drives a real
client, which is minutes with the builds around it, and `ci.yml` has to stay the thing
every push waits on. Run it before a release, after a change to the native agent's tools,
permissions or event stream, and before touching §4 of this file.

---

## 4. The number, when there is one

*(empty)*

When a Terminal-Bench 2.1 run completes, this section records — whatever the result —
the score with its confidence interval, the model and reasoning effort, the dataset id
and task count, the number of attempts per task, the `ouro` version and commit, the total
cost, the date, and a link to the uploaded job. A leaderboard row, if community
submissions have reopened by then, goes beside it.

Two expectations set in advance, so that nobody has to decide afterwards what the number
was supposed to mean:

- **A new harness starts below Claude Code.** The three-point harness gap on Terminal-Bench
  is earned by mechanics this project is still building. The first number will be behind,
  and it gets published anyway.
- **It gets published before it is optimised.** A first number chosen from several runs is
  not a first number.


---

## 5. The self corpus

**Ouroboros, graded on changes to Ouroboros.** Thirty tasks, each one a commit from this
repository's own history. The agent is given the commit's message and the titles of the
tests that commit added; it works in a clone of this repository whose history stops at the
commit's **parent**; and it is graded by taking its change as a diff, applying that diff to
a fresh tree at the parent, restoring those tests from the history, and running them.
Nobody wrote an assertion and nobody wrote an answer key — the history is both.

Run it, and what every flag means: [bench/self/README.md](../bench/self/README.md). The
extraction policy and the decisions behind it: [SELF.md §S0](SELF.md).

### What it measures, and what it does not

**Measured.** Whether the agent, driving a real model, can execute a change this code base
already received, well enough that tests it was never shown accept it, without editing the
tests it *was* given — against a grade nobody tuned.

**The instruction is the commit message, and it frequently describes the change.** It was
written by the person who made it, so it often names the function, the file, or the exact
behaviour. Of the thirty tasks, 28 carry a body beyond the subject and **14 name a file the
solution changes** by path or by name (16 if a module name derived from that path counts).
So the number is about *executing a described change*, not about discovering what to change.
`extract.exs --instruction subject-only` builds the corpus that asks the harder question —
subject, acceptance list and rules, with the body dropped — and no run of it has happened.

**Not measured**, on top of [§1](#1-what-is-measured-and-what-is-not)'s list:

- **Generalisation.** Every task is a change someone already made to *this* code base,
  ranked toward small fixes. A number here says the agent can re-derive a small fix in a
  repository it has the whole of. It does not transfer to another repository and it is not
  comparable to anything.
- **Whether the answer is the commit's answer.** A different change that passes the hidden
  tests without touching the given ones is a pass, which is the intent.
- **The model's own knowledge of this repository.** A model trained on public code may have
  seen these commits. This corpus cannot tell that apart from competence, and it does not
  try to.

### How the grade is protected, and where it still is not

An adversarial review of the first version made it say `pass` three ways without doing any
work. Each is now a control the `$0` selftest runs every time.

| what the review did | what it scored | what changed |
|---|---|---|
| added one new file under `test/support/` whose module body rewrote every restored hidden test at compile time — a file the grader *allows*, because writing your own tests is part of the work | **2/2 pass** | the grade is a **diff applied to a pristine tree**. The agent's `test/`, `mix.exs`, `.formatter.exs`, `deps/` and `_build/` never reach the grading VM |
| added `test: ["cmd true"]` to `mix.exs`, which makes `mix test` exit 0 over any suite | `mix test` on a suite asserting `1 == 2` exited **0** | a diff that touches anything outside `lib/`, `assets/`, `priv/`, `config/`, `docs/`, `README.md` is `refused`; and the verdict is ExUnit's `Result:` line, not the exit status |
| one `bash` call: `git log --all --grep "<the task's own subject>"`, then `git show` for every non-test file of that commit — the workspace was a worktree of this repository, so the answer commit was reachable | **1/1 pass** | the workspace is a **clone that fetches only the base's ancestors** through the `file://` transport. The answer's absence is asserted per task. 0.4 s per task |

Three more rules the same review forced: a completed turn that reports no `usage.cost_usd`
now stops a paid run (it used to count as $0, so a cap could never bind); the modified-test
check reads file *content* against the base commit's blobs rather than asking git, because
`git update-index --assume-unchanged` made both `git status` and `git diff` forget a test
that was sitting there blanked; and `result.json` records every flag, a digest of the
corpus, the client binary's sha256, a `-dirty` `ouro_sha`, and the grader's own command
line.

**Quote a number only with its `ouro_sha`, its `corpus_sha256`, its `model`, and
`run.cheat` absent.** Without those four it is a number from somewhere.

**What is still not defended.** The grading tree compiles and runs the agent's own `lib/`
code, and Elixir runs module bodies at compile time. Restoring the hidden tests *after* that
compile, and re-hashing them against `commit_sha` after the run, removes every way of
rewriting a test. Nothing here can tell ExUnit's summary from one the graded code printed
itself — no reader of the output of a VM the graded code runs in could.

### Two facts about the runtime this work turned up

- **`bench/local`'s key stripping was a no-op.** `Port.open`'s `env` option *extends* the
  caller's environment, so filtering a copy of `System.get_env/0` and passing the remainder
  removed nothing: every model key the operator had exported was in every child. Fixed —
  removals are `{name, false}` — and `bench/local/run.exs` now refuses to start its daemon
  if a dropped name still reaches a child, asserted by spawning `env` through that very
  environment.
- **The native `bash` tool never did leak model keys.** The review raised it as plausible;
  it is not true. `Provider.Native.Exec` gives erlexec `:clear` and rebuilds the child's
  environment from an allowlist, then drops anything `ProcessEnvironment.sensitive?/2`
  recognises, so a provider key is excluded twice over.
  `test/provider/native/bash_environment_test.exs` plants real keys and reads `env` back
  out of the tool. `GITHUB_TOKEN` does not cross either, which is a real limitation of the
  posture rather than an oversight.

### What has actually been run

> **No paid run has happened.** Not a bad one, not a provisional one — none. The corpus,
> the runner and the grader are written and their $0 half is tested; the number needs a
> model key and a spend, which this environment does not have. When it happens it goes
> below whatever it is, and the commitment is the same one §2 makes about Terminal-Bench.

The oracle: the corpus answered with each commit's own files through
[`bench/local`'s scripted model](../bench/local/README.md#the-scripted-model-seam), which
proves the workspaces, the diff collection, the pristine grading tree, the hidden-test
restore, the modified-test check and the budget arithmetic — and nothing about any model.

| | |
|---|---|
| Date | 2026-09-08 |
| Corpus | 30 tasks, extracted from `dev` at `c2d9f55` |
| Result | **30/30**, `$0.0000` spent of a `$1.00` cap |
| Wall | 1 660 s total: 660 s building the thirty workspaces, 625 s building the thirty grading trees, 189 s running the restored tests in them, and 12.3 s of agent turns |
| Work | 67 `write` calls, 67 approvals requested and 67 answered under `--approve-all` |
| Machine | macOS 15, Elixir 1.20.2, OTP 29, `ouro` debug build |

The twelve seconds is the honest shape of an oracle: the scripted model answers instantly,
so 99.3% of that wall clock is sixty trees being built and compiled. Two trees per task is
what the diff-on-a-pristine-tree grade costs — it roughly doubled the oracle's wall clock —
and it is the number to subtract when reading a paid run's, which is why setup, the agent's
turn and grading are timed separately per task. The history-cut clone itself is not the
cost: 0.50 s and 4.3 MiB of packed objects per task, measured over six of the thirty,
against 22 s of `mix compile` in the tree it produces.

`bench/self/selftest.sh` (`make bench-self`) was green on the same machine and day: twelve
phases, 118 assertions, 11 min 43 s, no key and no spend. It proves the verdict rule, the
refusals that come before anything is built, that the oracle's environment carries no
secret, the extractor's two gates against
a fixture history built to trip them, four corpora that are not corpora, and then — against
this repository's own commits — extraction, the oracle at $0, the spend cap, and eight
scripted agents that must not score, three of which are the review's exploits above.

### The paid command

```sh
cd tui && cargo build                        # the client the corpus grades
export OUROBOROS_NATIVE_MODEL=<provider:model>
bench/self/run.sh --spend 5.00               # or --model <provider:model>
```

**Name the model.** The packaged default, `openai_codex:gpt-5.6-sol`, is not one `llm_db`
prices, so a run that does not name a model is refused before the first task — checked on
2026-09-08 by asking this checkout's own `Provider.Native.Cost.cost_usd/5`, which answered
`nil` for it and a number for `anthropic:claude-sonnet-4-5` and `openai:gpt-4o`. The refusal
is deliberate: an unpriced model reports no `cost_usd`, a running total of nothing never
reaches a cap, and `--spend` would be decoration.

`--spend` is required and a model this node cannot price is refused before the first task.
The total is checked between tasks, so **one task can overshoot the cap by its own cost**;
what bounds a single task is its `timeout_secs`. A completed turn that reports no
`usage.cost_usd` stops the run at exit 64 rather than counting as $0, because a total that
cannot move is not a cap. Results, including every trajectory and the exact diff each task
was graded on, land under `bench/self/results/<timestamp>/` and are gitignored.

### The noise expectation

*(empty)*

Two runs of the same model over the same corpus will not produce the same number: the model
is sampled, and this repository has load-sensitive suites. This section records the observed
difference after the **first pair** of paid runs — same model, same corpus, back to back —
and every number in it will be measured rather than guessed. A tolerance chosen before the
measurement is a tolerance chosen to be met.
