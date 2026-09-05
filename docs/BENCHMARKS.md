# Benchmarks

Status: written 2026-08-23. Two things live here, and they measure different things.

> **There is no Terminal-Bench number for Ouroboros.** Not a bad one, not a provisional
> one — none. The adapter that would produce one is written and its decidable half is
> tested; the run needs a Linux build, a model key, and docker, and has not happened.
> When it happens the number goes in [§4](#4-the-number-when-there-is-one) whatever it
> is. That is the commitment `AGENT_EXPERIENCE.md` §10 makes, and this file is where it
> is kept.

| | [Terminal-Bench 2.1](#2-terminal-bench-21) | [The local corpus](#3-the-local-corpus) |
|---|---|---|
| Question | can the agent solve real terminal work? | does the agent's plumbing hold? |
| Model | a real one, paid for | a scripted one, free |
| Needs | docker, a key, a Linux `ouro` | Elixir and a built client |
| Runtime | hours | ~5 seconds |
| Comparable to other agents | yes, that is the point | no, and it never will be |
| Run it | `bench/terminal_bench/README.md` | `make bench-local` |
| Status here | never run | **17/17 green** on macOS 15 / Elixir 1.20.2 / OTP 29 |

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

**Measured by neither.**

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
export OURO_LINUX_DIST=/path/to/ouro-<version>-x86_64-unknown-linux-gnu   # `make dist` on Linux
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

1. **A Linux `ouro`.** ERTS does not cross-compile. `make dist` produces a client for the
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
