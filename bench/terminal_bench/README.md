# Ouroboros as a Terminal-Bench agent

An adapter that plugs `Ouroboros.Provider.Native` into **Terminal-Bench 2.1** so a number
can be produced and published. No number exists yet — see
[Verification status](#verification-status) for exactly what has and has not been run,
and [docs/BENCHMARKS.md](../../docs/BENCHMARKS.md) for the standing statement.

## What you need

| | |
|---|---|
| **docker** | Harbor runs each task in a container. Not required for this adapter's own tests. |
| **a model key** | One, for the provider your `-m` names. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, … |
| **a Linux `ouro`** | Built on Linux. **ERTS does not cross-compile**, so a Mac cannot produce it. |
| **harbor** | `uv tool install harbor` (or `"harbor[daytona]"` for the hosted sandbox). Python ≥ 3.12. |

### Building the Linux client

On a Linux host or in CI, from a checkout:

```sh
make dist          # -> dist/ouro-<version>-x86_64-unknown-linux-gnu
```

Then, wherever you run Harbor:

```sh
export OURO_LINUX_DIST=/path/to/ouro-<version>-x86_64-unknown-linux-gnu
```

A `.tar.gz`/`.tgz`/`.tar` containing the binary works too; the install script tries `tar`
first and falls back to treating the artifact as the binary. The architecture must match
the task image — Terminal-Bench images are `linux/amd64` unless a task says otherwise.

## Running it

```sh
export OURO_LINUX_DIST=/path/to/ouro-0.1.0-x86_64-unknown-linux-gnu
export ANTHROPIC_API_KEY=...

cd bench/terminal_bench

# one task, to see it work at all
harbor run -d terminal-bench/terminal-bench-2-1 \
  --agent ouroboros_agent.agent:OuroborosAgent \
  -m anthropic/claude-opus-4-1 \
  -t hello-world

# the whole set, five attempts per task, which is what the leaderboard asks for
harbor run -d terminal-bench/terminal-bench-2-1 \
  --agent ouroboros_agent.agent:OuroborosAgent \
  -m anthropic/claude-opus-4-1 \
  -k 5 -n 8
```

`--agent` takes an import path directly (`module.path:ClassName`);
`--agent-import-path` is the deprecated spelling and still works. Run from this directory
so `ouroboros_agent` is importable, or add it to `PYTHONPATH`.

Agent kwargs, via `--ak key=value`:

| kwarg | default | what it is |
|---|---|---|
| `workspace` | `/app` | the directory `ouro run --workspace` is pointed at, and the `cwd` for the exec. **UNVERIFIED** — inferred from convention, not read out of a task image. |
| `dist_path` | `$OURO_LINUX_DIST` | the Linux artifact, if you would rather not use the variable |
| `timeout_secs` | `900` | the client's own turn budget; Harbor's `[agent].timeout_sec` still applies on top |

## Expected cost

**Not measured — this adapter has never made a paid API call.** What can be said honestly:
Terminal-Bench 2.1 is 89 tasks, and a leaderboard submission is 5 attempts each, so a
full submission is 445 agent-hours-of-container and 445 model transcripts. Published
leaderboard rows carry a Cost column in the low hundreds of dollars for a frontier model
at that shape. Budget accordingly, start with `-t <one task>`, and read the real number
off your own first run rather than off this paragraph.

Ouroboros itself adds no markup: keys are yours, `Native.Cost` computes cost from
`llm_db` pricing, and the adapter reports it to Harbor as `AgentContext.cost_usd`.

## How it works

```
harbor run
  └─ OuroborosAgent.install(environment)
       ├─ upload_file($OURO_LINUX_DIST -> /opt/ouroboros-dist)
       ├─ exec_as_root(install_script())      unpack, chmod, `ouro version`
       └─ exec_as_root(daemon_command())      `ouro daemon` — spawn, publish, exit
  └─ OuroborosAgent.run(instruction, environment, context)
       ├─ environment.exec(run_command())     `ouro run … --stream-json > /logs/agent/stream.ndjson`
       ├─ parse_stream()                      -> tokens, cost, status, tools, approvals
       ├─ write trajectory.ndjson / trajectory.json / ouro-run.json into logs_dir
       ├─ populate context (n_input_tokens, n_output_tokens, n_cache_tokens, cost_usd, metadata)
       └─ environment.exec(stop_command())    best effort, to flush journals
  └─ Harbor copies tests/ into the container and runs tests/test.sh
```

The exact turn:

```sh
OUROBOROS_DATA_DIR=/opt/ouroboros/data /opt/ouroboros/ouro run '<instruction>' \
  --provider native --approve-all --stream-json --workspace /app --timeout 900
```

Six decisions worth knowing:

- **Nothing is built in the container.** ERTS does not cross-compile and a task image is
  not a build host. The artifact is built on Linux and uploaded.
- **Nothing is fetched.** No curl, no npm, no package index — a task may run with its
  network policy closed, and an agent that needs a download to install itself fails those
  tasks for a reason that has nothing to do with the model. There is a test for this.
- **`ouro --dev` is never used.** It runs `mix run --no-halt` in a checkout, and there is
  no checkout here. The packaged binary carries the release inside it, so `ouro daemon`
  spawns and exits — one cold start for the trial, not one per turn.
- **`--approve-all`, because there is no approver at a pipe.** Without it `ouro run`
  denies every approval with a stated reason, which would score zero for a reason that is
  not the model's fault.
- **`--stream-json`, not `--json`.** It is a superset: the normalised events *and* the
  result object, so the trajectory and the numbers come out of one invocation and cannot
  disagree.
- **A failed turn is not an exception.** `run()` uses `environment.exec` rather than
  Harbor's raising `exec_as_agent`, so a turn that ends `failed`, `interrupted` or
  `timeout` is recorded and the trial is still scored by the task's own tests. `install()`
  does raise, because an agent that cannot install has nothing to say.

### Success and failure are not ours

Harbor scores a trial by copying the task's `tests/` into the container after the agent
stops and running `tests/test.sh`, which writes `/logs/verifier/reward.txt`. This adapter
never reports pass or fail. It reports what the run cost and whether the client itself
crashed — `OuroRunResult.crashed` is true only for `lost`, `refused`, and an unparseable
run, never for a turn that merely went badly.

### Trajectories

Two files land in the trial's `agent/` directory:

- **`trajectory.ndjson`** — the raw `ouro run --stream-json` output, byte for byte. This
  is the trajectory of record: the golden-pinned event contract from `docs/TUI.md` §2.5,
  not a rendering of it.
- **`trajectory.json`** — a summary: tool calls paired to results by `call_id`, assistant
  text, approvals, plan updates, totals, and the result object. Its `schema` field says
  `ouroboros-run-stream/1`.

**ATIF is not emitted, and `SUPPORTS_ATIF = False`.** Harbor's interchange format was
`ATIF-v1.7` when this was written, and the pydantic models were not available to validate
against. A file labelled `ATIF-v1.7` that nobody checked against the v1.7 models is worse
than an unlabelled file — it is a claim nobody verified. Converting is a small job for
whoever runs the first submission, against the `harbor.models.trajectories` models of the
version they install; `trajectory.py` is the one place to change.

### Keys

Exactly one key reaches the container: the one named by the provider half of the model
spec, and only if the host has it set. It is passed on the `ouro run` exec rather than on
the daemon, so it spends as little time in a long-lived process environment as this design
allows. A container that received every key in the operator's shell is a container one bad
task can exfiltrate from.

## Submitting

**Community submissions to Terminal-Bench 2.1 were closed when this was written** — the
`harbor-framework/terminal-bench-2-1` README says only maintainer-run submissions are
added. Check before planning around it. The documented flow, for when it reopens:

```sh
harbor auth login
harbor run -d terminal-bench/terminal-bench-2-1 \
  --agent ouroboros_agent.agent:OuroborosAgent \
  -m <provider/model> --ak reasoning_effort=<effort> \
  -k 5 -n <concurrency> --upload --public

git clone https://github.com/harbor-framework/terminal-bench-2-1.git
cd terminal-bench-2-1/leaderboard
uv run lb submit https://hub.harborframework.com/jobs/<uuid>
```

Submissions may not modify timeouts or resources. CI validates, maintainers review the
trajectories, and a merge adds the row. Whatever the number is, it goes in
[docs/BENCHMARKS.md](../../docs/BENCHMARKS.md).

## Verification status

The honesty invariant applies to this file. Split plainly:

**Verified here, by running it** (macOS 15, Elixir 1.20.2, OTP 29, Python 3.14.7):

- All 64 unit tests: `bench/terminal_bench/run_tests.sh` → `Ran 64 tests … OK`.
- The **install script**, executed for real by `sh` against a temp directory: a bare fake
  binary, a `.tar.gz` with the binary nested inside, a missing artifact, an empty
  artifact, and an archive containing no `ouro` — each with the expected exit status and
  message. This is the container install path minus the container.
- The **result mapping**, against `tests/fixtures/completed_stream.ndjson` and
  `completed_result.json`, which are the unedited output of a real
  `ouro run --stream-json` captured from `bench/local/run.sh --filter 17-auto-edit --keep`
  on 2026-08-23. Tokens, cost, iterations, tools, approvals, `files_changed`
  deduplication, and every documented exit code.
- The **quoting** of a hostile instruction, by running the generated command line under
  `sh` with the binary replaced by `printf` and asserting nothing executed.
- The **trajectory summary**, on that same real stream.
- The **agent class's shape**, by parsing `agent.py`: the four abstract members, `async`
  on `install`/`run`, `run` returning `None`, `staticmethod name()`, `SUPPORTS_ATIF` false,
  `environment.exec` rather than the raising helper in `run`, `raise` in `install`, no
  build command anywhere.

**Not verified — on paper only:**

- **`agent.py` has never been imported or executed.** `harbor` was not installed, so the
  class has never been constructed and no method has ever run. The interface it targets
  was read from the Harbor sources (below), not exercised.
- **No container has ever been started.** No docker on the machine this was written on.
- **No Linux `ouro` dist exists.** ERTS does not cross-compile and this is a Mac, so the
  upload-and-unpack path has been tested against fake binaries, never a real one.
- **No model call has ever been made through this adapter**, so no cost figure and no
  latency figure here is measured.
- **`/app` as the task working directory** is a convention, not something read out of a
  task image.
- The `BaseInstalledAgent` constructor's private attribute names (`_model_name`,
  `_extra_env`) are read defensively with `getattr`, because they were taken from the
  source rather than from a run.

**The first person to run this should expect to debug it.** Start with one task.

## Primary sources for the harness interface

Terminal-Bench 2.x runs on **Harbor**, not on the `terminal-bench` package — whose last
release (0.2.18, 2025-09-26) predates 2.0 and whose
`terminal_bench.agents.base_agent.BaseAgent` / `AgentResult` / `TmuxSession` API is 1.x
only. The repositories were renamed under a new org; the old paths redirect.

| what | where |
|---|---|
| `BaseAgent` — `name`/`version`/`setup`/`run`, capability class-vars | [`src/harbor/agents/base.py`](https://raw.githubusercontent.com/harbor-framework/harbor/main/src/harbor/agents/base.py) |
| `BaseInstalledAgent` — `install`, `exec_as_root`/`exec_as_agent`, `ensure_system_dependencies` | [`src/harbor/agents/installed/base.py`](https://raw.githubusercontent.com/harbor-framework/harbor/main/src/harbor/agents/installed/base.py) |
| `AgentContext` — `n_input_tokens`, `n_cache_tokens`, `n_output_tokens`, `cost_usd`, `metadata` | [`src/harbor/models/agent/context.py`](https://raw.githubusercontent.com/harbor-framework/harbor/main/src/harbor/models/agent/context.py) |
| `BaseEnvironment` — `exec`/`upload_file`/`upload_dir`, `ExecResult` | [`src/harbor/environments/base.py`](https://raw.githubusercontent.com/harbor-framework/harbor/main/src/harbor/environments/base.py) |
| `--agent` taking an import path; `--ak`, `-k`, `-n` | [`src/harbor/cli/jobs.py`](https://raw.githubusercontent.com/harbor-framework/harbor/main/src/harbor/cli/jobs.py) |
| A real installed adapter, for the install idiom | [`src/harbor/agents/installed/claude_code.py`](https://raw.githubusercontent.com/harbor-framework/harbor/main/src/harbor/agents/installed/claude_code.py) |
| `/logs/agent`, `/logs/verifier`, `/tests`; `tests/test.sh` writing `reward.txt` | [harborframework.com/docs/tasks](https://harborframework.com/docs/tasks) |
| ATIF trajectory format | [harborframework.com/docs/agents/trajectory-format](https://harborframework.com/docs/agents/trajectory-format), [RFC 0001](https://github.com/harbor-framework/harbor/blob/main/rfcs/0001-trajectory-format.md) |
| Dataset id `terminal-bench/terminal-bench-2-1`, 89 tasks, submission flow, "community submissions are currently closed" | [`harbor-framework/terminal-bench-2-1` README](https://raw.githubusercontent.com/harbor-framework/terminal-bench-2-1/main/README.md) |
| The board this is aimed at | [tbench.ai/leaderboard/terminal-bench/2.1](https://www.tbench.ai/leaderboard/terminal-bench/2.1) |

Read on 2026-08-23, against `harbor` 0.22.0. Harbor releases often; if `--agent` or
`AgentContext` has moved, the source files above are the answer, not this table.

## Tests

```sh
bench/terminal_bench/run_tests.sh        # 64 tests, no docker, no key, no harbor
```

They import only the modules that do not import Harbor, which is the whole reason the
package is split that way.
