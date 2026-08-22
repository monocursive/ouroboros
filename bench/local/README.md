# The local eval corpus

Seventeen small, deterministic tasks that drive the native agent end to end — through the
real `ouro run` client, against a real spawned runtime — with **no model key, no network,
no docker, and no spend**.

```sh
make bench-local                    # or:
bench/local/run.sh                  # every task
bench/local/run.sh --filter bash    # only tasks whose id contains "bash"
bench/local/run.sh --keep           # leave the scratch dir behind to inspect
bench/local/run.sh --ouro PATH      # grade a specific client binary
```

Prerequisites: Elixir, and a built client (`cd tui && cargo build`). `run.sh` runs
`mix compile` for you and refuses with a message if the client is missing. Exit status is
non-zero if any task fails.

This is **not** Terminal-Bench and produces no comparable number. It measures whether the
plumbing holds, not whether a model is any good — see [docs/BENCHMARKS.md](../../docs/BENCHMARKS.md)
for what each of the two measures and what neither does.

## What a run does

1. Compiles `model/bench_script_model.ex` into the project's own `ebin`.
2. Writes every task's scripted responses, plus an `index.json`, into a scratch directory.
3. Starts one `ouro --dev daemon` on a scratch `OUROBOROS_DATA_DIR` (mode 0700) with a
   scratch `XDG_CONFIG_HOME`, so nothing in the operator's config or data can change the
   result, and with every known model-provider API key **removed from the environment**.
4. For each task: copies the fixture workspace to scratch, runs
   `ouro run "<instruction>" --provider native --workspace … --approval-mode … --stream-json --timeout …`,
   saves the NDJSON trajectory and the result object, then runs the task's `check.sh`.
5. Prints the table, stops the daemon, removes the scratch directory, and exits non-zero
   on any failure.

One daemon serves every task, which is what `ouro run` is designed for: a script calling
it in a loop should pay one cold start, not one per prompt.

## The scripted-model seam

`Ouroboros.Provider.Native.Model` is a one-callback behaviour, and
`config :ouroboros, :native_model_module` chooses the implementation. That is node
configuration on purpose — a request that could name the module the runtime calls would be
a way to run arbitrary code by opening a session — so the runner sets it on the daemon's
command line:

```
ELIXIR_ERL_OPTIONS="-ouroboros native_model_module 'Elixir.Ouroboros.Bench.ScriptModel'"
OUROBOROS_NATIVE_MODEL="bench-script:/path/to/scratch/scripts"
```

`test/support/native_model_script.ex` does the same thing for the unit tests, but encodes
an `Agent` pid in the model spec, which only works when the test and the loop share a
BEAM. The corpus drives a separate daemon, so its script has to be a file.

**Why the module is compiled into the project's `ebin`.** Mix prunes the code path to the
applications the project depends on, so a `-pa` directory and an `ERL_LIBS` application
are both gone by the time `mix run --no-halt` boots (verified on Elixir 1.20.2 / OTP 29).
The project's own ebin is the one path that survives. It is a build artifact of the bench:
`mix clean` removes it, and nothing in `lib/` refers to it.

**How a request finds its script.** `index.json` pairs each instruction with a script
file, and a request matches the entry whose instruction the user message *contains* —
because the runtime does not hand the model the prompt as typed, it wraps it in an
`<ouroboros-runtime version="1">` envelope. The runner refuses a corpus in which one
instruction contains another, which is what makes the longest match unambiguous. The Nth
model call of a turn takes the Nth response, where N is the number of assistant messages
already in the conversation — stateless, so nothing needs resetting between tasks.

## Writing a task

```
tasks/<nn-name>/
  task.json     title, exercises, instruction, approval_mode, approve_all, timeout_secs
  script.json   {"instruction": "...", "responses": [[chunk, …], …]}
  workspace/    the fixture, copied fresh for every run
  check.sh      executable; sources $BENCH_LIB/assert.sh
```

Chunk types are the normalized vocabulary of `Ouroboros.Provider.Native.Model`:

```json
{"type": "text",      "text": "..."}
{"type": "thinking",  "text": "..."}
{"type": "tool_call", "id": "c1", "name": "read", "input": {"path": "lib/a.ex"}}
{"type": "usage",     "input_tokens": 120, "output_tokens": 18}
{"type": "finish",    "reason": "stop"}
```

`run.exs` validates every script before starting a daemon, so a typo is a corpus error
with a task name on it rather than a turn that mysteriously answers "(bench script
exhausted)".

`check.sh` gets a shell-sourceable `facts.env` — no `jq`, no `python3`, no dependency —
holding `BENCH_STATUS`, `BENCH_EXIT`, `BENCH_ERROR`, `BENCH_TOOLS`, `BENCH_TOOL_ERRORS`,
`BENCH_EVENTS`, `BENCH_APPROVALS_REQUESTED`/`_ANSWERED`, `BENCH_TOTAL_TOKENS`,
`BENCH_FILES_CHANGED`, `BENCH_DURATION_MS`, `BENCH_WORKSPACE`, `BENCH_RESULT`, and
`BENCH_TRAJECTORY`. `lib/assert.sh` provides `expect_status`, `expect_tool`,
`expect_tool_error`, `expect_approvals`, `expect_file_contains`, `expect_trajectory_contains`
and friends; every assertion records a failure and keeps going, so one run reports every
broken expectation.

Two things to avoid when scripting: repeating a `(tool name, input)` pair three times in
one turn trips the loop's doom-loop guard and fails the turn; and a tool that needs the
file read first (`edit`, `apply_patch` on an update or delete) must have a `read` earlier
in the same script.

## What the corpus covers

| task | exercises |
|---|---|
| 01-read | `read`; a read is never gated |
| 02-write-approved | `write` under `prompt` with `--approve-all` |
| 03-write-denied | the same write without it: refused in band, nothing on disk |
| 04-edit-after-read | `read` then `edit` under `auto_edit`, no approval |
| 05-edit-without-read | the read-before-edit guard refusing, file untouched |
| 06-apply-patch-update | V4A `*** Update File:` after a read |
| 07-apply-patch-add | V4A `*** Add File:`, gated as a write |
| 08-bash | an approved command, its output, its uncheckpointed side effect |
| 09-bash-timeout | a 45 s sleep inside a 2 s budget, killed and reported |
| 10-grep | `grep`, asserting matches rather than which engine answered |
| 11-glob-ls | `glob` and `ls`, two tool calls in one turn |
| 12-code-intel-no-server | `code_intel` failing in band, agent routing around it |
| 13-ask-user-declined | a question nobody can answer; not an error |
| 14-ask-user-acknowledged | an approved question with no text; asked even under `auto_approve` |
| 15-plan | `plan` publishing `plan_updated` |
| 16-unknown-tool | a hallucinated tool name refused by name, not dropped |
| 17-auto-edit-boundary | `auto_edit` writes unasked but still gates a command |

## Two things this corpus found

Both are recorded in the task checks rather than hidden, and neither is fixed here — this
slice adds no code under `lib/`.

- **`files_changed` names one changed file twice.** `ouro run` collects the `file_change`
  payload's absolute `path` *and* the relative path it parses out of the unified diff
  header. `02-write-approved` pins the count at 2; the other write tasks assert
  containment, so only that one task changes if it is ever deduplicated.
- **`code_intel` is unreachable for an ordinary session.**
  `Ouroboros.CodeIntel.Registry.resolve/2` takes the workspace root from the node's
  `:workspace_allowed_roots`, which is empty on a default runtime and is *not* populated
  by admitting a session's workspace. Every path is therefore judged
  `{:outside_workspace, …}` before a language is considered, independently of whether any
  language server is installed. `12-code-intel-no-server` asserts the contract (in-band,
  bounded, non-fatal) and not the message, so fixing this does not turn the task red.
