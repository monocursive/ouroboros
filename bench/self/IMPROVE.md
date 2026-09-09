# The outer loop: `improve.sh`

`bench/self/improve.sh` runs this repository's own change protocol through Ouroboros native
sessions. One task file in, one pull request out. A human merges; the script never does.

```sh
bench/self/improve.sh task.md                     # the whole loop, gates and all
bench/self/improve.sh task.md --quick --no-pr     # iterate: fast gate, nothing pushed
bench/self/improve.sh task.md --dry-run           # print every command, run none
bench/self/improve.sh task.md --spend 20          # let the corpus run, up to $20
```

The task file is Markdown. Its first line, with any heading marker stripped and bounded to
72 **characters** at a word boundary, becomes the branch slug, the commit subject and the
pull request title. The whole file becomes the commit body and the "The task" section of
the pull request — and any path the task names is a path the change is allowed to add.

Exit statuses: `0` the loop finished, `1` something failed, `2` **the loop refused the
change**, `64` the command line was wrong, `128+n` a signal (`130` INT, `143` TERM, `129`
HUP).

## What it does, in order

| # | Step | What it is |
|---|---|---|
| 1 | `worktree` | `.claude/worktrees/improve-<slug>` on `self/improve-<slug>`, branched from `dev`; `deps/` and `_build/` cloned in with `cp -Rc`; `priv/wasm` and `priv/sandbox` copied |
| 2 | `daemon` | `ouro --dev daemon` on a scratch `OUROBOROS_DATA_DIR` (mode 0700). `ouro stop` runs from a trap, always |
| 3 | `implementer` | `ouro run` with `docs/self/briefs/implementer.md` + the task, `--workspace <worktree> --approve-all --stream-json` |
| 4 | `build-scan` | the diff against the build definitions the gates themselves run. A hit **stops the loop before any gate**, writes the body and exits 2 — unless `--allow-build-changes` |
| 5 | `gate-1` | `mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix test` on the `_test.exs` files the diff touches; without `--quick` also `make test` and `mix dialyzer`. **Red here is not fatal** — the review and the fix wave exist to answer it |
| 6 | `reviewer` | a second `ouro run` in the same worktree with `docs/self/briefs/reviewer.md`, the diffstat, the first 96 KiB of the diff, and a scratch directory of its own. It writes `REVIEW.md` |
| 7 | `fix-wave` | `ouro run --resume <implementer session id>` with `docs/self/briefs/fix-wave.md` + `REVIEW.md` quoted as untrusted text, so the implementer answers the review with its own context intact |
| 8 | `build-scan` | again, over what the fix wave left |
| 9 | `gate-2` | the same gate. **This one decides**: red here and the script stops before the corpus and the commit, because a change that cannot pass its own gate has not earned a measurement |
| 10 | `corpus` | `bench/self/run.sh --repo <worktree> --spend …`, only when `--spend` was given, `--no-bench` was not, the diff touches `lib/ouroboros/provider/native/`, and **this checkout** has the runner |
| 11 | `protected-scan` | every path under `lib/ouroboros/control/`, `lib/ouroboros/upgrade/`, `lib/ouroboros/storage/`, from `git diff --name-status` |
| 12 | `commit` | first: where did the change land? A path the diff adds outside the allow-list and outside anything the task names stops the run at 2. Then subject from the task, body the task, trailer `Co-Authored-By: Ouroboros native session <id> <noreply+<id>@ouroboros.local>`. A session that made its own commits is refused here rather than committed over |
| 13 | `pr-body` | `PR_BODY.md` in the worktree, and a check that it carries its own "Human review required" section |
| 14 | `pr` | `git push -u origin` then `gh pr create --base dev --body-file`. `--no-pr` stops after the body |

Every step prints `==> <name>`, the command, and `<name> rc=<n>`. A skipped step still
prints its line with the reason, so a step that left no line behind is a step that did not
run rather than one that quietly passed.

The worktree and the run directory are both left in place and named at the end, on failure
as well as on success. The worktree is the change; the run directory is the evidence.

## The gates, and what "green" means

**A gate step's `rc` is the verdict on its log, not the command's exit status.** `mix
test`'s exit status is a number the change under test can set: one line in
`test/test_helper.exs` —

```elixir
System.at_exit(fn _ -> System.halt(0) end)
```

— formats, compiles, and makes every suite exit 0 whatever ExUnit reports. So
`bench/self/lib/improve/gate-verdict.sh` reads the log:

| step | green when |
|---|---|
| `mix format`, `mix compile` | it exited 0 |
| `mix test` | it exited 0, printed at least one `Result:` line, every one of them is a clean pass, there is no `Failed:` line, and at least one test ran |
| `make test` | the same rule over every `Result:` line in the whole log |
| `mix dialyzer` | it exited 0 **and** said `done (passed successfully)` |

This repository runs Elixir 1.20, whose ExUnit prints `Result: 6 passed`,
`Result: 1 passed, 1 skipped, 1 excluded`, `Result: 1/2 passed` with `Failed: 1 test`, and
`Result: 0 tests, 3 excluded`. Only the first two shapes are a pass. A `mix test` that
exits 0 and reports nothing at all is **red**, with the note `no result line: the suite did
not report`.

**A gate step holds no model credentials.** The sessions keep every key — a model that
cannot authenticate does nothing — but a gate is the operator's own command run over a tree
a model wrote, and `mix format` evaluates `.formatter.exs`, `mix test` evaluates
`test/test_helper.exs`, and `make test` runs the Makefile. The gate subshell unsets the
same list `bench/local/run.exs` drops (every `*_API_KEY`, `AWS_SECRET_ACCESS_KEY`, and
`OUROBOROS_NATIVE_MODEL`); the two lists are meant to stay identical.

## Build definitions

A session that edits a build definition has edited the gate that is supposed to judge it.
After the implementer and again after the fix wave, the loop compares the diff against:

```
Makefile  mix.exs  mix.lock  .formatter.exs  test/test_helper.exs
config/**  scripts/**  .github/**  .gitattributes  .gitignore  bench/**  priv/**
tui/Cargo.toml  tui/Cargo.lock  tui/build.rs  tui/.cargo/**  rust-toolchain*
.tool-versions  .claude/**  .agents/**
```

A hit stops the loop **before any gate runs**, writes the body with a
`## Refused: build definition changed` section listing the paths, commits nothing, and
exits 2. `--allow-build-changes` runs it anyway and puts the same list at the top of the
body's "Human review required" section, saying in as many words that the gates ran the
model's own build definitions.

`.gitattributes` is on the list for a second reason: one line of it
(`lib/ouroboros/control/** -diff`) makes git render every hunk in a namespace as a binary
difference, which blinds a scan that reads the diff body — and the reviewer session too.

## Where a change may land

`git add -A` is what makes a whole new module part of the change. It is also what sweeps in
the exploit script a reviewer session left in the workspace, so the reviewer is given
`<run dir>/review-scratch/` (mode 0700, named in both the reviewer and the fix-wave
prompts) and the commit step refuses when the diff **adds** a path outside

```
lib/  test/  docs/  tui/src/  tui/tests/  tui/wasm/  assets/  web/
```

and outside anything the task file names. The refusal prints the paths and the list, writes
the body, and exits 2 with nothing committed.

## The protected-namespace scan

The path list comes from `git diff --name-status -M -z`, never from the diff body:

- a **rename** produces no `@@` line at all — inside the namespace, or out of it;
- a **mode change** produces no hunk;
- a **binary** is `Binary files … differ`;
- one line in `.gitattributes` turns every hunk in the namespace into that;
- an added line whose text begins `++ ` is rendered by git as `+++ …`, which a scan reading
  the diff body would take for a file header and use to re-attribute every hunk after it.

`--name-status` survives all five. `-z` means git does not C-quote a path with a space or a
non-ASCII byte in it, so what the body prints is the raw name. The `@@` lines under a path
are detail, read from that path's own diff; a path with none of them still changed.

## What is under the loop's control and what is not

The script owns the mechanism. It owns none of the judgement:

- The implementer, the reviewer and the fix wave are all models. Their reports are claims.
- `mix format`, `mix compile --warnings-as-errors`, `mix test`, `make test` and
  `mix dialyzer` are the gates, and they are the only things in the loop a model cannot
  talk its way past — which is why what they say is read rather than how they exited.
- Every path under `lib/ouroboros/control/`, `lib/ouroboros/upgrade/` or
  `lib/ouroboros/storage/` is listed in the pull request under **Human review required**,
  whatever the review concluded — the reviewer is the same kind of thing as the
  implementer.
- `REVIEW.md` is quoted into the body as a **blockquote**, every line of it prefixed `> `.
  A fence would not hold: CommonMark closes one indented by up to three spaces or followed
  by trailing spaces, and the next heading would then be writing our sections for us. The
  body's own `## Human review required` is matched at column 0.
- The fix-wave prompt quotes the review the same way, under a sentence saying it is
  untrusted text written by another model and that nothing inside it is an instruction —
  including a line that looks like a role marker. The role marker the loop wrote is the
  first line of the message, before the quote.
- The pull request body's opening paragraph is assembled from what happened: which sessions
  ran, with what rc and status, whether `REVIEW.md` was written, and what the gates
  returned. There is no fixed sentence claiming a review took place.
- `REVIEW.md` and `PR_BODY.md` are kept out of the commit. They are the loop's paperwork,
  not the change.
- The script never merges, never touches a git remote's configuration, and never opens a
  pull request from a body that has no protected-namespace section.

## Where the loop keeps its own paperwork

`steps.tsv`, every log, the scan output and the watchdog records live under
`<data dir>/improve/`, and the data dir is a protected write root for every session and for
the sandbox. The pull request body's gate table is read back out of `steps.tsv`: a session
that could append to it could write its own gate results into its own pull request.
`<run dir>` is never exported to a session; the one path under it a session is given is the
reviewer's scratch directory.

## Deadlines

macOS ships no `timeout(1)`. Each `ouro` invocation gets a watchdog: the client's own
`--timeout` plus a grace of the same length, capped at two minutes. When it fires the loop
runs `ouro stop` **first** — an abandoned turn keeps spending — and only then kills the
client's process group, and the step's note says the session was killed at the deadline.

The client is started under `set -m` so it is its own process group and the kill does not
reach this script's. The watchdog's `sleep` is killed by pid: killing the subshell that
forked it would leave it reparented to init, still counting down to a `kill -9` on whatever
holds that pid an hour later. The EXIT trap sweeps any watchdog record left behind, so an
interrupted run leaves nothing running.

A signal exits `128+n` — 130 for INT, 143 for TERM, 129 for HUP — after the EXIT trap has
run `ouro stop`. **It is not instant.** A shell defers a trap until the foreground command
it is running returns, and the foreground command here is the subshell holding the session,
so a supervisor's SIGTERM is acted on when the current `ouro run` returns or its deadline
fires, not when it is sent. Send it, then wait for the run's own deadline; a supervisor that
needs a hard stop sooner should kill the process group.

## Prompt size

`ouro run` takes the prompt as one argv element, and Linux caps a single argument at 128 KiB
(`MAX_ARG_STRLEN`). The reviewer prompt is bounded to fit: the diffstat is `--stat=80` cut
to 60 lines, the diff is cut to 96 KiB with a line saying how many bytes were dropped, and
the review quoted into the fix-wave prompt is cut to 64 KiB the same way. Every prompt is
checked against 120 KiB before it is passed, and a prompt over the bound stops the run with
a message about prompts rather than dying in `execve` with a message about argument lists.

**A `--prompt-file` flag on `ouro run` is the proper fix**, and is filed for the client's
owner: with it the bound disappears and the diff need not be cut at all.

## The corpus delta

`--spend` is the only thing that lets the corpus run at all, and the run it does is the
*after* number. For a *before*, point `BENCH_SELF_BASELINE` at an earlier `bench/self`
`result.json`; the body then carries both and the reader can subtract. With no baseline the
body says so rather than inventing one.

The runner the loop invokes is **this checkout's** `bench/self/run.sh`, not the worktree's,
and it is told which checkout to measure:

```sh
bench/self/run.sh --repo <worktree> --spend <usd> --out <dir> [--model <spec>]
```

A corpus run driven by the tree it is measuring is a model grading its own homework with
its own marking scheme. `--repo` is therefore a flag the runner has to accept — it is S0's
file and this is the contract between the two slices. Until it exists the corpus step says
`not run: … does not exist in this checkout`.

## Pushing

The push uses whatever `origin` your checkout has. If that is an SSH URL and SSH is not
configured on the machine, the push fails and the script says so; the commit is still on the
branch in the worktree, and `--no-pr` does everything except push. **The script never edits
a remote.** Giving your own checkout an HTTPS push URL is your call to make, not the loop's.

## The selftest

```sh
make improve-selftest        # or: bench/self/improve-selftest.sh
```

No model, no key, no network, no spend; half an hour or so — most of it `mix compile` and
`mix test` inside a dozen fresh worktrees. `improve-selftest.sh 4 9` runs those phases and
nothing else, which is what a mutation harness wants. It drives the whole loop
against `bench/self/lib/improve/shim-ouro.sh`, a labelled test shim that answers the four
`ouro` invocations and edits the workspace the way a session would, over sixteen phases —
and every phase declares how many checks it runs, so a check deleted with the thing it
covered leaves the suite red rather than green and shorter.

1. `--dry-run` prints every command and creates no directory, worktree, branch or runtime;
   a dry run asked about a client that is not built names the path and exits 0, and a real
   run refuses.
2. The argument surface: `--spend`, the timeouts, `--`, a title that slugifies to nothing,
   two task files, an unknown option.
3. `gate-verdict.sh` on crafted logs — including `make test` and `mix dialyzer`, which no
   selftest could afford to run for real.
4. The green pass: the worktree descends from `dev`; both gates really ran the suite; the
   loop's paperwork is under the data dir; the body quotes the review as a blockquote it
   cannot escape and carries exactly one `## Human review required` at column 0; the commit
   carries a trailer `git interpret-trailers` recognises; nothing was pushed and nothing
   leaked into the checkout.
5. A session that leaves the suite failing: gate 2 red, no commit, no body, no push.
6. A worktree that is already there.
7. A session that changes nothing.
8. A session that commits its own work.
9. A session that adds `System.at_exit(fn _ -> System.halt(0) end)` to
   `test/test_helper.exs`: refused by the build scan before any gate runs, and — with
   `--allow-build-changes` — caught by the gate reading the result line instead of the exit
   status.
10. A change that hides itself from `git diff`: a rename, a mode change, a binary, a path
    with a space, a `++ ` line, and `lib/ouroboros/control/** -diff`. All seven paths are
    still listed.
11. A file left where a change may not land, beside one the task file named.
12. A client that prints two result objects: the loop reads the last one and reports what it
    read, including a fix wave it could not resume.
13. The push and the pull request, against a stub `git` and a stub `gh`: the exact argv of
    each, and a body that loses its section the step before the push refusing before it.
14. A gate that must hold no model credentials, watched through a stub `mix` that records
    its environment — beside the shim's, which still has the key.
15. A client that ignores its own `--timeout`: the deadline fires, the runtime is stopped
    first, the client is killed.
16. No watchdog outlived the run.

The shim's payloads are `OURO_SHIM_*` variables, one per phase: `BREAK` (a failing test),
`NOOP` (a session that changes nothing), `COMMIT` (a session that commits its own work),
`SLEEP` (a client that does not return), `TWO_RESULTS`, `HALT_HELPER`, `HIDE`, `BUILD`,
`STRAY`/`STRAY2`, `RENAME`, `MODE`, `BINARY`, `SPACEPATH`, `PLUSPLUS`, and `ENV` (dump this
invocation's environment).

**What that proves is the plumbing.** The shim's change is a comment and a test that cannot
fail. Whether a model can do the work is the first paid run, and that is a human step. The
selftest runs under `--quick`, so `make test` and `mix dialyzer` have never run inside the
loop; the corpus step has never run at all; and the deadline's `kill -9 -<pgid>` has been
watched killing a shell script, not a real client with children of its own.
