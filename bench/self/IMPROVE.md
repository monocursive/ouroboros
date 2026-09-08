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
72 columns at a word boundary, becomes the branch slug, the commit subject and the pull
request title. The whole file becomes the commit body and the "The task" section of the
pull request.

## What it does, in order

| # | Step | What it is |
|---|---|---|
| 1 | `worktree` | `.claude/worktrees/improve-<slug>` on `self/improve-<slug>`, branched from `dev`; `deps/` and `_build/` cloned in with `cp -Rc`; `priv/wasm` and `priv/sandbox` copied |
| 2 | `daemon` | `ouro --dev daemon` on a scratch `OUROBOROS_DATA_DIR` (mode 0700). `ouro stop` runs from a trap, always |
| 3 | `implementer` | `ouro run` with `docs/self/briefs/implementer.md` + the task, `--workspace <worktree> --approve-all --stream-json` |
| 4 | `gate-1` | `mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix test` on the `_test.exs` files the diff touches; without `--quick` also `make test` and `mix dialyzer`. **Red here is not fatal** — the review and the fix wave exist to answer it |
| 5 | `reviewer` | a second `ouro run` in the same worktree with `docs/self/briefs/reviewer.md`, the diffstat and the first 1200 diff lines. It writes `REVIEW.md` |
| 6 | `fix-wave` | `ouro run --resume <implementer session id>` with `docs/self/briefs/fix-wave.md` + `REVIEW.md`, so the implementer answers the review with its own context intact |
| 7 | `gate-2` | the same gate. **This one decides**: red here and the script stops before the corpus and the commit, because a change that cannot pass its own gate has not earned a measurement |
| 8 | `corpus` | `bench/self/run.sh --spend …`, only when `--spend` was given, `--no-bench` was not, the diff touches `lib/ouroboros/provider/native/`, and the worktree has the runner |
| 9 | `commit` | subject from the task, body the task, trailer `Co-Authored-By: Ouroboros native session <id>`. A session that made its own commits is refused here rather than committed over |
| 10 | `protected-scan` | every hunk under `lib/ouroboros/control/`, `lib/ouroboros/upgrade/`, `lib/ouroboros/storage/` |
| 11 | `pr-body` | `PR_BODY.md` in the worktree, and a check that it carries its own "Human review required" section |
| 12 | `pr` | `git push -u origin` then `gh pr create --base dev --body-file`. `--no-pr` stops after the body |

Every step prints `==> <name>`, the command, and `<name> rc=<n>`. A skipped step still
prints its line with the reason, so a step that left no line behind is a step that did not
run rather than one that quietly passed.

The worktree and the run directory are both left in place and named at the end, on failure
as well as on success. The worktree is the change; the run directory is the evidence.

## What is under the loop's control and what is not

The script owns the mechanism. It owns none of the judgement:

- The implementer, the reviewer and the fix wave are all models. Their reports are claims.
- `mix format`, `mix compile --warnings-as-errors`, `mix test`, `make test` and
  `mix dialyzer` are the gates, and they are the only things in the loop a model cannot
  talk its way past.
- Every hunk under `lib/ouroboros/control/`, `lib/ouroboros/upgrade/` or
  `lib/ouroboros/storage/` is listed in the pull request under **Human review required**,
  whatever the review concluded — the reviewer is the same kind of thing as the
  implementer.
- `REVIEW.md` is quoted into the body inside a six-backtick fence, and any line that could
  close that fence is replaced. It is the one piece of model-written text in the body, and
  it does not get to write the body's sections.
- `REVIEW.md` and `PR_BODY.md` are kept out of the commit. They are the loop's paperwork,
  not the change.
- The script never merges, never touches a git remote's configuration, and never opens a
  pull request from a body that has no protected-namespace section.

## The corpus delta

`--spend` is the only thing that lets the corpus run at all, and the run it does is the
*after* number. For a *before*, point `BENCH_SELF_BASELINE` at an earlier
`bench/self` `result.json`; the body then carries both and the reader can subtract. With no
baseline the body says so rather than inventing one.

## Pushing

The push uses whatever `origin` your checkout has. If that is an SSH URL and SSH is not
configured on the machine, the push fails and the script says so; the commit is still on the
branch in the worktree, and `--no-pr` does everything except push. **The script never edits
a remote.** Giving your own checkout an HTTPS push URL is your call to make, not the loop's.

## The selftest

```sh
bench/self/improve-selftest.sh
```

No model, no key, no network, no spend, about three minutes. It drives the whole loop
against `bench/self/lib/improve/shim-ouro.sh`, a labelled test shim that answers the four
`ouro` invocations and edits the workspace the way a session would, over five phases:

1. `--dry-run` prints every command and creates no directory, worktree, branch or runtime.
2. The loop runs green: the worktree descends from `dev`, both gates really ran the suite
   (the ExUnit line, not just an rc), `REVIEW.md` exists, the body carries the review and
   the `grants.ex` hunk under "Human review required", one commit carries the session
   trailer without the paperwork, and nothing was pushed.
3. A session that leaves the suite failing: gate 2 is red, the loop exits non-zero and
   there is no commit, no body and no push.
4. A session that changes nothing: the loop refuses before it gates or reviews anything.
5. A session that commits its own work: the gates still run and the loop refuses at the
   commit step, so no pull request carries commits without the task title and the trailer.

What that proves is the plumbing. The shim's "change" is a comment and a test that cannot
fail. Whether a model can do the work is the first paid run, and that is a human step.
