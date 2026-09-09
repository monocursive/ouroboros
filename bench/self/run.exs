#!/usr/bin/env elixir

# The self corpus runner. See bench/self/README.md and docs/BENCHMARKS.md §5.
#
# A plain `elixir` script for `bench/local/run.exs`'s reason: it starts and stops a
# *separate* runtime and talks to it only through `ouro run`, so being inside that
# runtime's own BEAM would prove less than it looks. Standard library only.
#
# Unlike `bench/local`, this one can spend money. `--spend <usd>` is required, the model
# must be one this node can price, and the running total is checked before every task.

Code.require_file("lib/support.exs", Path.dirname(__ENV__.file))

defmodule Bench.Self.Oracle do
  @moduledoc """
  The $0 proof that the grader works.

  The scripted model from `bench/local/model/` — the same file, compiled into the project's
  own `ebin` the same way — is handed a script per task: one `write` per changed non-test
  file carrying that file's bytes at `commit_sha`, then a short closing turn. It is the
  commit's own answer, delivered through the real tool path, the real permission gate and
  the real client.

  `write` is used rather than `apply_patch` because `Tools.Write` has no read-before-write
  guard (`lib/ouroboros/provider/native/tools/write.ex`) and whole-file content is exact,
  where a generated V4A patch would be a second thing that can be wrong. What the oracle
  proves is the *grader*, not the patch format.

  If this run does not grade every task `pass` at $0, something in the worktree, the hidden
  test restore, the modified-test check or the budget arithmetic is broken — which is the
  entire point of running it.
  """

  alias Bench.Self.{Git, Hidden}

  @modes ~w(none no-solution blank-tests commit-tests hide-tests delete-tests
            stage-new-test game-support lib-rewrite mixexs-alias history-cheat)

  @blank """
  defmodule Bench.Self.Oracle.BlankedTest do
    use ExUnit.Case, async: true

    test "blanked by the oracle cheat seam" do
      assert true
    end
  end
  """

  # The review's exploit, as written by the reviewer and kept close to their words. A
  # module body runs at COMPILE time, in the same BEAM that `mix test` then loads the test
  # files into; `test/support` is on `elixirc_paths(:test)`; and a NEW file under `test/`
  # is allowed by design, because writing your own tests is part of the work. Against the
  # tree-grading version of this corpus it rewrote every restored hidden test between the
  # check and the run, and scored 2/2.
  @support ~S"""
  defmodule ZzBenchSelfExploit do
    @moduledoc false

    for path <- Path.wildcard("test/**/*_test.exs") do
      name = path |> :erlang.md5() |> Base.encode16() |> binary_part(0, 16)

      File.write!(
        path,
        "defmodule ZzNeutralised" <> name <> " do\n" <>
          "  use ExUnit.Case, async: true\n\n" <>
          "  test \"neutralised by a new file under test/support\" do\n" <>
          "    assert true\n  end\nend\n"
      )
    end
  end
  """

  # The same mechanism as `@support`, from a file that IS graded. `lib/` is a source root a
  # task may change, so this reaches the grading tree, and its module body runs there at
  # compile time. What contains it is *order*: the grading tree compiles the diff before the
  # hidden tests are restored, so whatever this writes is overwritten by the restore that
  # follows it. The test it writes fails on purpose, so a grader that restored first and
  # compiled second would report `tests_failed` and this control would go red.
  @rewrite ~S"""
  defmodule ZzBenchSelfLibRewrite do
    @moduledoc false

    for path <- Path.wildcard("test/**/*_test.exs") do
      name = path |> :erlang.md5() |> Base.encode16() |> binary_part(0, 16)

      File.write!(
        path,
        "defmodule ZzLibRewritten" <> name <> " do\n" <>
          "  use ExUnit.Case, async: true\n\n" <>
          "  test \"rewritten from lib/ at compile time\" do\n" <>
          "    assert false\n  end\nend\n"
      )
    end
  end
  """

  @doc "The cheat modes `--oracle-cheat` accepts."
  @spec modes() :: [String.t()]
  def modes, do: @modes

  @doc """
  The script for one task, in one of eleven modes.

  `none` is the oracle. The other ten are **negative controls**: each one is an agent that
  must not score — or, twice, one that must — and each is refused outside `--oracle`.
  Three of them are the review's own exploits, kept as scripts rather than as prose.

    * `no-solution` answers with nothing at all. Every task must then fail
      `tests_failed` — which is only true if the grader really restores the hidden tests
      from `commit_sha`. Without the restore, the *parent's* copy of the test would run,
      and the parent's copy passes: a runner that skipped the restore would grade this
      cheat as a full pass.
    * `blank-tests` writes the real solution **and** overwrites a hidden test that already
      existed at `base_sha` with a file that asserts nothing. Every task must then fail
      `modified_tests`.
    * `commit-tests` does the same and then **commits** it, so `git status` is clean.
    * `hide-tests` does the same and then `git update-index --assume-unchanged`es it, so
      that `git status` *and* `git diff` both report a clean tree over a modified file.
      Both must still be `modified_tests`: the check is against `base_sha`'s blobs and
      never asks the index, which is the point of running them.
    * `delete-tests` deletes a pre-existing hidden test rather than blanking it. A file
      that is gone is a file that changed, and `modified_tests` is the same answer.
    * `stage-new-test` writes the real solution and adds a test of its own, staged and then
      edited — `AM` to `git status`, and failed as a modification by the check this
      replaces. It must **pass**.
    * `game-support` writes no solution and one new `test/support/*.ex` whose module body
      rewrites every restored hidden test at compile time. It scored 2/2 against the tree
      grader. It must now grade `tests_failed`: the file is the agent's, it stays in the
      agent's tree, and nothing in the grading tree ever compiles it.
    * `lib-rewrite` writes the real solution **and** a `lib/` file doing the same thing from
      a path that *is* graded. It must **pass**: the grading tree compiles the diff before
      it restores the hidden tests, so the rewrite is overwritten by the restore. The test
      it writes fails on purpose, so a grader that restored first would go red here.
    * `mixexs-alias` writes the real solution and a `mix.exs` carrying a `test:` alias,
      which makes `mix test` exit 0 over any suite. It must grade `refused`: `mix.exs` is
      not a source root a task may change.
    * `history-cheat` runs one `bash` call — `git log --all --grep "<its own subject>"`,
      then `git show "$sha:$f"` for every non-test file of that commit. It scored 1/1 when
      the workspace was a worktree of this repository. It must now find nothing.
  """
  @spec script(Path.t(), map(), String.t()) :: {:ok, map()} | {:error, String.t()}
  def script(_repo, task, "no-solution") do
    {:ok,
     %{
       "instruction" => task["instruction"],
       "responses" => [
         [
           %{"type" => "text", "text" => "Doing nothing at all."},
           %{"type" => "usage", "input_tokens" => 0, "output_tokens" => 0},
           %{"type" => "finish", "reason" => "stop"}
         ]
       ]
     }}
  end

  def script(_repo, task, "game-support"),
    do: {:ok, wrap(task, [call(0, "test/support/zz_bench_self_exploit.ex", @support)])}

  def script(_repo, task, "history-cheat"), do: {:ok, wrap(task, [hunt(task)])}

  def script(repo, task, mode) do
    with {:ok, calls} <- writes(repo, task),
         {:ok, extra} <- extra(repo, task, mode) do
      {:ok, wrap(task, calls ++ extra)}
    end
  end

  defp writes(repo, task) do
    task["solution_files"]
    |> Enum.reduce_while({:ok, []}, fn path, {:ok, calls} ->
      case Git.show(repo, task["commit_sha"], path) do
        {:ok, body} -> {:cont, {:ok, calls ++ [call(length(calls) + 1, path, body)]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp extra(_repo, _task, "none"), do: {:ok, []}
  defp extra(repo, task, "blank-tests"), do: {:ok, elem(blanking(repo, task), 1)}
  defp extra(repo, task, "commit-tests"), do: {:ok, elem(blanking(repo, task), 1) ++ [commit()]}
  defp extra(_repo, _task, "stage-new-test"), do: {:ok, [staged()]}

  defp extra(_repo, _task, "lib-rewrite"),
    do: {:ok, [call(80, "lib/zz_bench_self_lib_rewrite.ex", @rewrite)]}

  defp extra(repo, task, "hide-tests") do
    case blanking(repo, task) do
      {nil, calls} -> {:ok, calls}
      {path, calls} -> {:ok, calls ++ [hidden(path)]}
    end
  end

  defp extra(repo, task, "delete-tests") do
    case blanking(repo, task) do
      {nil, _calls} -> {:ok, []}
      {path, _calls} -> {:ok, [removed(path)]}
    end
  end

  defp extra(repo, task, "mixexs-alias") do
    with {:ok, body} <- aliased(repo, task), do: {:ok, [call(90, "mix.exs", body)]}
  end

  defp blanking(repo, task) do
    task["hidden_tests"]
    |> Hidden.graded()
    |> Enum.find(&Git.exists?(repo, task["base_sha"], &1))
    |> case do
      nil -> {nil, []}
      path -> {path, [call(0, path, @blank)]}
    end
  end

  # One alias, in the one file the modified-test check never looked at, is enough to make
  # `mix test <a suite asserting 1 == 2>` exit 0.
  #
  # It goes at the head of the project's own keyword list rather than into a `defp aliases`
  # block, because `Keyword.get/2` takes the first match: this both adds an `aliases` to a
  # `mix.exs` that has none and overrides the one a `mix.exs` that has some declares. Every
  # `mix.exs` in this history opens `def project do\n    [`, and so does the fixture's.
  defp aliased(repo, task) do
    anchor = "def project do\n    [\n"

    case Git.show(repo, task["base_sha"], "mix.exs") do
      {:ok, body} ->
        case String.split(body, anchor, parts: 2) do
          [head, tail] -> {:ok, head <> anchor <> "      aliases: [test: [\"cmd true\"]],\n" <> tail}
          _absent -> {:error, "mix.exs at #{task["base_sha"]} has no `def project do` list to doctor"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp commit do
    shell(
      "oracle-commit",
      "git add -A && git commit -q -m 'the agent commits its edit' && git status --porcelain",
      "commit the change, so git status is clean"
    )
  end

  # `--assume-unchanged` makes git's *index* stop looking at a file: `git status` and
  # `git diff` both report the tree as clean while the modified bytes sit on disk. The
  # review proved it against a check that asked git. The check asks the file now.
  #
  # `set -e` matters: writing to `.git` is fenced, and the runtime only offers the
  # one-command escalation when the denied command *fails*. Without it `git update-index`
  # would be refused, the script would carry on to exit 0, and this control would pass for
  # the wrong reason — which is what it did the first time it was written.
  defp hidden(path) do
    shell(
      "oracle-hide",
      "set -e\ngit update-index --assume-unchanged " <>
        Bench.Self.Shell.quote_arg(path) <> "\ngit status --porcelain\ngit diff --name-only\n",
      "hide the edit from git's index"
    )
  end

  # A file that is gone is a file that changed. The grading tree restores it from git
  # either way, so this buys an agent nothing — but "not modified or deleted" is the rule
  # the instruction states, and a rule with no control is a rule nobody checks.
  defp removed(path) do
    shell(
      "oracle-remove",
      "rm -f " <> Bench.Self.Shell.quote_arg(path) <> "\ngit status --porcelain\n",
      "delete the test"
    )
  end

  # A new file, staged, then edited: `git status` calls that `AM`, and the check this
  # replaces read the `M` and failed a file that did not exist at the base at all. It must
  # pass — writing your own tests is part of the work, and doing it in two steps is not a
  # different act.
  defp staged do
    body =
      "defmodule BenchSelfAgentAddedTest do\\n  use ExUnit.Case\\n\\n  test \\\"mine\\\" do\\n    assert true\\n  end\\nend\\n"

    shell(
      "oracle-stage",
      "printf '" <>
        body <>
        "' > test/bench_self_agent_added_test.exs\n" <>
        "git add test/bench_self_agent_added_test.exs\n" <>
        "printf '\\n# edited after staging, which git calls AM\\n' >> test/bench_self_agent_added_test.exs\n" <>
        "git status --porcelain\n",
      "add a test of my own, stage it, then edit it again"
    )
  end

  defp shell(id, command, description) do
    %{
      "type" => "tool_call",
      "id" => id,
      "name" => "bash",
      "input" => %{"command" => command, "description" => description}
    }
  end

  # What any agent with a shell can do when its workspace shares the repository's object
  # store: the instruction *is* the commit's subject, so the answer is one grep away.
  defp hunt(task) do
    quoted = "'" <> String.replace(task["subject"], "'", "'\\''") <> "'"

    command =
      "set -u\n" <>
        "sha=$(git log --all -F --format=%H -1 --grep " <> quoted <> " || true)\n" <>
        "echo FOUND=${sha:-none}\n" <>
        "if [ -n \"${sha:-}\" ]; then\n" <>
        "  for f in $(git show --name-only --format= \"$sha\" | grep -v '^test/'); do\n" <>
        "    mkdir -p \"$(dirname \"$f\")\"; git show \"$sha:$f\" > \"$f\"\n" <>
        "  done\n" <>
        "fi\n" <>
        "echo CHANGED; git status --porcelain | head -20\n"

    shell("oracle-history", command, "look the answer up in this workspace's own history")
  end

  defp call(index, path, body) do
    %{
      "type" => "tool_call",
      "id" => "oracle-" <> Integer.to_string(index),
      "name" => "write",
      "input" => %{"path" => path, "content" => body}
    }
  end

  defp wrap(task, calls) do
    %{
      "instruction" => task["instruction"],
      "responses" => [
        [%{"type" => "text", "text" => "Writing the change."} | calls],
        [
          %{"type" => "text", "text" => "Done."},
          %{"type" => "usage", "input_tokens" => 0, "output_tokens" => 0},
          %{"type" => "finish", "reason" => "stop"}
        ]
      ]
    }
  end
end

defmodule Bench.Self.Grade do
  @moduledoc """
  What counts as solving a task, in order, and the one reason a failure is given.

  1. The run finished `completed` inside its timeout.
  2. The task names at least one `_test.exs` to grade against.
  3. No file that already existed under `test/` differs in **content** from `base_sha`.
  4. The change touches only the source roots a task may change.
  5. `task.json`'s pins agree with the history.
  6. The change, applied to a **fresh tree at `base_sha`**, compiles; the hidden tests are
     restored into it from `commit_sha` *after* that compile; `mix test` reports them all
     passing; and their bytes are still `commit_sha`'s when it is over.

  **The agent's tree is not graded.** It was, and the review took it apart twice over: one
  new file under `test/support/` rewrote every restored test at compile time (allowed by
  design — new test files are the agent's to write), and one alias in `mix.exs` made
  `mix test` exit 0 over a suite asserting `1 == 2`. Both scored a full pass. So what is
  graded is a *patch*: `git diff --binary <base_sha>` over `lib/`, `assets/`, `priv/`,
  `config/`, `docs/` and `README.md`, applied to a worktree at `base_sha` whose `deps/`
  and `_build/` come from the checkout. The agent's `test/`, `mix.exs`, `.formatter.exs`,
  `_build/` and `deps/` never reach the grading VM. A diff that touches anything else is
  `refused` rather than filtered: an agent that rewrote `mix.exs` did not do the task.

  **The verdict is what ExUnit reported**, not the exit status — see `Bench.Self.Verdict`,
  which applies `bench/self/lib/improve/gate-verdict.sh`'s rule.

  What is left, and is stated rather than defended: the grading tree compiles and runs the
  agent's own `lib/` code, and Elixir runs module bodies at compile time. Restoring the
  hidden tests *after* that compile makes a compile-time rewrite pointless, and
  `Hidden.intact/4` re-reads their bytes after the run, so a later one is caught. Nothing
  here can tell ExUnit's summary from one the graded code printed itself.
  """

  alias Bench.Self.{Change, Git, Hidden, Verdict, Workspace}

  @type verdict :: {:pass, map()} | {:fail, String.t(), String.t(), map()}

  @empty %{grade_ms: 0, grade_setup_ms: 0, grade_command: ""}

  @spec run(map(), map(), Path.t(), map(), keyword()) :: verdict()
  def run(task, config, dir, report, opts) do
    with :ok <- completed(report),
         {:ok, graded} <- graded(task),
         {:ok, change} <- change(dir, task, opts),
         :ok <- untouched(config.history, dir, task),
         :ok <- permitted(change),
         :ok <- pinned(config.history, task) do
      tested(task, config, change, graded, opts)
    else
      {:fail, reason, detail} -> {:fail, reason, detail, @empty}
    end
  end

  defp completed(%{"status" => "completed"}), do: :ok
  defp completed(%{"status" => "timeout"}), do: {:fail, "timeout", "the turn hit its --timeout"}

  defp completed(%{"harness" => "killed"}),
    do: {:fail, "timeout", "the client outlived its own timeout and was killed"}

  defp completed(report),
    do:
      {:fail, "not_completed",
       "status " <>
         to_string(Map.get(report, "status", "no-result")) <>
         case Map.get(report, "error") do
           nil -> ""
           error -> ": " <> String.slice(to_string(error), 0, 200)
         end}

  # `mix test` with no paths runs the whole suite, which would grade a task against a
  # corpus entry that names none of its own tests. Refused rather than answered, and
  # refused first: it is a fact about the corpus, and it costs one list filter.
  defp graded(task) do
    case Hidden.graded(task["hidden_tests"]) do
      [] -> {:fail, "setup_failed", "the task names no `_test.exs` among its hidden tests"}
      paths -> {:ok, paths}
    end
  end

  defp change(dir, task, opts) do
    case Change.collect(dir, task["base_sha"]) do
      {:ok, change} ->
        case Keyword.get(opts, :patch) do
          nil -> :ok
          path -> File.write!(path, change.patch)
        end

        {:ok, change}

      {:error, reason} ->
        {:fail, "setup_failed", reason}
    end
  end

  # By content, against `base_sha`'s blobs, and never through the index: the review made
  # `git status` and `git diff` both forget a modified test with one
  # `git update-index --assume-unchanged`.
  defp untouched(repo, dir, task) do
    case Change.modified_tests(repo, dir, task["base_sha"]) do
      {:ok, []} -> :ok
      {:ok, paths} -> {:fail, "modified_tests", Enum.join(Enum.take(paths, 10), "; ")}
      {:error, reason} -> {:fail, "setup_failed", reason}
    end
  end

  defp permitted(%{refused: []}), do: :ok

  defp permitted(%{refused: paths}),
    do:
      {:fail, "refused",
       "the change touches " <>
         Enum.join(Enum.take(paths, 10), ", ") <>
         "; a task may change " <> Enum.join(Change.allowed(), ", ")}

  # The corpus on disk is a list of pins; git is the authority for what those pins point at.
  # If they disagree — a hand-edited `task.json` that quietly dropped a test path — the task
  # is not graded, because the weaker grade would look exactly like a pass.
  defp pinned(repo, task) do
    case Hidden.paths(repo, task["base_sha"], task["commit_sha"]) do
      {:ok, paths} ->
        if paths == Enum.sort(task["hidden_tests"]) do
          :ok
        else
          {:fail, "setup_failed",
           "hidden_tests disagrees with the history: " <>
             inspect(paths -- task["hidden_tests"]) <>
             " missing, " <> inspect(task["hidden_tests"] -- paths) <> " extra"}
        end

      {:error, reason} ->
        {:fail, "setup_failed", reason}
    end
  end

  # ------------------------------------------------------------- the grading tree

  defp tested(task, config, change, graded, opts) do
    timeout_ms = Keyword.get(opts, :timeout_ms, 900_000)
    setup_ms = Keyword.get(opts, :setup_timeout_ms, 900_000)
    log = Keyword.get(opts, :log)
    dir = Keyword.fetch!(opts, :grade_dir)
    command = Workspace.test_command(graded)

    File.mkdir_p!(Path.dirname(dir))

    try do
      case Workspace.prepare(config.history, dir, task["base_sha"],
             envs: ["test"],
             support_from: config.support,
             timeout_ms: setup_ms,
             log: log
           ) do
        {:error, reason} ->
          {:fail, "setup_failed", "the grading tree: " <> reason, %{@empty | grade_command: command}}

        {:ok, %{setup_ms: built_ms}} ->
          extra = %{grade_ms: 0, grade_setup_ms: built_ms, grade_command: command}

          case apply_and_run(task, config, change, graded, dir, log, timeout_ms, extra) do
            {:pass, more} -> {:pass, Map.merge(extra, more)}
            {:fail, reason, detail, more} -> {:fail, reason, detail, Map.merge(extra, more)}
          end
      end
    after
      unless config.keep, do: Workspace.remove(config.history, dir)
    end
  end

  defp apply_and_run(task, config, change, graded, dir, log, timeout_ms, extra) do
    with :ok <- applied(dir, change),
         :ok <- compiled(dir, log),
         :ok <- restored(config.history, dir, task),
         {:ok, status, ms, out} <- suite(dir, graded, timeout_ms, log, extra),
         :ok <- reported(out, status, graded, ms, extra),
         :ok <- unchanged(config.history, dir, task, ms, extra) do
      {:pass, %{grade_ms: ms}}
    else
      {:fail, reason, detail} -> {:fail, reason, detail, %{}}
      {:fail, reason, detail, more} -> {:fail, reason, detail, more}
    end
  end

  defp applied(_dir, %{patch: ""}), do: :ok

  defp applied(dir, change) do
    patch = Path.join(dir, ".bench-self-change.patch")
    File.write!(patch, change.patch)

    try do
      case Git.apply_patch(dir, patch) do
        :ok -> :ok
        {:error, reason} -> {:fail, "setup_failed", "the agent's change did not apply: " <> reason}
      end
    after
      File.rm(patch)
    end
  end

  # Before the restore, on purpose: an Elixir module body runs at compile time, in the BEAM
  # `mix test` is about to load the hidden tests into. Compiling first means whatever such
  # a body writes into `test/` is overwritten by the restore that follows it.
  defp compiled(dir, log) do
    case Workspace.recompile(dir, ["test"], log: log) do
      :ok -> :ok
      {:error, reason} -> {:fail, "tests_failed", "the change does not compile: " <> reason}
    end
  end

  defp restored(repo, dir, task) do
    case Hidden.restore(repo, dir, task["commit_sha"], task["hidden_tests"]) do
      :ok -> :ok
      {:error, reason} -> {:fail, "setup_failed", reason}
    end
  end

  defp suite(dir, graded, timeout_ms, log, extra) do
    case Workspace.test(dir, graded, timeout_ms: timeout_ms) do
      {:ok, status, ms, out} ->
        append(log, out)
        {:ok, status, ms, out}

      {:timeout, ms, out} ->
        append(log, out)
        {:fail, "tests_failed", "mix test timed out after #{timeout_ms}ms", %{extra | grade_ms: ms}}
    end
  end

  defp reported(out, status, graded, ms, extra) do
    case Verdict.of(out, status, length(graded)) do
      {:ok, _summary} -> :ok
      {:error, note} -> {:fail, "tests_failed", note, %{extra | grade_ms: ms}}
    end
  end

  defp unchanged(repo, dir, task, ms, extra) do
    case Hidden.intact(repo, dir, task["commit_sha"], task["hidden_tests"]) do
      :ok -> :ok
      {:error, reason} -> {:fail, "tests_failed", reason, %{extra | grade_ms: ms}}
    end
  end

  defp append(nil, _text), do: :ok

  defp append(path, text) do
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, text, [:append])
  end
end

defmodule Bench.Self.Runner do
  @moduledoc "One runtime, every task through `ouro run`, graded, reported, budgeted."

  alias Bench.Self.{Env, Exec, Fs, Git, Grade, Oracle, Prompt, TaskFile, Workspace}

  @daemon_boot_ms 240_000
  @setup_ms 900_000
  @grade_ms 900_000

  def main(argv) do
    {opts, _rest} =
      OptionParser.parse!(argv,
        strict: [
          spend: :float,
          model: :string,
          oracle: :boolean,
          filter: :string,
          out: :string,
          tasks_dir: :string,
          repo: :string,
          history: :string,
          ouro: :string,
          keep: :boolean,
          timeout: :integer,
          approve_all: :boolean,
          fake_cost_usd: :float,
          fake_status: :string,
          oracle_as_paid: :boolean,
          oracle_cheat: :string
        ]
      )

    root = Path.expand(Path.dirname(__ENV__.file))
    own = Path.expand(Path.join(root, "../.."))
    checkout = Path.expand(opts[:repo] || own)
    history = Path.expand(opts[:history] || own)
    oracle? = opts[:oracle] == true
    run_id = stamp()

    with :ok <- spend_given(opts),
         :ok <- seam_guarded(opts, oracle?),
         :ok <- readable(checkout, "--repo"),
         :ok <- readable(history, "--history"),
         {:ok, ouro} <- resolve_ouro(checkout, opts[:ouro]),
         {:ok, tasks} <- corpus(root, checkout, opts),
         {:ok, model} <- model(checkout, opts, oracle?) do
      config = %{
        checkout: checkout,
        history: history,
        # `deps/` and `_build/` are cloned from the checkout — but only into a tree of the
        # same project. A `--history` that is a different repository (the selftest's
        # fixture) gets nothing, and builds itself.
        support: if(Git.same_repository?(checkout, history), do: checkout, else: nil),
        root: root,
        run_id: run_id,
        ouro: ouro,
        oracle?: oracle?,
        oracle_as_paid?: opts[:oracle_as_paid] == true,
        model: model,
        spend_cap: opts[:spend],
        fake_cost: opts[:fake_cost_usd],
        fake_status: opts[:fake_status],
        cheat: opts[:oracle_cheat] || "none",
        approve_all?: opts[:approve_all] != false,
        timeout: opts[:timeout],
        keep: opts[:keep] == true,
        flags: flags(opts),
        tasks_dir: tasks_dir(root, opts),
        out: Path.expand(opts[:out] || Path.join([root, "results", run_id]))
      }

      scratch = Fs.scratch_dir("ouroboros-bench-self")
      File.mkdir_p!(config.out)

      say("corpus  #{length(tasks)} tasks from #{config.tasks_dir}")
      say("client  #{ouro}")
      say("model   #{model}#{if oracle?, do: " (oracle, $0)", else: ""}")
      say("runtime #{checkout}")
      if history != checkout, do: say("history #{history}")

      if config.cheat != "none",
        do: say("cheat   --oracle-cheat #{config.cheat}: a negative control, every task must FAIL")

      say("budget  $#{:erlang.float_to_binary(config.spend_cap, decimals: 2)}")
      say("scratch #{scratch}")
      say("out     #{config.out}")

      status =
        try do
          run_all(tasks, Map.put(config, :scratch, scratch))
        after
          stop_daemon(ouro, scratch)
          sweep_refs(config)
          unless config.keep, do: File.rm_rf(scratch)
          if config.keep, do: say("kept    #{scratch}")
        end

      System.halt(status)
    else
      {:error, message} -> die(message)
    end
  end

  defp readable(path, flag) do
    if File.dir?(Path.join(path, ".git")) or File.regular?(Path.join(path, ".git")),
      do: :ok,
      else: {:error, "#{flag} #{path} is not a git repository"}
  end

  # Every flag this run was given, as given. `result.json` carries them, because a number
  # quoted out of a `--filter`ed or `--oracle-cheat`ed run is not the number it looks like.
  defp flags(opts) do
    ~w(filter oracle oracle_cheat fake_cost_usd fake_status oracle_as_paid approve_all
       timeout tasks_dir repo history model keep)a
    |> Enum.map(&{to_string(&1), opts[&1]})
    |> Map.new()
    |> Map.put("no_approve_all", opts[:approve_all] == false)
  end

  # A run registers a ref per task and deletes it as soon as the clone has it. This is the
  # sweep for the paths that do not return: an interrupted run, a killed client. Reported
  # rather than silent, because a leftover ref is a thing somebody has to know about.
  defp sweep_refs(config) do
    case Git.temporary_refs(config.history) do
      [] ->
        :ok

      refs ->
        mine = Enum.filter(refs, &String.starts_with?(&1, Git.task_ref(config.run_id, "")))
        Enum.each(mine, &Git.delete_ref(config.history, &1))

        say("refs    swept #{length(mine)} temporary ref(s) this run left behind")

        case refs -- mine do
          [] -> :ok
          other -> say("refs    #{length(other)} ref(s) under #{Git.ref_prefix()} are another run's; left alone")
        end
    end
  end

  # --------------------------------------------------------------- the refusals

  defp spend_given(opts) do
    case opts[:spend] do
      nil ->
        {:error,
         "--spend <usd> is required. This corpus runs a real model against real " <>
           "credentials; a run without a stated ceiling is a run nobody bounded. " <>
           "The oracle is free and still needs one: --oracle --spend 1"}

      value when value <= 0 ->
        {:error, "--spend must be greater than 0 (got #{value})"}

      _value ->
        :ok
    end
  end

  # The two seams exist so `selftest.sh` can prove the budget stops a run and the grader
  # refuses a cheat, all without spending anything. Both are refused outside `--oracle`,
  # where `--fake-cost-usd` could be mistaken for a discount on a real run and
  # `--oracle-cheat` would silently replace the model's answer with a scripted one.
  defp seam_guarded(opts, oracle?) do
    cond do
      not is_nil(opts[:fake_cost_usd]) and not oracle? ->
        {:error, "--fake-cost-usd is a test seam and is only accepted with --oracle"}

      is_number(opts[:fake_cost_usd]) and opts[:fake_cost_usd] < 0 ->
        {:error, "--fake-cost-usd must not be negative"}

      not is_nil(opts[:oracle_cheat]) and not oracle? ->
        {:error, "--oracle-cheat is a test seam and is only accepted with --oracle"}

      not is_nil(opts[:oracle_cheat]) and opts[:oracle_cheat] not in Oracle.modes() ->
        {:error, "--oracle-cheat must be one of " <> Enum.join(Oracle.modes(), ", ")}

      not is_nil(opts[:fake_status]) and not oracle? ->
        {:error, "--fake-status is a test seam and is only accepted with --oracle"}

      opts[:oracle_as_paid] == true and not oracle? ->
        {:error, "--oracle-as-paid is a test seam and is only accepted with --oracle"}

      true ->
        :ok
    end
  end

  # The client this repository builds, not one on PATH, and between the release and debug
  # builds the NEWEST — `bench/local` learned both of these the hard way.
  # A named binary that is not there is a refusal, not a fallback. `OURO_BIN` used to be
  # tried and quietly skipped when the path did not exist, so a typo in it graded whatever
  # `tui/target` happened to hold — which is precisely the confusion the refusal exists to
  # prevent.
  defp resolve_ouro(repo, explicit) do
    env = System.get_env("OURO_BIN")

    cond do
      is_binary(explicit) ->
        named(explicit, "--ouro")

      is_binary(env) and env != "" ->
        named(env, "OURO_BIN")

      true ->
        case newest_first(repo) do
          [] ->
            {:error,
             "no ouro binary under #{repo}/tui/target: build one with `cd tui && cargo build`, " <>
               "or name one with --ouro PATH or OURO_BIN"}

          [path | _rest] ->
            {:ok, Path.expand(path)}
        end
    end
  end

  defp named(path, flag) do
    if File.regular?(path),
      do: {:ok, Path.expand(path)},
      else: {:error, "#{flag} names #{path}, which is not a file"}
  end

  defp newest_first(repo) do
    ["tui/target/release/ouro", "tui/target/debug/ouro"]
    |> Enum.map(&Path.join(repo, &1))
    |> Enum.filter(&File.regular?/1)
    |> Enum.sort_by(&File.stat!(&1, time: :posix).mtime, :desc)
  end

  defp tasks_dir(root, opts), do: Path.expand(opts[:tasks_dir] || Path.join(root, "tasks"))

  defp corpus(root, checkout, opts) do
    dir = tasks_dir(root, opts)

    with {:ok, tasks} <- TaskFile.load_all(dir, opts[:filter]),
         :ok <- non_empty(tasks, dir),
         :ok <- unique_ids(tasks),
         :ok <- unique_instructions(tasks),
         :ok <- acceptable_instructions(tasks, checkout) do
      {:ok, tasks}
    end
  end

  # A corpus entry whose instruction carries one of the prompt assembler's own delimiters
  # is one the runtime refuses before the agent sees it. Graded, it would read as the
  # agent failing; refused here, it reads as what it is. `extract.exs` drops such
  # candidates, so this fires only for a corpus somebody extended by hand.
  defp acceptable_instructions(tasks, repo) do
    with {:ok, delimiters} <- Prompt.reserved_delimiters(repo) do
      case Enum.find(tasks, &Prompt.reserved?(&1["instruction"], delimiters)) do
        nil ->
          :ok

        task ->
          {:error,
           task["id"] <> "'s instruction carries a reserved prompt delimiter (" <>
             Enum.join(delimiters, ", ") <> "); the runtime would refuse it before the agent saw it"}
      end
    end
  end

  defp non_empty([], dir), do: {:error, "no tasks in #{dir} matched"}
  defp non_empty(_tasks, _dir), do: :ok

  # The scripted model matches an instruction by containment. A corpus where one contains
  # another has an ambiguous oracle, so it is refused rather than silently mis-scripted —
  # `bench/local` refuses for the same reason.
  # Two directories with the same `id` are two tasks the results table cannot tell apart,
  # and the containment check below would compare each of them only with the other's
  # namesake. Refused before either becomes a number.
  defp unique_ids(tasks) do
    case tasks |> Enum.group_by(& &1["id"]) |> Enum.find(fn {_id, group} -> length(group) > 1 end) do
      nil ->
        :ok

      {id, group} ->
        {:error, "#{length(group)} tasks share the id #{id}: " <> Enum.map_join(group, ", ", & &1["dir"])}
    end
  end

  # Pairs are told apart by *directory*, not by id: a corpus in which two entries share an
  # id would otherwise have each of them compared with everything except its twin, which
  # is the one comparison that matters.
  defp unique_instructions(tasks) do
    pairs =
      for a <- tasks,
          b <- tasks,
          a["dir"] != b["dir"],
          String.contains?(b["instruction"], a["instruction"]),
          do: {a["id"], b["id"]}

    case pairs do
      [] -> :ok
      [{inner, outer} | _rest] -> {:error, "#{inner}'s instruction is contained in #{outer}'s"}
    end
  end

  # The budget is only a budget if the model can be priced. `Native.Cost.cost_usd/5`
  # answers `nil` for a model `llm_db` does not know, and a run whose spend total is
  # permanently zero would sail past any cap. Asked of the runtime itself, in the runtime's
  # own build, rather than reimplemented here.
  defp model(_repo, opts, true), do: {:ok, opts[:model] || "bench-script (oracle)"}

  defp model(repo, opts, false) do
    spec = opts[:model] || System.get_env("OUROBOROS_NATIVE_MODEL")

    snippet = """
    spec = System.get_env("BENCH_SELF_MODEL")
    spec = if spec in [nil, ""], do: Application.get_env(:ouroboros, :native_model), else: spec
    IO.puts("BENCH_MODEL " <> to_string(spec))

    case Ouroboros.Provider.Native.Cost.cost_usd(spec, 1_000_000, 1_000_000, 0, 0) do
      nil -> IO.puts("BENCH_PRICED no"); System.halt(1)
      cost -> IO.puts("BENCH_PRICED yes " <> to_string(cost))
    end
    """

    case Exec.run(mix(), ["run", "--no-start", "-e", snippet],
           cd: repo,
           timeout_ms: 300_000,
           stderr: :stdout,
           env: Env.build(%{"MIX_ENV" => "dev", "BENCH_SELF_MODEL" => spec || ""})
         ) do
      {:ok, 0, out} ->
        {:ok, captured(out, "BENCH_MODEL ") || spec || "unknown"}

      {:ok, _code, out} ->
        {:error,
         "this node cannot price " <> (captured(out, "BENCH_MODEL ") || to_string(spec)) <>
           ", so --spend could not bound the run. Name a model llm_db prices with --model, " <>
           "or run with --oracle.\n" <> String.trim(out)}

      {:timeout, _out} ->
        {:error, "the pricing pre-flight (`mix run --no-start`) timed out"}
    end
  end

  defp captured(output, prefix) do
    output
    |> String.split("\n")
    |> Enum.find_value(fn line ->
      if String.starts_with?(line, prefix), do: String.trim(String.replace_prefix(line, prefix, ""))
    end)
  end

  # --------------------------------------------------------------- the run

  defp run_all(tasks, config) do
    data = Path.join(config.scratch, "data")
    config_home = Path.join(config.scratch, "config")
    scripts = Path.join(config.scratch, "scripts")

    Enum.each([data, config_home, scripts], &File.mkdir_p!/1)
    File.chmod!(data, 0o700)
    File.chmod!(config_home, 0o700)
    Enum.each([data, config_home], &private!/1)

    if config.oracle? do
      write_scripts(tasks, scripts, config)
      compile_model(config)
    end

    started_at = DateTime.utc_now()
    wall_started = System.monotonic_time(:millisecond)
    start_daemon(config, data, config_home, scripts)

    {rows, spent, stopped} =
      Enum.reduce_while(tasks, {[], 0.0, nil}, fn task, {rows, spent, _running} ->
        if spent >= config.spend_cap do
          {:cont,
           {[
              skipped(task, "spend_cap", "the running total reached --spend before this task started")
              | rows
            ], spent, nil}}
        else
          row = run_one(task, config, data, config_home)

          if row.unpriced,
            do: {:halt, {[row | rows], spent, :unpriced_turn}},
            else: {:cont, {[row | rows], Float.round(spent + row.cost_usd, 6), nil}}
        end
      end)

    rows = stopped_rows(Enum.reverse(rows), tasks, stopped)
    wall_ms = System.monotonic_time(:millisecond) - wall_started

    write_result(rows, spent, started_at, wall_ms, config)
    report(rows, spent, wall_ms, config, stopped)
  end

  # Asserted rather than assumed. These two directories hold this run's sessions and its
  # config; a mode that let anybody else read them is one `File.chmod!` away from being
  # invisible, and a corpus that reports a posture it did not check is reporting a hope.
  defp private!(dir) do
    case File.stat(dir) do
      {:ok, %File.Stat{mode: mode}} ->
        if Bitwise.band(mode, 0o077) != 0 do
          die(
            "#{dir} is mode 0#{Integer.to_string(Bitwise.band(mode, 0o777), 8)}; this run's " <>
              "data and config directories must not be readable by anyone else"
          )
        end

      {:error, reason} ->
        die("#{dir} could not be inspected: #{inspect(reason)}")
    end
  end

  defp stopped_rows(rows, _tasks, nil), do: rows

  defp stopped_rows(rows, tasks, :unpriced_turn) do
    done = MapSet.new(rows, & &1.id)

    rows ++
      for task <- tasks, not MapSet.member?(done, task["id"]) do
        skipped(task, "unpriced_turn", "the run stopped: an earlier turn reported no cost")
      end
  end

  defp skipped(task, reason, detail) do
    %{
      id: task["id"],
      ran: false,
      grade: "skip",
      reason: reason,
      detail: detail,
      status: "not-run",
      cost_usd: 0.0,
      unpriced: false,
      tokens: 0,
      tool_calls: 0,
      approvals_requested: 0,
      approvals_answered: 0,
      files_changed: 0,
      setup_ms: 0,
      wall_ms: 0,
      grade_ms: 0,
      grade_setup_ms: 0,
      grade_command: ""
    }
  end

  defp run_one(task, config, data, config_home) do
    logs = Path.join(config.out, task["id"])
    File.mkdir_p!(logs)

    dir = Path.join([config.scratch, "work", task["id"]])
    File.mkdir_p!(Path.dirname(dir))
    timeout = config.timeout || task["timeout_secs"]

    # The workspace is a clone whose history stops at the base, and the task's own answer
    # is asserted absent from it before the agent is let near it. A worktree shares the
    # repository's object store, and the review turned that into a full pass with one
    # `git log --all --grep "<the instruction's own subject>"`.
    mode = {:clone, Git.task_ref(config.run_id, task["id"])}

    try do
      case Workspace.prepare(config.history, dir, task["base_sha"],
             mode: mode,
             support_from: config.support,
             absent: task["commit_sha"],
             envs: warm(config),
             timeout_ms: @setup_ms,
             log: Path.join(logs, "setup.log")
           ) do
        {:error, reason} ->
          say("task    #{task["id"]} setup_failed")
          Map.merge(skipped(task, "setup_failed", reason), %{grade: "FAIL", ran: true})

        {:ok, %{setup_ms: setup_ms}} ->
          agent(task, config, data, config_home, dir, logs, timeout, setup_ms)
      end
    after
      unless config.keep, do: Workspace.remove(config.history, dir, mode: mode)
    end
  end

  # The paid path warms both environments, because the agent will `mix compile` in dev and
  # `mix test` in test and neither should be charged to its turn. The oracle warms only
  # `test`: the scripted model runs no commands, and the only compile that follows is the
  # grader's. Same tree either way — only what is already built in it differs.
  defp warm(%{oracle?: true}), do: ["test"]
  defp warm(_config), do: ["dev", "test"]

  defp agent(task, config, data, config_home, dir, logs, timeout, setup_ms) do
    argv =
      [
        "run",
        task["instruction"],
        "--provider",
        "native",
        "--workspace",
        dir,
        "--approval-mode",
        "prompt",
        "--stream-json",
        "--timeout",
        Integer.to_string(timeout)
      ] ++
        if(config.approve_all?, do: ["--approve-all"], else: []) ++
        if(config.oracle?, do: [], else: ["--model", config.model])

    {outcome, wall_ms} =
      Exec.timed(config.ouro, argv,
        cd: config.checkout,
        # A client that ignored its own --timeout still must not hang the corpus.
        timeout_ms: (timeout + 60) * 1_000,
        max_output_bytes: 8 * 1024 * 1024,
        stderr: Path.join(logs, "ouro.stderr"),
        env: client_env(config, data, config_home)
      )

    {stdout, killed?} =
      case outcome do
        {:ok, _code, out} -> {out, false}
        {:timeout, out} -> {out, true}
      end

    File.write!(Path.join(logs, "trajectory.ndjson"), stdout)
    events = parse_events(stdout)
    report = Enum.find(events, &(&1["type"] == "result")) || %{}
    report = if killed?, do: Map.put(report, "harness", "killed"), else: report
    report = if config.fake_status, do: Map.put(report, "status", config.fake_status), else: report
    File.write!(Path.join(logs, "result.json"), JSON.encode!(report))

    case cost(report, config) do
      :unpriced ->
        verdict = {:fail, "setup_failed", unpriced_detail(), %{}}
        row = %{row(task, report, events, verdict, setup_ms, wall_ms, 0.0) | unpriced: true}
        say("task    #{task["id"]} FAIL setup_failed unpriced_turn")
        row

      {:ok, cost} ->
        verdict =
          Grade.run(task, config, dir, report,
            timeout_ms: @grade_ms,
            setup_timeout_ms: @setup_ms,
            log: Path.join(logs, "grade.log"),
            patch: Path.join(logs, "change.patch"),
            grade_dir: Path.join([config.scratch, "grade", task["id"]])
          )

        row = row(task, report, events, verdict, setup_ms, wall_ms, cost)
        say("task    #{task["id"]} #{row.grade} #{row.reason}")
        row
    end
  end

  defp unpriced_detail do
    "unpriced_turn: the turn completed and reported no usage.cost_usd, so it would have " <>
      "counted as $0 against --spend. A cap that a task can slip past is not a cap; the run stops here."
  end

  defp row(task, report, events, verdict, setup_ms, wall_ms, cost) do
    {grade, reason, detail, extra} =
      case verdict do
        {:pass, extra} -> {"pass", "-", "", extra}
        {:fail, reason, detail, extra} -> {"FAIL", reason, detail, extra}
      end

    %{
      id: task["id"],
      ran: true,
      grade: grade,
      reason: reason,
      detail: detail,
      status: to_string(Map.get(report, "status", "no-result")),
      cost_usd: cost,
      unpriced: false,
      tokens: get_in(report, ["usage", "total_tokens"]) || 0,
      tool_calls: Enum.count(events, &(&1["type"] == "tool_call")),
      approvals_requested: get_in(report, ["approvals", "requested"]) || 0,
      approvals_answered: get_in(report, ["approvals", "answered"]) || 0,
      files_changed: length(Map.get(report, "files_changed", [])),
      setup_ms: setup_ms,
      wall_ms: wall_ms,
      grade_ms: Map.get(extra, :grade_ms, 0),
      grade_setup_ms: Map.get(extra, :grade_setup_ms, 0),
      grade_command: Map.get(extra, :grade_command, "")
    }
  end

  # `usage.cost_usd` is absent when the node could not price the response.
  #
  # It used to count as $0, which the review showed makes `--spend` decoration: every turn
  # of a run whose model this node cannot price is free, the running total never moves, and
  # the cap is never reached. On a paid path an absent number is therefore `:unpriced`, and
  # the run stops rather than carrying on spending money it is not counting. The oracle is
  # exempt because it spends nothing by construction — `--oracle-as-paid` removes the
  # exemption, which is how the selftest proves the rule without a key.
  defp cost(_report, %{fake_cost: fake}) when is_number(fake), do: {:ok, fake * 1.0}

  defp cost(report, config) do
    case get_in(report, ["usage", "cost_usd"]) do
      value when is_number(value) -> {:ok, value * 1.0}
      _absent -> if priced_path?(config), do: :unpriced, else: {:ok, 0.0}
    end
  end

  defp priced_path?(config), do: not config.oracle? or config.oracle_as_paid?

  defp parse_events(stdout) do
    stdout
    |> String.split("\n", trim: true)
    |> Enum.flat_map(fn line ->
      case JSON.decode(line) do
        {:ok, object} when is_map(object) -> [object]
        _other -> []
      end
    end)
  end

  # --------------------------------------------------------------- the runtime

  defp write_scripts(tasks, scripts, config) do
    entries =
      Enum.map(tasks, fn task ->
        case Oracle.script(config.history, task, config.cheat) do
          {:ok, script} ->
            name = task["id"] <> ".json"
            File.write!(Path.join(scripts, name), JSON.encode!(script))
            %{"instruction" => task["instruction"], "script" => name}

          {:error, reason} ->
            die("the oracle could not read #{task["id"]}'s solution: #{reason}")
        end
      end)

    File.write!(Path.join(scripts, "index.json"), JSON.encode!(%{"entries" => entries}))
  end

  # Mix prunes the code path to this project's own applications, so the scripted model has
  # to live in the project's own ebin. The source is `bench/local`'s, unchanged and not
  # copied: one scripted model, one place it is maintained.
  defp compile_model(config) do
    ebin = Path.join(config.checkout, "_build/#{mix_env()}/lib/ouroboros/ebin")
    source = Path.join(config.checkout, "bench/local/model/bench_script_model.ex")

    unless File.dir?(ebin), do: die("#{ebin} does not exist; run `mix compile` first")
    unless File.regular?(source), do: die("#{source} is missing")

    case Exec.run(System.find_executable("elixirc") || "elixirc",
           ["--ignore-module-conflict", "-o", ebin, source],
           cd: config.checkout,
           timeout_ms: 120_000,
           stderr: :stdout,
           env: Env.build(%{"ELIXIR_ERL_OPTIONS" => "-pa " <> ebin})
         ) do
      {:ok, 0, _out} -> :ok
      {:ok, code, out} -> die("compiling the scripted model failed (#{code}):\n#{out}")
      {:timeout, out} -> die("compiling the scripted model timed out:\n#{out}")
    end
  end

  defp mix_env, do: System.get_env("MIX_ENV") || "dev"

  defp start_daemon(config, data, config_home, scripts) do
    say("daemon  starting `ouro --dev daemon` on a scratch data dir")

    case Exec.run(config.ouro, ["--dev", "daemon"],
           cd: config.checkout,
           timeout_ms: @daemon_boot_ms,
           stderr: Path.join(config.scratch, "daemon.stderr"),
           env: daemon_env(config, data, config_home, scripts)
         ) do
      {:ok, 0, out} ->
        port = Regex.run(~r/port\s+(\d+)/, out) |> then(&(&1 && Enum.at(&1, 1)))
        say("daemon  ready on port #{port || "?"}")
        :ok

      {:ok, code, out} ->
        die("`ouro --dev daemon` exited #{code}:\n#{out}\n#{tail(config.scratch)}")

      {:timeout, out} ->
        die("`ouro --dev daemon` did not come up in #{@daemon_boot_ms}ms:\n#{out}")
    end
  end

  # The paid posture: the environment is passed through, keys and `XDG_CONFIG_HOME`
  # included, because the packaged default model authenticates through it. Only
  # `OUROBOROS_DATA_DIR` is scratch, so nothing this run does touches the operator's
  # sessions, and `ouro stop` can only ever mean this runtime.
  #
  # The oracle posture is `bench/local`'s: a scratch config home and every provider key
  # removed, because a corpus that cannot spend is one that cannot spend by accident.
  defp daemon_env(%{oracle?: true}, data, config_home, scripts) do
    Env.build(
      %{
        "OUROBOROS_DATA_DIR" => data,
        "XDG_CONFIG_HOME" => config_home,
        "OUROBOROS_NATIVE_MODEL" => "bench-script:" <> scripts,
        "ELIXIR_ERL_OPTIONS" => "-ouroboros native_model_module 'Elixir.Ouroboros.Bench.ScriptModel'"
      },
      Env.secrets()
    )
  end

  defp daemon_env(config, data, _config_home, _scripts) do
    overrides = %{"OUROBOROS_DATA_DIR" => data}
    overrides = if config.model, do: Map.put(overrides, "OUROBOROS_NATIVE_MODEL", config.model), else: overrides
    Env.build(overrides)
  end

  defp client_env(%{oracle?: true}, data, config_home) do
    Env.build(%{"OUROBOROS_DATA_DIR" => data, "XDG_CONFIG_HOME" => config_home}, Env.secrets())
  end

  defp client_env(_config, data, _config_home), do: Env.build(%{"OUROBOROS_DATA_DIR" => data})

  # Always scoped to the scratch data dir: an unscoped `ouro stop` would go looking for the
  # operator's own runtime, which is not the one this script is responsible for.
  defp stop_daemon(ouro, scratch) do
    data = Path.join(scratch, "data")

    if File.dir?(data) and File.regular?(ouro) do
      case Exec.run(ouro, ["stop"],
             cd: File.cwd!(),
             timeout_ms: 60_000,
             stderr: Path.join(scratch, "stop.stderr"),
             env: Env.build(%{"OUROBOROS_DATA_DIR" => data})
           ) do
        {:ok, 0, _out} -> say("daemon  stopped")
        {:ok, code, out} -> say("daemon  `ouro stop` exited #{code}: #{String.trim(out)}")
        {:timeout, _out} -> say("daemon  `ouro stop` timed out")
      end
    end

    :ok
  end

  defp tail(scratch) do
    case File.read(Path.join(scratch, "daemon.stderr")) do
      {:ok, body} -> body |> String.split("\n") |> Enum.take(-20) |> Enum.join("\n")
      _error -> ""
    end
  end

  # --------------------------------------------------------------- reporting

  defp write_result(rows, spent, started_at, wall_ms, config) do
    ran = Enum.filter(rows, & &1.ran)
    passed = Enum.count(ran, &(&1.grade == "pass"))

    result = %{
      "run" => %{
        "model" => config.model,
        "oracle" => config.oracle?,
        "cheat" => if(config.cheat == "none", do: nil, else: config.cheat),
        "flags" => config.flags,
        "corpus_sha256" => corpus_digest(config),
        "ouro_sha" => ouro_sha(config),
        "ouro_bin" => config.ouro,
        "ouro_bin_sha256" => digest(config.ouro),
        "checkout" => config.checkout,
        "history" => config.history,
        "grader" => "MIX_ENV=test mix test <the task's hidden _test.exs paths>, in a fresh worktree at base_sha",
        "started_at" => DateTime.to_iso8601(started_at),
        "spend_cap" => config.spend_cap,
        "spent" => spent,
        "tasks" => length(rows),
        "ran" => length(ran),
        "passed" => passed,
        "pass_rate" => if(ran == [], do: 0.0, else: Float.round(passed / length(ran), 4)),
        "wall_ms" => wall_ms
      },
      "tasks" =>
        Enum.map(rows, fn row ->
          %{
            "id" => row.id,
            "grade" => row.grade,
            "reason" => row.reason,
            "detail" => row.detail,
            "cost_usd" => row.cost_usd,
            "unpriced" => row.unpriced,
            "tokens" => row.tokens,
            "tool_calls" => row.tool_calls,
            "approvals_requested" => row.approvals_requested,
            "approvals_answered" => row.approvals_answered,
            "files_changed" => row.files_changed,
            "setup_ms" => row.setup_ms,
            "wall_ms" => row.wall_ms,
            "grade_setup_ms" => row.grade_setup_ms,
            "grade_ms" => row.grade_ms,
            "grade_command" => row.grade_command,
            "status" => row.status
          }
        end)
    }

    File.write!(Path.join(config.out, "result.json"), JSON.encode!(result) <> "\n")
  end

  # What a quoted number has to be able to show. A `result.json` used to be unable to say
  # whether it came from a filtered run, a cheated one, a `--fake-cost-usd` one, or a
  # checkout with uncommitted changes in it — all four of which the review produced, and
  # each of which looks exactly like a real run once the file is out of its directory.
  defp ouro_sha(config) do
    sha = Git.out(config.checkout, ["rev-parse", "HEAD"]) || "unknown"
    if Git.dirty?(config.checkout), do: sha <> "-dirty", else: sha
  end

  # Over the sorted `task.json` bytes: the corpus is a list of pins, and two runs that
  # quote the same digest were graded against the same pins.
  defp corpus_digest(config) do
    case File.ls(config.tasks_dir) do
      {:ok, names} ->
        names
        |> Enum.sort()
        |> Enum.map(&Path.join([config.tasks_dir, &1, "task.json"]))
        |> Enum.filter(&File.regular?/1)
        |> Enum.reduce(:crypto.hash_init(:sha256), &:crypto.hash_update(&2, File.read!(&1)))
        |> :crypto.hash_final()
        |> Base.encode16(case: :lower)

      {:error, _reason} ->
        "unknown"
    end
  end

  defp digest(path) do
    if File.regular?(path) do
      path
      |> File.stream!(65_536)
      |> Enum.reduce(:crypto.hash_init(:sha256), &:crypto.hash_update(&2, &1))
      |> :crypto.hash_final()
      |> Base.encode16(case: :lower)
    else
      "unknown"
    end
  end

  defp report(rows, spent, wall_ms, config, stopped) do
    width = rows |> Enum.map(&String.length(&1.id)) |> Enum.max(fn -> 0 end) |> max(4)

    IO.puts("")

    IO.puts(
      pad("task", width) <> "  " <> pad("grade", 5) <> "  " <> pad("reason", 15) <>
        lead("setup", 10) <> lead("agent", 10) <> lead("graded", 10) <> lead("tokens", 8) <>
        lead("cost", 10) <> "  status"
    )

    IO.puts(String.duplicate("-", width + 74))

    Enum.each(rows, fn row ->
      IO.puts(
        pad(row.id, width) <> "  " <> pad(row.grade, 5) <> "  " <> pad(row.reason, 15) <>
          lead("#{row.setup_ms} ms", 10) <> lead("#{row.wall_ms} ms", 10) <>
          lead("#{row.grade_setup_ms + row.grade_ms} ms", 10) <> lead(row.tokens, 8) <>
          lead("$" <> money(row.cost_usd), 10) <> "  " <> row.status
      )
    end)

    failures = Enum.filter(rows, &(&1.grade == "FAIL"))

    unless failures == [] do
      IO.puts("")

      Enum.each(failures, fn row ->
        IO.puts("FAIL #{row.id} — #{row.reason}")
        IO.puts(indent(row.detail))
        IO.puts("     logs: #{Path.join(config.out, row.id)}")
      end)
    end

    ran = Enum.filter(rows, & &1.ran)
    skipped = Enum.reject(rows, & &1.ran)
    passed = Enum.count(ran, &(&1.grade == "pass"))

    IO.puts("")

    IO.puts(
      "#{passed}/#{length(ran)} passed in #{wall_ms} ms, $#{money(spent)} spent of a " <>
        "$#{money(config.spend_cap)} cap"
    )

    if config.cheat != "none" do
      IO.puts("")

      IO.puts(
        "this run was --oracle-cheat #{config.cheat}: a negative control, not a measurement. " <>
          "result.json says so in run.cheat, and no number from it is quotable."
      )
    end

    unless skipped == [] do
      case stopped do
        :unpriced_turn ->
          IO.puts(
            "stopped: a turn completed and reported no usage.cost_usd, so the running total " <>
              "could not bind. #{length(skipped)} task(s) did not run:"
          )

        _cap ->
          IO.puts("stopped at the spend cap; #{length(skipped)} task(s) did not run:")
      end

      Enum.each(skipped, &IO.puts("  " <> &1.id))
    end

    IO.puts("result  #{Path.join(config.out, "result.json")}")

    cond do
      stopped == :unpriced_turn ->
        64

      config.oracle? and is_nil(config.fake_cost) and spent > 0.0 ->
        IO.puts("")
        IO.puts("the oracle reported $#{money(spent)}; it must spend nothing")
        1

      failures != [] ->
        1

      skipped != [] ->
        3

      true ->
        0
    end
  end

  defp money(value), do: :erlang.float_to_binary(value * 1.0, decimals: 4)

  defp stamp do
    DateTime.utc_now()
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601(:basic)
  end

  defp pad(value, width), do: String.pad_trailing(to_string(value), width)
  defp lead(value, width), do: String.pad_leading(to_string(value), width)

  defp indent(text),
    do: text |> String.split("\n") |> Enum.map_join("\n", &("     " <> &1))

  defp say(message), do: IO.puts(:stderr, message)

  defp die(message) do
    IO.puts(:stderr, "bench.self: " <> message)
    System.halt(64)
  end

  defp mix, do: System.find_executable("mix") || "mix"
end

Bench.Self.Runner.main(System.argv())
