#!/usr/bin/env elixir

# Build `bench/self/tasks/` out of this repository's own history. See bench/self/README.md.
#
# A plain `elixir` script, standard library only, for the same reason `bench/local/run.exs`
# is one: it builds and compiles trees at other commits, and doing that from inside the
# runtime's own Mix project would tangle the two build states.
#
#     elixir bench/self/extract.exs --replace                       the whole corpus
#     elixir bench/self/extract.exs --commits a1b2c3,d4e5f6 --out DIR --replace
#     elixir bench/self/extract.exs --verify bench/self/tasks/01-...
#
# A task is a *pin*: shas and paths. Nothing here copies a test into the corpus, because a
# copy is a thing that can be edited without the history noticing.

Code.require_file("lib/support.exs", Path.dirname(__ENV__.file))

defmodule Bench.Self.Extract.Candidate do
  @moduledoc """
  Which commits could be a task, and in what order they are tried.

  The filters are the plan's: a commit that touches `lib/`, adds or modifies at least one
  `test/**/*_test.exs`, is not a merge, and stays out of the trees whose changes this
  corpus cannot grade — `tui/` (Rust, built separately), `assets/`, `.github/`, `scripts/`.
  Three more the source forced:

    * a commit that changes `mix.exs` or `mix.lock` is dropped, because the dependency set
      under it is not the one the cloned `_build` was compiled against;
    * a commit whose *non-test* diff deletes a file is dropped, because the oracle answers
      with `write` calls and cannot express a removal;
    * `bench/` joins the excluded trees, so that no task in this corpus is a task about
      this corpus.

  Ranking is `fix` first, then the smaller non-test diff first. The bias is deliberate: a
  fix has a failing test and a small, local cause, which is the shape of task this
  benchmark is about.
  """

  alias Bench.Self.Git

  @excluded ~w(tui/ assets/ .github/ scripts/ bench/)
  @build_files ~w(mix.exs mix.lock)

  @type t :: %{
          sha: String.t(),
          base: String.t(),
          subject: String.t(),
          fix?: boolean(),
          non_test_lines: non_neg_integer(),
          hidden: [String.t()],
          solution: [String.t()]
        }

  @doc "Every candidate under `ref`, ranked, and a count per static drop class."
  @spec select(Path.t(), String.t(), keyword()) :: {[t()], %{String.t() => non_neg_integer()}}
  def select(repo, ref, opts) do
    max_diff_lines = Keyword.fetch!(opts, :max_diff_lines)

    repo
    |> commits(ref)
    |> Enum.reduce({[], %{}}, fn commit, {kept, dropped} ->
      case examine(repo, commit, max_diff_lines) do
        {:ok, candidate} -> {[candidate | kept], dropped}
        {:drop, class} -> {kept, Map.update(dropped, class, 1, &(&1 + 1))}
      end
    end)
    |> then(fn {kept, dropped} -> {rank(Enum.reverse(kept)), dropped} end)
  end

  @spec rank([t()]) :: [t()]
  def rank(candidates),
    do: Enum.sort_by(candidates, fn c -> {if(c.fix?, do: 0, else: 1), c.non_test_lines, c.sha} end)

  @doc """
  One named commit, examined with the size filter lifted. `--commits` uses this.

  A merge is dropped here as it is in `select/3`. The sweep asks `git log --no-merges` and
  never sees one; this door is the one a caller names a sha at, and a merge's "diff against
  its first parent" is the other branch's work, which is not a task anybody did.
  """
  @spec named(Path.t(), String.t()) :: {:ok, t()} | {:drop, String.t()}
  def named(repo, sha) do
    with full when is_binary(full) <- Git.out(repo, ["rev-parse", sha <> "^{commit}"]),
         parents when parents != [] <- Git.parents(repo, full),
         [parent] <- parents,
         subject when is_binary(subject) <- Git.out(repo, ["--no-pager", "log", "-1", "--format=%s", full]) do
      examine(repo, %{sha: full, base: parent, subject: subject}, :infinity)
    else
      [_first, _second | _more] -> {:drop, "merge_commit"}
      _unknown -> {:drop, "unknown_commit"}
    end
  end

  # One `git log` for the whole history rather than two `rev-parse`s per commit: 610
  # commits is 1 220 processes that do not need to exist. `%P` is empty for the root
  # commit, which is the only commit with no parent to diff against.
  defp commits(repo, ref) do
    case Git.run(repo, ["--no-pager", "log", "--no-merges", "--format=%H\t%P\t%s", ref],
           timeout_ms: 120_000,
           max_output_bytes: 8 * 1024 * 1024
         ) do
      {:ok, output} ->
        output
        |> String.split("\n", trim: true)
        |> Enum.flat_map(fn line ->
          case String.split(line, "\t", parts: 3) do
            [sha, parents, subject] ->
              case String.split(parents, " ", trim: true) do
                [base | _rest] -> [%{sha: sha, base: base, subject: subject}]
                [] -> []
              end

            _other ->
              []
          end
        end)

      {:error, _reason} ->
        []
    end
  end

  defp examine(repo, commit, max_diff_lines) do
    with {:ok, entries} <- entries(repo, commit),
         :ok <- shape(entries) do
      measure(repo, commit, entries, max_diff_lines)
    end
  end

  defp entries(repo, commit) do
    case Git.name_status(repo, commit.base, commit.sha) do
      {:ok, []} -> {:drop, "empty_diff"}
      {:ok, entries} -> {:ok, entries}
      {:error, _reason} -> {:drop, "unreadable_diff"}
    end
  end

  defp shape(entries) do
    paths = Enum.map(entries, fn {_status, path} -> path end)

    cond do
      not Enum.any?(paths, &String.starts_with?(&1, "lib/")) ->
        {:drop, "no_lib_change"}

      not Enum.any?(entries, fn {status, path} ->
        not String.starts_with?(status, "D") and test_file?(path)
      end) ->
        {:drop, "no_test_added_or_modified"}

      Enum.any?(paths, fn path -> Enum.any?(@excluded, &String.starts_with?(path, &1)) end) ->
        {:drop, "excluded_tree"}

      Enum.any?(paths, &(&1 in @build_files)) ->
        {:drop, "build_files_changed"}

      Enum.any?(entries, fn {status, path} ->
        String.starts_with?(status, "D") and not under_test?(path)
      end) ->
        {:drop, "non_test_deletion"}

      true ->
        :ok
    end
  end

  defp measure(repo, commit, entries, max_diff_lines) do
    solution =
      entries
      |> Enum.reject(fn {_status, path} -> under_test?(path) end)
      |> Enum.map(fn {_status, path} -> path end)
      |> Enum.sort()

    hidden =
      entries
      |> Enum.reject(fn {status, path} ->
        String.starts_with?(status, "D") or not under_test?(path)
      end)
      |> Enum.map(fn {_status, path} -> path end)
      |> Enum.sort()

    cond do
      solution == [] ->
        {:drop, "no_non_test_change"}

      true ->
        lines = Git.diff_lines(repo, commit.base, commit.sha, [".", ":(exclude)test"])

        if max_diff_lines != :infinity and lines > max_diff_lines do
          {:drop, "diff_too_large"}
        else
          {:ok,
           %{
             sha: commit.sha,
             base: commit.base,
             subject: commit.subject,
             fix?: String.starts_with?(commit.subject, "fix"),
             non_test_lines: lines,
             hidden: hidden,
             solution: solution
           }}
        end
    end
  end

  defp test_file?(path), do: under_test?(path) and String.ends_with?(path, "_test.exs")
  defp under_test?(path), do: path == "test" or String.starts_with?(path, "test/")
end

defmodule Bench.Self.Extract.Instruction do
  @moduledoc """
  What the agent is told.

  The subject, the body with its trailers and any pasted diff removed, and an **Acceptance**
  list of the hidden tests' `test "…"` titles — never their bodies. Many commit bodies in
  this history are a subject and nothing else, so the titles are usually the only statement
  of intent a task has; a title is also roughly what a maintainer would write in an issue,
  which is the register this benchmark is trying to be honest about.

  The titles are the ones the commit *adds*. A title already present at the parent says
  nothing about what changed. When a commit only edits existing test bodies, that file's
  own titles are used, so a task is never handed an empty acceptance list.

  The rules paragraph states the grading conditions the agent could otherwise only discover
  by failing them. Saying them does not make gaming easier — the grader enforces them
  either way — and not saying them would be measuring a rule nobody was told.

  **The body frequently describes the change.** A commit message written by the person who
  made the change often names the function, the file, or the exact behaviour; the corpus
  measures executing a described change against tests nobody showed the agent, and this
  file is where that is decided rather than hidden. `subject-only` is the harder question,
  and `--instruction subject-only` is how a second corpus asks it: the subject, the
  acceptance list, and the rules, with the body dropped.
  """

  alias Bench.Self.Git

  @kinds ~w(full subject-only)
  @max_titles 12
  @max_body 4_000
  @title ~r/^\s*test[\s(]+"((?:[^"\\]|\\.)*)"/m

  @rules "Rules. Files that already exist under `test/` must not be modified or deleted — " <>
           "the change is graded against tests restored from the history after the session " <>
           "ends, applied to a fresh checkout of the starting commit. New test files of " <>
           "your own are allowed and are left in place, but they are yours: they are not " <>
           "copied into the tree the grade runs in. The change is collected as a diff over " <>
           "`lib/`, `assets/`, `priv/`, `config/`, `docs/` and `README.md`; a change to any " <>
           "other path — `mix.exs` and `.formatter.exs` included — is refused rather than " <>
           "graded. Work only inside this worktree."

  @doc "The instruction kinds `--instruction` accepts."
  @spec kinds() :: [String.t()]
  def kinds, do: @kinds

  @spec build(Path.t(), map(), String.t()) :: String.t()
  def build(repo, candidate, kind \\ "full") do
    [head(repo, candidate.sha, kind), acceptance(titles(repo, candidate)), @rules]
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n\n")
  end

  defp head(repo, sha, "subject-only"), do: Git.out(repo, ["--no-pager", "log", "-1", "--format=%s", sha]) || ""
  defp head(repo, sha, _full), do: subject_and_body(repo, sha)

  @doc ~S'The `test "…"` titles a commit adds to its hidden test files.'
  @spec titles(Path.t(), map()) :: [String.t()]
  def titles(repo, candidate) do
    candidate.hidden
    |> Enum.filter(&String.ends_with?(&1, "_test.exs"))
    |> Enum.flat_map(fn path ->
      at_commit = file_titles(repo, candidate.sha, path)

      case at_commit -- file_titles(repo, candidate.base, path) do
        [] -> at_commit
        fresh -> fresh
      end
    end)
    |> Enum.uniq()
    |> Enum.take(@max_titles)
  end

  defp file_titles(repo, sha, path) do
    case Git.show(repo, sha, path) do
      {:ok, body} ->
        @title
        |> Regex.scan(body, capture: :all_but_first)
        |> Enum.map(fn [title] -> String.replace(title, "\\\"", "\"") end)

      {:error, _reason} ->
        []
    end
  end

  defp subject_and_body(repo, sha) do
    subject = Git.out(repo, ["--no-pager", "log", "-1", "--format=%s", sha]) || ""
    raw = Git.out(repo, ["--no-pager", "log", "-1", "--format=%b", sha]) || ""

    body =
      raw
      |> String.split("\n")
      |> Enum.take_while(&(not String.starts_with?(&1, "diff --git")))
      |> Enum.reject(&trailer?/1)
      |> Enum.join("\n")
      |> String.trim()
      |> String.slice(0, @max_body)

    if body == "", do: subject, else: subject <> "\n\n" <> body
  end

  defp trailer?(line) do
    down = line |> String.trim() |> String.downcase()

    Enum.any?(
      ["co-authored-by:", "signed-off-by:", "generated with", "🤖"],
      &String.starts_with?(down, &1)
    )
  end

  defp acceptance([]), do: ""

  defp acceptance(titles) do
    "Acceptance. These tests are restored into the worktree after the session ends and " <>
      "must pass:\n" <> Enum.map_join(titles, "\n", &("  - " <> &1))
  end
end

defmodule Bench.Self.Extract do
  @moduledoc "Candidate selection, verification in a real tree, and the corpus on disk."

  alias Bench.Self.Extract.{Candidate, Instruction}
  alias Bench.Self.{Fs, Git, Hidden, Prompt, TaskFile, Workspace}

  @defaults %{
    ref: "dev",
    max_tasks: 30,
    max_diff_lines: 300,
    task_ceiling_secs: 600,
    max_solution_bytes: 393_216,
    max_candidates: 90,
    commit_checks: 2,
    jobs: 3
  }

  def main(argv) do
    {opts, _rest} =
      OptionParser.parse!(argv,
        strict: [
          out: :string,
          ref: :string,
          commits: :string,
          verify: :string,
          history: :string,
          instruction: :string,
          reinstruct: :string,
          max_tasks: :integer,
          max_diff_lines: :integer,
          task_ceiling_secs: :integer,
          max_solution_bytes: :integer,
          max_candidates: :integer,
          commit_checks: :integer,
          jobs: :integer,
          replace: :boolean,
          keep: :boolean
        ]
      )

    root = Path.expand(Path.dirname(__ENV__.file))
    own = Path.expand(Path.join(root, "../.."))

    # `--history` is the repository whose commits become tasks; it defaults to this
    # checkout, and the selftest points it at a two-file fixture repository so that the
    # extractor's own gates — a parent that already passes, a commit that does not — can be
    # proved in seconds rather than argued about. The *checkout* stays this one either way:
    # the reserved prompt delimiters are a property of the runtime under test, and the
    # `deps/`/`_build/` that get cloned into a tree belong to this project.
    repo = Path.expand(opts[:history] || own)

    config =
      @defaults
      |> Map.merge(Map.new(Keyword.take(opts, Map.keys(@defaults))))
      |> Map.merge(%{
        repo: repo,
        checkout: own,
        support: if(Git.same_repository?(own, repo), do: own, else: nil),
        instruction_kind: opts[:instruction] || "full",
        root: root,
        out: Path.expand(opts[:out] || Path.join(root, "tasks")),
        keep: opts[:keep] == true
      })

    cond do
      config.instruction_kind not in Instruction.kinds() ->
        die("--instruction must be one of " <> Enum.join(Instruction.kinds(), ", "))

      is_binary(opts[:reinstruct]) ->
        System.halt(reinstruct(config, Path.expand(opts[:reinstruct])))

      is_binary(opts[:verify]) ->
        System.halt(verify_existing(config, Path.expand(opts[:verify])))

      true ->
        extract(config, opts)
    end
  end

  # ------------------------------------------------------------------ --reinstruct

  # Rewrites an existing corpus's instructions from the history, without rebuilding a tree.
  #
  # An instruction is derived — subject, body, the titles the commit adds, the rules — so
  # when the derivation changes, the corpus is stale rather than wrong, and re-deriving it
  # is not the same job as re-extracting it. Re-extraction would pick different commits;
  # this keeps the pins and rewrites the prose. It is also how a `subject-only` corpus is
  # made from a `full` one: same thirty commits, one variable changed.
  defp reinstruct(config, dir) do
    case TaskFile.load_all(dir, nil) do
      {:error, reason} ->
        say("reinstruct  #{reason}")
        64

      {:ok, []} ->
        say("reinstruct  #{dir} holds no tasks")
        64

      {:ok, tasks} ->
        Enum.each(tasks, fn task ->
          instruction = Instruction.build(config.repo, candidate(task), config.instruction_kind)

          task
          |> Map.drop(["dir"])
          |> Map.put("instruction", instruction)
          |> Map.put("instruction_kind", config.instruction_kind)
          |> then(&TaskFile.write(task["dir"], &1))

          say("reinstruct  #{task["id"]} #{String.length(instruction)} characters")
        end)

        say("reinstruct  #{length(tasks)} task(s) in #{dir} are now #{config.instruction_kind}")
        collisions(dir)
    end
  end

  defp collisions(dir) do
    reloaded =
      case TaskFile.load_all(dir, nil) do
        {:ok, list} -> list
        {:error, _reason} -> []
      end

    pairs =
      for a <- reloaded,
          b <- reloaded,
          a["dir"] != b["dir"],
          String.contains?(b["instruction"], a["instruction"]),
          do: {a["id"], b["id"]}

    case pairs do
      [] ->
        0

      [{inner, outer} | _rest] ->
        say("reinstruct  #{inner}'s instruction is now contained in #{outer}'s; the runner will refuse this corpus")
        1
    end
  end

  defp candidate(task) do
    %{
      sha: task["commit_sha"],
      base: task["base_sha"],
      subject: task["subject"],
      fix?: false,
      non_test_lines: get_in(task, ["measured", "diff_lines"]) || 0,
      hidden: task["hidden_tests"],
      solution: task["solution_files"]
    }
  end

  # ------------------------------------------------------------------ extraction

  defp extract(config, opts) do
    :ok = ensure_out(config.out, opts[:replace] == true)
    scratch = Fs.scratch_dir("ouroboros-bench-self-extract")
    say("repo    #{config.repo}")
    say("out     #{config.out}")
    say("scratch #{scratch}")

    {candidates, static_drops} = candidates(config, opts[:commits])
    say("static  #{length(candidates)} candidates survived the static filters")

    config =
      config
      |> Map.put(:scratch, scratch)
      |> Map.put(:delimiters, delimiters(config.checkout))
    considered = Enum.take(candidates, config.max_candidates)

    {accepted, dynamic_drops} =
      try do
        verify_all(considered, config)
      after
        unless config.keep, do: File.rm_rf(scratch)
      end

    tasks = write_corpus(accepted, config)
    report(tasks, static_drops, dynamic_drops, length(candidates), length(considered), config)
    System.halt(if tasks == [], do: 1, else: 0)
  end

  defp candidates(config, nil),
    do: Candidate.select(config.repo, config.ref, max_diff_lines: config.max_diff_lines)

  # `--commits` is the selftest's door: named commits, verified exactly as any other
  # candidate is, with the size filter lifted because the caller named them on purpose.
  defp candidates(config, list) do
    list
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reduce({[], %{}}, fn sha, {kept, dropped} ->
      case Candidate.named(config.repo, sha) do
        {:ok, candidate} -> {[candidate | kept], dropped}
        {:drop, class} -> {kept, Map.update(dropped, class, 1, &(&1 + 1))}
      end
    end)
    |> then(fn {kept, dropped} -> {Enum.reverse(kept), dropped} end)
  end

  defp ensure_out(out, replace?) do
    existing =
      case File.ls(out) do
        {:ok, names} -> Enum.filter(names, &File.regular?(Path.join([out, &1, "task.json"])))
        {:error, _reason} -> []
      end

    cond do
      existing == [] ->
        File.mkdir_p!(out)
        :ok

      replace? ->
        Enum.each(existing, &File.rm_rf!(Path.join(out, &1)))
        :ok

      true ->
        die("#{out} already holds #{length(existing)} tasks; pass --replace to rebuild them")
    end
  end

  # Chunked rather than one `async_stream` over everything, so verification stops as soon
  # as `--max-tasks` have passed: the ranking is the point, and compiling the whole tail to
  # throw it away would be minutes for nothing.
  defp verify_all(candidates, config) do
    candidates
    |> Enum.chunk_every(config.jobs)
    |> Enum.reduce_while({[], []}, fn chunk, {accepted, dropped} ->
      results =
        chunk
        |> Task.async_stream(&verify(&1, config), max_concurrency: config.jobs, timeout: :infinity)
        |> Enum.map(fn {:ok, result} -> result end)

      accepted = accepted ++ for({:ok, task} <- results, do: task)
      dropped = dropped ++ for({:drop, sha, class, detail} <- results, do: {sha, class, detail})

      if length(accepted) >= config.max_tasks,
        do: {:halt, {Enum.take(accepted, config.max_tasks), dropped}},
        else: {:cont, {accepted, dropped}}
    end)
  end

  @doc false
  def verify(candidate, config) do
    short = String.slice(candidate.sha, 0, 8)
    graded = Enum.filter(candidate.hidden, &String.ends_with?(&1, "_test.exs"))

    with {:ok, bytes} <- payload(candidate, config),
         :ok <- gradable(graded),
         {:ok, instruction} <- instruction(candidate, config),
         {:ok, measured} <- prove(candidate, graded, config) do
      say("verify  #{short} ok   #{candidate.non_test_lines} non-test lines, " <>
            "#{length(graded)} graded file(s), #{bytes} solution bytes")

      {:ok, task(candidate, measured, instruction, config.instruction_kind)}
    else
      {:drop, class, detail} ->
        say("verify  #{short} drop #{class}#{if detail == "", do: "", else: " — " <> detail}")
        {:drop, candidate.sha, class, detail}
    end
  end

  # The oracle answers a task with one `write` per changed non-test file, so every one of
  # them has to be text this script can put in a JSON script file, and the whole set has to
  # fit the scripted model's own per-file ceiling. A task whose solution does not fit is
  # dropped rather than left in the corpus as one the $0 gate cannot prove.
  defp payload(candidate, config) do
    Enum.reduce_while(candidate.solution, {:ok, 0}, fn path, {:ok, total} ->
      case Git.show(config.repo, candidate.sha, path) do
        {:ok, body} ->
          cond do
            not String.valid?(body) ->
              {:halt, {:drop, "solution_not_utf8", path}}

            total + byte_size(body) > config.max_solution_bytes ->
              {:halt, {:drop, "solution_too_large", "#{total + byte_size(body)} bytes"}}

            true ->
              {:cont, {:ok, total + byte_size(body)}}
          end

        {:error, reason} ->
          {:halt, {:drop, "solution_unreadable", reason}}
      end
    end)
  end

  defp gradable([]), do: {:drop, "no_graded_test_file", ""}
  defp gradable(_paths), do: :ok

  # A commit message about the prompt boundary quotes the boundary, and the runtime refuses
  # a prompt that carries one of its own delimiters. Such a task can never be attempted, so
  # it is dropped here rather than left in the corpus to fail `not_completed` and read like
  # the agent's fault. The list comes from the runtime; see `Bench.Self.Prompt`.
  defp instruction(candidate, config) do
    text = Instruction.build(config.repo, candidate, config.instruction_kind)

    if Prompt.reserved?(text, config.delimiters),
      do: {:drop, "instruction_reserved_delimiter", "the runtime refuses a prompt carrying its own delimiters"},
      else: {:ok, text}
  end

  defp delimiters(repo) do
    case Prompt.reserved_delimiters(repo) do
      {:ok, list} -> list
      {:error, reason} -> die(reason)
    end
  end

  # The proof that a task is a task: the hidden tests fail at the parent and pass at the
  # commit, in a tree built exactly the way the runner will build it.
  defp prove(candidate, graded, config) do
    short = String.slice(candidate.sha, 0, 12)
    dir = Path.join(config.scratch, short)
    log = Path.join([config.scratch, "logs", short <> ".log"])
    ceiling_ms = config.task_ceiling_secs * 1_000

    try do
      with {:ok, %{setup_ms: setup_ms}} <- prepared(config, dir, candidate.base, ceiling_ms, log),
           :ok <- restored(config.repo, dir, candidate.sha, candidate.hidden),
           {:ok, parent_ms} <- fails_at_parent(dir, graded, ceiling_ms, log),
           :ok <- under_ceiling(setup_ms + parent_ms, ceiling_ms),
           :ok <- moved_to(dir, candidate.sha),
           {:ok, commit_ms} <- passes_at_commit(dir, graded, ceiling_ms, log, config.commit_checks) do
        {:ok, %{setup_ms: setup_ms, parent_test_ms: parent_ms, commit_test_ms: commit_ms}}
      end
    after
      unless config.keep, do: Git.worktree_remove(config.repo, dir)
    end
  end

  defp prepared(%{repo: repo, support: support}, dir, base, ceiling_ms, log) do
    case Workspace.prepare(repo, dir, base,
           envs: ["test"],
           support_from: support,
           timeout_ms: ceiling_ms,
           log: log
         ) do
      {:ok, prepared} -> {:ok, prepared}
      {:error, reason} -> {:drop, "setup_failed", reason}
    end
  end

  defp restored(repo, dir, sha, hidden) do
    case Hidden.restore(repo, dir, sha, hidden) do
      :ok -> :ok
      {:error, reason} -> {:drop, "restore_failed", reason}
    end
  end

  defp fails_at_parent(dir, graded, ceiling_ms, log) do
    case Workspace.test(dir, graded, timeout_ms: ceiling_ms) do
      {:ok, 0, ms, out} ->
        append(log, "$ mix test (parent, expected to fail)\n" <> out)
        {:drop, "parent_already_passes", "#{ms}ms"}

      {:ok, _status, ms, out} ->
        append(log, "$ mix test (parent)\n" <> out)
        {:ok, ms}

      {:timeout, ms, out} ->
        append(log, "$ mix test (parent, timed out)\n" <> out)
        {:drop, "parent_test_timeout", "#{ms}ms"}
    end
  end

  defp under_ceiling(ms, ceiling_ms) when ms <= ceiling_ms, do: :ok
  defp under_ceiling(ms, ceiling_ms), do: {:drop, "over_task_ceiling", "#{ms}ms > #{ceiling_ms}ms"}

  defp moved_to(dir, sha) do
    case Git.run(dir, ["checkout", "--force", "--detach", sha], timeout_ms: 300_000) do
      {:ok, _out} -> :ok
      {:error, reason} -> {:drop, "checkout_failed", reason}
    end
  end

  # The commit's own tests must pass, more than once.
  #
  # `--commit-checks` is not in the plan; the corpus asked for it. This repository has
  # load-sensitive suites, and extraction runs `--jobs` worktrees compiling and testing at
  # the same time. A task whose *reference answer* passes only sometimes is noise in the
  # measurement: the first full oracle run failed `c7e6a528` at
  # `test/workspace_returns_test.exs:312` after extraction had watched the same file pass.
  # Two runs with different ExUnit seeds, under the same load, is the cheapest screen that
  # catches that class; it is not a proof of determinism and does not claim to be.
  defp passes_at_commit(dir, graded, ceiling_ms, log, checks) do
    Enum.reduce_while(1..max(checks, 1), {:ok, 0}, fn attempt, {:ok, slowest} ->
      case Workspace.test(dir, graded, timeout_ms: ceiling_ms) do
        {:ok, 0, ms, out} ->
          append(log, "$ mix test (commit, attempt #{attempt})\n" <> out)
          {:cont, {:ok, max(slowest, ms)}}

        {:ok, status, ms, out} ->
          append(log, "$ mix test (commit, attempt #{attempt}, expected to pass)\n" <> out)
          {:halt, {:drop, "commit_does_not_pass", "attempt #{attempt} exited #{status} after #{ms}ms"}}

        {:timeout, ms, out} ->
          append(log, "$ mix test (commit, attempt #{attempt}, timed out)\n" <> out)
          {:halt, {:drop, "commit_test_timeout", "attempt #{attempt} after #{ms}ms"}}
      end
    end)
  end

  # 300 s of reading and thinking, plus three times what the change itself costs to build
  # and prove, bounded either side. A budget, not a prediction: `--timeout` overrides it,
  # and a task that ends early costs nothing.
  defp timeout_secs(measured) do
    (300 + 3 * div(measured.setup_ms + measured.commit_test_ms, 1_000))
    |> max(600)
    |> min(1_800)
  end

  defp task(candidate, measured, instruction, kind) do
    %{
      "base_sha" => candidate.base,
      "instruction" => instruction,
      "instruction_kind" => kind,
      "commit_sha" => candidate.sha,
      "subject" => candidate.subject,
      "hidden_tests" => candidate.hidden,
      "solution_files" => candidate.solution,
      "timeout_secs" => timeout_secs(measured),
      "measured" => %{
        "compile_ms" => measured.setup_ms,
        "test_ms" => measured.commit_test_ms,
        "diff_lines" => candidate.non_test_lines
      }
    }
  end

  # ------------------------------------------------------------------ the corpus

  defp write_corpus(accepted, config) do
    accepted
    |> reject_collisions()
    |> Enum.with_index(1)
    |> Enum.map(fn {task, index} -> Map.put(task, "id", id(index, task["subject"])) end)
    |> tap(fn tasks -> Enum.each(tasks, &TaskFile.write(Path.join(config.out, &1["id"]), &1)) end)
  end

  # The scripted model matches an instruction by containment, so a corpus in which one
  # instruction contains another has an ambiguous oracle. `bench/local` refuses such a
  # corpus; here the extractor is the one building it, so it drops the contained task and
  # says so, rather than shipping something the $0 gate cannot run.
  defp reject_collisions(tasks) do
    Enum.reject(tasks, fn task ->
      collides? =
        Enum.any?(tasks, fn other ->
          other["commit_sha"] != task["commit_sha"] and
            String.contains?(other["instruction"], task["instruction"])
        end)

      if collides?,
        do: say("corpus  #{String.slice(task["commit_sha"], 0, 8)} dropped: its instruction is contained in another's")

      collides?
    end)
  end

  @max_slug 40

  defp id(index, subject) do
    slug =
      subject
      |> String.replace(~r/^[a-z]+\(([^)]+)\):\s*/, "\\1 ")
      |> String.replace(~r/^[a-z]+:\s*/, "")
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]+/, "-")
      |> String.trim("-")
      |> shorten()

    String.pad_leading(Integer.to_string(index), 2, "0") <> "-" <> if(slug == "", do: "task", else: slug)
  end

  # Cut back to the last whole word rather than mid-syllable: an id is read in a table and
  # in a directory listing, and `…-the-sess` is worse than one word short.
  defp shorten(slug) when byte_size(slug) <= @max_slug, do: slug

  defp shorten(slug) do
    slug
    |> String.slice(0, @max_slug)
    |> String.replace(~r/-[a-z0-9]*$/, "")
    |> String.trim("-")
  end

  # ------------------------------------------------------------------ --verify

  defp verify_existing(config, dir) do
    case TaskFile.load(dir) do
      {:error, reason} ->
        say("verify  #{reason}")
        64

      {:ok, task} ->
        scratch = Fs.scratch_dir("ouroboros-bench-self-verify")

        config =
          config
          |> Map.put(:scratch, scratch)
          |> Map.put(:delimiters, delimiters(config.checkout))

        candidate = %{
          sha: task["commit_sha"],
          base: task["base_sha"],
          subject: task["subject"],
          fix?: false,
          non_test_lines: get_in(task, ["measured", "diff_lines"]) || 0,
          hidden: task["hidden_tests"],
          solution: task["solution_files"]
        }

        try do
          case verify(candidate, config) do
            {:ok, _task} ->
              say("verify  #{task["id"]} still holds")
              0

            {:drop, _sha, class, detail} ->
              say("verify  #{task["id"]} no longer holds: #{class} #{detail}")
              1
          end
        after
          unless config.keep, do: File.rm_rf(scratch)
        end
    end
  end

  # ------------------------------------------------------------------ reporting

  defp report(tasks, static_drops, dynamic_drops, candidates, considered, config) do
    IO.puts("")
    IO.puts("extracted #{length(tasks)} tasks into #{config.out}")
    IO.puts("")

    IO.puts(
      pad("task", 46) <> pad("commit", 10) <> pad("lines", 7) <> pad("hidden", 8) <>
        pad("instr", 8) <> pad("setup", 10) <> pad("test", 10) <> "timeout"
    )

    IO.puts(String.duplicate("-", 108))

    Enum.each(tasks, fn task ->
      IO.puts(
        pad(task["id"], 46) <>
          pad(String.slice(task["commit_sha"], 0, 8), 10) <>
          pad(get_in(task, ["measured", "diff_lines"]), 7) <>
          pad(length(task["hidden_tests"]), 8) <>
          pad(String.length(task["instruction"]), 8) <>
          pad("#{get_in(task, ["measured", "compile_ms"])} ms", 10) <>
          pad("#{get_in(task, ["measured", "test_ms"])} ms", 10) <>
          "#{task["timeout_secs"]} s"
      )
    end)

    IO.puts("")
    distribution("non-test diff lines", Enum.map(tasks, &get_in(&1, ["measured", "diff_lines"])))
    distribution("instruction characters", Enum.map(tasks, &String.length(&1["instruction"])))
    distribution("hidden test files", Enum.map(tasks, &length(&1["hidden_tests"])))
    distribution("solution files", Enum.map(tasks, &length(&1["solution_files"])))

    IO.puts("")
    verified = length(tasks) + length(dynamic_drops)

    IO.puts(
      "candidates after the static filters: #{candidates}; #{considered} offered to " <>
        "verification, #{verified} reached it before --max-tasks was met"
    )
    IO.puts("dropped by the static filters:")
    Enum.each(Enum.sort(static_drops), fn {class, count} -> IO.puts("  " <> pad(class, 34) <> to_string(count)) end)

    if dynamic_drops != [] do
      IO.puts("dropped during verification:")

      dynamic_drops
      |> Enum.group_by(fn {_sha, class, _detail} -> class end)
      |> Enum.sort()
      |> Enum.each(fn {class, entries} ->
        IO.puts("  " <> pad(class, 34) <> to_string(length(entries)))
        Enum.each(entries, fn {sha, _class, detail} -> IO.puts("      #{String.slice(sha, 0, 8)}  #{detail}") end)
      end)
    end
  end

  defp distribution(_label, []), do: :ok

  defp distribution(label, values) do
    sorted = Enum.sort(values)
    n = length(sorted)

    IO.puts(
      pad(label, 24) <>
        "min #{List.first(sorted)}  median #{Enum.at(sorted, div(n, 2))}  " <>
        "mean #{div(Enum.sum(sorted), n)}  max #{List.last(sorted)}  (n=#{n})"
    )
  end

  defp append(nil, _text), do: :ok

  defp append(path, text) do
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, text <> "\n", [:append])
  end

  defp pad(value, width), do: String.pad_trailing(to_string(value), width)

  defp say(message), do: IO.puts(:stderr, message)

  defp die(message) do
    IO.puts(:stderr, "bench.self.extract: " <> message)
    System.halt(64)
  end
end

Bench.Self.Extract.main(System.argv())
