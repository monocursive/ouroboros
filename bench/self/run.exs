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

  @modes ~w(none no-solution blank-tests)

  @blank """
  defmodule Bench.Self.Oracle.BlankedTest do
    use ExUnit.Case, async: true

    test "blanked by the oracle cheat seam" do
      assert true
    end
  end
  """

  @doc "The three cheat modes `--oracle-cheat` accepts."
  @spec modes() :: [String.t()]
  def modes, do: @modes

  @doc """
  The script for one task, in one of three modes.

  `none` is the oracle. The other two are the **negative controls** that make
  `selftest.sh` a proof rather than a demonstration, and each is refused outside
  `--oracle`:

    * `no-solution` answers with nothing at all. Every task must then fail
      `tests_failed` — which is only true if the grader really restores the hidden tests
      from `commit_sha`. Without the restore, the *parent's* copy of the test would run,
      and the parent's copy passes: a runner that skipped the restore would grade this
      cheat as a full pass.
    * `blank-tests` writes the real solution **and** overwrites a hidden test that already
      existed at `base_sha` with a file that asserts nothing. Every task must then fail
      `modified_tests`. Without the modified-test check the restore would put the real
      test back and the task would pass, so this is the control for check 2 exactly.
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

  def script(repo, task, mode) do
    with {:ok, calls} <- writes(repo, task) do
      {:ok, wrap(task, calls ++ blanking(repo, task, mode))}
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

  defp blanking(_repo, _task, "none"), do: []

  defp blanking(repo, task, "blank-tests") do
    task["hidden_tests"]
    |> Hidden.graded()
    |> Enum.find(&Git.exists?(repo, task["base_sha"], &1))
    |> case do
      nil -> []
      path -> [call(0, path, @blank)]
    end
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
  2. No file that already existed under `test/` was modified or deleted.
  3. The hidden tests, restored from `commit_sha`, pass under a wall clock.

  Step 2 is checked two ways. `git status --porcelain -- test/` is the plan's check and
  sees the working tree. `git diff --name-status <base_sha> -- test/` is the one that
  matters: it compares the tree against the commit the task started from, so an agent that
  *committed* its edit to a test — leaving `git status` clean — is still caught. Untracked
  new files appear in neither, which is the intent: writing your own tests is allowed.
  """

  alias Bench.Self.{Git, Hidden, Workspace}

  @dirty ~w(M D R C T U)

  @type verdict :: {:pass, map()} | {:fail, String.t(), String.t(), map()}

  @spec run(map(), Path.t(), Path.t(), map(), keyword()) :: verdict()
  def run(task, repo, dir, report, opts) do
    timeout_ms = Keyword.get(opts, :timeout_ms, 900_000)
    log = Keyword.get(opts, :log)

    with :ok <- completed(report),
         :ok <- tests_untouched(dir, task["base_sha"]),
         :ok <- pinned(repo, task),
         {:ok, graded} <- graded(task),
         :ok <- restored(repo, dir, task) do
      case Workspace.test(dir, graded, timeout_ms: timeout_ms) do
        {:ok, 0, ms, out} ->
          append(log, out)
          {:pass, %{grade_ms: ms}}

        {:ok, status, ms, out} ->
          append(log, out)
          {:fail, "tests_failed", "mix test exited #{status}: " <> tail(out), %{grade_ms: ms}}

        {:timeout, ms, out} ->
          append(log, out)
          {:fail, "tests_failed", "mix test timed out after #{timeout_ms}ms", %{grade_ms: ms}}
      end
    else
      {:fail, reason, detail} -> {:fail, reason, detail, %{grade_ms: 0}}
    end
  end

  defp completed(%{"status" => "completed"}), do: :ok
  defp completed(%{"status" => "timeout"}), do: {:fail, "timeout", "the turn hit its --timeout"}
  defp completed(%{"harness" => "killed"}), do: {:fail, "timeout", "the client outlived its own timeout and was killed"}

  defp completed(report),
    do: {:fail, "not_completed", "status " <> to_string(Map.get(report, "status", "no-result")) <>
           case Map.get(report, "error") do
             nil -> ""
             error -> ": " <> String.slice(to_string(error), 0, 200)
           end}

  defp tests_untouched(dir, base_sha) do
    with :ok <- porcelain_clean(dir),
         :ok <- diff_clean(dir, base_sha) do
      :ok
    end
  end

  defp porcelain_clean(dir) do
    case Git.run(dir, ["status", "--porcelain", "--", "test"]) do
      {:ok, output} ->
        case Enum.filter(String.split(output, "\n", trim: true), &dirty_status?/1) do
          [] -> :ok
          lines -> {:fail, "modified_tests", Enum.join(Enum.take(lines, 10), "; ")}
        end

      {:error, reason} ->
        {:fail, "setup_failed", reason}
    end
  end

  defp diff_clean(dir, base_sha) do
    case Git.name_status(dir, base_sha, nil, ["test"]) do
      {:ok, []} ->
        :ok

      {:ok, entries} ->
        case Enum.reject(entries, fn {status, _path} -> String.starts_with?(status, "A") end) do
          [] -> :ok
          bad -> {:fail, "modified_tests", Enum.map_join(bad, "; ", fn {s, p} -> s <> " " <> p end)}
        end

      {:error, reason} ->
        {:fail, "setup_failed", reason}
    end
  end

  # `git status --porcelain` puts the index state first and the worktree state second, so a
  # modification is `M` in either column. `??` (untracked) and a plain `A` (a new file the
  # agent staged) are the two shapes that are allowed.
  defp dirty_status?(line) do
    line
    |> String.slice(0, 2)
    |> String.graphemes()
    |> Enum.any?(&(&1 in @dirty))
  end

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
           "hidden_tests disagrees with the history: " <> inspect(paths -- task["hidden_tests"]) <>
             " missing, " <> inspect(task["hidden_tests"] -- paths) <> " extra"}
        end

      {:error, reason} ->
        {:fail, "setup_failed", reason}
    end
  end

  # `mix test` with no paths runs the whole suite, which would grade a task against a
  # corpus entry that names none of its own tests. Refused rather than answered.
  defp graded(task) do
    case Hidden.graded(task["hidden_tests"]) do
      [] -> {:fail, "setup_failed", "the task names no `_test.exs` among its hidden tests"}
      paths -> {:ok, paths}
    end
  end

  defp restored(repo, dir, task) do
    case Hidden.restore(repo, dir, task["commit_sha"], task["hidden_tests"]) do
      :ok -> :ok
      {:error, reason} -> {:fail, "setup_failed", reason}
    end
  end

  defp append(nil, _text), do: :ok

  defp append(path, text) do
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, text, [:append])
  end

  defp tail(output), do: output |> String.split("\n") |> Enum.take(-8) |> Enum.join("\n") |> String.trim()
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
          ouro: :string,
          keep: :boolean,
          timeout: :integer,
          approve_all: :boolean,
          fake_cost_usd: :float,
          oracle_cheat: :string
        ]
      )

    root = Path.expand(Path.dirname(__ENV__.file))
    repo = Path.expand(Path.join(root, "../.."))
    oracle? = opts[:oracle] == true

    with :ok <- spend_given(opts),
         :ok <- seam_guarded(opts, oracle?),
         {:ok, ouro} <- resolve_ouro(repo, opts[:ouro]),
         {:ok, tasks} <- corpus(root, opts),
         {:ok, model} <- model(repo, opts, oracle?) do
      config = %{
        repo: repo,
        root: root,
        ouro: ouro,
        oracle?: oracle?,
        model: model,
        spend_cap: opts[:spend],
        fake_cost: opts[:fake_cost_usd],
        cheat: opts[:oracle_cheat] || "none",
        approve_all?: opts[:approve_all] != false,
        timeout: opts[:timeout],
        keep: opts[:keep] == true,
        tasks_dir: tasks_dir(root, opts),
        out: Path.expand(opts[:out] || Path.join([root, "results", stamp()]))
      }

      scratch = Fs.scratch_dir("ouroboros-bench-self")
      File.mkdir_p!(config.out)

      say("corpus  #{length(tasks)} tasks from #{config.tasks_dir}")
      say("client  #{ouro}")
      say("model   #{model}#{if oracle?, do: " (oracle, $0)", else: ""}")

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
          unless config.keep, do: File.rm_rf(scratch)
          if config.keep, do: say("kept    #{scratch}")
        end

      System.halt(status)
    else
      {:error, message} -> die(message)
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

      true ->
        :ok
    end
  end

  # The client this repository builds, not one on PATH, and between the release and debug
  # builds the NEWEST — `bench/local` learned both of these the hard way.
  defp resolve_ouro(repo, explicit) do
    candidates =
      case explicit do
        nil -> [System.get_env("OURO_BIN") | newest_first(repo)]
        path -> [path]
      end

    case Enum.find(Enum.reject(candidates, &is_nil/1), &File.regular?/1) do
      nil -> {:error, "no ouro binary: build one with `cd tui && cargo build`, or pass --ouro PATH or OURO_BIN"}
      path -> {:ok, Path.expand(path)}
    end
  end

  defp newest_first(repo) do
    ["tui/target/release/ouro", "tui/target/debug/ouro"]
    |> Enum.map(&Path.join(repo, &1))
    |> Enum.filter(&File.regular?/1)
    |> Enum.sort_by(&File.stat!(&1, time: :posix).mtime, :desc)
  end

  defp tasks_dir(root, opts), do: Path.expand(opts[:tasks_dir] || Path.join(root, "tasks"))

  defp corpus(root, opts) do
    dir = tasks_dir(root, opts)

    with {:ok, tasks} <- TaskFile.load_all(dir, opts[:filter]),
         :ok <- non_empty(tasks, dir),
         :ok <- unique_instructions(tasks),
         :ok <- acceptable_instructions(tasks, root) do
      {:ok, tasks}
    end
  end

  # A corpus entry whose instruction carries one of the prompt assembler's own delimiters
  # is one the runtime refuses before the agent sees it. Graded, it would read as the
  # agent failing; refused here, it reads as what it is. `extract.exs` drops such
  # candidates, so this fires only for a corpus somebody extended by hand.
  defp acceptable_instructions(tasks, root) do
    repo = Path.expand(Path.join(root, "../.."))

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
  defp unique_instructions(tasks) do
    pairs =
      for a <- tasks,
          b <- tasks,
          a["id"] != b["id"],
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

    if config.oracle? do
      write_scripts(tasks, scripts, config)
      compile_model(config)
    end

    started_at = DateTime.utc_now()
    wall_started = System.monotonic_time(:millisecond)
    start_daemon(config, data, config_home, scripts)

    {rows, spent} =
      Enum.reduce(tasks, {[], 0.0}, fn task, {rows, spent} ->
        if spent >= config.spend_cap do
          {[skipped(task) | rows], spent}
        else
          row = run_one(task, config, data, config_home)
          {[row | rows], Float.round(spent + row.cost_usd, 6)}
        end
      end)

    rows = Enum.reverse(rows)
    wall_ms = System.monotonic_time(:millisecond) - wall_started

    write_result(rows, spent, started_at, wall_ms, config)
    report(rows, spent, wall_ms, config)
  end

  defp skipped(task) do
    %{
      id: task["id"],
      ran: false,
      grade: "skip",
      reason: "spend_cap",
      detail: "the running total reached --spend before this task started",
      status: "not-run",
      cost_usd: 0.0,
      tokens: 0,
      tool_calls: 0,
      approvals_requested: 0,
      approvals_answered: 0,
      files_changed: 0,
      setup_ms: 0,
      wall_ms: 0,
      grade_ms: 0
    }
  end

  defp run_one(task, config, data, config_home) do
    logs = Path.join(config.out, task["id"])
    File.mkdir_p!(logs)

    dir = Path.join([config.scratch, "work", task["id"]])
    File.mkdir_p!(Path.dirname(dir))
    timeout = config.timeout || task["timeout_secs"]

    try do
      case Workspace.prepare(config.repo, dir, task["base_sha"],
             envs: warm(config),
             timeout_ms: @setup_ms,
             log: Path.join(logs, "setup.log")
           ) do
        {:error, reason} ->
          say("task    #{task["id"]} setup_failed")
          Map.merge(skipped(task), %{grade: "FAIL", reason: "setup_failed", detail: reason, ran: true})

        {:ok, %{setup_ms: setup_ms}} ->
          agent(task, config, data, config_home, dir, logs, timeout, setup_ms)
      end
    after
      unless config.keep, do: Git.worktree_remove(config.repo, dir)
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
        cd: config.repo,
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
    File.write!(Path.join(logs, "result.json"), JSON.encode!(report))

    verdict =
      Grade.run(task, config.repo, dir, report, timeout_ms: @grade_ms, log: Path.join(logs, "grade.log"))

    row = row(task, report, events, verdict, setup_ms, wall_ms, config)
    say("task    #{task["id"]} #{row.grade} #{row.reason}")
    row
  end

  defp row(task, report, events, verdict, setup_ms, wall_ms, config) do
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
      cost_usd: cost(report, config),
      tokens: get_in(report, ["usage", "total_tokens"]) || 0,
      tool_calls: Enum.count(events, &(&1["type"] == "tool_call")),
      approvals_requested: get_in(report, ["approvals", "requested"]) || 0,
      approvals_answered: get_in(report, ["approvals", "answered"]) || 0,
      files_changed: length(Map.get(report, "files_changed", [])),
      setup_ms: setup_ms,
      wall_ms: wall_ms,
      grade_ms: Map.get(extra, :grade_ms, 0)
    }
  end

  # `usage.cost_usd` is absent when the node could not price the response. On the paid path
  # the pre-flight already refused such a model, so an absent number here is a turn that
  # reported no usage at all, which costs nothing to add. `--fake-cost-usd` replaces it, and
  # only under `--oracle`.
  defp cost(_report, %{fake_cost: fake}) when is_number(fake), do: fake * 1.0

  defp cost(report, _config) do
    case get_in(report, ["usage", "cost_usd"]) do
      value when is_number(value) -> value * 1.0
      _absent -> 0.0
    end
  end

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
        case Oracle.script(config.repo, task, config.cheat) do
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
    ebin = Path.join(config.repo, "_build/#{mix_env()}/lib/ouroboros/ebin")
    source = Path.join(config.repo, "bench/local/model/bench_script_model.ex")

    unless File.dir?(ebin), do: die("#{ebin} does not exist; run `mix compile` first")
    unless File.regular?(source), do: die("#{source} is missing")

    case Exec.run(System.find_executable("elixirc") || "elixirc",
           ["--ignore-module-conflict", "-o", ebin, source],
           cd: config.repo,
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
           cd: config.repo,
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
      Env.provider_keys()
    )
  end

  defp daemon_env(config, data, _config_home, _scripts) do
    overrides = %{"OUROBOROS_DATA_DIR" => data}
    overrides = if config.model, do: Map.put(overrides, "OUROBOROS_NATIVE_MODEL", config.model), else: overrides
    Env.build(overrides)
  end

  defp client_env(%{oracle?: true}, data, config_home) do
    Env.build(%{"OUROBOROS_DATA_DIR" => data, "XDG_CONFIG_HOME" => config_home}, Env.provider_keys())
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
        "ouro_sha" => Git.out(config.repo, ["rev-parse", "HEAD"]) || "unknown",
        "ouro_bin" => config.ouro,
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
            "tokens" => row.tokens,
            "tool_calls" => row.tool_calls,
            "approvals_requested" => row.approvals_requested,
            "approvals_answered" => row.approvals_answered,
            "files_changed" => row.files_changed,
            "setup_ms" => row.setup_ms,
            "wall_ms" => row.wall_ms,
            "grade_ms" => row.grade_ms,
            "status" => row.status
          }
        end)
    }

    File.write!(Path.join(config.out, "result.json"), JSON.encode!(result) <> "\n")
  end

  defp report(rows, spent, wall_ms, config) do
    width = rows |> Enum.map(&String.length(&1.id)) |> Enum.max(fn -> 0 end) |> max(4)

    IO.puts("")

    IO.puts(
      pad("task", width) <> "  " <> pad("grade", 5) <> "  " <> pad("reason", 15) <>
        lead("setup", 10) <> lead("agent", 10) <> lead("tests", 10) <> lead("tokens", 8) <>
        lead("cost", 10) <> "  status"
    )

    IO.puts(String.duplicate("-", width + 74))

    Enum.each(rows, fn row ->
      IO.puts(
        pad(row.id, width) <> "  " <> pad(row.grade, 5) <> "  " <> pad(row.reason, 15) <>
          lead("#{row.setup_ms} ms", 10) <> lead("#{row.wall_ms} ms", 10) <>
          lead("#{row.grade_ms} ms", 10) <> lead(row.tokens, 8) <>
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

    unless skipped == [] do
      IO.puts("stopped at the spend cap; #{length(skipped)} task(s) did not run:")
      Enum.each(skipped, &IO.puts("  " <> &1.id))
    end

    IO.puts("result  #{Path.join(config.out, "result.json")}")

    cond do
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
