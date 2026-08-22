#!/usr/bin/env elixir

# The local eval corpus runner. See bench/local/README.md and docs/BENCHMARKS.md.
#
# Deliberately a plain `elixir` script rather than a Mix task: it starts and stops a
# *separate* runtime and talks to it only through `ouro run`, so being inside that
# runtime's own BEAM would prove less than it looks. It uses nothing outside Elixir's
# standard library — `JSON` is stdlib since 1.18 — so `make bench-local` needs no
# dependency the repository does not already require.

defmodule Bench.Shell do
  @moduledoc "POSIX shell quoting, for the one place a command line has to be a string."

  @spec quote_arg(String.t()) :: String.t()
  def quote_arg(arg), do: "'" <> String.replace(arg, "'", "'\\''") <> "'"

  @spec line([String.t()]) :: String.t()
  def line(argv), do: Enum.map_join(argv, " ", &quote_arg/1)
end

defmodule Bench.Exec do
  @moduledoc """
  Bounded process execution.

  `System.cmd/3` has no deadline, and a corpus whose whole point is that it finishes
  cannot be the thing that hangs CI. Every child here runs under a wall clock; when it
  expires the process group is killed and the caller is told, rather than waited on.
  """

  @spec run(String.t(), [String.t()], keyword()) ::
          {:ok, integer(), String.t()} | {:timeout, String.t()}
  def run(program, argv, opts) do
    cd = Keyword.fetch!(opts, :cd)
    env = Keyword.get(opts, :env, [])
    deadline_ms = Keyword.get(opts, :timeout_ms, 120_000)
    stderr_path = Keyword.get(opts, :stderr)

    command =
      case stderr_path do
        nil -> "exec " <> Bench.Shell.line([program | argv])
        path -> "exec " <> Bench.Shell.line([program | argv]) <> " 2>" <> Bench.Shell.quote_arg(path)
      end

    port =
      Port.open({:spawn_executable, sh()}, [
        :binary,
        :exit_status,
        :hide,
        args: ["-c", command],
        cd: cd,
        env: Enum.map(env, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)
      ])

    collect(port, [], System.monotonic_time(:millisecond) + deadline_ms)
  end

  defp collect(port, chunks, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    receive do
      {^port, {:data, data}} ->
        collect(port, [data | chunks], deadline)

      {^port, {:exit_status, status}} ->
        {:ok, status, chunks |> Enum.reverse() |> IO.iodata_to_binary()}
    after
      max(remaining, 0) ->
        kill(port)
        {:timeout, chunks |> Enum.reverse() |> IO.iodata_to_binary()}
    end
  end

  # `Port.close/1` on a spawned executable closes the pipe; the child is signalled by the
  # OS pid so that a process ignoring EOF still goes away.
  defp kill(port) do
    case Port.info(port, :os_pid) do
      {:os_pid, pid} -> System.cmd("kill", ["-9", Integer.to_string(pid)], stderr_to_stdout: true)
      _gone -> :ok
    end

    _ = (fn -> Port.close(port) end).()
    :ok
  rescue
    ArgumentError -> :ok
  end

  defp sh, do: System.find_executable("sh") || "/bin/sh"
end

defmodule Bench.Facts do
  @moduledoc """
  The flat, shell-sourceable view of one run that a `check.sh` reads.

  A check written in `sh` should not have to parse JSON, and this repository cannot
  assume `jq` or `python3` is installed. So the runner does the parsing once and writes
  `facts.env`: single-quoted `BENCH_*` assignments a POSIX shell can `.` directly. The
  raw result object and the whole NDJSON trajectory are still on disk beside it for a
  check that wants to `grep` them.
  """

  @spec render(map()) :: String.t()
  def render(facts) do
    facts
    |> Enum.sort_by(fn {key, _value} -> key end)
    |> Enum.map_join("", fn {key, value} ->
      "BENCH_#{key}=" <> Bench.Shell.quote_arg(to_string(value)) <> "\n"
    end)
  end
end

defmodule Bench.Corpus do
  @moduledoc "Reading, validating, and indexing the task set."

  @required ~w(title instruction exercises)

  @spec load(Path.t(), String.t() | nil) :: {:ok, [map()]} | {:error, String.t()}
  def load(root, filter) do
    dirs =
      root
      |> Path.join("tasks")
      |> File.ls!()
      |> Enum.sort()
      |> Enum.map(&Path.join([root, "tasks", &1]))
      |> Enum.filter(&File.dir?/1)

    with {:ok, tasks} <- reduce(dirs, []),
         :ok <- unique_instructions(tasks) do
      {:ok, apply_filter(tasks, filter)}
    end
  end

  defp reduce([], acc), do: {:ok, Enum.reverse(acc)}

  defp reduce([dir | rest], acc) do
    case task(dir) do
      {:ok, task} -> reduce(rest, [task | acc])
      {:error, reason} -> {:error, reason}
    end
  end

  defp task(dir) do
    id = Path.basename(dir)

    with {:ok, meta} <- json(Path.join(dir, "task.json")),
         :ok <- required(meta, id),
         {:ok, script} <- json(Path.join(dir, "script.json")),
         :ok <- validate_script(script, id),
         :ok <- check_present(dir, id),
         :ok <- workspace_present(dir, id) do
      {:ok,
       %{
         id: id,
         dir: dir,
         title: meta["title"],
         instruction: meta["instruction"],
         exercises: meta["exercises"],
         approval_mode: meta["approval_mode"] || "prompt",
         approve_all: meta["approve_all"] == true,
         timeout_secs: meta["timeout_secs"] || 60,
         script: script
       }}
    end
  end

  defp json(path) do
    with {:ok, body} <- File.read(path),
         {:ok, decoded} when is_map(decoded) <- JSON.decode(body) do
      {:ok, decoded}
    else
      {:error, :enoent} -> {:error, "#{path} is missing"}
      {:error, reason} -> {:error, "#{path} is unreadable: #{inspect(reason)}"}
      {:ok, _other} -> {:error, "#{path} is not a JSON object"}
    end
  end

  defp required(meta, id) do
    case Enum.reject(@required, &is_map_key(meta, &1)) do
      [] -> :ok
      missing -> {:error, "#{id}/task.json is missing #{Enum.join(missing, ", ")}"}
    end
  end

  defp check_present(dir, id) do
    path = Path.join(dir, "check.sh")

    cond do
      not File.exists?(path) -> {:error, "#{id}/check.sh is missing"}
      not executable?(path) -> {:error, "#{id}/check.sh is not executable"}
      true -> :ok
    end
  end

  defp executable?(path) do
    case File.stat(path) do
      {:ok, %File.Stat{mode: mode}} -> Bitwise.band(mode, 0o100) != 0
      _error -> false
    end
  end

  defp workspace_present(dir, id) do
    if File.dir?(Path.join(dir, "workspace")),
      do: :ok,
      else: {:error, "#{id}/workspace/ is missing"}
  end

  # The scripted model matches an instruction by containment, because the runtime wraps
  # the prompt in its own envelope before the model sees it. That is only unambiguous
  # while no instruction contains another, so the corpus is refused if one does.
  defp unique_instructions(tasks) do
    pairs =
      for a <- tasks,
          b <- tasks,
          a.id != b.id,
          String.contains?(b.instruction, a.instruction),
          do: {a.id, b.id}

    case pairs do
      [] -> :ok
      [{inner, outer} | _rest] -> {:error, "#{inner}'s instruction is contained in #{outer}'s"}
    end
  end

  # Validating here rather than in the model module means a typo is a corpus error with a
  # task name on it, not a turn that mysteriously answers "(bench script exhausted)".
  @kinds ~w(text thinking tool_call usage finish)

  defp validate_script(%{"responses" => responses}, id) when is_list(responses) do
    responses
    |> Enum.with_index()
    |> Enum.find_value(fn {chunks, index} ->
      cond do
        not is_list(chunks) ->
          "#{id}/script.json response #{index} is not a list"

        bad = Enum.find(chunks, &(not valid_chunk?(&1))) ->
          "#{id}/script.json response #{index} has an invalid chunk: #{inspect(bad)}"

        true ->
          nil
      end
    end)
    |> case do
      nil -> :ok
      message -> {:error, message}
    end
  end

  defp validate_script(_other, id), do: {:error, "#{id}/script.json has no `responses` list"}

  defp valid_chunk?(%{"type" => "tool_call", "id" => id, "name" => name} = call)
       when is_binary(id) and is_binary(name),
       do: is_map(Map.get(call, "input", %{}))

  defp valid_chunk?(%{"type" => type, "text" => text}) when type in ~w(text thinking),
    do: is_binary(text)

  defp valid_chunk?(%{"type" => "usage"}), do: true
  defp valid_chunk?(%{"type" => "finish"}), do: true
  defp valid_chunk?(%{"type" => type}) when type in @kinds, do: false
  defp valid_chunk?(_other), do: false

  defp apply_filter(tasks, nil), do: tasks
  defp apply_filter(tasks, filter), do: Enum.filter(tasks, &String.contains?(&1.id, filter))
end

defmodule Bench.Runner do
  @moduledoc "Spawn one runtime, run every task through `ouro run`, check, report."

  @daemon_boot_ms 240_000
  @check_timeout_ms 60_000

  def main(argv) do
    {opts, _rest} =
      OptionParser.parse!(argv,
        strict: [filter: :string, keep: :boolean, verbose: :boolean, ouro: :string]
      )

    root = Path.expand(Path.dirname(__ENV__.file))
    repo = Path.expand(Path.join(root, "../.."))

    with {:ok, ouro} <- resolve_ouro(repo, opts[:ouro]),
         {:ok, tasks} <- Bench.Corpus.load(root, opts[:filter]),
         :ok <- non_empty(tasks) do
      scratch = scratch_dir()
      say("corpus  #{length(tasks)} tasks from #{Path.relative_to(root, repo)}/tasks")
      say("client  #{Path.relative_to(ouro, repo)}")
      say("scratch #{scratch}")

      # `System.halt/1` does not unwind, so the exit status is carried back here and the
      # VM is stopped only after the daemon has been asked to stop and the scratch
      # directory is gone. Halting inside `run_all` leaked a runtime per invocation.
      status =
        try do
          run_all(tasks, ouro: ouro, repo: repo, root: root, scratch: scratch, opts: opts)
        after
          stop_daemon(ouro, scratch)
          unless opts[:keep], do: File.rm_rf(scratch)
          if opts[:keep], do: say("kept    #{scratch}")
        end

      System.halt(status)
    else
      {:error, message} -> die(message)
    end
  end

  defp non_empty([]), do: {:error, "no tasks matched"}
  defp non_empty(_tasks), do: :ok

  # The client this repository builds, not one on PATH: a corpus that silently graded a
  # different binary than the checkout would be worse than no corpus.
  defp resolve_ouro(repo, explicit) do
    candidates =
      case explicit do
        nil ->
          [
            System.get_env("OURO_BIN"),
            Path.join(repo, "tui/target/release/ouro"),
            Path.join(repo, "tui/target/debug/ouro")
          ]

        path ->
          [path]
      end

    case Enum.find(Enum.reject(candidates, &is_nil/1), &File.regular?/1) do
      nil ->
        {:error,
         "no ouro binary: build one with `cd tui && cargo build`, or pass --ouro PATH " <>
           "or OURO_BIN"}

      path ->
        {:ok, Path.expand(path)}
    end
  end

  defp scratch_dir do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-bench-local-#{System.system_time(:second)}-#{:rand.uniform(100_000)}"
      )

    File.mkdir_p!(dir)
    File.chmod!(dir, 0o700)
    physical(dir)
  end

  # macOS hands out a `$TMPDIR` under `/var`, which is a symlink to `/private/var`. The
  # runtime resolves the paths it touches and reports the physical ones, so a workspace
  # named through the symlink makes every path in every payload disagree with the one
  # the corpus asked for — and at least one tool compares them. Resolving once here
  # keeps that platform detail out of seventeen task files.
  defp physical(dir) do
    case System.cmd("sh", ["-c", "cd " <> Bench.Shell.quote_arg(dir) <> " && pwd -P"]) do
      {output, 0} -> String.trim(output)
      _error -> dir
    end
  end

  defp run_all(tasks, config) do
    scratch = config[:scratch]
    scripts = Path.join(scratch, "scripts")
    data = Path.join(scratch, "data")
    config_home = Path.join(scratch, "config")

    File.mkdir_p!(scripts)
    File.mkdir_p!(data)
    File.mkdir_p!(config_home)
    File.chmod!(data, 0o700)
    File.chmod!(config_home, 0o700)

    write_scripts(tasks, scripts)
    compile_model(config)
    start_daemon(config, scripts, data, config_home)

    rows = Enum.map(tasks, &run_one(&1, config, data, config_home))
    report(rows)
  end

  defp write_scripts(tasks, scripts) do
    entries =
      Enum.map(tasks, fn task ->
        name = task.id <> ".json"
        File.write!(Path.join(scripts, name), JSON.encode!(task.script))
        %{"instruction" => task.instruction, "script" => name}
      end)

    File.write!(Path.join(scripts, "index.json"), JSON.encode!(%{"entries" => entries}))
  end

  # Mix prunes the code path to this project's own applications, so an `-pa` directory
  # or an `ERL_LIBS` application is gone by the time `mix run --no-halt` boots. The one
  # path that survives is the project's own ebin, so that is where the scripted model
  # goes. It is a build artifact of the bench, not of the release: `mix clean` removes
  # it and nothing in `lib/` refers to it.
  defp compile_model(config) do
    repo = config[:repo]
    ebin = Path.join(repo, "_build/#{mix_env()}/lib/ouroboros/ebin")

    unless File.dir?(ebin) do
      die("#{ebin} does not exist; run `mix compile` first")
    end

    source = Path.join(config[:root], "model/bench_script_model.ex")

    case Bench.Exec.run(
           System.find_executable("elixirc") || "elixirc",
           ["--ignore-module-conflict", "-o", ebin, source],
           cd: repo,
           timeout_ms: 120_000,
           env: [{"ELIXIR_ERL_OPTIONS", "-pa " <> ebin}]
         ) do
      {:ok, 0, _out} -> :ok
      {:ok, code, out} -> die("compiling the scripted model failed (#{code}):\n#{out}")
      {:timeout, out} -> die("compiling the scripted model timed out:\n#{out}")
    end
  end

  defp mix_env, do: System.get_env("MIX_ENV") || "dev"

  defp start_daemon(config, scripts, data, config_home) do
    say("daemon  starting `ouro --dev daemon` on a scratch data dir")

    case Bench.Exec.run(config[:ouro], ["--dev", "daemon"],
           cd: config[:repo],
           timeout_ms: @daemon_boot_ms,
           stderr: Path.join(config[:scratch], "daemon.stderr"),
           env: daemon_env(scripts, data, config_home)
         ) do
      {:ok, 0, out} ->
        port = Regex.run(~r/port\s+(\d+)/, out) |> then(&(&1 && Enum.at(&1, 1)))
        say("daemon  ready on port #{port || "?"}")
        :ok

      {:ok, code, out} ->
        die("`ouro --dev daemon` exited #{code}:\n#{out}\n#{tail(config[:scratch])}")

      {:timeout, out} ->
        die("`ouro --dev daemon` did not come up in #{@daemon_boot_ms}ms:\n#{out}")
    end
  end

  defp daemon_env(scripts, data, config_home) do
    base_env() ++
      [
        {"OUROBOROS_DATA_DIR", data},
        {"XDG_CONFIG_HOME", config_home},
        {"OUROBOROS_NATIVE_MODEL", "bench-script:" <> scripts},
        {"ELIXIR_ERL_OPTIONS",
         "-ouroboros native_model_module 'Elixir.Ouroboros.Bench.ScriptModel'"}
      ]
  end

  # The corpus must not read a key even by accident. Nothing here needs one, the scripted
  # model never makes a request, and a variable that is not passed cannot be spent.
  @dropped ~w(
    ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY GOOGLE_API_KEY GROQ_API_KEY
    OPENROUTER_API_KEY XAI_API_KEY MISTRAL_API_KEY DEEPSEEK_API_KEY TOGETHER_API_KEY
    CEREBRAS_API_KEY PERPLEXITY_API_KEY ZAI_API_KEY AWS_SECRET_ACCESS_KEY
    OUROBOROS_NATIVE_MODEL OUROBOROS_DATA_DIR XDG_CONFIG_HOME ELIXIR_ERL_OPTIONS
  )

  defp base_env do
    System.get_env()
    |> Enum.reject(fn {key, _value} -> key in @dropped end)
    |> Enum.sort()
  end

  defp run_one(task, config, data, config_home) do
    workspace = Path.join([config[:scratch], "work", task.id])
    File.mkdir_p!(Path.dirname(workspace))
    File.cp_r!(Path.join(task.dir, "workspace"), workspace)

    logs = Path.join([config[:scratch], "logs", task.id])
    File.mkdir_p!(logs)

    trajectory = Path.join(logs, "trajectory.ndjson")
    result_path = Path.join(logs, "result.json")
    facts_path = Path.join(logs, "facts.env")

    argv =
      [
        "run",
        task.instruction,
        "--provider",
        "native",
        "--workspace",
        workspace,
        "--approval-mode",
        task.approval_mode,
        "--stream-json",
        "--timeout",
        Integer.to_string(task.timeout_secs)
      ] ++ if task.approve_all, do: ["--approve-all"], else: []

    started = System.monotonic_time(:millisecond)

    outcome =
      Bench.Exec.run(config[:ouro], argv,
        cd: config[:repo],
        # A client that ignored its own `--timeout` still must not hang the corpus.
        timeout_ms: (task.timeout_secs + 30) * 1000,
        stderr: Path.join(logs, "ouro.stderr"),
        env: base_env() ++ [{"OUROBOROS_DATA_DIR", data}, {"XDG_CONFIG_HOME", config_home}]
      )

    wall = System.monotonic_time(:millisecond) - started

    {exit_code, stdout} =
      case outcome do
        {:ok, code, out} -> {code, out}
        {:timeout, out} -> {:killed, out}
      end

    File.write!(trajectory, stdout)
    events = parse_events(stdout)
    result = Enum.find(events, &(&1["type"] == "result")) || %{}
    File.write!(result_path, JSON.encode!(result))

    facts =
      facts(task, events, result, exit_code, workspace, result_path, trajectory)

    File.write!(facts_path, Bench.Facts.render(facts))

    {check_ok, check_out} = check(task, facts_path, config)

    %{
      id: task.id,
      title: task.title,
      exercises: task.exercises,
      status: to_string(Map.get(result, "status", "no-result")),
      exit: exit_code,
      duration_ms: wall,
      tokens: get_in(result, ["usage", "total_tokens"]) || 0,
      ok: check_ok,
      detail: check_out,
      logs: logs
    }
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

  defp facts(task, events, result, exit_code, workspace, result_path, trajectory) do
    tools =
      events
      |> Enum.filter(&(&1["type"] == "tool_call"))
      |> Enum.map(&get_in(&1, ["payload", "name"]))
      |> Enum.reject(&is_nil/1)

    tool_errors =
      events
      |> Enum.filter(&(&1["type"] == "tool_result" and get_in(&1, ["payload", "is_error"]) == true))
      |> Enum.map(&get_in(&1, ["payload", "name"]))
      |> Enum.reject(&is_nil/1)

    usage = Map.get(result, "usage", %{})
    files = Map.get(result, "files_changed", [])
    approvals = Map.get(result, "approvals", %{})

    %{
      "TASK" => task.id,
      "STATUS" => Map.get(result, "status", "no-result"),
      "EXIT" => exit_code,
      "ERROR" => Map.get(result, "error", ""),
      "TOOLS" => Enum.join(tools, " "),
      "TOOL_ERRORS" => Enum.join(tool_errors, " "),
      "EVENTS" => events |> Enum.map(&Map.get(&1, "type", "")) |> Enum.uniq() |> Enum.join(" "),
      "APPROVALS_REQUESTED" => Map.get(approvals, "requested", 0),
      "APPROVALS_ANSWERED" => Map.get(approvals, "answered", 0),
      "TOTAL_TOKENS" => Map.get(usage, "total_tokens", 0),
      "INPUT_TOKENS" => Map.get(usage, "input_tokens", 0),
      "OUTPUT_TOKENS" => Map.get(usage, "output_tokens", 0),
      "FILES_CHANGED" => Enum.join(files, " "),
      "FILES_CHANGED_COUNT" => length(files),
      "DURATION_MS" => Map.get(result, "duration_ms", 0),
      "WORKSPACE" => workspace,
      "RESULT" => result_path,
      "TRAJECTORY" => trajectory
    }
  end

  defp check(task, facts_path, config) do
    script = Path.join(task.dir, "check.sh")

    case Bench.Exec.run(script, [],
           cd: task.dir,
           timeout_ms: @check_timeout_ms,
           env:
             base_env() ++
               [
                 {"BENCH_FACTS", facts_path},
                 {"BENCH_LIB", Path.join(config[:root], "lib")}
               ]
         ) do
      {:ok, 0, _out} -> {true, ""}
      {:ok, _code, out} -> {false, String.trim(out)}
      {:timeout, _out} -> {false, "check.sh timed out after #{@check_timeout_ms}ms"}
    end
  end

  # Always scoped to the scratch data dir. An unscoped `ouro stop` would go looking for
  # the operator's own publication, which is a different runtime than the one this script
  # is responsible for.
  defp stop_daemon(ouro, scratch) do
    data = Path.join(scratch, "data")

    if File.dir?(data) and File.regular?(ouro) do
      case Bench.Exec.run(ouro, ["stop"],
             cd: File.cwd!(),
             timeout_ms: 60_000,
             stderr: Path.join(scratch, "stop.stderr"),
             env: base_env() ++ [{"OUROBOROS_DATA_DIR", data}]
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

  # ------------------------------------------------------------------- reporting

  defp report(rows) do
    widths = %{
      task: max_width(rows, & &1.id, "task"),
      run: max_width(rows, & &1.status, "run"),
      exercises: max_width(rows, &Enum.join(&1.exercises, ","), "exercises")
    }

    IO.puts("")
    header(widths)

    Enum.each(rows, fn row ->
      IO.puts(
        [
          pad(row.id, widths.task),
          "  ",
          pad(if(row.ok, do: "ok", else: "FAIL"), 4),
          "  ",
          pad(row.status, widths.run),
          "  ",
          String.pad_leading("#{row.duration_ms} ms", 9),
          "  ",
          String.pad_leading(to_string(row.tokens), 6),
          "  ",
          pad(Enum.join(row.exercises, ","), widths.exercises)
        ]
        |> IO.iodata_to_binary()
      )
    end)

    failures = Enum.reject(rows, & &1.ok)

    unless failures == [] do
      IO.puts("")

      Enum.each(failures, fn row ->
        IO.puts("FAIL #{row.id} - #{row.title}")
        IO.puts(indent(row.detail))
        IO.puts("     logs: #{row.logs}")
      end)
    end

    total_ms = rows |> Enum.map(& &1.duration_ms) |> Enum.sum()
    total_tokens = rows |> Enum.map(& &1.tokens) |> Enum.sum()

    IO.puts("")

    IO.puts(
      "#{length(rows) - length(failures)}/#{length(rows)} passed in #{total_ms} ms, " <>
        "#{total_tokens} scripted tokens, $0.00 spent"
    )

    if failures == [], do: 0, else: 1
  end

  defp header(widths) do
    IO.puts(
      [
        pad("task", widths.task),
        "  ",
        pad("chk", 4),
        "  ",
        pad("run", widths.run),
        "  ",
        String.pad_leading("duration", 9),
        "  ",
        String.pad_leading("tokens", 6),
        "  ",
        pad("exercises", widths.exercises)
      ]
      |> IO.iodata_to_binary()
    )

    IO.puts(String.duplicate("-", widths.task + widths.run + widths.exercises + 31))
  end

  defp max_width(rows, fun, label),
    do: rows |> Enum.map(&String.length(fun.(&1))) |> Enum.max(fn -> 0 end) |> max(String.length(label))

  defp pad(value, width), do: String.pad_trailing(to_string(value), width)

  defp indent(text),
    do: text |> String.split("\n") |> Enum.map_join("\n", &("     " <> &1))

  defp say(message), do: IO.puts(:stderr, message)

  defp die(message) do
    IO.puts(:stderr, "bench.local: " <> message)
    System.halt(64)
  end
end

Bench.Runner.main(System.argv())
