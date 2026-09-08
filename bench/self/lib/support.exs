# Shared by `bench/self/extract.exs` and `bench/self/run.exs`, loaded with
# `Code.require_file/2` because the two are plain `elixir` scripts rather than Mix tasks
# — the same reason `bench/local/run.exs` is one. Standard library only.
#
# The point of sharing is not brevity. The extractor proves a task by building a tree and
# running the hidden tests in it, and the runner grades an agent in a tree built the same
# way; if the two ever built *different* trees the corpus would measure the difference
# rather than the agent. One `Bench.Self.Workspace.prepare/4` is what makes that a fact
# instead of a convention.

defmodule Bench.Self.Shell do
  @moduledoc "POSIX shell quoting, for the one place a command line has to be a string."

  @spec quote_arg(String.t()) :: String.t()
  def quote_arg(arg), do: "'" <> String.replace(arg, "'", "'\\''") <> "'"

  @spec line([String.t()]) :: String.t()
  def line(argv), do: Enum.map_join(argv, " ", &quote_arg/1)
end

defmodule Bench.Self.Exec do
  @moduledoc """
  Bounded process execution, `bench/local/run.exs`'s `Bench.Exec` with two additions.

  Every child runs under a wall clock and is killed by its OS pid when the clock expires,
  because a corpus whose whole claim is that it finishes cannot be the thing that hangs.
  The additions are an output cap — a `mix test` that fails can print megabytes, and the
  runner holds one of those per task — and `stderr: :stdout` for the commands whose
  diagnosis is on stderr.
  """

  @default_cap 256 * 1024

  @type outcome :: {:ok, integer(), String.t()} | {:timeout, String.t()}

  @spec run(String.t(), [String.t()], keyword()) :: outcome()
  def run(program, argv, opts) do
    cd = Keyword.fetch!(opts, :cd)
    env = Keyword.get(opts, :env, [])
    deadline_ms = Keyword.get(opts, :timeout_ms, 120_000)
    cap = Keyword.get(opts, :max_output_bytes, @default_cap)

    command =
      case Keyword.get(opts, :stderr) do
        nil -> "exec " <> Bench.Self.Shell.line([program | argv])
        :stdout -> "exec " <> Bench.Self.Shell.line([program | argv]) <> " 2>&1"
        path -> "exec " <> Bench.Self.Shell.line([program | argv]) <> " 2>" <> Bench.Self.Shell.quote_arg(path)
      end

    port =
      Port.open({:spawn_executable, sh()}, [
        :binary,
        :exit_status,
        :hide,
        args: ["-c", command],
        cd: cd,
        env: Enum.map(env, &variable/1)
      ])

    collect(port, [], 0, cap, System.monotonic_time(:millisecond) + deadline_ms)
  end

  @doc "`run/3` plus the wall time it took, which is the number the corpus reports."
  @spec timed(String.t(), [String.t()], keyword()) :: {outcome(), non_neg_integer()}
  def timed(program, argv, opts) do
    started = System.monotonic_time(:millisecond)
    outcome = run(program, argv, opts)
    {outcome, System.monotonic_time(:millisecond) - started}
  end

  defp collect(port, chunks, bytes, cap, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    receive do
      {^port, {:data, data}} ->
        {chunks, bytes} = keep([data | chunks], bytes + byte_size(data), cap)
        collect(port, chunks, bytes, cap, deadline)

      {^port, {:exit_status, status}} ->
        {:ok, status, flatten(chunks)}
    after
      max(remaining, 0) ->
        kill(port)
        {:timeout, flatten(chunks)}
    end
  end

  # The tail is what diagnoses a failure: a compiler names the file it choked on at the
  # end, and ExUnit's counts are the last line. Dropping the head keeps a runaway child
  # from being a memory bug in the harness.
  defp keep(chunks, bytes, cap) when bytes <= cap * 2, do: {chunks, bytes}

  defp keep(chunks, _bytes, cap) do
    {kept, bytes} =
      Enum.reduce_while(chunks, {[], 0}, fn chunk, {acc, size} ->
        if size >= cap,
          do: {:halt, {acc, size}},
          else: {:cont, {[chunk | acc], size + byte_size(chunk)}}
      end)

    {Enum.reverse(kept), bytes}
  end

  defp flatten(chunks), do: chunks |> Enum.reverse() |> IO.iodata_to_binary()

  # `Port.close/1` closes the pipe; the child is signalled by OS pid so that a process
  # ignoring EOF still goes away. Only ever a pid this script started.
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

  # `:erlang.open_port`'s `env` option *extends* the caller's environment: a variable left
  # out of the list is still inherited by the child. Removing one is `{name, false}`, and
  # nothing else. A list that merely omits a key removes nothing — which is why
  # `Bench.Self.Env` emits the removals explicitly rather than filtering a copy of
  # `System.get_env/0`.
  defp variable({key, false}), do: {String.to_charlist(key), false}
  defp variable({key, value}), do: {String.to_charlist(key), String.to_charlist(value)}

  defp sh, do: System.find_executable("sh") || "/bin/sh"
end

defmodule Bench.Self.Env do
  @moduledoc """
  The environment a child is given.

  `bench/local` strips every model key, because the scripted model must not be able to
  spend even by accident. This corpus runs a *real* model on the paid path, so the rule
  inverts: the environment is passed through, `XDG_CONFIG_HOME` included, because the
  packaged default authenticates through it. Only `OUROBOROS_DATA_DIR` is scratch. The
  oracle path is `bench/local`'s posture exactly, and says so.
  """

  @keys ~w(
    ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY GOOGLE_API_KEY GROQ_API_KEY
    OPENROUTER_API_KEY XAI_API_KEY MISTRAL_API_KEY DEEPSEEK_API_KEY TOGETHER_API_KEY
    CEREBRAS_API_KEY PERPLEXITY_API_KEY ZAI_API_KEY AWS_SECRET_ACCESS_KEY
  )

  @doc "Every known model-provider key, the set the oracle refuses to pass on."
  @spec provider_keys() :: [String.t()]
  def provider_keys, do: @keys

  @doc """
  The changes a child's environment needs: `overrides` set, `drop` removed.

  Deltas rather than a whole environment, because a port's `env` option extends the
  caller's rather than replacing it. A variable is removed by naming it with `false`; one
  that is merely absent from the list is still inherited. Filtering a copy of
  `System.get_env/0` therefore removes nothing at all, which is a quiet way for a corpus
  to believe it has taken the keys away when it has not.
  """
  @spec build(map(), [String.t()]) :: [{String.t(), String.t() | false}]
  def build(overrides \\ %{}, drop \\ []) do
    removals =
      drop
      |> Enum.reject(&Map.has_key?(overrides, &1))
      |> Enum.sort()
      |> Enum.map(&{&1, false})

    removals ++ Enum.sort(overrides)
  end
end

defmodule Bench.Self.Fs do
  @moduledoc "Scratch directories, and the copy that is free on APFS."

  @doc """
  A 0700 scratch directory under `$TMPDIR`, resolved to its physical path.

  macOS hands out a `$TMPDIR` under `/var`, a symlink to `/private/var`. The runtime
  resolves the paths it touches and reports the physical ones, so a workspace named
  through the symlink makes every path in every payload disagree with the one the corpus
  asked for. `bench/local` learned this; the same one line keeps it out of everything
  downstream.
  """
  @spec scratch_dir(String.t()) :: Path.t()
  def scratch_dir(prefix) do
    dir =
      Path.join(
        System.get_env("BENCH_SELF_TMPDIR") || System.tmp_dir!(),
        "#{prefix}-#{System.system_time(:second)}-#{:rand.uniform(100_000)}"
      )

    File.mkdir_p!(dir)
    File.chmod!(dir, 0o700)
    physical(dir)
  end

  @spec physical(Path.t()) :: Path.t()
  def physical(dir) do
    case System.cmd("sh", ["-c", "cd " <> Bench.Self.Shell.quote_arg(dir) <> " && pwd -P"]) do
      {output, 0} -> String.trim(output)
      _error -> dir
    end
  end

  @doc """
  Copy `src` to `dst`, cloning where the filesystem can.

  `cp -Rc` asks APFS for `clonefile(2)`: the copy shares the source's blocks until one of
  them is written, so a 300 MB `_build` costs metadata and no data. It is a macOS-only
  flag — `uname` decides — and everywhere else this is an ordinary recursive copy.
  """
  @spec clone(Path.t(), Path.t(), keyword()) :: :ok | {:error, String.t()}
  def clone(src, dst, opts \\ []) do
    flag = if darwin?(), do: "-Rc", else: "-R"

    case Bench.Self.Exec.run(cp(), [flag, src, dst],
           cd: Path.dirname(dst),
           timeout_ms: Keyword.get(opts, :timeout_ms, 600_000),
           stderr: :stdout
         ) do
      {:ok, 0, _out} -> :ok
      {:ok, code, out} -> {:error, "cp #{flag} #{src} #{dst} exited #{code}: #{String.trim(out)}"}
      {:timeout, _out} -> {:error, "cp #{flag} #{src} #{dst} timed out"}
    end
  end

  @spec darwin?() :: boolean()
  def darwin?, do: :os.type() == {:unix, :darwin}

  defp cp, do: System.find_executable("cp") || "/bin/cp"
end

defmodule Bench.Self.Git do
  @moduledoc """
  The git this corpus needs, and nothing more.

  Every worktree this creates is registered in the repository's own `.git/worktrees`, so
  creation and removal are serialised through a `:global` lock: two extraction jobs adding
  a worktree at the same moment race on that directory. `remove/2` is called from an
  `after` on every path, including failure, and only ever names a directory this script
  made.
  """

  alias Bench.Self.{Exec, Shell}

  @lock :bench_self_git_worktree

  @doc "Runs git in `repo`, with stderr folded into the captured output."
  @spec run(Path.t(), [String.t()], keyword()) :: {:ok, String.t()} | {:error, String.t()}
  def run(repo, argv, opts \\ []) do
    opts = Keyword.merge([cd: repo, timeout_ms: 120_000, stderr: :stdout], opts)

    case Exec.run(git(), argv, opts) do
      {:ok, 0, out} -> {:ok, out}
      {:ok, code, out} -> {:error, "git #{Enum.join(argv, " ")} exited #{code}: #{String.trim(out)}"}
      {:timeout, _out} -> {:error, "git #{Enum.join(argv, " ")} timed out"}
    end
  end

  @doc "`run/3`'s output, trimmed, or `nil`."
  @spec out(Path.t(), [String.t()], keyword()) :: String.t() | nil
  def out(repo, argv, opts \\ []) do
    case run(repo, argv, opts) do
      {:ok, output} -> String.trim(output)
      {:error, _reason} -> nil
    end
  end

  @doc """
  The bytes of one path at one commit.

  stderr is *not* folded in here: this output is file content, and a warning mixed into it
  would be written to disk as if the commit had contained it.
  """
  @spec show(Path.t(), String.t(), String.t()) :: {:ok, binary()} | {:error, String.t()}
  def show(repo, sha, path) do
    case Exec.run(git(), ["--no-pager", "show", sha <> ":" <> path],
           cd: repo,
           timeout_ms: 60_000,
           max_output_bytes: 8 * 1024 * 1024
         ) do
      {:ok, 0, body} -> {:ok, body}
      {:ok, code, _body} -> {:error, "git show #{sha}:#{path} exited #{code}"}
      {:timeout, _body} -> {:error, "git show #{sha}:#{path} timed out"}
    end
  end

  @doc "Whether `path` exists at `sha`."
  @spec exists?(Path.t(), String.t(), String.t()) :: boolean()
  def exists?(repo, sha, path) do
    case Exec.run(git(), ["cat-file", "-e", sha <> ":" <> path],
           cd: repo,
           timeout_ms: 60_000,
           stderr: :stdout
         ) do
      {:ok, 0, _out} -> true
      _absent -> false
    end
  end

  @doc """
  `--name-status` between two commits, as `{status, path}` pairs.

  Always `--no-renames`. A rename then reads as a delete and an add, which is what both
  callers want: the extractor drops a task whose non-test diff deletes anything (the
  oracle writes files and cannot express a removal), and the hidden set takes the added
  path and ignores the deleted one.

  `sha` of `nil` means the **working tree** rather than a second commit. That is the form
  the grader needs: it compares what is on disk against the commit the task started from,
  so an agent that committed its edit is compared just the same as one that did not.
  """
  @spec name_status(Path.t(), String.t(), String.t() | nil, [String.t()]) ::
          {:ok, [{String.t(), String.t()}]} | {:error, String.t()}
  def name_status(repo, base, sha, pathspec \\ []) do
    range = if is_nil(sha), do: [base], else: [base, sha]

    case run(repo, ["--no-pager", "diff", "--no-renames", "--name-status"] ++ range ++ ["--"] ++ pathspec) do
      {:ok, output} ->
        {:ok,
         output
         |> String.split("\n", trim: true)
         |> Enum.flat_map(fn line ->
           case String.split(line, "\t", parts: 2) do
             [status, path] -> [{String.trim(status), String.trim(path)}]
             _other -> []
           end
         end)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Added and deleted lines between two commits over `pathspec`."
  @spec diff_lines(Path.t(), String.t(), String.t(), [String.t()]) :: non_neg_integer()
  def diff_lines(repo, base, sha, pathspec \\ []) do
    case run(repo, ["--no-pager", "diff", "--no-renames", "--numstat", base, sha, "--"] ++ pathspec) do
      {:ok, output} ->
        output
        |> String.split("\n", trim: true)
        |> Enum.reduce(0, fn line, total ->
          case String.split(line, "\t", parts: 3) do
            [added, deleted, _path] ->
              total + integer(added) + integer(deleted)

            _other ->
              total
          end
        end)

      {:error, _reason} ->
        0
    end
  end

  @doc "Adds a detached worktree at `sha`. Serialised; see the moduledoc."
  @spec worktree_add(Path.t(), Path.t(), String.t()) :: :ok | {:error, String.t()}
  def worktree_add(repo, dir, sha) do
    :global.trans({@lock, self()}, fn ->
      case run(repo, ["worktree", "add", "--detach", dir, sha], timeout_ms: 300_000) do
        {:ok, _out} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  @doc """
  Removes a worktree this script made, and prunes only if the removal did not take.

  A bare `git worktree prune` is deliberately not run on the happy path: other worktrees
  of this repository belong to other people, and pruning is a repository-wide sweep.
  """
  @spec worktree_remove(Path.t(), Path.t()) :: :ok
  def worktree_remove(repo, dir) do
    :global.trans({@lock, self()}, fn ->
      case run(repo, ["worktree", "remove", "--force", dir], timeout_ms: 300_000) do
        {:ok, _out} ->
          :ok

        {:error, _reason} ->
          File.rm_rf(dir)
          _ = run(repo, ["worktree", "prune"], timeout_ms: 120_000)
          :ok
      end
    end)
  end

  defp integer(text) do
    case Integer.parse(text) do
      {value, _rest} -> value
      :error -> 0
    end
  end

  defp git, do: System.find_executable("git") || "/usr/bin/git"

  @doc false
  def quote_arg(arg), do: Shell.quote_arg(arg)
end

defmodule Bench.Self.Workspace do
  @moduledoc """
  One tree at one commit, built the same way for the extractor and for the runner.

  A detached worktree at `sha`, with `deps/`, `_build/` and the two sealed helper
  directories cloned in from the repository, `mix deps.get` when the commit's `mix.lock`
  is not the one those `deps/` were fetched for, and `mix compile` per environment. The
  compile is the runner's *setup*: it is timed separately from the agent's turn, because
  a benchmark that charged the agent for a cold build would be measuring this machine.
  """

  alias Bench.Self.{Env, Exec, Fs, Git}

  @cloned ~w(deps _build)
  @seeded ~w(priv/wasm priv/sandbox)

  @type prepared :: %{setup_ms: non_neg_integer(), log: Path.t() | nil}

  @doc """
  Builds the tree at `sha` in `dir`. The caller owns removal, on every path.

  Options: `:envs` (default `["test"]`), `:timeout_ms` per compile (default 600 000),
  `:log` (a file every child's output is appended to).
  """
  @spec prepare(Path.t(), Path.t(), String.t(), keyword()) ::
          {:ok, prepared()} | {:error, String.t()}
  def prepare(repo, dir, sha, opts \\ []) do
    envs = Keyword.get(opts, :envs, ["test"])
    timeout_ms = Keyword.get(opts, :timeout_ms, 600_000)
    log = Keyword.get(opts, :log)
    started = System.monotonic_time(:millisecond)

    with :ok <- Git.worktree_add(repo, dir, sha),
         :ok <- clone_support(repo, dir),
         :ok <- deps(repo, dir, timeout_ms, log),
         :ok <- compile(dir, envs, timeout_ms, log) do
      {:ok, %{setup_ms: System.monotonic_time(:millisecond) - started, log: log}}
    end
  end

  @doc "`mix test <paths>` in a prepared tree. `{:ok, exit_status, ms}` or `{:timeout, ms}`."
  @spec test(Path.t(), [String.t()], keyword()) ::
          {:ok, integer(), non_neg_integer(), String.t()} | {:timeout, non_neg_integer(), String.t()}
  def test(dir, paths, opts \\ []) do
    timeout_ms = Keyword.get(opts, :timeout_ms, 600_000)

    {outcome, ms} =
      Exec.timed(mix(), ["test" | paths],
        cd: dir,
        timeout_ms: timeout_ms,
        stderr: :stdout,
        env: Env.build(%{"MIX_ENV" => "test"})
      )

    case outcome do
      {:ok, status, out} -> {:ok, status, ms, out}
      {:timeout, out} -> {:timeout, ms, out}
    end
  end

  defp clone_support(repo, dir) do
    Enum.reduce_while(@cloned ++ @seeded, :ok, fn relative, :ok ->
      source = Path.join(repo, relative)
      target = Path.join(dir, relative)

      cond do
        not File.exists?(source) ->
          {:cont, :ok}

        File.exists?(target) ->
          {:cont, :ok}

        true ->
          File.mkdir_p!(Path.dirname(target))

          case Fs.clone(source, target) do
            :ok -> {:cont, :ok}
            {:error, reason} -> {:halt, {:error, reason}}
          end
      end
    end)
  end

  # `deps/` was fetched for the repository's own lock. A commit whose lock differs needs
  # the versions it pinned, and Mix refuses to compile against the wrong ones rather than
  # guessing — which is the right refusal, and is why this is a byte comparison and not a
  # retry on an error message.
  defp deps(repo, dir, timeout_ms, log) do
    if File.read(Path.join(repo, "mix.lock")) == File.read(Path.join(dir, "mix.lock")) do
      :ok
    else
      case Exec.run(mix(), ["deps.get"],
             cd: dir,
             timeout_ms: timeout_ms,
             stderr: :stdout,
             env: Env.build(%{"MIX_ENV" => "test"})
           ) do
        {:ok, 0, out} ->
          append(log, "$ mix deps.get\n" <> out)
          :ok

        {:ok, code, out} ->
          append(log, "$ mix deps.get\n" <> out)
          {:error, "mix deps.get exited #{code}: " <> tail(out)}

        {:timeout, out} ->
          append(log, "$ mix deps.get (timed out)\n" <> out)
          {:error, "mix deps.get timed out after #{timeout_ms}ms"}
      end
    end
  end

  defp compile(dir, envs, timeout_ms, log) do
    Enum.reduce_while(envs, :ok, fn env, :ok ->
      case Exec.run(mix(), ["compile"],
             cd: dir,
             timeout_ms: timeout_ms,
             stderr: :stdout,
             env: Env.build(%{"MIX_ENV" => env})
           ) do
        {:ok, 0, out} ->
          append(log, "$ MIX_ENV=#{env} mix compile\n" <> out)
          {:cont, :ok}

        {:ok, code, out} ->
          append(log, "$ MIX_ENV=#{env} mix compile\n" <> out)
          {:halt, {:error, "MIX_ENV=#{env} mix compile exited #{code}: " <> tail(out)}}

        {:timeout, out} ->
          append(log, "$ MIX_ENV=#{env} mix compile (timed out)\n" <> out)
          {:halt, {:error, "MIX_ENV=#{env} mix compile timed out after #{timeout_ms}ms"}}
      end
    end)
  end

  defp append(nil, _text), do: :ok

  defp append(path, text) do
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, text <> "\n", [:append])
  end

  defp tail(output), do: output |> String.split("\n") |> Enum.take(-12) |> Enum.join("\n") |> String.trim()

  defp mix, do: System.find_executable("mix") || "mix"
end

defmodule Bench.Self.Hidden do
  @moduledoc """
  The hidden test set: what it is, where its bytes come from, and how it is restored.

  The corpus on disk is a list of *pins* — shas and paths. Content is read from git at run
  time, so the number stays reproducible for as long as the history is, and a corpus file
  cannot quietly weaken a task by carrying a doctored copy of its test.
  """

  alias Bench.Self.Git

  @doc """
  Every path under `test/` the commit added or modified, deletions excluded.

  `test/support/**` is included: a commit whose fixture and test moved together is only
  gradable with both, and a corpus that restored the test but not the fixture would be
  grading a compile error.
  """
  @spec paths(Path.t(), String.t(), String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def paths(repo, base, commit) do
    case Git.name_status(repo, base, commit, ["test"]) do
      {:ok, entries} ->
        {:ok,
         entries
         |> Enum.reject(fn {status, _path} -> String.starts_with?(status, "D") end)
         |> Enum.map(fn {_status, path} -> path end)
         |> Enum.sort()
         |> Enum.uniq()}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "The `_test.exs` members of a hidden set — the only ones ExUnit is given."
  @spec graded([String.t()]) :: [String.t()]
  def graded(paths), do: Enum.filter(paths, &String.ends_with?(&1, "_test.exs"))

  @doc """
  Writes every hidden path into `dir` from `commit`, replacing whatever is there.

  The existing entry is removed first rather than written through: `File.write/2` follows
  a symlink, and a tree in which a hidden path has become a link is a tree in which the
  grader would be writing somewhere it did not choose. Removing first makes the write land
  on a real file at the path ExUnit is about to be handed.
  """
  @spec restore(Path.t(), Path.t(), String.t(), [String.t()]) :: :ok | {:error, String.t()}
  def restore(repo, dir, commit, paths) do
    Enum.reduce_while(paths, :ok, fn path, :ok ->
      target = Path.join(dir, path)

      with {:ok, body} <- Git.show(repo, commit, path),
           :ok <- File.mkdir_p(Path.dirname(target)),
           _removed = File.rm(target),
           :ok <- File.write(target, body) do
        {:cont, :ok}
      else
        {:error, reason} when is_binary(reason) -> {:halt, {:error, reason}}
        {:error, reason} -> {:halt, {:error, "#{path}: #{inspect(reason)}"}}
      end
    end)
  end
end

defmodule Bench.Self.Prompt do
  @moduledoc """
  Which instructions the runtime will accept as a prompt.

  `Ouroboros.AgentProfile.reserved_delimiter?/1` refuses text that would forge one of the
  prompt assembler's block boundaries, and `Runtime.Exposure.wrap_prompt_capture/2` applies
  it to every session prompt. A commit message *about* that boundary quotes the tags, so a
  task built from one is a task the runtime will not accept — the corpus found exactly one
  (`7e610856`, `fix(prompt): make the profile/session boundary real`), which failed
  `not_completed` with the runtime's own refusal in it.

  The list is asked of the runtime rather than copied here. A copy is a second source of
  truth for a rule that exists to be exact, and it would go stale the first time a
  delimiter is added.
  """

  alias Bench.Self.{Env, Exec}

  @snippet ~S|IO.puts("BENCH_DELIMITERS " <> Enum.join(Ouroboros.AgentProfile.reserved_delimiters(), " "))|

  @doc "The delimiters this checkout's runtime refuses inside a prompt."
  @spec reserved_delimiters(Path.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def reserved_delimiters(repo) do
    case Exec.run(mix(), ["run", "--no-start", "-e", @snippet],
           cd: repo,
           timeout_ms: 300_000,
           stderr: :stdout,
           env: Env.build(%{"MIX_ENV" => "dev"})
         ) do
      {:ok, 0, out} ->
        case captured(out) do
          [] -> {:error, "the runtime named no reserved prompt delimiters:\n" <> String.trim(out)}
          list -> {:ok, list}
        end

      {:ok, code, out} ->
        {:error, "asking the runtime for its reserved prompt delimiters exited #{code}:\n" <> String.trim(out)}

      {:timeout, _out} ->
        {:error, "asking the runtime for its reserved prompt delimiters timed out"}
    end
  end

  @doc "Whether `text` carries one of them, and would therefore be refused."
  @spec reserved?(String.t(), [String.t()]) :: boolean()
  def reserved?(text, delimiters), do: Enum.any?(delimiters, &String.contains?(text, &1))

  defp captured(output) do
    output
    |> String.split("\n")
    |> Enum.find_value([], fn line ->
      if String.starts_with?(line, "BENCH_DELIMITERS "),
        do: line |> String.replace_prefix("BENCH_DELIMITERS ", "") |> String.split(" ", trim: true)
    end)
  end

  defp mix, do: System.find_executable("mix") || "mix"
end

defmodule Bench.Self.TaskFile do
  @moduledoc "Reading and writing `tasks/<id>/task.json`, and refusing a corpus that is not one."

  @required ~w(id base_sha commit_sha subject instruction hidden_tests solution_files timeout_secs)

  @spec load_all(Path.t(), String.t() | nil) :: {:ok, [map()]} | {:error, String.t()}
  def load_all(root, filter) do
    with {:ok, names} <- listing(root) do
      names
      |> Enum.sort()
      |> Enum.map(&Path.join(root, &1))
      |> Enum.filter(&File.dir?/1)
      |> Enum.reduce_while({:ok, []}, fn dir, {:ok, acc} ->
        case load(dir) do
          {:ok, task} -> {:cont, {:ok, [task | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
      |> case do
        {:ok, tasks} -> filtered(Enum.reverse(tasks), filter)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @spec load(Path.t()) :: {:ok, map()} | {:error, String.t()}
  def load(dir) do
    path = Path.join(dir, "task.json")

    with {:ok, body} <- File.read(path),
         {:ok, meta} when is_map(meta) <- JSON.decode(body),
         :ok <- required(meta, path) do
      {:ok, Map.put(meta, "dir", dir)}
    else
      {:error, :enoent} -> {:error, "#{path} is missing"}
      {:error, reason} when is_binary(reason) -> {:error, reason}
      {:error, reason} -> {:error, "#{path} is unreadable: #{inspect(reason)}"}
      {:ok, _other} -> {:error, "#{path} is not a JSON object"}
    end
  end

  @spec write(Path.t(), map()) :: :ok
  def write(dir, task) do
    File.mkdir_p!(dir)
    File.write!(Path.join(dir, "task.json"), encode(task))
    :ok
  end

  @doc """
  Canonical JSON: keys in a fixed order, one field per line, newline-terminated.

  A corpus is reviewed in a diff. `JSON.encode!/1` would order keys by however the map
  hashed, so a re-extraction that changed nothing would still produce a diff.
  """
  @spec encode(map()) :: String.t()
  def encode(task) do
    order = ~w(id base_sha commit_sha subject instruction hidden_tests solution_files timeout_secs measured)

    body =
      order
      |> Enum.filter(&Map.has_key?(task, &1))
      |> Enum.map_join(",\n", fn key -> "  " <> JSON.encode!(key) <> ": " <> value(task[key]) end)

    "{\n" <> body <> "\n}\n"
  end

  defp value(list) when is_list(list) do
    case list do
      [] -> "[]"
      _ -> "[\n" <> Enum.map_join(list, ",\n", &("    " <> JSON.encode!(&1))) <> "\n  ]"
    end
  end

  defp value(map) when is_map(map) do
    "{" <> (map |> Enum.sort() |> Enum.map_join(", ", fn {k, v} -> JSON.encode!(to_string(k)) <> ": " <> JSON.encode!(v) end)) <> "}"
  end

  defp value(other), do: JSON.encode!(other)

  defp listing(root) do
    case File.ls(root) do
      {:ok, names} -> {:ok, names}
      {:error, :enoent} -> {:error, "#{root} does not exist; run bench/self/extract.exs first"}
      {:error, reason} -> {:error, "#{root} is unreadable: #{inspect(reason)}"}
    end
  end

  defp required(meta, path) do
    case Enum.reject(@required, &is_map_key(meta, &1)) do
      [] -> :ok
      missing -> {:error, "#{path} is missing #{Enum.join(missing, ", ")}"}
    end
  end

  defp filtered(tasks, nil), do: {:ok, tasks}

  defp filtered(tasks, filter),
    do: {:ok, Enum.filter(tasks, &String.contains?(&1["id"], filter))}
end
