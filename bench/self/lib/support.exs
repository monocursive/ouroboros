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
  @cut_prefix "\n[bench.self: output cut after "

  @type outcome :: {:ok, integer(), String.t()} | {:timeout, String.t()}

  @doc """
  Whether a captured output was cut short by its cap.

  A reader that derives a *verdict* from a child's output has to know this: a cut
  capture is missing whatever the child said last, and treating it as a summary that
  simply was not printed would turn a truncation into a grade.
  """
  @spec cut?(String.t()) :: boolean()
  def cut?(output), do: String.contains?(output, @cut_prefix)

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

    # stdin is left alone unless a caller names a file: `ouro run` owns its own, and a
    # harness that quietly redirected it would be changing the thing it is measuring.
    command =
      case Keyword.get(opts, :stdin_file) do
        nil -> command
        path -> command <> " <" <> Bench.Self.Shell.quote_arg(path)
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

    collect(port, [], 0, false, cap, System.monotonic_time(:millisecond) + deadline_ms)
  end

  @doc "`run/3` plus the wall time it took, which is the number the corpus reports."
  @spec timed(String.t(), [String.t()], keyword()) :: {outcome(), non_neg_integer()}
  def timed(program, argv, opts) do
    started = System.monotonic_time(:millisecond)
    outcome = run(program, argv, opts)
    {outcome, System.monotonic_time(:millisecond) - started}
  end

  defp collect(port, chunks, bytes, cut?, cap, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    receive do
      {^port, {:data, data}} ->
        {chunks, bytes, cut?} = keep(chunks, bytes, cut?, data, cap)
        collect(port, chunks, bytes, cut?, cap, deadline)

      {^port, {:exit_status, status}} ->
        {:ok, status, flatten(chunks, cut?, cap)}
    after
      max(remaining, 0) ->
        kill(port)
        {:timeout, flatten(chunks, cut?, cap)}
    end
  end

  # The head, and the cut is marked. This is a reversal of what this function used to do,
  # and the reason is `Bench.Self.Verdict`: the grade is now read *out of* `mix test`'s
  # own output rather than off its exit status. Keeping the tail would mean a child that
  # can keep writing can push the real summary out of the window and leave a forged one
  # behind it — the same class of attack as `System.halt(0)`, which is why the exit status
  # stopped being the verdict in the first place. Keeping the head instead makes a
  # runaway child lose its summary, and a reader that finds none fails closed.
  defp keep(chunks, bytes, true, _data, _cap), do: {chunks, bytes, true}

  defp keep(chunks, bytes, false, data, cap) do
    room = max(cap - bytes, 0)

    if byte_size(data) <= room do
      {[data | chunks], bytes + byte_size(data), false}
    else
      {[binary_part(data, 0, room) | chunks], cap, true}
    end
  end

  defp flatten(chunks, cut?, cap) do
    text = chunks |> Enum.reverse() |> IO.iodata_to_binary()

    if cut?,
      do: text <> @cut_prefix <> Integer.to_string(cap) <> " bytes]\n",
      else: text
  end

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
    CEREBRAS_API_KEY PERPLEXITY_API_KEY ZAI_API_KEY
    AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    GITHUB_TOKEN OUROBOROS_GATEWAY_TOKEN OUROBOROS_WEB_TOKEN
    OUROBOROS_CLUSTER_GOSSIP_SECRET
  )

  @doc """
  Every secret the **oracle** refuses to pass on.

  Wider than the model keys, because the oracle runs no model and no operator tool: it
  answers from a script and spends nothing by construction, so a variable it cannot use
  is one it should not carry. `GITHUB_TOKEN` and the three `OUROBOROS_*` secrets are
  here for that reason and that reason only — the *paid* path passes the environment
  through on purpose, where an operator may well want their agent to use `gh`.
  """
  @spec secrets() :: [String.t()]
  def secrets, do: @keys

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
  @ref_prefix "refs/bench-self"
  @base_branch "bench-self-base"
  # `git init` points HEAD at its default branch, and git refuses to fetch into the branch
  # HEAD is on — even an unborn one. So the empty repository starts on a name nothing ever
  # fetches into, and the base arrives on its own branch beside it.
  @init_branch "bench-self-empty"

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
    # stderr goes to /dev/null rather than to this process's own: asking for a path a
    # commit does not have is a *question* here — the extractor asks it of every hidden
    # test at the parent — and git answers a question it does not like with `fatal:` on
    # stderr. The exit status is the answer; the noise would read like a broken run.
    case Exec.run(git(), ["--no-pager", "show", sha <> ":" <> path],
           cd: repo,
           timeout_ms: 60_000,
           stderr: "/dev/null",
           max_output_bytes: 8 * 1024 * 1024
         ) do
      {:ok, 0, body} -> {:ok, body}
      {:ok, code, _body} -> {:error, "git show #{sha}:#{path} exited #{code}"}
      {:timeout, _body} -> {:error, "git show #{sha}:#{path} timed out"}
    end
  end

  @doc """
  Whether this repository has `sha` as a commit.

  The workspace asserts this is **false** for its task's `commit_sha`: the history cut is
  a property to be checked per task, not one to be assumed because the code that makes it
  looks right.
  """
  @spec has_commit?(Path.t(), String.t()) :: boolean()
  def has_commit?(repo, sha) do
    case Exec.run(git(), ["cat-file", "-e", sha <> "^{commit}"],
           cd: repo,
           timeout_ms: 60_000,
           stderr: :stdout
         ) do
      {:ok, 0, _out} -> true
      _absent -> false
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

  @doc """
  `git diff --binary` between `base` and the working tree, over `pathspec`.

  stderr is *not* folded in, for `show/3`'s reason: this output is a patch, and a warning
  mixed into it would be applied as if the agent had written it.
  """
  @spec diff_binary(Path.t(), String.t(), [String.t()]) :: {:ok, binary()} | {:error, String.t()}
  def diff_binary(dir, base, pathspec) do
    case Exec.run(git(), ["--no-pager", "diff", "--binary", "--no-renames", base, "--"] ++ pathspec,
           cd: dir,
           timeout_ms: 120_000,
           max_output_bytes: 8 * 1024 * 1024
         ) do
      {:ok, 0, body} -> {:ok, body}
      {:ok, code, body} -> {:error, "git diff --binary #{base} exited #{code}: " <> String.slice(body, 0, 400)}
      {:timeout, _body} -> {:error, "git diff --binary #{base} timed out"}
    end
  end

  @doc "Applies a patch `diff_binary/3` produced, in `dir`."
  @spec apply_patch(Path.t(), Path.t()) :: :ok | {:error, String.t()}
  def apply_patch(dir, patch_file) do
    case run(dir, ["apply", "--binary", "--whitespace=nowarn", patch_file], timeout_ms: 120_000) do
      {:ok, _out} -> :ok
      {:error, reason} -> {:error, reason}
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
  Removes a worktree this script made, and deregisters only that one if it did not take.

  `git worktree prune` is never run. It is a repository-wide sweep: it deregisters every
  worktree whose directory has gone, including the ones other people are in the middle of
  using. What has to be removed here is one administrative directory — the one whose
  `gitdir` file names the path this script made — so that is what is removed.
  """
  @spec worktree_remove(Path.t(), Path.t()) :: :ok
  def worktree_remove(repo, dir) do
    :global.trans({@lock, self()}, fn ->
      case run(repo, ["worktree", "remove", "--force", dir], timeout_ms: 300_000) do
        {:ok, _out} ->
          :ok

        {:error, _reason} ->
          File.rm_rf(dir)
          deregister(repo, dir)
          :ok
      end
    end)
  end

  defp deregister(repo, dir) do
    case out(repo, ["rev-parse", "--git-common-dir"]) do
      nil ->
        :ok

      common ->
        wanted = Path.expand(dir)

        [Path.expand(common, repo), "worktrees", "*", "gitdir"]
        |> Path.join()
        |> Path.wildcard()
        |> Enum.filter(fn gitdir ->
          case File.read(gitdir) do
            {:ok, body} -> Path.expand(Path.dirname(String.trim(body))) == wanted
            _unreadable -> false
          end
        end)
        |> Enum.each(&File.rm_rf(Path.dirname(&1)))

        :ok
    end
  end

  @doc """
  A workspace at `sha` whose history **stops** there.

  `git worktree add` shares the repository's object store, so the commit that is a task's
  answer — and every commit after it — is reachable from inside the worktree, and the
  instruction is that commit's own subject. One `git log --all --grep` and a `git show`
  per file is then a full pass with no reading and no reasoning; the review proved it.

  This builds the workspace as a real clone instead: a temporary ref at `sha`, then a
  fetch of that ref alone through the **`file://` transport**, which packs only the
  objects reachable from what was asked for. A plain path clone would hardlink the whole
  object store and hand the answer back. The ref is deleted as soon as the fetch returns,
  on every path.

  The history *up to* the base is all there, which is the point: reading how this code
  base got here is legitimate engineering context, and cutting it would measure something
  nobody does.
  """
  @spec clone_at(Path.t(), Path.t(), String.t(), String.t(), keyword()) :: :ok | {:error, String.t()}
  def clone_at(repo, dir, sha, ref, opts \\ []) do
    timeout_ms = Keyword.get(opts, :timeout_ms, 600_000)
    File.mkdir_p!(dir)

    try do
      with :ok <- update_ref(repo, ref, sha),
           {:ok, _out} <-
             run(dir, ["-c", "init.defaultBranch=" <> @init_branch, "init", "--quiet"],
               timeout_ms: timeout_ms
             ),
           {:ok, _out} <-
             run(dir, ["fetch", "--quiet", "--no-tags", "file://" <> repo, ref <> ":refs/heads/" <> @base_branch],
               timeout_ms: timeout_ms
             ),
           {:ok, _out} <-
             run(dir, ["checkout", "--quiet", "--detach", "refs/heads/" <> @base_branch], timeout_ms: timeout_ms),
           {:ok, _out} <- run(dir, ["config", "user.email", "bench-self@localhost"]),
           {:ok, _out} <- run(dir, ["config", "user.name", "bench.self"]) do
        :ok
      end
    after
      delete_ref(repo, ref)
    end
  end

  @doc "The `refs/` prefix every temporary ref this corpus makes lives under."
  @spec ref_prefix() :: String.t()
  def ref_prefix, do: @ref_prefix

  @doc "The temporary ref one task's clone fetches from."
  @spec task_ref(String.t(), String.t()) :: String.t()
  def task_ref(run_id, id), do: Enum.join([@ref_prefix, run_id, id], "/")

  @spec update_ref(Path.t(), String.t(), String.t()) :: :ok | {:error, String.t()}
  def update_ref(repo, ref, sha) do
    case run(repo, ["update-ref", ref, sha]) do
      {:ok, _out} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @spec delete_ref(Path.t(), String.t()) :: :ok
  def delete_ref(repo, ref) do
    _ = run(repo, ["update-ref", "-d", ref])
    :ok
  end

  @doc "Every ref under this corpus's own prefix — empty is the invariant a run leaves behind."
  @spec temporary_refs(Path.t()) :: [String.t()]
  def temporary_refs(repo) do
    case run(repo, ["for-each-ref", "--format=%(refname)", @ref_prefix]) do
      {:ok, output} -> String.split(output, "\n", trim: true)
      {:error, _reason} -> []
    end
  end

  @doc """
  Every blob at `sha` under `pathspec`, as `%{path => object id}`.

  `-z` rather than the default listing: without it a path with an unusual byte is
  C-quoted, and a reader that did not unquote would compare a name to a different name.
  """
  @spec blobs(Path.t(), String.t(), [String.t()]) :: {:ok, %{String.t() => String.t()}} | {:error, String.t()}
  def blobs(repo, sha, pathspec \\ []) do
    case run(repo, ["--no-pager", "ls-tree", "-r", "-z", sha, "--"] ++ pathspec,
           max_output_bytes: 4 * 1024 * 1024
         ) do
      {:ok, output} ->
        {:ok,
         output
         |> String.split(<<0>>, trim: true)
         |> Enum.flat_map(fn entry ->
           with [meta, path] <- String.split(entry, "\t", parts: 2),
                [_mode, "blob", object] <- String.split(meta, " ", trim: true) do
             [{path, object}]
           else
             _other -> []
           end
         end)
         |> Map.new()}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  `git hash-object` for files on disk, as `%{path => object id}`.

  This is how a modified file is detected: by content, against the blob the base commit
  holds. The index is not consulted, because the index is the agent's — one
  `git update-index --assume-unchanged` makes `git status` and `git diff` forget a file
  that is sitting there modified, which the review proved.

  Every path must exist; a caller separates the missing ones first and reports them as
  deletions. A path that has become a symlink is hashed as the bytes it points at, which
  is a difference from what git would store — noted rather than defended, because the
  agent's `test/` tree is not what is graded any more.
  """
  @spec hash_objects(Path.t(), [String.t()]) :: {:ok, %{String.t() => String.t()}} | {:error, String.t()}
  def hash_objects(_dir, []), do: {:ok, %{}}

  def hash_objects(dir, paths) do
    paths
    |> Enum.chunk_every(200)
    |> Enum.reduce_while({:ok, %{}}, fn chunk, {:ok, acc} ->
      case run(dir, ["hash-object", "--"] ++ chunk, max_output_bytes: 1024 * 1024) do
        {:ok, output} ->
          hashes = String.split(output, "\n", trim: true)

          if length(hashes) == length(chunk) do
            {:cont, {:ok, Map.merge(acc, Map.new(Enum.zip(chunk, hashes)))}}
          else
            {:halt, {:error, "git hash-object answered #{length(hashes)} ids for #{length(chunk)} paths"}}
          end

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
  end

  @doc """
  Whether two paths are the same git repository.

  Not the same directory: a linked worktree, the improve loop's `--repo`, and the checkout
  itself are three paths and one object store. What this answers is whether a `deps/` and
  `_build/` built in one belong in a tree built from the other.
  """
  @spec same_repository?(Path.t(), Path.t()) :: boolean()
  def same_repository?(a, b) do
    case {common_dir(a), common_dir(b)} do
      {nil, _other} -> false
      {_one, nil} -> false
      {one, other} -> one == other
    end
  end

  defp common_dir(path) do
    case out(path, ["rev-parse", "--git-common-dir"]) do
      nil -> nil
      dir -> Path.expand(dir, path)
    end
  end

  @doc "The parents of one commit. Two or more is a merge."
  @spec parents(Path.t(), String.t()) :: [String.t()]
  def parents(repo, sha) do
    case out(repo, ["--no-pager", "log", "-1", "--format=%P", sha]) do
      nil -> []
      text -> String.split(text, " ", trim: true)
    end
  end

  @doc "Whether the repository has uncommitted changes — the `-dirty` in a reported sha."
  @spec dirty?(Path.t()) :: boolean()
  def dirty?(repo) do
    case run(repo, ["status", "--porcelain"], max_output_bytes: 1024 * 1024) do
      {:ok, output} -> String.trim(output) != ""
      {:error, _reason} -> false
    end
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

  A tree at `sha`, with `deps/`, `_build/` and the two sealed helper directories cloned in
  from the checkout, `mix deps.get` when the commit's `mix.lock` is not the one those
  `deps/` were fetched for, and `mix compile` per environment. The
  compile is the runner's *setup*: it is timed separately from the agent's turn, because
  a benchmark that charged the agent for a cold build would be measuring this machine.
  """

  alias Bench.Self.{Env, Exec, Fs, Git}

  @cloned ~w(deps _build)
  @seeded ~w(priv/wasm)
  @test_output_cap 8 * 1024 * 1024

  @type prepared :: %{setup_ms: non_neg_integer(), log: Path.t() | nil}

  @doc """
  The paths this module puts into a tree that the tree's own commit does not carry.

  `Bench.Self.Change` needs them by name. `.gitignore` at an older commit does not
  necessarily ignore all three — `priv/wasm` is a recent entry — so without this list the
  sealed helper binary reads as a file the *agent* added, lands in the graded diff, and the
  patch then fails to apply against a grading tree that was handed the same binary.
  """
  @spec seeded() :: [String.t()]
  def seeded, do: @cloned ++ @seeded

  @doc """
  Builds the tree at `sha` in `dir`. The caller owns removal, on every path.

  Two shapes of tree, and which one is which matters:

    * `mode: {:clone, ref}` builds the **agent's workspace** — a clone whose history stops
      at `sha` (`Bench.Self.Git.clone_at/5`), because a worktree shares the repository's
      object store and would hand the agent the commit that is the answer;
    * `mode: :worktree` (the default) builds the **grading tree** and the extractor's
      proving tree — cheaper, and reachability does not matter where no agent runs.

  Options: `:mode`, `:support_from` (where `deps/`, `_build/` and the sealed helpers are
  cloned from — default `repo`, `nil` for a history that is not this project; for the
  grading tree always the *checkout*, never the agent's workspace), `:absent` (a sha the
  built tree must not be able to reach), `:envs` (default `["test"]`), `:timeout_ms` per
  child (default 600 000), `:log` (a file every child's output is appended to).
  """
  @spec prepare(Path.t(), Path.t(), String.t(), keyword()) ::
          {:ok, prepared()} | {:error, String.t()}
  def prepare(repo, dir, sha, opts \\ []) do
    envs = Keyword.get(opts, :envs, ["test"])
    timeout_ms = Keyword.get(opts, :timeout_ms, 600_000)
    log = Keyword.get(opts, :log)
    support = Keyword.get(opts, :support_from, repo)
    started = System.monotonic_time(:millisecond)

    with :ok <- build(repo, dir, sha, Keyword.get(opts, :mode, :worktree), timeout_ms),
         :ok <- absent(dir, Keyword.get(opts, :absent)),
         :ok <- clone_support(support, dir),
         :ok <- deps(support, dir, timeout_ms, log),
         :ok <- compile(dir, envs, timeout_ms, log) do
      {:ok, %{setup_ms: System.monotonic_time(:millisecond) - started, log: log}}
    end
  end

  @doc "Removes a tree this module built, in the shape it was built in."
  @spec remove(Path.t(), Path.t(), keyword()) :: :ok
  def remove(repo, dir, opts \\ []) do
    case Keyword.get(opts, :mode, :worktree) do
      :worktree ->
        Git.worktree_remove(repo, dir)

      {:clone, _ref} ->
        File.rm_rf(dir)
        :ok
    end
  end

  @doc "`mix compile` in a tree something has changed in since `prepare/4` built it."
  @spec recompile(Path.t(), [String.t()], keyword()) :: :ok | {:error, String.t()}
  def recompile(dir, envs, opts \\ []),
    do: compile(dir, envs, Keyword.get(opts, :timeout_ms, 600_000), Keyword.get(opts, :log))

  defp build(repo, dir, sha, :worktree, _timeout_ms), do: Git.worktree_add(repo, dir, sha)

  defp build(repo, dir, sha, {:clone, ref}, timeout_ms),
    do: Git.clone_at(repo, dir, sha, ref, timeout_ms: timeout_ms)

  defp absent(_dir, nil), do: :ok

  defp absent(dir, sha) do
    if Git.has_commit?(dir, sha) do
      {:error,
       "#{String.slice(sha, 0, 12)} is reachable from the workspace: the history was not " <>
         "cut, and the task's own answer is one `git log --all --grep` away"}
    else
      :ok
    end
  end

  @doc """
  `mix test <paths>` in a prepared tree.

  `{:ok, exit_status, ms, output}` or `{:timeout, ms, output}`. The output cap is
  deliberately generous, because `Bench.Self.Verdict` reads the grade out of this text and
  a cut capture is a failed grade rather than a summary that was not printed.
  """
  @spec test(Path.t(), [String.t()], keyword()) ::
          {:ok, integer(), non_neg_integer(), String.t()} | {:timeout, non_neg_integer(), String.t()}
  def test(dir, paths, opts \\ []) do
    timeout_ms = Keyword.get(opts, :timeout_ms, 600_000)

    {outcome, ms} =
      Exec.timed(mix(), ["test" | paths],
        cd: dir,
        timeout_ms: timeout_ms,
        stderr: :stdout,
        max_output_bytes: @test_output_cap,
        env: Env.build(%{"MIX_ENV" => "test"})
      )

    case outcome do
      {:ok, status, out} -> {:ok, status, ms, out}
      {:timeout, out} -> {:timeout, ms, out}
    end
  end

  @doc "The command line `test/3` runs, for the record a run leaves behind."
  @spec test_command([String.t()]) :: String.t()
  def test_command(paths), do: "MIX_ENV=test mix test " <> Bench.Self.Shell.line(paths)

  # `nil` is "there is nothing of this project to clone in" — a history that is not this
  # checkout's repository, which is how the selftest builds a two-file fixture project
  # without a 300 MB `_build` belonging to something else landing in it.
  defp clone_support(nil, _dir), do: :ok

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
  defp deps(nil, _dir, _timeout_ms, _log), do: :ok

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
           :ok <- real_directories(dir, path),
           _removed = File.rm(target),
           :ok <- File.write(target, body) do
        {:cont, :ok}
      else
        {:error, reason} when is_binary(reason) -> {:halt, {:error, reason}}
        {:error, reason} -> {:halt, {:error, "#{path}: #{inspect(reason)}"}}
      end
    end)
  end

  @doc """
  Whether every restored path still holds `commit`'s bytes.

  Run **after** the graded `mix test`, and the reason is that a grading tree runs the
  agent's own code: an Elixir module body executes at compile time, in the same BEAM that
  is about to load these files. Restoring after the compile makes a compile-time rewrite
  pointless; hashing afterwards makes one at any later moment visible instead of silent.
  """
  @spec intact(Path.t(), Path.t(), String.t(), [String.t()]) :: :ok | {:error, String.t()}
  def intact(repo, dir, commit, paths) do
    with {:ok, wanted} <- Git.blobs(repo, commit, paths) do
      {present, gone} = Enum.split_with(paths, &File.regular?(Path.join(dir, &1)))

      case Git.hash_objects(dir, present) do
        {:ok, got} ->
          changed = Enum.filter(present, &(Map.get(got, &1) != Map.get(wanted, &1)))

          case Enum.sort(gone ++ changed) do
            [] -> :ok
            bad -> {:error, "the restored hidden tests changed while grading: " <> Enum.join(bad, ", ")}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # `File.write/2` follows a symlink, and `File.rm/1` before it removes only the last
  # component. A tree in which `test/support` has become a link to somewhere else is one
  # where the grader would be writing where it did not choose, so every component below
  # the tree root has to be a real directory.
  defp real_directories(dir, path) do
    path
    |> Path.dirname()
    |> Path.split()
    |> Enum.reduce_while({:ok, dir}, fn segment, {:ok, at} ->
      next = Path.join(at, segment)

      case File.lstat(next) do
        {:ok, %File.Stat{type: :directory}} -> {:cont, {:ok, next}}
        {:ok, %File.Stat{type: type}} -> {:halt, {:error, "#{path}: #{next} is a #{type}, not a directory"}}
        {:error, :enoent} -> {:cont, {:ok, next}}
        {:error, reason} -> {:halt, {:error, "#{path}: #{next} is unreadable (#{inspect(reason)})"}}
      end
    end)
    |> case do
      {:ok, _at} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end

defmodule Bench.Self.Verdict do
  @moduledoc """
  What one `mix test` **reported**, as opposed to how its process ended.

  `mix test`'s exit status is a number the code under test can set — one
  `System.at_exit(fn _ -> System.halt(0) end)` in `test/test_helper.exs` makes every suite
  exit 0, and the review proved the neighbouring trick: a `test: ["cmd true"]` alias in
  `mix.exs` made `mix test` exit 0 over a suite asserting `1 == 2`. So the verdict is
  ExUnit's own summary line.

  The rule is the one `bench/self/lib/improve/gate-verdict.sh` applies to the improve
  loop's gate: the same rule in a second language rather than a second rule, because the
  two grade the same repository's suites and disagreeing about what green means would be
  worse than either answer on its own. Green is

    * the process exited 0,
    * the capture was not cut short by the harness cap,
    * at least one `Result:` line, and every one of them a clean pass,
    * no `Failed:` line, and
    * at least `least` passing tests — the number of hidden `_test.exs` files, because a
      file that ran contributed at least one test.

  Elixir 1.20's ExUnit prints `Result: 6 passed`, `Result: 1 passed, 1 skipped,
  1 excluded`, `Result: 1/2 passed` beside `Failed: 1 test`, and `Result: 0 tests,
  3 excluded`. Only the first two shapes are a pass; `<m>/<n> passed` is a failure summary
  and `0 tests` is a suite that ran nothing.

  What this cannot do is tell ExUnit's summary from one the code under test printed
  itself. Nothing that parses the output of a VM the graded code runs in can. What it
  does is remove the *cheap* forgeries: an exit status, a truncated capture, a suite that
  reported nothing, and a summary that reports fewer tests than there are files.
  """

  @spec of(String.t(), integer(), non_neg_integer()) :: {:ok, String.t()} | {:error, String.t()}
  def of(output, status, least) do
    lines = summary_lines(output)
    summary = Enum.join(lines, " ")
    {results, passes, failed, passed} = counts(lines)

    cond do
      status != 0 ->
        {:error, "mix test exited #{status}" <> note(summary)}

      Bench.Self.Exec.cut?(output) ->
        {:error, "mix test exited 0 but its output was cut short by the harness cap" <> note(summary)}

      results == 0 ->
        {:error, "mix test exited 0 but printed no `Result:` line: the suite did not report"}

      failed > 0 ->
        {:error, "mix test exited 0 but the suite reported a failure" <> note(summary)}

      passes != results ->
        {:error, "mix test exited 0 but a result line is not a pass" <> note(summary)}

      passed < least ->
        {:error,
         "mix test exited 0 reporting #{passed} passing test(s) for #{least} hidden test " <>
           "file(s)" <> note(summary)}

      true ->
        {:ok, summary}
    end
  end

  defp summary_lines(output) do
    output
    |> String.split("\n")
    |> Enum.filter(&(String.starts_with?(&1, "Result:") or String.starts_with?(&1, "Failed:")))
    |> Enum.map(&String.trim/1)
  end

  defp counts(lines) do
    Enum.reduce(lines, {0, 0, 0, 0}, fn line, {results, passes, failed, passed} ->
      case String.split(line, ~r/\s+/, trim: true) do
        ["Failed:" | _rest] ->
          {results, passes, failed + 1, passed}

        ["Result:", count | rest] ->
          if integer(count) != nil and match?(["passed" <> _tail | _more], rest),
            do: {results + 1, passes + 1, failed, passed + integer(count)},
            else: {results + 1, passes, failed, passed}

        _other ->
          {results + 1, passes, failed, passed}
      end
    end)
  end

  defp integer(text) do
    case Integer.parse(text) do
      {value, ""} -> value
      _other -> nil
    end
  end

  defp note(""), do: ""
  defp note(summary), do: ": " <> summary
end

defmodule Bench.Self.Change do
  @moduledoc """
  What the agent changed, as a patch that can be applied somewhere else.

  The grader grades this, not the tree the agent worked in, and that is the whole answer
  to the review's first exploit. A file the agent adds under `test/` is *allowed* — writing
  your own tests is part of the work — but `test/support/**` is on `elixirc_paths(:test)`,
  so such a file is compiled into the grading VM, its module body runs there, and the
  review's `zz_bench_self_exploit.ex` used exactly that to rewrite every restored hidden
  test between the check and the run. `mix.exs` is the same shape of hole one level up:
  `test: ["cmd true"]` and the suite "passes".

  So: the change is collected as `git diff --binary <base_sha>` over the source roots this
  corpus actually uses, and *only* those. Everything else is a refusal rather than a
  filtered-out edit, because an agent that rewrote `mix.exs` did not do the task, and
  silently grading the rest of its diff would report a number for work nobody checked.

  The allowed roots are derived, not chosen: every `solution_files` entry across the
  thirty tasks is under `lib/`, `priv/`, `docs/`, `config/` or `README.md`, and `assets/`
  joins them as the one remaining source root of this repository. `config/` is here on
  those grounds and is worth naming: `config/*.exs` is Elixir the build evaluates, so it
  can run code in the grading VM the way `test/support` can. What contains it is order —
  the grading tree compiles the diff *before* the hidden tests are restored — and
  `Bench.Self.Hidden.intact/4`, which re-reads their bytes afterwards.
  """

  alias Bench.Self.Git

  @allowed_roots ~w(lib/ assets/ priv/ config/ docs/)
  @allowed_files ~w(README.md)

  @type collected :: %{
          patch: binary(),
          graded: [String.t()],
          new_tests: [String.t()],
          refused: [String.t()]
        }

  @doc "The roots a graded diff may touch."
  @spec allowed() :: [String.t()]
  def allowed, do: @allowed_roots ++ @allowed_files

  @doc """
  Collects the working tree's change against `base`, classified.

  `git add -N` first: an untracked file is in no diff at all, and a change the grader
  cannot see is a change it would grade as absent.
  """
  @spec collect(Path.t(), String.t()) :: {:ok, collected()} | {:error, String.t()}
  def collect(dir, base) do
    with {:ok, _out} <- Git.run(dir, ["add", "--intent-to-add", "--", "."]),
         {:ok, entries} <- Git.name_status(dir, base, nil, []) do
      classified = Enum.group_by(entries, &class(elem(&1, 0), elem(&1, 1)), &elem(&1, 1))
      graded = Enum.sort(Map.get(classified, :graded, []))

      case patch(dir, base, graded) do
        {:ok, patch} ->
          {:ok,
           %{
             patch: patch,
             graded: graded,
             new_tests: Enum.sort(Map.get(classified, :new_test, [])),
             refused: Enum.sort(Map.get(classified, :refused, []))
           }}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Every pre-existing path under `test/` whose **content** differs from `base`, plus the
  ones that are gone.

  By content, and never through the index: `git update-index --assume-unchanged` makes
  both `git status` and `git diff` forget a file that is sitting there modified, which the
  review proved against the previous check. Hashing the file answers the question the
  index was being asked. It also settles the false positive the previous check had — a new
  file that was staged and then edited reads as `AM`, which is not a modification of
  anything, because the path did not exist at `base` and so is not in this list at all.
  """
  @spec modified_tests(Path.t(), Path.t(), String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def modified_tests(repo, dir, base) do
    with {:ok, wanted} <- Git.blobs(repo, base, ["test"]) do
      {present, gone} =
        wanted
        |> Map.keys()
        |> Enum.sort()
        |> Enum.split_with(&File.regular?(Path.join(dir, &1)))

      case Git.hash_objects(dir, present) do
        {:ok, got} ->
          changed = Enum.filter(present, &(Map.get(got, &1) != Map.get(wanted, &1)))
          {:ok, Enum.sort(gone ++ changed)}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp class(status, path) do
    cond do
      harness?(path) -> :harness
      under_test?(path) and String.starts_with?(status, "A") -> :new_test
      under_test?(path) -> :modified_test
      allowed?(path) -> :graded
      true -> :refused
    end
  end

  # `deps/`, `_build/` and the two sealed helper directories are put into every tree by
  # `Bench.Self.Workspace`, not by the agent. `.gitignore` hides them at recent commits and
  # not at older ones, so at an older base they read as files somebody added — and a diff
  # that carried `priv/wasm/ouro-wasm` would fail to apply against a grading tree that was
  # handed the same binary. They are neither graded nor refused, because they are not the
  # agent's.
  defp harness?(path),
    do: Enum.any?(Bench.Self.Workspace.seeded(), &(path == &1 or String.starts_with?(path, &1 <> "/")))

  defp under_test?(path), do: path == "test" or String.starts_with?(path, "test/")

  defp allowed?(path),
    do: path in @allowed_files or Enum.any?(@allowed_roots, &String.starts_with?(path, &1))

  defp patch(_dir, _base, []), do: {:ok, ""}
  defp patch(dir, base, paths), do: Git.diff_binary(dir, base, paths)
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
      |> Enum.reduce_while({:ok, [], []}, fn dir, {:ok, acc, skipped} ->
        # A directory that holds no `task.json` is not a task — a scratch directory, a
        # `.DS_Store`'s parent, a half-written extraction. It is reported and passed over,
        # because refusing the whole corpus for it would make one stray directory the
        # reason a benchmark cannot run.
        if File.regular?(Path.join(dir, "task.json")) do
          case load(dir) do
            {:ok, task} -> {:cont, {:ok, [task | acc], skipped}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        else
          {:cont, {:ok, acc, [dir | skipped]}}
        end
      end)
      |> case do
        {:ok, tasks, skipped} ->
          Enum.each(Enum.reverse(skipped), &IO.puts(:stderr, "corpus  #{&1} holds no task.json; skipped"))
          filtered(Enum.reverse(tasks), filter)

        {:error, reason} ->
          {:error, reason}
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
    order =
      ~w(id base_sha commit_sha subject instruction instruction_kind hidden_tests
         solution_files timeout_secs measured)

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
