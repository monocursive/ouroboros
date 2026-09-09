defmodule Ouroboros.Workspace.Worktree do
  @moduledoc """
  Git worktrees as session isolation, provisioned without a shell.

  `Ouroboros.Workspace`'s own note said a future provisioner "should create a worktree
  without shell interpolation, verify the resulting directory here, acquire its lease,
  and record cleanup as a separate recoverable operation." This is that provisioner, and
  it keeps all four promises literally.

  ## Never a shell string

  Every `git` invocation is an argv **list** passed to
  `Ouroboros.Provider.Native.Exec`. There is no interpolation into a command line, so a
  session id or workspace path containing `;`, `$(…)`, a newline, or a leading `-` is an
  argument and cannot become a command. The runner also bounds output, wall time, and the
  whole process group. `test/workspace_worktree_test.exs` asserts the exact argv list
  through an injectable runner, which is the only way that claim stays true after
  somebody edits this file. `git` itself is found on `PATH` and refused by name when it
  is absent, rather than being assumed.

  ## The layout

      <data_dir>/worktrees/<sha256(repository)[0..15]>/<session-id>

  The repository hash keeps two repositories with the same basename apart; the session id
  is validated as a directory name before it is joined, because it arrives from a caller.
  The created path is canonicalized with `Ouroboros.Workspace.Path` — symlinks resolved
  one segment at a time — before it is handed to the lease machinery, so every
  containment check in the runtime applies to the worktree and not to the string this
  module built.

  ## Cleanup is recoverable, and never destroys work

  A marker file under the worktree root lists every worktree this runtime created. On
  close, a worktree is removed **only when `git status --porcelain` inside it is empty**;
  a worktree with uncommitted changes is left on disk and the caller is told, in the
  terminal event, exactly where it is. `reconcile/1` at boot re-reads the marker, removes
  the clean strays a crash left behind, and reports the dirty ones instead of removing
  them. There is no code path in this module that deletes an uncommitted change.
  """

  alias Ouroboros.Workspace.Path, as: WorkspacePath
  alias Ouroboros.Provider.Native.Exec

  require Logger

  @marker "created.json"
  @marker_version 1
  @max_entries 500
  @git_timeout_ms 120_000
  @max_git_timeout_ms 600_000
  @session_id_regex ~r/\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/

  @typedoc "One provisioned worktree."
  @type t :: %{
          path: String.t(),
          root: String.t(),
          branch: String.t() | nil,
          base_commit: String.t(),
          repository: String.t(),
          session_id: String.t(),
          created_at: String.t(),
          node: String.t()
        }

  # ---------------------------------------------------------------- create

  @doc """
  Creates a detached worktree of `workspace` for `session_id`.

  Options:

    * `:require_clean` — refuse when the repository has uncommitted changes (default
      `false`; a dirty repository is a normal state to branch from, and refusing it by
      default would make the option useless for the case it exists for).
    * `:runner` — a two-argument function `(argv, cwd)` returning `{:ok, output}` or
      `{:error, {status, output}}`. Tests inject one; production uses `git` on `PATH`.
    * `:root` — the worktree root, default `<data_dir>/worktrees`.

  Returns `{:ok, worktree}` where `path` is the worktree's top directory and `root` is
  the directory the session should actually run in — the two differ when the workspace
  was a subdirectory of its repository, in which case the same relative subdirectory
  inside the worktree is the session's root.
  """
  @spec create(String.t(), String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def create(workspace, session_id, opts \\ []) do
    runner = runner(opts)

    with :ok <- validate_session_id(session_id),
         :ok <- ensure_git(not Keyword.has_key?(opts, :runner)),
         {:ok, repository} <- WorkspacePath.canonicalize(workspace),
         {:ok, toplevel} <- toplevel(runner, repository),
         {:ok, relative} <- inside(repository, toplevel),
         :ok <- check_clean(runner, toplevel, Keyword.get(opts, :require_clean, false)),
         {:ok, base_commit} <- head(runner, toplevel),
         {:ok, target} <- prepare_target(toplevel, session_id, opts),
         :ok <- add(runner, toplevel, target, base_commit),
         {:ok, canonical} <- canonicalize_created(target),
         {:ok, root} <- session_root(canonical, relative) do
      worktree = %{
        path: canonical,
        root: root,
        # `--detach` deliberately: a worktree that created a branch would leave a ref
        # behind after cleanup, and a session is not a branch. `nil` is the honest value
        # for "this worktree is on no branch", not a placeholder.
        branch: nil,
        base_commit: base_commit,
        repository: toplevel,
        session_id: session_id,
        created_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        node: Atom.to_string(node())
      }

      case record(worktree, opts) do
        :ok ->
          {:ok, worktree}

        {:error, reason} ->
          cleanup = cleanup_unrecorded(runner, canonical, toplevel)
          {:error, {:worktree_unrecorded, canonical, reason, cleanup}}
      end
    end
  end

  # ---------------------------------------------------------------- planes

  @doc "Creates a recorded detached worktree from a node-owned bare mirror."
  def create_detached(repository, commit, session_id, opts \\ []) do
    base_runner = runner(opts)

    runner = fn args, cwd ->
      base_runner.(["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false" | args], cwd)
    end

    with :ok <- validate_session_id(session_id),
         true <- Ouroboros.Workspace.Git.valid_commit?(commit),
         true <- admissible?(opts),
         {:ok, repository} <- WorkspacePath.canonicalize(repository),
         {:ok, target} <- prepare_target(repository, session_id, opts),
         :ok <- add(runner, repository, target, commit),
         {:ok, canonical} <- canonicalize_created(target) do
      worktree = %{
        path: canonical,
        root: canonical,
        branch: nil,
        base_commit: commit,
        repository: repository,
        session_id: session_id,
        created_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        node: Atom.to_string(node()),
        provisioned: true,
        repo_id: Keyword.get(opts, :repo_id),
        source_node: Keyword.get(opts, :source_node),
        git_dir: Ouroboros.Workspace.Access.recorded_git_dir(canonical, repository)
      }

      case record(worktree, opts) do
        :ok -> {:ok, worktree}
        {:error, reason} -> {:error, {:worktree_unrecorded, canonical, reason, :retained}}
      end
    else
      false -> {:error, :detached_worktree_not_admitted}
      error -> error
    end
  end

  @doc """
  Provisions a worktree for a session or task record that asked for one.

  Takes any map carrying `:workspace`, `:worktree_requested` and `:worktree` — the shape
  `Ouroboros.Interactive.State` has — and returns it with `:workspace` pointing at the
  worktree and `:worktree` recording what was made.
  A record that did not ask, or that already has one, is returned unchanged: this runs on
  every admission, including the one after a restart, and re-provisioning there would
  strand the directory the session was already working in.

  The provider never learns any of this. It receives a `cwd`, and the value of that `cwd`
  is the only thing that changed.
  """
  @spec provision(map(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def provision(%{worktree: existing} = record, _session_id, _opts) when is_map(existing),
    do: {:ok, record}

  def provision(%{worktree_requested: true, workspace: workspace} = record, session_id, opts) do
    if admissible?(opts) do
      case create(workspace, session_id, opts) do
        {:ok, worktree} ->
          {:ok, %{record | workspace: worktree.root, worktree: public(worktree)}}

        {:error, _reason} = error ->
          error
      end
    else
      {:error,
       {:worktree_root_not_admitted, root(opts),
        "add it to `workspace_allowed_roots` (OUROBOROS_WORKSPACE_ROOTS) so a worktree " <>
          "can be leased like any other directory"}}
    end
  end

  def provision(record, _session_id, _opts), do: {:ok, record}

  @doc """
  Retires the worktree a record holds, if it holds one.

  `:not_applicable` for a record with no worktree. Otherwise the same three answers
  `remove/2` gives, and the record comes back with the outcome recorded on it so a
  listing of a closed session still says where the work was left.
  """
  @spec retire(map(), keyword()) ::
          {:ok, map(), :removed | {:kept, term()}} | :not_applicable | {:error, term()}
  # Already retired. `terminate/2` runs after the terminal transition that retired it, so
  # without this a kept worktree would be reported twice on the session's own log.
  def retire(%{worktree: %{"retired" => retired}}, _opts) when is_binary(retired),
    do: :not_applicable

  def retire(%{worktree: %{"path" => path} = worktree} = record, opts) do
    target =
      case Map.get(worktree, "repository") do
        repository when is_binary(repository) -> %{path: path, repository: repository}
        _missing -> path
      end

    case remove(target, opts) do
      {:ok, :removed} ->
        {:ok, %{record | worktree: Map.put(worktree, "retired", "removed")}, :removed}

      {:ok, {:kept, reason}} ->
        retired =
          worktree
          |> Map.put("retired", "kept")
          |> Map.put("retained_reason", describe_reason(reason))

        {:ok, %{record | worktree: retired}, {:kept, reason}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def retire(_record, _opts), do: :not_applicable

  @doc "The durable, string-keyed projection of one worktree."
  @spec public(t()) :: map()
  def public(worktree) do
    %{
      "path" => worktree.path,
      "root" => worktree.root,
      "branch" => worktree.branch,
      "base_commit" => worktree.base_commit,
      "repository" => worktree.repository
    }
    |> Map.merge(
      Map.new([:provisioned, :repo_id, :source_node, :git_dir], fn key ->
        {Atom.to_string(key), Map.get(worktree, key)}
      end)
    )
  end

  defp describe_reason(:dirty), do: "uncommitted changes"
  defp describe_reason({:git_failed, output}), do: "git refused: #{output}"
  defp describe_reason(reason), do: inspect(reason)

  # ---------------------------------------------------------------- remove

  @doc """
  Removes a worktree, but only when it holds no uncommitted work.

  Returns `{:ok, :removed}`, or `{:ok, {:kept, reason}}` with the worktree still on disk.
  `reason` is `:dirty` for uncommitted changes — including untracked files — and
  `{:git_failed, output}` when `git worktree remove` itself refused. Neither is an error:
  a worktree kept because it holds work is the correct outcome, and the caller says so in
  its terminal event.
  """
  @spec remove(t() | String.t(), keyword()) ::
          {:ok, :removed} | {:ok, {:kept, term()}} | {:error, term()}
  def remove(worktree, opts \\ [])

  def remove(path, opts) when is_binary(path) do
    case find(path, opts) do
      nil -> {:error, {:unknown_worktree, path}}
      entry -> remove(entry, opts)
    end
  end

  def remove(%{path: path}, opts) do
    # Provenance comes from the durable marker, including through alternate path spellings.
    with {:ok, canonical} <- WorkspacePath.canonicalize(path),
         entry when is_map(entry) <- find(canonical, opts) || find(path, opts) do
      remove_recorded(entry, opts)
    else
      nil ->
        {:error, {:unknown_worktree, path}}

      {:error, _} ->
        if File.exists?(path),
          do: {:error, {:unknown_worktree, path}},
          else:
            (
              forget(path, opts)
              {:ok, :removed}
            )
    end
  end

  def remove(_worktree, _opts), do: {:error, :invalid_worktree}

  defp remove_recorded(%{path: path} = worktree, opts) do
    runner = runner(opts)

    cond do
      not File.dir?(path) ->
        _ = forget(path, opts)
        {:ok, :removed}

      Map.get(worktree, :provisioned, false) ->
        # A clean Git status does not mean remote work reached its parent: committed
        # child edits are clean too. Boot reconciliation must keep these as well.
        remove_returned(worktree, opts)

      dirty?(runner, path) ->
        {:ok, {:kept, :dirty}}

      true ->
        case runner.(["worktree", "remove", path], repository(worktree)) do
          {:ok, _output} ->
            _ = forget(path, opts)
            {:ok, :removed}

          {:error, {_status, output}} ->
            {:ok, {:kept, {:git_failed, String.trim(to_string(output))}}}
        end
    end
  end

  defp remove_returned(worktree, opts) do
    alias Ouroboros.Workspace.{Deliveries, Git, Snapshot}

    case {Keyword.get(opts, :returned_snapshot), Keyword.get(opts, :return_receipt)} do
      {%{commit: commit, tree: tree, head: head} = snapshot,
       %{acknowledged: true, returned_commit: commit, task_id: task_id, manifest: files}} ->
        verification_id = "verify-" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

        result =
          with true <- snapshot.root == worktree.path and task_id == worktree.session_id,
               {:ok, current} <-
                 Snapshot.commit(worktree.path, verification_id, return_snapshot: true),
               true <- current.tree == tree and current.head == head,
               {:ok, current_files} <- Deliveries.inventory(worktree.path),
               true <- current_files == files,
               {:ok, _} <-
                 Git.run(worktree.repository, [
                   "-c",
                   "core.hooksPath=/dev/null",
                   "worktree",
                   "remove",
                   "--force",
                   worktree.path
                 ]) do
            _ = forget(worktree.path, opts)
            _ = Snapshot.release(worktree.repository, task_id)
            {:ok, :removed}
          else
            false -> {:ok, {:kept, :changed_since_return}}
            {:error, reason} -> {:ok, {:kept, {:return_cleanup_failed, reason}}}
          end

        _ = Snapshot.release(worktree.repository, verification_id)
        result

      _ ->
        {:ok, {:kept, :awaiting_return}}
    end
  end

  # ---------------------------------------------------------------- reconcile

  @doc """
  Reconciles the marker with the filesystem at boot.

  Removes worktrees this runtime created that are now clean and unclaimed, reports the
  dirty ones without touching them, and forgets entries whose directory is gone. The
  report is the point: an operator who lost a machine mid-session is owed a list of the
  directories that still hold their work, not a tidy filesystem.
  """
  @spec reconcile(keyword()) :: %{
          removed: [String.t()],
          kept: [%{path: String.t(), reason: term()}],
          missing: [String.t()]
        }
  def reconcile(opts \\ []) do
    entries = list(opts)

    Enum.reduce(entries, %{removed: [], kept: [], missing: []}, fn entry, acc ->
      cond do
        not File.dir?(entry.path) ->
          _ = forget(entry.path, opts)
          %{acc | missing: acc.missing ++ [entry.path]}

        true ->
          case remove(entry, opts) do
            {:ok, :removed} ->
              %{acc | removed: acc.removed ++ [entry.path]}

            # Anything that is not a removal leaves the directory alone and is reported.
            # `remove/2` refuses rather than raises, so there is no third shape to handle.
            {:ok, {:kept, reason}} ->
              %{acc | kept: acc.kept ++ [%{path: entry.path, reason: reason}]}
          end
      end
    end)
  end

  # ---------------------------------------------------------------- marker

  @doc "Every worktree this runtime recorded, oldest first."
  @spec list(keyword()) :: [t()]
  def list(opts \\ []) do
    opts
    |> marker_path()
    |> read_marker()
  end

  @doc "One recorded worktree by path, or `nil`."
  @spec find(String.t(), keyword()) :: t() | nil
  def find(path, opts \\ []), do: Enum.find(list(opts), &(&1.path == path))

  @doc """
  The directory this node keeps worktrees under.

  `<data_dir>/worktrees` when this node has a data directory, and a directory under the
  system temp root when it does not — the same honest fallback
  `Ouroboros.Provider.Native.Paths` takes, with the same consequence stated: a worktree
  under the temp root does not survive a reboot, so `reconcile/1` may find nothing after
  one.
  """
  @spec root(keyword()) :: String.t()
  def root(opts \\ []) do
    Keyword.get_lazy(opts, :root, fn ->
      case Application.get_env(:ouroboros, :data_dir) do
        path when is_binary(path) and path != "" ->
          Elixir.Path.join(path, "worktrees")

        _unset ->
          Elixir.Path.join(System.tmp_dir!(), "ouroboros-worktrees-#{:erlang.phash2(node())}")
      end
    end)
  end

  @doc """
  Whether this node's workspace admission will accept a worktree at all.

  A worktree is leased through the same `Ouroboros.Workspace` machinery as any other
  directory, so the worktree root has to be inside `:workspace_allowed_roots`. When it is
  not, `create/3` still succeeds and the *lease* fails, which is a confusing place to
  learn it — so callers ask here first and refuse with a sentence naming the fix.
  """
  @spec admissible?(keyword()) :: boolean()
  def admissible?(opts \\ []) do
    roots = Application.get_env(:ouroboros, :workspace_allowed_roots, [])
    candidate = canonical_or_literal(root(opts))

    Enum.any?(roots, fn allowed ->
      case WorkspacePath.canonicalize(allowed) do
        {:ok, canonical} -> is_binary(candidate) and WorkspacePath.within?(candidate, canonical)
        {:error, _reason} -> false
      end
    end)
  end

  # Resolve the existing ancestor when the first worktree directory has not yet been
  # created. Comparing a literal /var path with its canonical /private/var grant would
  # otherwise refuse a correctly configured fresh Mac. Unreadable paths and symlink
  # errors still fail closed; only a missing directory can use this future path.
  defp canonical_or_literal(path) do
    case WorkspacePath.canonicalize(path) do
      {:ok, canonical} ->
        canonical

      {:error, _reason} ->
        case File.lstat(path) do
          {:error, :enoent} ->
            parent = Elixir.Path.dirname(path)

            if parent != path do
              case canonical_or_literal(parent) do
                canonical when is_binary(canonical) ->
                  Elixir.Path.join(canonical, Elixir.Path.basename(path))

                _ ->
                  nil
              end
            end

          _ ->
            nil
        end
    end
  end

  # ---------------------------------------------------------------- git

  # Only the real runner needs `git` on `PATH`. An injected runner is the test's own
  # function and answering "git is missing" for it would be a false refusal.
  defp ensure_git(false), do: :ok

  defp ensure_git(true) do
    if System.find_executable("git"),
      do: :ok,
      else: {:error, {:git_unavailable, "git was not found on PATH"}}
  end

  # `git rev-parse --show-toplevel` is the whole repository check: it fails outside a
  # working tree and answers the repository root inside one, including inside another
  # worktree — which is why a worktree of a worktree is allowed rather than special-cased.
  defp toplevel(runner, repository) do
    case runner.(["rev-parse", "--show-toplevel"], repository) do
      {:ok, output} ->
        case output |> to_string() |> String.trim() do
          "" -> {:error, {:not_a_git_repository, repository}}
          path -> WorkspacePath.canonicalize(path)
        end

      {:error, _reason} ->
        {:error, {:not_a_git_repository, repository}}
    end
  end

  defp inside(repository, toplevel) do
    cond do
      repository == toplevel -> {:ok, ""}
      WorkspacePath.within?(repository, toplevel) -> {:ok, relative(repository, toplevel)}
      true -> {:error, {:workspace_outside_repository, repository, toplevel}}
    end
  end

  defp check_clean(_runner, _toplevel, false), do: :ok

  defp check_clean(runner, toplevel, true) do
    if dirty?(runner, toplevel),
      do: {:error, {:repository_dirty, toplevel}},
      else: :ok
  end

  # `--porcelain` includes untracked files, which is deliberate: an untracked file a
  # session created is uncommitted work, and a cleanup that ignored it would delete it.
  defp dirty?(runner, path) do
    case runner.(["status", "--porcelain"], path) do
      {:ok, output} -> output |> to_string() |> String.trim() != ""
      # A status this module cannot read is treated as dirty. Failing closed here means
      # the worst case is a directory left behind, not work destroyed.
      {:error, _reason} -> true
    end
  end

  defp head(runner, toplevel) do
    case runner.(["rev-parse", "HEAD"], toplevel) do
      {:ok, output} ->
        case output |> to_string() |> String.trim() do
          "" -> {:error, {:no_head_commit, toplevel}}
          commit -> {:ok, commit}
        end

      {:error, {_status, output}} ->
        {:error, {:no_head_commit, toplevel, String.trim(to_string(output))}}
    end
  end

  defp add(runner, toplevel, target, base_commit) do
    case runner.(["worktree", "add", "--detach", target, base_commit], toplevel) do
      {:ok, _output} ->
        :ok

      {:error, {_status, output}} ->
        {:error, {:worktree_add_failed, String.trim(to_string(output))}}
    end
  end

  # The one place a real `git` is spawned. `Exec.run/3` preserves argv boundaries,
  # bounds output and time, and reaps the whole process group on expiry.
  defp run_git(args, cwd, timeout_ms) when is_list(args) and is_binary(cwd) do
    case Exec.run("git", args, cd: cwd, timeout_ms: timeout_ms) do
      {:ok, %{timed_out?: true, output: output}} ->
        {:error, {124, "git timed out after #{timeout_ms} ms\n" <> output}}

      {:ok, %{status: 0, output: output}} ->
        {:ok, output}

      {:ok, %{status: status, output: output}} ->
        {:error, {status, output}}

      {:error, reason} ->
        {:error, {127, "git unavailable: #{inspect(reason)}"}}
    end
  end

  defp runner(opts) do
    case Keyword.get(opts, :runner) do
      runner when is_function(runner, 2) ->
        runner

      _default ->
        timeout =
          case Keyword.get(opts, :git_timeout_ms, @git_timeout_ms) do
            value when is_integer(value) and value > 0 -> min(value, @max_git_timeout_ms)
            _invalid -> @git_timeout_ms
          end

        fn args, cwd -> run_git(args, cwd, timeout) end
    end
  end

  # ---------------------------------------------------------------- paths

  defp validate_session_id(id) when is_binary(id) do
    if Regex.match?(@session_id_regex, id) and ".." not in Elixir.Path.split(id),
      do: :ok,
      else: {:error, {:invalid_worktree_session_id, id}}
  end

  defp validate_session_id(id), do: {:error, {:invalid_worktree_session_id, inspect(id)}}

  defp prepare_target(toplevel, session_id, opts) do
    parent = Elixir.Path.join(root(opts), repository_tag(toplevel))
    target = Elixir.Path.join(parent, session_id)

    cond do
      File.exists?(target) ->
        {:error, {:worktree_exists, target}}

      true ->
        case File.mkdir_p(parent) do
          :ok ->
            _ = File.chmod(parent, 0o700)
            {:ok, target}

          {:error, reason} ->
            {:error, {:worktree_root_unavailable, parent, reason}}
        end
    end
  end

  defp repository_tag(toplevel) do
    :sha256
    |> :crypto.hash(toplevel)
    |> Base.url_encode64(padding: false)
    |> binary_part(0, 16)
  end

  defp canonicalize_created(target) do
    case WorkspacePath.canonicalize(target) do
      {:ok, canonical} -> {:ok, canonical}
      {:error, reason} -> {:error, {:worktree_unverifiable, target, reason}}
    end
  end

  defp session_root(worktree_path, ""), do: {:ok, worktree_path}

  defp session_root(worktree_path, relative) do
    case WorkspacePath.canonicalize(Elixir.Path.join(worktree_path, relative)) do
      {:ok, canonical} ->
        # Containment, restated rather than assumed: the session's root must be inside the
        # worktree this module just made, whatever the relative path or a symlink did.
        if WorkspacePath.within?(canonical, worktree_path),
          do: {:ok, canonical},
          else: {:error, {:worktree_subpath_escapes, canonical, worktree_path}}

      {:error, reason} ->
        {:error, {:worktree_subpath_missing, relative, reason}}
    end
  end

  defp repository(%{repository: repository}), do: repository

  defp relative(path, prefix),
    do: binary_part(path, byte_size(prefix) + 1, byte_size(path) - byte_size(prefix) - 1)

  # ---------------------------------------------------------------- marker io

  defp marker_path(opts), do: Elixir.Path.join(root(opts), @marker)

  defp record(worktree, opts) do
    update_marker(opts, fn entries ->
      entries
      |> Enum.reject(&(&1.path == worktree.path))
      |> Kernel.++([worktree])
      |> Enum.take(-@max_entries)
    end)
  end

  defp cleanup_unrecorded(runner, path, repository) do
    case runner.(["worktree", "remove", path], repository) do
      {:ok, _output} -> :removed
      {:error, reason} -> {:retained, reason}
    end
  rescue
    error -> {:retained, {:cleanup_failed, Exception.message(error)}}
  catch
    kind, reason -> {:retained, {:cleanup_failed, kind, reason}}
  end

  defp forget(path, opts) do
    update_marker(opts, fn entries -> Enum.reject(entries, &(&1.path == path)) end)
  end

  # The marker is a recoverable index shared by every session owner on this node.
  # `:global.trans` serializes the read-modify-write boundary; without it concurrent
  # creates each read the same old list and the last rename silently drops the others.
  defp update_marker(opts, fun) do
    path = marker_path(opts)

    case :global.trans(
           {{__MODULE__, path}, self()},
           fn -> write_marker(path, fun) end,
           [node()],
           20
         ) do
      :aborted ->
        {:error, :worktree_marker_lock_unavailable}

      result ->
        result
    end
  end

  defp write_marker(path, fun) do
    with :ok <- File.mkdir_p(Elixir.Path.dirname(path)),
         {:ok, current} <- read_marker_for_update(path),
         entries = fun.(current),
         {:ok, json} <-
           encode_json(%{
             "version" => @marker_version,
             "updated_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
             "worktrees" => Enum.map(entries, &encode/1)
           }) do
      temporary =
        path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

      try do
        with :ok <- File.write(temporary, "", [:exclusive, :sync]),
             :ok <- File.chmod(temporary, 0o600),
             :ok <- File.write(temporary, json, [:binary, :sync]),
             :ok <- File.rename(temporary, path),
             :ok <- sync_directory(Elixir.Path.dirname(path)) do
          :ok
        end
      after
        _ = File.rm(temporary)
      end
    else
      {:error, reason} ->
        Logger.warning("worktree marker write failed: #{inspect(reason)}")
        {:error, {:worktree_marker_write_failed, reason}}
    end
  end

  defp read_marker_for_update(path) do
    case File.read(path) do
      {:error, :enoent} ->
        {:ok, []}

      {:ok, json} ->
        case decode_json(json) do
          {:ok, %{"version" => @marker_version, "worktrees" => list}} when is_list(list) ->
            {:ok, Enum.flat_map(list, &decode/1)}

          _invalid ->
            {:error, :worktree_marker_corrupt}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp sync_directory(directory) do
    with {:ok, device} <- :file.open(String.to_charlist(directory), [:read, :raw, :directory]) do
      result = :file.sync(device)
      close = :file.close(device)

      case {result, close} do
        {:ok, :ok} -> :ok
        {{:error, reason}, _} -> {:error, {:directory_sync_failed, reason}}
        {:ok, {:error, reason}} -> {:error, {:directory_close_failed, reason}}
      end
    end
  end

  defp read_marker(path) do
    with {:ok, json} <- File.read(path),
         {:ok, %{"version" => @marker_version, "worktrees" => list}} when is_list(list) <-
           decode_json(json) do
      Enum.flat_map(list, &decode/1)
    else
      _absent_or_corrupt -> []
    end
  end

  defp encode_json(payload) do
    {:ok, JSON.encode!(payload)}
  rescue
    error -> {:error, {:worktree_marker_unencodable, Exception.message(error)}}
  end

  defp decode_json(json) do
    {:ok, JSON.decode!(json)}
  rescue
    _error -> {:error, :worktree_marker_corrupt}
  end

  defp encode(worktree) do
    %{
      "path" => worktree.path,
      "root" => worktree.root,
      "branch" => worktree.branch,
      "base_commit" => worktree.base_commit,
      "repository" => worktree.repository,
      "session_id" => worktree.session_id,
      "created_at" => worktree.created_at,
      "node" => worktree.node
    }
    |> Map.merge(
      Map.new([:provisioned, :repo_id, :source_node, :git_dir], fn key ->
        {Atom.to_string(key), Map.get(worktree, key)}
      end)
    )
  end

  defp decode(%{"path" => path, "repository" => repository} = entry)
       when is_binary(path) and is_binary(repository) do
    [
      %{
        path: path,
        root: Map.get(entry, "root", path),
        branch: Map.get(entry, "branch"),
        base_commit: Map.get(entry, "base_commit", ""),
        repository: repository,
        session_id: Map.get(entry, "session_id", ""),
        created_at: Map.get(entry, "created_at", ""),
        node: Map.get(entry, "node", ""),
        provisioned: Map.get(entry, "provisioned", false),
        repo_id: Map.get(entry, "repo_id"),
        source_node: Map.get(entry, "source_node"),
        git_dir: Map.get(entry, "git_dir")
      }
    ]
  end

  defp decode(_entry), do: []
end
