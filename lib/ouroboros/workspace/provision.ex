defmodule Ouroboros.Workspace.Provision do
  @moduledoc """
  Ships a pinned working-tree snapshot to a fleet node. Only repository identity,
  objects, commit IDs and bounded metadata cross distribution; source paths stay here.
  The target resolves and admits its own worktree when the child starts.
  """
  alias Ouroboros.Workspace.{Bundle, Git, Mirrors, Snapshot}

  @deadline_ms 600_000
  @chunk_timeout_ms 30_000

  def prepare(workspace, target, task_id, opts \\ []) do
    opts =
      Keyword.put(
        opts,
        :deadline,
        now() + bounded_option(opts, :provision_deadline_ms, @deadline_ms, @deadline_ms)
      )

    with {:ok, snapshot} <- Snapshot.commit(workspace, task_id, opts) do
      case ship(snapshot, target, opts) do
        {:ok, provision} ->
          {:ok, provision}

        {:error, reason} = error ->
          # Cleanup has its own small budget: using an expired transfer deadline here
          # would leave every timed-out attempt pinned forever without running Git.
          cleanup_opts = opts |> Keyword.delete(:deadline) |> Keyword.put(:timeout_ms, 5_000)

          case Snapshot.release(snapshot.root, task_id, cleanup_opts) do
            {:ok, _} -> error
            cleanup -> {:error, {:provision_cleanup_failed, reason, cleanup}}
          end
      end
    end
  end

  defp ship(snapshot, target, opts) do
    deadline = Keyword.fetch!(opts, :deadline)

    with {:ok, heads} <- rpc(target, Mirrors, :heads, [snapshot.repo_id], deadline, opts),
         {:ok, basis} <- common_heads(snapshot.root, heads, opts),
         {:ok, temporary} <- Git.temp_directory() do
      try do
        path = Path.join(temporary, "snapshot.bundle")

        with {:ok, _} <-
               Git.run(
                 snapshot.root,
                 [
                   "bundle",
                   "create",
                   path,
                   Snapshot.ref(snapshot.task_id) | Enum.map(basis, &("^" <> &1))
                 ],
                 opts
               ),
             {:ok, metadata} <-
               Bundle.metadata(
                 path,
                 snapshot.commit,
                 snapshot.task_id,
                 bounded_option(
                   opts,
                   :provision_max_bytes,
                   Bundle.max_bytes(),
                   Bundle.max_bytes()
                 )
               ),
             {:ok, token} <-
               rpc(
                 target,
                 Mirrors,
                 :begin_import,
                 [snapshot.repo_id, metadata, node()],
                 deadline,
                 opts
               ) do
          result =
            with :ok <- send_chunks(path, target, Mirrors, token, deadline, opts),
                 {:ok, _} <-
                   rpc(
                     target,
                     Mirrors,
                     :finish_import,
                     [token, snapshot.commit],
                     deadline,
                     opts,
                     260_000
                   ) do
              {:ok,
               %{
                 snapshot: snapshot,
                 repo_id: snapshot.repo_id,
                 commit: snapshot.commit,
                 task_id: snapshot.task_id,
                 bytes: metadata.bytes,
                 chunks: div(metadata.bytes + Bundle.chunk_bytes() - 1, Bundle.chunk_bytes()),
                 basis: basis,
                 source_node: node()
               }}
            end

          if match?({:error, _}, result),
            do: rpc(target, Mirrors, :cancel_import, [token], now() + 5_000, opts, 5_000)

          result
        end
      after
        File.rm_rf(temporary)
      end
    end
  end

  def remote_metadata(provision),
    do: Map.take(provision, [:repo_id, :commit, :task_id, :bytes, :chunks, :basis, :source_node])

  def instructions(provision) do
    snapshot = provision.snapshot

    "This is a snapshot of #{snapshot.name} at #{snapshot.commit} from machine #{node()}, " <>
      "taken #{snapshot.created_at}. Ignored files did not travel; install dependencies " <>
      "with the project's own commands before building. Commit your changes; uncommitted " <>
      "work is returned too. Put files to deliver in .ouroboros/deliver/.\n\n"
  end

  # Used by the return path too. Streaming holds only one bounded chunk in memory.
  def send_chunks(path, target, receiver, token, deadline, opts \\ []) do
    path
    |> File.stream!(Bundle.chunk_bytes())
    |> Enum.reduce_while({:ok, 0}, fn chunk, {:ok, offset} ->
      case rpc(target, receiver, :put_chunk, [token, offset, chunk], deadline, opts) do
        :ok -> {:cont, {:ok, offset + byte_size(chunk)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, _bytes} -> :ok
      error -> error
    end
  end

  def rpc(target, module, function, args, deadline, opts \\ [], timeout \\ @chunk_timeout_ms) do
    remaining = deadline - now()

    if remaining <= 0 do
      {:error, :provision_deadline_exceeded}
    else
      case Keyword.get(opts, :rpc) do
        rpc when is_function(rpc, 5) ->
          rpc.(target, module, function, args, min(timeout, remaining))

        _ ->
          :erpc.call(target, module, function, args, min(timeout, remaining))
      end
    end
  catch
    :error, {:exception, :undef, _} -> {:error, {:provisioning_unavailable, target}}
    :error, :undef -> {:error, {:provisioning_unavailable, target}}
    kind, reason -> {:error, {:provision_transport, target, kind, reason}}
  end

  defp common_heads(root, heads, opts) when is_list(heads) and length(heads) <= 64 do
    if Enum.all?(heads, &Git.valid_commit?/1) do
      {:ok,
       Enum.filter(heads, fn head ->
         match?({:ok, _}, Git.run(root, ["cat-file", "-e", head <> "^{commit}"], opts))
       end)}
    else
      {:error, :invalid_mirror_heads}
    end
  end

  defp common_heads(_, _, _), do: {:error, :invalid_mirror_heads}

  defp bounded_option(opts, key, default, ceiling) do
    case Keyword.get(opts, key, default) do
      n when is_integer(n) and n > 0 -> min(n, ceiling)
      _ -> default
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
