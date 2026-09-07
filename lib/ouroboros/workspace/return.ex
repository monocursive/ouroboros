defmodule Ouroboros.Workspace.Return do
  @moduledoc "Capture a provisioned child's committed and dirty work, return it, then retire safely."
  alias Ouroboros.Workspace.{Bundle, Deliveries, Git, Provision, Returns, Snapshot, Worktree}
  @deadline_ms 600_000

  def finish(worktree, provision, opts \\ []) do
    ceiling = System.monotonic_time(:millisecond) + @deadline_ms

    opts =
      opts
      |> Keyword.update(:deadline, ceiling, &min(&1, ceiling))
      |> Keyword.put_new(:deliver_max_bytes, delivery_limit())

    root = worktree["path"]

    with {:ok, snapshot} <-
           Snapshot.commit(
             root,
             provision.task_id,
             Keyword.merge(opts, return_snapshot: true, return_base: provision.commit)
           ),
         {:ok, deliveries} <- Deliveries.capture(root, provision.task_id, snapshot.commit, opts) do
      try do
        with {:ok, receipt} <- ship(snapshot, provision, deliveries, opts) do
          case Worktree.remove(
                 root,
                 Keyword.merge(opts, returned_snapshot: snapshot, return_receipt: receipt)
               ) do
            {:ok, :removed} ->
              {:ok, receipt, Map.put(worktree, "retired", "removed")}

            other ->
              {:ok,
               Map.put(
                 receipt,
                 :return_error,
                 "Changes reached the parent, but the worktree was kept at #{root}: #{inspect(other)}"
               ), Map.put(worktree, "retired", "kept")}
          end
        end
      after
        File.rm_rf(deliveries.temporary)
      end
    end
  catch
    kind, reason -> {:error, {:return_failed, kind, reason}}
  end

  defp delivery_limit do
    case Application.get_env(:ouroboros, :deliver_max_bytes) do
      n when is_integer(n) and n > 0 -> min(n, Deliveries.max_bytes())
      _ -> Deliveries.max_bytes()
    end
  end

  defp ship(snapshot, provision, deliveries, opts) do
    with {:ok, temporary} <- Git.temp_directory() do
      try do
        bundle = Path.join(temporary, "return.bundle")

        with {:ok, _} <-
               Git.run(
                 snapshot.root,
                 [
                   "bundle",
                   "create",
                   bundle,
                   Snapshot.ref(snapshot.task_id),
                   "^" <> provision.commit
                 ],
                 opts
               ),
             {:ok, metadata} <- Bundle.metadata(bundle, snapshot.commit, snapshot.task_id),
             :ok <- upload(bundle, :bundle, metadata, provision, opts),
             :ok <- upload_deliveries(deliveries, provision, opts),
             {:ok, receipt} <-
               Provision.rpc(
                 provision.source_node,
                 Returns,
                 :acknowledge,
                 [provision.return_token, snapshot.commit, deliveries.files],
                 Keyword.fetch!(opts, :deadline),
                 opts,
                 260_000
               ) do
          {:ok, receipt}
        end
      after
        File.rm_rf(temporary)
      end
    end
  end

  defp upload_deliveries(%{metadata: nil}, _provision, _opts), do: :ok

  defp upload_deliveries(deliveries, provision, opts),
    do: upload(deliveries.path, :deliveries, deliveries.metadata, provision, opts)

  defp upload(path, kind, metadata, provision, opts) do
    target = provision.source_node
    deadline = Keyword.fetch!(opts, :deadline)

    with {:ok, token} <- begin_import(provision, kind, metadata, deadline, opts, 25) do
      result =
        with :ok <- Provision.send_chunks(path, target, Returns, token, deadline, opts),
             {:ok, _} <-
               Provision.rpc(
                 target,
                 Returns,
                 :finish_import,
                 [token, metadata.commit],
                 deadline,
                 opts,
                 260_000
               ),
             do: :ok

      if match?({:error, _}, result),
        do: Provision.rpc(target, Returns, :cancel_import, [token], deadline, opts)

      result
    end
  end

  defp begin_import(provision, kind, metadata, deadline, opts, delay) do
    case Provision.rpc(
           provision.source_node,
           Returns,
           :begin_import,
           [provision.return_token, kind, metadata],
           deadline,
           opts
         ) do
      {:error, :return_repository_busy} ->
        remaining = deadline - System.monotonic_time(:millisecond)

        if remaining > 0 do
          Process.sleep(min(delay, remaining))
          begin_import(provision, kind, metadata, deadline, opts, min(delay * 2, 500))
        else
          {:error, :provision_deadline_exceeded}
        end

      result ->
        result
    end
  end
end
