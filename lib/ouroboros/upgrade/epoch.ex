defmodule Ouroboros.Upgrade.Epoch do
  @moduledoc """
  Allocates the monotonic epoch a new artifact will carry.

  A node executor accepts an artifact only if its epoch is strictly greater than the last
  epoch that node committed, and it decides that before it inspects the artifact at all.
  The epoch is therefore the cluster's replay defence: an old artifact re-presented later
  is refused for its number, whatever its bytes say.

  `next/2` reads `last_epoch` from every target node's executor, takes the maximum, and
  allocates one above it. Two things make that safe against this process dying:

    * the allocation is written to durable storage *before* it is returned, and the next
      allocation starts above that watermark even when the nodes report something lower.
      A forge that crashes between allocating an epoch and using it burns the number
      rather than reissuing it. Numbers are cheap; a repeated one is a replay window.
    * a node whose status cannot be read is a refusal, not a zero. An unreachable node
      may hold a higher epoch than any node that answered, so allocating above what the
      reachable subset reports would produce a number that node will reject.

  `:global.trans/2` serializes concurrent allocations across a connected cluster. It is
  not partition-safe, and the durable watermark is per-forge-node, so two partitioned
  forges can allocate the same number. The defence that does not depend on coordination
  is on the target: `NodeExecutor.prepare/2` rejects a stale or repeated epoch outright.

  Storage comes from `config :ouroboros, :epoch_storage` — ETS in dev and test, a synced
  `Ouroboros.Storage.DurableFile` in production. With an ETS adapter the watermark dies
  with the VM, which is exactly the property production configuration removes.
  """

  alias Ouroboros.Upgrade.Coordinator

  @storage_key {:ouroboros, :forge_epoch, 1}
  @lock_retries 20

  @doc """
  Allocates the next epoch for a deployment to `nodes`.

  Options: `:storage` (an explicit `{adapter, opts}` pair), `:status_timeout`, and
  `:lock_retries`.
  """
  @spec next([node()], keyword()) :: {:ok, pos_integer()} | {:error, term()}
  def next(nodes, opts \\ [])

  def next([_ | _] = nodes, opts) when is_list(opts) do
    with {:ok, storage} <- storage(opts) do
      allocate(nodes, storage, opts)
    end
  end

  def next(nodes, _opts), do: {:error, {:invalid_nodes, nodes}}

  @doc "Returns the durable allocation watermark without allocating anything."
  @spec watermark(keyword()) :: {:ok, non_neg_integer()} | {:error, term()}
  def watermark(opts \\ []) do
    with {:ok, storage} <- storage(opts) do
      read_watermark(storage)
    end
  end

  defp allocate(nodes, storage, opts) do
    locked(opts, fn ->
      with {:ok, observed} <- cluster_epoch(nodes, opts),
           {:ok, persisted} <- read_watermark(storage) do
        epoch = max(observed, persisted) + 1

        case write_watermark(storage, epoch) do
          :ok -> {:ok, epoch}
          {:error, reason} -> {:error, {:epoch_persist_failed, reason}}
        end
      end
    end)
  end

  # The lock is cluster-wide but best-effort; failing to take it within a bounded number
  # of retries is reported rather than downgraded into an unserialized allocation, and
  # bounded retries are what keep a stuck holder from hanging a forge forever.
  defp locked(opts, fun) do
    retries = Keyword.get(opts, :lock_retries, @lock_retries)

    case :global.trans({__MODULE__, :allocation}, fun, [node() | Node.list()], retries) do
      :aborted -> {:error, :epoch_lock_unavailable}
      result -> result
    end
  end

  defp cluster_epoch(nodes, opts) do
    status_opts =
      case Keyword.fetch(opts, :status_timeout) do
        {:ok, timeout} -> [status_timeout: timeout]
        :error -> []
      end

    case Coordinator.status(nodes, status_opts) do
      {:ok, statuses} -> highest_epoch(statuses)
      {:error, statuses} -> {:error, {:epoch_status_unavailable, unreadable(statuses)}}
    end
  end

  defp highest_epoch(statuses) do
    Enum.reduce_while(statuses, {:ok, 0}, fn {target, status}, {:ok, highest} ->
      case Map.get(status, :last_epoch) do
        epoch when is_integer(epoch) and epoch >= 0 -> {:cont, {:ok, max(highest, epoch)}}
        other -> {:halt, {:error, {:invalid_node_epoch, target, other}}}
      end
    end)
  end

  defp unreadable(statuses) do
    for {target, value} <- statuses, not is_map(value), into: %{}, do: {target, value}
  end

  defp read_watermark(%{adapter: adapter, opts: opts}) do
    case adapter_call(adapter, :get_checkpoint, [@storage_key, opts]) do
      :not_found -> {:ok, 0}
      {:ok, epoch} when is_integer(epoch) and epoch >= 0 -> {:ok, epoch}
      {:ok, invalid} -> {:error, {:corrupt_epoch_watermark, invalid}}
      {:error, reason} -> {:error, {:epoch_watermark_unreadable, reason}}
      other -> {:error, {:invalid_epoch_storage_response, other}}
    end
  end

  defp write_watermark(%{adapter: adapter, opts: opts}, epoch) do
    case adapter_call(adapter, :put_checkpoint, [@storage_key, epoch, opts]) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_epoch_storage_response, other}}
    end
  end

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, inspect(reason)}}
  end

  defp storage(opts) do
    configured =
      Keyword.get_lazy(opts, :storage, fn ->
        Application.get_env(
          :ouroboros,
          :epoch_storage,
          {Jido.Storage.ETS, table: :ouroboros_forge_epochs}
        )
      end)

    {adapter, adapter_opts} = Jido.Storage.normalize_storage(configured)

    if Keyword.keyword?(adapter_opts) do
      {:ok, %{adapter: adapter, opts: adapter_opts}}
    else
      {:error, :invalid_epoch_storage}
    end
  rescue
    _error -> {:error, :invalid_epoch_storage}
  catch
    _kind, _reason -> {:error, :invalid_epoch_storage}
  end
end
