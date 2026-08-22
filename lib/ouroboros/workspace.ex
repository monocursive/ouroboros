defmodule Ouroboros.Workspace do
  @moduledoc """
  Safe, node-local workspace admission for coding tasks.

  Configure one or more existing `:allowed_roots`, then acquire either an
  `:exclusive` or `:shared_read` lease before starting a coding run. All roots
  are resolved component-by-component, including symbolic links, before the
  allow-list and conflict checks are applied.

  Git worktree creation is intentionally outside this component, and now lives in
  `Ouroboros.Workspace.Worktree`: it creates a worktree without shell interpolation,
  the resulting directory is verified here through the same canonicalisation and
  allow-list as any other root, its lease is acquired here, and cleanup is a separate
  recoverable operation with its own marker and boot-time reconcile. Admission still
  never mutates a repository — the provisioner does, before admission is asked.

  This manager is node-local. Deployments sharing a filesystem across BEAM
  nodes must route admission through one authority or add distributed
  consensus; Erlang distribution alone does not make these leases global.
  """

  alias Ouroboros.Workspace.{Lease, Manager}

  @type server :: GenServer.server()

  @doc "Starts a supervised workspace lease manager."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ [])

  def start_link(opts) when is_list(opts) do
    if Keyword.keyword?(opts),
      do: Manager.start_link(opts),
      else: {:error, {:invalid_workspace_options, opts}}
  end

  def start_link(opts), do: {:error, {:invalid_workspace_options, opts}}

  @doc false
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    opts
    |> Manager.child_spec()
    |> Map.put(:start, {__MODULE__, :start_link, [Keyword.delete(opts, :id)]})
  end

  @doc "Canonicalizes and authorizes an existing directory without leasing it."
  @spec validate_root(String.t(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def validate_root(root, opts \\ []) do
    with :ok <- validate_options(opts, [:server]) do
      GenServer.call(server(opts), {:validate_root, root})
    end
  end

  @doc """
  Acquires a lease owned by the calling process.

  The returned capability may be held by a recovery/coordinator process to
  release the lease on the owner's behalf. It is never returned by inspection
  APIs and the manager stores only its SHA-256 digest.
  """
  @spec acquire(String.t(), String.t(), keyword()) ::
          {:ok, Ouroboros.Workspace.Lease.t(), String.t()} | {:error, term()}
  def acquire(root, task_id, opts \\ []) do
    with :ok <- validate_options(opts, [:mode, :server]) do
      mode = Keyword.get(opts, :mode, :exclusive)
      GenServer.call(server(opts), {:acquire, root, task_id, mode, :generic})
    end
  end

  @doc false
  @spec acquire_managed(String.t(), String.t(), :coding | :interactive, keyword()) ::
          {:ok, Ouroboros.Workspace.Lease.t(), String.t()} | {:error, term()}
  def acquire_managed(root, task_id, kind, opts \\ []) do
    with true <-
           kind in [:coding, :interactive] || {:error, {:invalid_workspace_owner_kind, kind}},
         :ok <- validate_options(opts, [:mode, :server]) do
      mode = Keyword.get(opts, :mode, :exclusive)
      GenServer.call(server(opts), {:acquire, root, task_id, mode, kind})
    end
  end

  @doc """
  Releases a lease.

  Repeated release is idempotent for its original owner or a holder of the
  capability. Other callers receive `{:error, :not_lease_owner}`.
  """
  @spec release(String.t() | Ouroboros.Workspace.Lease.t(), keyword()) ::
          :ok | {:error, term()}
  def release(lease_or_id, opts \\ []) do
    with :ok <- validate_options(opts, [:capability, :server]),
         {:ok, lease_id} <- lease_id(lease_or_id) do
      capability = Keyword.get(opts, :capability)
      GenServer.call(server(opts), {:release, lease_id, capability})
    end
  end

  @doc "Returns active or recently released status without exposing PIDs or capabilities."
  @spec status(String.t() | Ouroboros.Workspace.Lease.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def status(lease_or_id, opts \\ []) do
    with :ok <- validate_options(opts, [:server]),
         {:ok, lease_id} <- lease_id(lease_or_id) do
      GenServer.call(server(opts), {:status, lease_id})
    end
  end

  @doc "Lists active leases as durable-facing maps."
  @spec list(keyword()) :: [map()] | {:error, term()}
  def list(opts \\ []) do
    with :ok <- validate_options(opts, [:server]) do
      GenServer.call(server(opts), :list)
    end
  end

  @doc "Returns allowed roots and active leases for diagnostics."
  @spec summary(keyword()) :: map() | {:error, term()}
  def summary(opts \\ []) do
    with :ok <- validate_options(opts, [:server]) do
      GenServer.call(server(opts), :summary)
    end
  end

  @doc "Acquires a lease for the duration of a function and always releases it."
  @spec with_lease(String.t(), String.t(), keyword(), (map() -> result)) ::
          result | {:error, term()}
        when result: var
  def with_lease(root, task_id, opts \\ [], fun) when is_function(fun, 1) do
    case acquire(root, task_id, opts) do
      {:ok, lease, capability} ->
        try do
          fun.(lease)
        after
          release_opts = [server: server(opts), capability: capability]
          _ = release(lease, release_opts)
        end

      {:error, _reason} = error ->
        error
    end
  end

  defp validate_options(opts, allowed) when is_list(opts) do
    if Keyword.keyword?(opts) do
      case Keyword.keys(opts) -- allowed do
        [] -> :ok
        [unknown | _] -> {:error, {:unknown_workspace_option, unknown}}
      end
    else
      {:error, {:invalid_workspace_options, opts}}
    end
  end

  defp validate_options(opts, _allowed), do: {:error, {:invalid_workspace_options, opts}}

  defp lease_id(id) when is_binary(id) and byte_size(id) > 0, do: {:ok, id}
  defp lease_id(%Lease{id: id}) when is_binary(id) and byte_size(id) > 0, do: {:ok, id}
  defp lease_id(value), do: {:error, {:invalid_workspace_lease, value}}

  defp server(opts), do: Keyword.get(opts, :server, Manager)
end
