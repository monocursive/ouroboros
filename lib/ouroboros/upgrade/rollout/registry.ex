defmodule Ouroboros.Upgrade.Rollout.Registry do
  @moduledoc """
  The durable deployment-level record of every capability this cluster has forged.

  Node executors journal what one node did. This registry journals what the *rollout*
  intended and what became of it, on the node that drove it. It is written before the
  mutation it describes, in the same order every other store in this codebase uses: the
  `:deploying` checkpoint is durable before `Coordinator.deploy/3` is called, so a forge
  that dies mid-rollout leaves evidence that a rollout was in flight instead of leaving a
  capability nobody remembers deploying.

  Four states, and the difference between the last two is the whole point:

    * `:deploying` - checkpointed, outcome not yet known. A `:deploying` entry found at
      startup means a rollout was interrupted and its nodes must be inspected.
    * `:live` - committed and health-checked on every target.
    * `:rolled_back` - every target proved it compensated. Only proof earns this state.
    * `:quarantined` - the outcome is ambiguous somewhere. A node that never answered
      may be running the code; saying "rolled back" here would be a claim nobody made.

  A quarantined entry has no automatic exit. Clearing it means reconciling the nodes
  themselves through `NodeExecutor.reconcile_quarantine/1` and deciding, as an operator,
  what the cluster is actually running.

  Storage comes from `config :ouroboros, :capability_storage`: ETS in dev and test, a
  synced `Ouroboros.Storage.DurableFile` in production. As with every other store here,
  ETS means the record dies with the VM, and the durability level is reported rather
  than assumed.
  """

  use GenServer

  @store_key {:ouroboros, :capability_rollouts, 1}
  @checkpoint_version 1
  @states [:deploying, :live, :rolled_back, :quarantined]
  @default_limit 200

  @transitions %{
    deploying: [:live, :rolled_back, :quarantined],
    live: [:rolled_back, :quarantined],
    rolled_back: [:quarantined],
    quarantined: []
  }

  defmodule Entry do
    @moduledoc "One capability rollout and everything known about its outcome."

    @enforce_keys [:artifact_id, :module, :epoch, :nodes, :state, :created_at, :updated_at]
    defstruct @enforce_keys ++ [source_sha256: nil, test_report: %{}, detail: nil]

    @type state :: :deploying | :live | :rolled_back | :quarantined
    @type t :: %__MODULE__{
            artifact_id: String.t(),
            module: module(),
            epoch: pos_integer(),
            nodes: [node()],
            state: state(),
            source_sha256: String.t() | nil,
            test_report: map(),
            detail: term(),
            created_at: String.t(),
            updated_at: String.t()
          }
  end

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Checkpoints the intent to deploy a capability, before anything is mutated.

  Requires `:artifact_id`, `:module`, `:epoch`, and `:nodes`; accepts `:source_sha256`
  and `:test_report`.
  """
  @spec deploying(keyword() | map(), GenServer.server()) :: {:ok, Entry.t()} | {:error, term()}
  def deploying(attrs, server \\ __MODULE__) do
    GenServer.call(server, {:deploying, Map.new(attrs)})
  end

  @doc "Moves a rollout to a new state, refusing transitions that would lose information."
  @spec mark(String.t(), Entry.state(), keyword(), GenServer.server()) ::
          {:ok, Entry.t()} | {:error, term()}
  def mark(artifact_id, state, opts \\ [], server \\ __MODULE__)
      when is_binary(artifact_id) and is_atom(state) and is_list(opts) do
    GenServer.call(server, {:mark, artifact_id, state, Keyword.get(opts, :detail)})
  end

  @spec get(String.t(), GenServer.server()) :: {:ok, Entry.t()} | :not_found
  def get(artifact_id, server \\ __MODULE__) when is_binary(artifact_id) do
    GenServer.call(server, {:get, artifact_id})
  end

  @spec list(GenServer.server()) :: [Entry.t()]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc "Returns every rollout for one capability module, oldest first."
  @spec history(module(), GenServer.server()) :: [Entry.t()]
  def history(module, server \\ __MODULE__) when is_atom(module) do
    server |> list() |> Enum.filter(&(&1.module == module))
  end

  @doc "Returns the rollouts currently believed to be live."
  @spec live(GenServer.server()) :: [Entry.t()]
  def live(server \\ __MODULE__), do: server |> list() |> Enum.filter(&(&1.state == :live))

  @type durability :: :ephemeral_checkpoint | :durable_checkpoint | :synced_checkpoint

  @spec durability(GenServer.server()) :: durability()
  def durability(server \\ __MODULE__), do: GenServer.call(server, :durability)

  @doc false
  def checkpoint_key, do: @store_key

  @impl true
  def init(opts) do
    with {:ok, storage} <- storage_config(opts),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage),
         {:ok, rollouts} <- load(adapter, adapter_opts) do
      {:ok,
       %{
         adapter: adapter,
         opts: adapter_opts,
         rollouts: rollouts,
         limit: limit(opts),
         durability: durability_level(adapter)
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:deploying, attrs}, _from, state) do
    with {:ok, entry} <- build_entry(attrs),
         :ok <- ensure_absent(state, entry.artifact_id) do
      persist(entry, state)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:mark, artifact_id, next, detail}, _from, state) do
    with {:ok, entry} <- fetch(state, artifact_id),
         :ok <- ensure_transition(entry.state, next) do
      persist(%{entry | state: next, detail: detail, updated_at: now()}, state)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:get, artifact_id}, _from, state) do
    case fetch(state, artifact_id) do
      {:ok, entry} -> {:reply, {:ok, entry}, state}
      {:error, _reason} -> {:reply, :not_found, state}
    end
  end

  def handle_call(:list, _from, state) do
    {:reply, state.rollouts |> Map.values() |> Enum.sort_by(& &1.created_at), state}
  end

  def handle_call(:durability, _from, state), do: {:reply, state.durability, state}

  defp build_entry(attrs) do
    with {:ok, artifact_id} <- fetch_binary(attrs, :artifact_id),
         {:ok, module} <- fetch_module(attrs),
         {:ok, epoch} <- fetch_epoch(attrs),
         {:ok, nodes} <- fetch_nodes(attrs) do
      timestamp = now()

      {:ok,
       %Entry{
         artifact_id: artifact_id,
         module: module,
         epoch: epoch,
         nodes: nodes,
         state: :deploying,
         source_sha256: Map.get(attrs, :source_sha256),
         test_report: Map.get(attrs, :test_report, %{}),
         created_at: timestamp,
         updated_at: timestamp
       }}
    end
  end

  defp ensure_absent(state, artifact_id) do
    if Map.has_key?(state.rollouts, artifact_id),
      do: {:error, {:already_recorded, artifact_id}},
      else: :ok
  end

  defp fetch(state, artifact_id) do
    case Map.fetch(state.rollouts, artifact_id) do
      {:ok, entry} -> {:ok, entry}
      :error -> {:error, {:unknown_rollout, artifact_id}}
    end
  end

  defp ensure_transition(from, to) do
    cond do
      to not in @states -> {:error, {:invalid_state, to}}
      to in Map.get(@transitions, from, []) -> :ok
      true -> {:error, {:invalid_transition, from, to}}
    end
  end

  # The effect this registry describes happens after its checkpoint, so a failed write is
  # reported without touching in-memory state: the caller must not proceed.
  defp persist(entry, state) do
    rollouts = state.rollouts |> Map.put(entry.artifact_id, entry) |> prune(state.limit)

    case adapter_call(state.adapter, :put_checkpoint, [
           @store_key,
           checkpoint(rollouts),
           state.opts
         ]) do
      :ok -> {:reply, {:ok, entry}, %{state | rollouts: rollouts}}
      {:error, reason} -> {:reply, {:error, {:rollout_checkpoint_failed, reason}}, state}
      other -> {:reply, {:error, {:invalid_rollout_storage_response, other}}, state}
    end
  end

  # Growth is bounded by dropping the oldest *settled* rollbacks only. A `:deploying`,
  # `:live`, or `:quarantined` entry is unfinished business and is never discarded to make
  # room for history.
  defp prune(rollouts, limit) when map_size(rollouts) <= limit, do: rollouts

  defp prune(rollouts, limit) do
    droppable =
      rollouts
      |> Map.values()
      |> Enum.filter(&(&1.state == :rolled_back))
      |> Enum.sort_by(& &1.updated_at)

    Enum.reduce_while(droppable, rollouts, fn entry, acc ->
      if map_size(acc) > limit do
        {:cont, Map.delete(acc, entry.artifact_id)}
      else
        {:halt, acc}
      end
    end)
  end

  defp checkpoint(rollouts), do: %{version: @checkpoint_version, rollouts: rollouts}

  defp load(adapter, adapter_opts) do
    case adapter_call(adapter, :get_checkpoint, [@store_key, adapter_opts]) do
      :not_found ->
        {:ok, %{}}

      {:ok, %{version: @checkpoint_version, rollouts: rollouts}} when is_map(rollouts) ->
        if valid_rollouts?(rollouts),
          do: {:ok, rollouts},
          else: {:error, :invalid_rollout_checkpoint}

      # A checkpoint this build cannot interpret is preserved, not overwritten. The same
      # rule the node executor's journal follows: refuse rather than coerce.
      {:ok, %{version: version}} ->
        {:error, {:unsupported_rollout_checkpoint, version}}

      {:ok, _invalid} ->
        {:error, :invalid_rollout_checkpoint}

      {:error, reason} ->
        {:error, {:rollout_checkpoint_unreadable, reason}}

      other ->
        {:error, {:invalid_rollout_storage_response, other}}
    end
  end

  defp valid_rollouts?(rollouts) do
    Enum.all?(rollouts, fn
      {id, %Entry{artifact_id: id} = entry} when is_binary(id) -> entry.state in @states
      _other -> false
    end)
  end

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, inspect(reason)}}
  end

  defp storage_config(opts) do
    case Keyword.fetch(opts, :storage) do
      {:ok, storage} ->
        {:ok, storage}

      :error ->
        case Application.get_env(:ouroboros, :capability_storage) do
          nil -> {:ok, {Jido.Storage.ETS, table: :ouroboros_capabilities}}
          storage -> {:ok, storage}
        end
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_capability_storage, Exception.message(error)}}
  end

  defp limit(opts) do
    case Keyword.get_lazy(opts, :limit, fn ->
           Application.get_env(:ouroboros, :capability_rollout_limit, @default_limit)
         end) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> @default_limit
    end
  end

  defp durability_level(Jido.Storage.ETS), do: :ephemeral_checkpoint
  defp durability_level(Ouroboros.Storage.DurableFile), do: :synced_checkpoint
  defp durability_level(_adapter), do: :durable_checkpoint

  defp fetch_binary(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      {:ok, other} -> {:error, {:invalid_attribute, key, other}}
      :error -> {:error, {:missing_attribute, key}}
    end
  end

  defp fetch_module(attrs) do
    case Map.fetch(attrs, :module) do
      {:ok, module} when is_atom(module) and not is_nil(module) -> {:ok, module}
      {:ok, other} -> {:error, {:invalid_attribute, :module, other}}
      :error -> {:error, {:missing_attribute, :module}}
    end
  end

  defp fetch_epoch(attrs) do
    case Map.fetch(attrs, :epoch) do
      {:ok, epoch} when is_integer(epoch) and epoch > 0 -> {:ok, epoch}
      {:ok, other} -> {:error, {:invalid_attribute, :epoch, other}}
      :error -> {:error, {:missing_attribute, :epoch}}
    end
  end

  defp fetch_nodes(attrs) do
    case Map.fetch(attrs, :nodes) do
      {:ok, [_ | _] = nodes} ->
        if Enum.all?(nodes, &is_atom/1),
          do: {:ok, nodes},
          else: {:error, {:invalid_attribute, :nodes, nodes}}

      {:ok, other} ->
        {:error, {:invalid_attribute, :nodes, other}}

      :error ->
        {:error, {:missing_attribute, :nodes}}
    end
  end

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
