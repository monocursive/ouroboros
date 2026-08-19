defmodule Ouroboros.Upgrade.Rollout.Registry do
  @moduledoc """
  The durable deployment-level record of every capability this cluster has forged.

  Node executors journal what one node did. This registry journals what the *rollout*
  intended and what became of it, on the node that drove it. It is written before the
  mutation it describes, in the same order every other store in this codebase uses: the
  `:deploying` checkpoint is durable before `Coordinator.deploy/3` is called, so a forge
  that dies mid-rollout leaves evidence that a rollout was in flight instead of leaving a
  capability nobody remembers deploying.

  Five states, and the difference between rollback and quarantine is the whole point:

    * `:deploying` - checkpointed, outcome not yet known. A `:deploying` entry found at
      startup means a rollout was interrupted and its nodes must be inspected.
    * `:live` - committed and health-checked on every target, and still the version this
      plane believes is running there.
    * `:superseded` - was live, then a later compare-replace of the same module on
      overlapping nodes reached `:live`. Finished history, not current inventory.
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

  ## `eval_report`, and the checkpoint version that carries it

  An entry also holds whatever `Ouroboros.Upgrade.Rollout.Evaluation` proved on the way
  to this state: counts, timings, and the first few failures per node, never full probe
  transcripts. A rollout record that grew with the size of the specs it ran would be a
  durable store nobody can bound, so an oversized or unportable report is replaced by a
  marker saying so rather than truncated into something that reads like evidence.

  That field is why the checkpoint is version 2. A version-1 checkpoint is *upgraded* on
  read — every entry keeps what it recorded and gains `eval_report: nil`, which is the
  truth: those rollouts were never evaluated. Anything else is still refused rather than
  coerced, the way the node executor's journal refuses a shape it cannot interpret.
  """

  use GenServer

  alias Ouroboros.Upgrade.Beam

  @store_key {:ouroboros, :capability_rollouts, 1}
  @checkpoint_version 2
  @upgradable_versions [1]
  @states [:deploying, :live, :superseded, :rolled_back, :quarantined]
  @default_limit 200
  @max_eval_report_bytes 32_768

  @transitions %{
    deploying: [:live, :rolled_back, :quarantined],
    live: [:rolled_back, :quarantined, :superseded],
    superseded: [:quarantined],
    rolled_back: [:quarantined],
    quarantined: []
  }

  defmodule Entry do
    @moduledoc "One capability rollout and everything known about its outcome."

    @enforce_keys [:artifact_id, :module, :epoch, :nodes, :state, :created_at, :updated_at]

    defstruct @enforce_keys ++
                [source_sha256: nil, test_report: %{}, detail: nil, eval_report: nil]

    @type state :: :deploying | :live | :superseded | :rolled_back | :quarantined
    @type t :: %__MODULE__{
            artifact_id: String.t(),
            module: module(),
            epoch: pos_integer(),
            nodes: [node()],
            state: state(),
            source_sha256: String.t() | nil,
            test_report: map(),
            detail: term(),
            eval_report: map() | nil,
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

  @doc """
  Moves a rollout to a new state, refusing transitions that would lose information.

  `:detail` records the evidence for the transition. `:eval_report` records what an
  evaluation gate proved on the way to it; omitting it keeps whatever the entry already
  held, so marking an entry twice cannot erase the report that justified the first mark.
  """
  @spec mark(String.t(), Entry.state(), keyword(), GenServer.server()) ::
          {:ok, Entry.t()} | {:error, term()}
  def mark(artifact_id, state, opts \\ [], server \\ __MODULE__)
      when is_binary(artifact_id) and is_atom(state) and is_list(opts) do
    GenServer.call(
      server,
      {:mark, artifact_id, state, Keyword.get(opts, :detail), Keyword.get(opts, :eval_report)}
    )
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

  def handle_call({:mark, artifact_id, next, detail, eval_report}, _from, state) do
    with {:ok, entry} <- fetch(state, artifact_id),
         :ok <- ensure_transition(entry.state, next) do
      persist(
        %{
          entry
          | state: next,
            detail: detail,
            eval_report: bound_report(eval_report) || entry.eval_report,
            updated_at: now()
        },
        state
      )
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

  # A report is somebody else's summary of somebody else's node, so it is admitted on
  # this store's terms or not at all: portable, and small enough that a bounded registry
  # stays bounded. A rejected report leaves a marker rather than a half-report, because a
  # truncated map still reads like evidence.
  defp bound_report(nil), do: nil

  defp bound_report(report) do
    cond do
      not Beam.portable_term?(report) ->
        %{eval_report: :unportable, rendered: inspect(report, limit: 5, printable_limit: 200)}

      byte_size(:erlang.term_to_binary(report)) > @max_eval_report_bytes ->
        %{eval_report: :too_large, bytes: byte_size(:erlang.term_to_binary(report))}

      true ->
        report
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
    rollouts = state.rollouts |> put_entry(entry) |> prune(state.limit)

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

  # Marking a module live displaces any overlapping live record of the same module in
  # the same persist. Two `:live` rows for one module would make `live/1` over-report
  # and let a later forge of the old digest claim the work was already done.
  defp put_entry(rollouts, %Entry{state: :live} = live) do
    rollouts
    |> Map.put(live.artifact_id, live)
    |> Map.new(fn
      {id, _entry} when id == live.artifact_id ->
        {id, live}

      {id, %Entry{} = entry} ->
        if entry.state == :live and entry.module == live.module and
             Enum.any?(entry.nodes, &(&1 in live.nodes)) do
          {id,
           %{
             entry
             | state: :superseded,
               detail: %{replaced_by: live.artifact_id},
               updated_at: live.updated_at
           }}
        else
          {id, entry}
        end

      other ->
        other
    end)
  end

  defp put_entry(rollouts, entry), do: Map.put(rollouts, entry.artifact_id, entry)

  # Growth is bounded by dropping the oldest settled history only. A `:deploying`,
  # `:live`, or `:quarantined` entry is unfinished business and is never discarded to make
  # room for history. `:superseded` is finished inventory, same as a proven rollback.
  defp prune(rollouts, limit) when map_size(rollouts) <= limit, do: rollouts

  defp prune(rollouts, limit) do
    droppable =
      rollouts
      |> Map.values()
      |> Enum.filter(&(&1.state in [:rolled_back, :superseded]))
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

      {:ok, %{version: version, rollouts: rollouts}} when is_map(rollouts) ->
        upgrade(version, rollouts)

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

  defp upgrade(@checkpoint_version, rollouts), do: accept(rollouts)

  # Widening an entry is the one migration that loses nothing: every field a version-1
  # rollout recorded is kept, and the field it never had becomes `nil`, which is exactly
  # what "this rollout was never evaluated" means. A newer checkpoint is still refused,
  # because a field this build would silently drop is not a field it may rewrite.
  defp upgrade(version, rollouts) when version in @upgradable_versions do
    rollouts
    |> Map.new(fn
      {id, %Entry{} = entry} -> {id, struct(Entry, Map.from_struct(entry))}
      {id, other} -> {id, other}
    end)
    |> accept()
  end

  defp upgrade(version, _rollouts), do: {:error, {:unsupported_rollout_checkpoint, version}}

  defp accept(rollouts) do
    if valid_rollouts?(rollouts),
      do: {:ok, rollouts},
      else: {:error, :invalid_rollout_checkpoint}
  end

  # Field access is deliberately by `Map.get/2`: a struct-shaped term missing a key is a
  # checkpoint to refuse, not an exception to raise out of `init/1`.
  defp valid_rollouts?(rollouts) do
    Enum.all?(rollouts, fn
      {id, %Entry{} = entry} when is_binary(id) ->
        Map.get(entry, :artifact_id) == id and Map.get(entry, :state) in @states and
          Map.has_key?(entry, :eval_report)

      _other ->
        false
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
