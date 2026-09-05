defmodule Ouroboros.Team.Store do
  @moduledoc "Serialized per-record checkpoints for durable team snapshots."

  use GenServer

  alias Ouroboros.Team.Snapshot
  alias Ouroboros.Storage.Records

  @store_key {:ouroboros, :teams, 1}

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @spec create(Snapshot.t(), GenServer.server()) :: :ok | {:error, term()}
  def create(%Snapshot{} = snapshot, server \\ __MODULE__) do
    GenServer.call(server, {:create, snapshot})
  end

  @spec put(Snapshot.t(), GenServer.server()) :: :ok | {:error, term()}
  def put(%Snapshot{} = snapshot, server \\ __MODULE__) do
    GenServer.call(server, {:put, snapshot})
  end

  @spec get(String.t(), GenServer.server()) :: {:ok, Snapshot.t()} | :not_found | {:error, term()}
  def get(id, server \\ __MODULE__) when is_binary(id), do: GenServer.call(server, {:get, id})

  @spec list(GenServer.server()) :: [Snapshot.t()] | {:error, term()}
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @type durability :: :ephemeral_checkpoint | :durable_checkpoint | :synced_checkpoint

  @spec durability(GenServer.server()) :: durability()
  def durability(server \\ __MODULE__), do: GenServer.call(server, :durability)

  @doc false
  def checkpoint_key, do: @store_key

  @impl true
  def init(opts) do
    with {:ok, storage} <- storage_config(opts),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage),
         {:ok, teams} <- Records.load(repository(adapter, adapter_opts), &decode_snapshot/2) do
      {:ok,
       %{
         repo: repository(adapter, adapter_opts),
         teams: teams,
         durability: durability_level(adapter)
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:create, %Snapshot{} = snapshot}, _from, state) do
    cond do
      not Snapshot.valid?(snapshot) ->
        {:reply, {:error, :invalid_team_snapshot}, state}

      Map.has_key?(state.teams, snapshot.id) ->
        {:reply, {:error, :already_exists}, state}

      true ->
        persist(snapshot, state)
    end
  end

  def handle_call({:put, %Snapshot{} = snapshot}, _from, state) do
    if Snapshot.valid?(snapshot) do
      persist(snapshot, state)
    else
      {:reply, {:error, :invalid_team_snapshot}, state}
    end
  end

  def handle_call({:get, id}, _from, state) do
    reply =
      case Map.fetch(state.teams, id),
        do: (
          {:ok, snapshot} -> {:ok, snapshot}
          :error -> :not_found
        )

    {:reply, reply, state}
  end

  def handle_call(:list, _from, state) do
    snapshots = state.teams |> Map.values() |> Enum.sort_by(& &1.created_at)
    {:reply, snapshots, state}
  end

  def handle_call(:durability, _from, state), do: {:reply, state.durability, state}

  defp durability_level(Jido.Storage.ETS), do: :ephemeral_checkpoint
  defp durability_level(Ouroboros.Storage.DurableFile), do: :synced_checkpoint
  defp durability_level(_adapter), do: :durable_checkpoint

  defp storage_config(opts) do
    case Keyword.fetch(opts, :storage) do
      {:ok, storage} ->
        {:ok, storage}

      :error ->
        case Application.get_env(:ouroboros, :team_storage) do
          nil ->
            case Application.fetch_env(:ouroboros, :coding_storage) do
              {:ok, storage} -> {:ok, storage}
              :error -> {:error, :team_storage_not_configured}
            end

          storage ->
            {:ok, storage}
        end
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_team_storage, Exception.message(error)}}
  end

  defp repository(adapter, opts) do
    Records.new(adapter, opts, @store_key, %{
      invalid: :invalid_team_checkpoint,
      unreadable: :team_checkpoint_unreadable,
      migration: :team_checkpoint_migration_failed,
      quarantine: :team_quarantine_failed
    })
  end

  defp persist(snapshot, state) do
    teams = Map.put(state.teams, snapshot.id, snapshot)

    Records.reply(Records.put(state.repo, state.teams, snapshot.id, snapshot), :ok, state, %{
      state
      | teams: teams
    })
  end

  defp decode_snapshot(id, %Snapshot{id: id} = snapshot) when is_binary(id) do
    if Snapshot.valid?(snapshot), do: {:ok, snapshot}, else: :error
  end

  defp decode_snapshot(_id, _snapshot), do: :error
end
