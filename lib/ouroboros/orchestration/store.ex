defmodule Ouroboros.Orchestration.Store do
  @moduledoc "Serialized per-record persistence for orchestration plans."

  use GenServer

  alias Ouroboros.Orchestration.Plan
  alias Ouroboros.Storage.Records

  @default_key {:ouroboros, :orchestration_plans, 1}

  @type server :: GenServer.server()

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name_option(name))
  end

  @spec create(server(), Plan.t()) :: :ok | {:error, term()}
  def create(server \\ __MODULE__, %Plan{} = plan), do: GenServer.call(server, {:create, plan})

  @spec put(server(), Plan.t()) :: :ok | {:error, term()}
  def put(server \\ __MODULE__, %Plan{} = plan), do: GenServer.call(server, {:put, plan})

  @spec get(server(), String.t()) :: {:ok, Plan.t()} | :not_found
  def get(server \\ __MODULE__, id), do: GenServer.call(server, {:get, id})

  @spec list(server()) :: {:ok, [Plan.t()]}
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @impl true
  def init(opts) do
    with :ok <- validate_options(opts),
         storage <-
           Keyword.get(
             opts,
             :storage,
             Application.get_env(
               :ouroboros,
               :orchestration_storage,
               {Jido.Storage.ETS, table: :ouroboros_orchestration_storage}
             )
           ),
         {adapter, adapter_opts} <- Jido.Storage.normalize_storage(storage),
         key <- Keyword.get(opts, :key, @default_key) do
      load(adapter, adapter_opts, key)
    else
      {:error, reason} -> {:stop, reason}
    end
  rescue
    error -> {:stop, {:invalid_orchestration_store_options, Exception.message(error)}}
  end

  @impl true
  def handle_call({:create, %Plan{} = plan}, _from, state) do
    with :ok <- Plan.validate(plan),
         :ok <- ensure_absent(state.plans, plan.id) do
      persist(plan, state)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:put, %Plan{} = plan}, _from, state) do
    with :ok <- Plan.validate(plan),
         {:ok, current} <- fetch_existing(state.plans, plan.id),
         :ok <- next_version(current, plan) do
      if current == plan do
        {:reply, :ok, state}
      else
        persist(plan, state)
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:get, id}, _from, state) do
    reply =
      case Map.fetch(state.plans, id),
        do: (
          {:ok, plan} -> {:ok, plan}
          :error -> :not_found
        )

    {:reply, reply, state}
  end

  def handle_call(:list, _from, state) do
    plans = state.plans |> Map.values() |> Enum.sort_by(&{&1.created_at, &1.id})
    {:reply, {:ok, plans}, state}
  end

  defp load(adapter, opts, key) do
    repo =
      Records.new(adapter, opts, key, %{
        invalid: :invalid_orchestration_checkpoint,
        unreadable: :orchestration_checkpoint_unreadable,
        migration: :orchestration_checkpoint_migration_failed,
        quarantine: :orchestration_quarantine_failed
      })

    case Records.load(repo, &decode_record/2) do
      {:ok, records} -> {:ok, %{repo: repo, plans: records}}
      {:error, reason} -> {:stop, reason}
    end
  end

  defp decode_record(id, %Plan{id: id} = record) when is_binary(id) do
    with {:ok, upgraded} <- Plan.upgrade(record),
         :ok <- Plan.validate(upgraded),
         do: {:ok, upgraded}
  end

  defp decode_record(_id, _record), do: :error

  defp persist(record, state) do
    updated = Map.put(state.plans, record.id, record)

    Records.reply(Records.put(state.repo, state.plans, record.id, record), :ok, state, %{
      state
      | plans: updated
    })
  end

  defp validate_options(opts) do
    if Keyword.keyword?(opts), do: :ok, else: {:error, :invalid_options}
  end

  defp ensure_absent(plans, id) do
    if Map.has_key?(plans, id), do: {:error, :already_exists}, else: :ok
  end

  defp fetch_existing(plans, id) do
    case Map.fetch(plans, id) do
      {:ok, plan} -> {:ok, plan}
      :error -> {:error, :not_found}
    end
  end

  defp next_version(plan, plan), do: :ok

  defp next_version(%Plan{version: current}, %Plan{version: incoming})
       when incoming == current + 1,
       do: :ok

  defp next_version(%Plan{version: current}, %Plan{version: incoming}),
    do: {:error, {:stale_plan_version, current, incoming}}

  defp name_option(nil), do: []
  defp name_option(name), do: [name: name]
end
