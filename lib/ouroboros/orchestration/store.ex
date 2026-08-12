defmodule Ouroboros.Orchestration.Store do
  @moduledoc """
  Serialized aggregate persistence for orchestration plans.

  Every plan and its discoverable index share one Jido.Storage checkpoint. A
  scheduler transition therefore either publishes the whole new aggregate or
  leaves the previous aggregate intact.
  """

  use GenServer

  alias Ouroboros.Orchestration.Plan

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
      persist(Map.put(state.plans, plan.id, plan), state)
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
        persist(Map.put(state.plans, plan.id, plan), state)
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
    case adapter.get_checkpoint(key, opts) do
      :not_found -> {:ok, %{adapter: adapter, opts: opts, key: key, plans: %{}}}
      {:ok, plans} when is_map(plans) -> validate_loaded(plans, adapter, opts, key)
      {:ok, _invalid} -> {:stop, :invalid_orchestration_checkpoint}
      {:error, reason} -> {:stop, {:orchestration_checkpoint_unreadable, reason}}
      other -> {:stop, {:invalid_storage_response, other}}
    end
  end

  defp validate_loaded(plans, adapter, opts, key) do
    valid? =
      Enum.all?(plans, fn
        {id, %Plan{id: id} = plan} when is_binary(id) -> Plan.validate(plan) == :ok
        _other -> false
      end)

    if valid?,
      do: {:ok, %{adapter: adapter, opts: opts, key: key, plans: plans}},
      else: {:stop, :invalid_orchestration_checkpoint}
  end

  defp persist(plans, state) do
    case state.adapter.put_checkpoint(state.key, plans, state.opts) do
      :ok -> {:reply, :ok, %{state | plans: plans}}
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, {:error, {:invalid_storage_response, other}}, state}
    end
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
