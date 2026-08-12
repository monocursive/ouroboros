defmodule Ouroboros.Control.Store do
  @moduledoc """
  Atomic checkpoint storage for autonomous control runs.

  All runs and their index share one adapter checkpoint, matching the durable
  aggregate pattern used by orchestration without reaching into its internals.
  """

  use GenServer

  alias Ouroboros.Control.Run

  @default_key {:ouroboros, :control_runs, 1}

  @type server :: GenServer.server()

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name_option(name))
  end

  @spec create(server(), Run.t()) :: :ok | {:error, term()}
  def create(server \\ __MODULE__, %Run{} = run), do: GenServer.call(server, {:create, run})

  @spec put(server(), Run.t()) :: :ok | {:error, term()}
  def put(server \\ __MODULE__, %Run{} = run), do: GenServer.call(server, {:put, run})

  @spec get(server(), String.t()) :: {:ok, Run.t()} | :not_found
  def get(server \\ __MODULE__, id), do: GenServer.call(server, {:get, id})

  @spec list(server()) :: {:ok, [Run.t()]}
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
               :control_storage,
               {Jido.Storage.ETS, table: :ouroboros_control_storage}
             )
           ),
         {adapter, adapter_opts} <- Jido.Storage.normalize_storage(storage),
         key <- Keyword.get(opts, :key, @default_key) do
      load(adapter, adapter_opts, key)
    else
      {:error, reason} -> {:stop, reason}
    end
  rescue
    error -> {:stop, {:invalid_control_store_options, Exception.message(error)}}
  end

  @impl true
  def handle_call({:create, %Run{} = run}, _from, state) do
    with :ok <- Run.validate(run),
         :ok <- ensure_absent(state.runs, run.id) do
      persist(Map.put(state.runs, run.id, run), state)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:put, %Run{} = run}, _from, state) do
    with :ok <- Run.validate(run),
         {:ok, current} <- fetch(state.runs, run.id),
         :ok <- next_version(current, run) do
      if current == run do
        {:reply, :ok, state}
      else
        persist(Map.put(state.runs, run.id, run), state)
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:get, id}, _from, state) do
    reply =
      case Map.fetch(state.runs, id),
        do: (
          {:ok, run} -> {:ok, run}
          :error -> :not_found
        )

    {:reply, reply, state}
  end

  def handle_call(:list, _from, state) do
    runs = state.runs |> Map.values() |> Enum.sort_by(&{&1.created_at, &1.id})
    {:reply, {:ok, runs}, state}
  end

  defp load(adapter, opts, key) do
    case adapter.get_checkpoint(key, opts) do
      :not_found -> {:ok, %{adapter: adapter, opts: opts, key: key, runs: %{}}}
      {:ok, runs} when is_map(runs) -> validate_loaded(runs, adapter, opts, key)
      {:ok, _invalid} -> {:stop, :invalid_control_checkpoint}
      {:error, reason} -> {:stop, {:control_checkpoint_unreadable, reason}}
      other -> {:stop, {:invalid_storage_response, other}}
    end
  end

  defp validate_loaded(runs, adapter, opts, key) do
    valid? =
      Enum.all?(runs, fn
        {id, %Run{id: id} = run} when is_binary(id) -> Run.validate(run) == :ok
        _other -> false
      end)

    if valid?,
      do: {:ok, %{adapter: adapter, opts: opts, key: key, runs: runs}},
      else: {:stop, :invalid_control_checkpoint}
  end

  defp persist(runs, state) do
    case state.adapter.put_checkpoint(state.key, runs, state.opts) do
      :ok -> {:reply, :ok, %{state | runs: runs}}
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, {:error, {:invalid_storage_response, other}}, state}
    end
  end

  defp fetch(runs, id) do
    case Map.fetch(runs, id) do
      {:ok, run} -> {:ok, run}
      :error -> {:error, :not_found}
    end
  end

  defp ensure_absent(runs, id) do
    if Map.has_key?(runs, id), do: {:error, :already_exists}, else: :ok
  end

  defp next_version(run, run), do: :ok

  defp next_version(%Run{version: current}, %Run{version: incoming})
       when incoming == current + 1,
       do: :ok

  defp next_version(%Run{version: current}, %Run{version: incoming}),
    do: {:error, {:stale_run_version, current, incoming}}

  defp validate_options(opts) do
    if Keyword.keyword?(opts), do: :ok, else: {:error, :invalid_options}
  end

  defp name_option(nil), do: []
  defp name_option(name), do: [name: name]
end
