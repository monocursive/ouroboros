defmodule Ouroboros.Control.Store do
  @moduledoc "Serialized per-record persistence for control runs."

  use GenServer

  alias Ouroboros.Control.Run
  alias Ouroboros.Storage.Records

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
      persist(run, state)
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
        persist(run, state)
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
    repo =
      Records.new(adapter, opts, key, %{
        invalid: :invalid_control_checkpoint,
        unreadable: :control_checkpoint_unreadable,
        migration: :control_checkpoint_migration_failed,
        quarantine: :control_quarantine_failed
      })

    case Records.load(repo, &decode_record/2) do
      {:ok, records} -> {:ok, %{repo: repo, runs: records}}
      {:error, reason} -> {:stop, reason}
    end
  end

  defp decode_record(id, %Run{id: id} = record) when is_binary(id) do
    case Run.validate(record) do
      :ok -> {:ok, record}
      error -> error
    end
  end

  defp decode_record(_id, _record), do: :error

  defp persist(record, state) do
    updated = Map.put(state.runs, record.id, record)

    Records.reply(Records.put(state.repo, state.runs, record.id, record), :ok, state, %{
      state
      | runs: updated
    })
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
