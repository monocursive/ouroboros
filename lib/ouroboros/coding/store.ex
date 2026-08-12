defmodule Ouroboros.Coding.Store do
  @moduledoc """
  Serialized persistence boundary for coding-task checkpoints.

  Development and tests use ETS. Production is configured in `runtime.exs` to use
  `Jido.Storage.File` beneath `OUROBOROS_DATA_DIR`. The task map and its index are one
  checkpoint, so every accepted transition is atomically discoverable after restart.
  A transactional shared storage adapter can replace it for clustered recovery.
  """

  use GenServer

  alias Ouroboros.Coding.TaskState

  @store_key {:ouroboros, :coding_tasks, 1}

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @spec put(TaskState.t()) :: :ok | {:error, term()}
  def put(%TaskState{} = state), do: GenServer.call(__MODULE__, {:put, state})

  @spec create(TaskState.t()) :: :ok | {:error, term()}
  def create(%TaskState{} = state), do: GenServer.call(__MODULE__, {:create, state})

  @spec get(String.t()) :: {:ok, TaskState.t()} | :not_found | {:error, term()}
  def get(id), do: GenServer.call(__MODULE__, {:get, id})

  @spec list() :: [TaskState.t()]
  def list, do: GenServer.call(__MODULE__, :list)

  @impl true
  def init(opts) do
    storage =
      Keyword.get_lazy(opts, :storage, fn ->
        Application.fetch_env!(:ouroboros, :coding_storage)
      end)

    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)

    case adapter.get_checkpoint(@store_key, adapter_opts) do
      :not_found ->
        {:ok, %{adapter: adapter, opts: adapter_opts, tasks: %{}}}

      {:ok, tasks} when is_map(tasks) ->
        if valid_tasks?(tasks) do
          {:ok, %{adapter: adapter, opts: adapter_opts, tasks: tasks}}
        else
          {:stop, :invalid_coding_task_checkpoint}
        end

      {:ok, _invalid} ->
        {:stop, :invalid_coding_task_checkpoint}

      {:error, reason} ->
        {:stop, {:coding_task_checkpoint_unreadable, reason}}

      other ->
        {:stop, {:invalid_storage_response, other}}
    end
  end

  @impl true
  def handle_call({:create, %TaskState{} = task}, _from, state) do
    if Map.has_key?(state.tasks, task.id) do
      {:reply, {:error, :already_exists}, state}
    else
      persist_task(task, state)
    end
  end

  def handle_call({:put, %TaskState{} = task}, _from, state) do
    persist_task(task, state)
  end

  def handle_call({:get, id}, _from, state) do
    reply =
      case Map.fetch(state.tasks, id) do
        {:ok, task} -> {:ok, task}
        :error -> :not_found
      end

    {:reply, reply, state}
  end

  def handle_call(:list, _from, state) do
    tasks =
      state.tasks
      |> Map.values()
      |> Enum.sort_by(& &1.created_at, :desc)

    {:reply, tasks, state}
  end

  defp persist_task(task, state) do
    tasks = Map.put(state.tasks, task.id, task)

    case state.adapter.put_checkpoint(@store_key, tasks, state.opts) do
      :ok -> {:reply, :ok, %{state | tasks: tasks}}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp valid_tasks?(tasks) do
    Enum.all?(tasks, fn
      {id, %TaskState{id: id}} when is_binary(id) -> true
      _other -> false
    end)
  end
end
