defmodule Ouroboros.Coding.Store do
  @moduledoc """
  Serialized persistence boundary for coding-task checkpoints.

  Development and tests use ETS. Production is configured in `runtime.exs` to use
  `Jido.Storage.File` beneath `OUROBOROS_DATA_DIR`. The task map and its index are one
  checkpoint, so every accepted transition is atomically discoverable after restart.
  A transactional shared storage adapter can replace it for clustered recovery.

  Every storage adapter call is guarded. A file-backed adapter raises rather than
  returns on an unwritable data directory, and this process owns the head of a
  `rest_for_one` tree: an unguarded raise would tear down every downstream plane.
  """

  use GenServer

  alias Ouroboros.Coding.TaskState

  @store_key {:ouroboros, :coding_tasks, 1}

  @type summary :: %{
          id: String.t(),
          node: node(),
          status: TaskState.status(),
          terminal?: boolean(),
          result: map() | nil,
          error: term(),
          updated_at: String.t()
        }

  @type recoverable :: %{
          id: String.t(),
          node: node(),
          status: TaskState.status(),
          terminal?: boolean(),
          updated_at: String.t()
        }

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @spec put(TaskState.t()) :: :ok | {:error, term()}
  def put(%TaskState{} = state), do: GenServer.call(__MODULE__, {:put, state})

  @spec create(TaskState.t()) :: :ok | {:error, term()}
  def create(%TaskState{} = state), do: GenServer.call(__MODULE__, {:create, state})

  @spec get(String.t()) :: {:ok, TaskState.t()} | :not_found | {:error, term()}
  def get(id), do: GenServer.call(__MODULE__, {:get, id})

  @doc """
  Returns one task's routing and completion projection without its event list.

  The reply is `{:ok, %{id:, node:, status:, terminal?:, result:, error:, updated_at:}}`
  or `:not_found`. Callers that only poll for completion should prefer this over
  `get/1`: it never copies the retained event list out of the store process.
  """
  @spec get_summary(String.t()) :: {:ok, summary()} | :not_found | {:error, term()}
  def get_summary(id), do: GenServer.call(__MODULE__, {:get_summary, id})

  @spec list() :: [TaskState.t()]
  def list, do: GenServer.call(__MODULE__, :list)

  @doc """
  Returns the projection recovery needs, computed inside the store process.

  Each entry is `%{id:, node:, status:, terminal?:, updated_at:}`. Recovery runs on a
  one-second tick, and deep-copying every retained event list on every tick is the
  cost this exists to avoid.
  """
  @spec list_recoverable() :: [recoverable()]
  def list_recoverable, do: GenServer.call(__MODULE__, :list_recoverable)

  @doc "Deletes one terminal task. Non-terminal tasks are refused."
  @spec delete(String.t()) :: :ok | :not_found | {:error, term()}
  def delete(id), do: GenServer.call(__MODULE__, {:delete, id})

  @doc "Deletes terminal tasks whose last transition is older than `older_than_ms`."
  @spec prune_terminal(non_neg_integer()) :: {:ok, [String.t()]} | {:error, term()}
  def prune_terminal(older_than_ms)
      when is_integer(older_than_ms) and older_than_ms >= 0 do
    GenServer.call(__MODULE__, {:prune_terminal, older_than_ms})
  end

  def prune_terminal(older_than_ms), do: {:error, {:invalid_retention, older_than_ms}}

  @impl true
  def init(opts) do
    storage =
      Keyword.get_lazy(opts, :storage, fn ->
        Application.fetch_env!(:ouroboros, :coding_storage)
      end)

    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)

    case adapter_call(adapter, :get_checkpoint, [@store_key, adapter_opts]) do
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
    cond do
      not creatable_task?(task) -> {:reply, {:error, :invalid_task_state}, state}
      Map.has_key?(state.tasks, task.id) -> {:reply, {:error, :already_exists}, state}
      true -> persist_task(task, state)
    end
  end

  def handle_call({:put, %TaskState{} = task}, _from, state) do
    if storable_task?(task),
      do: persist_task(task, state),
      else: {:reply, {:error, :invalid_task_state}, state}
  end

  def handle_call({:get, id}, _from, state) do
    reply =
      case Map.fetch(state.tasks, id) do
        {:ok, task} -> {:ok, task}
        :error -> :not_found
      end

    {:reply, reply, state}
  end

  def handle_call({:get_summary, id}, _from, state) do
    reply =
      case Map.fetch(state.tasks, id) do
        {:ok, task} -> {:ok, summary(task)}
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

  def handle_call(:list_recoverable, _from, state) do
    {:reply, Enum.map(state.tasks, fn {_id, task} -> recoverable(task) end), state}
  end

  def handle_call({:delete, id}, _from, state) do
    case Map.fetch(state.tasks, id) do
      :error ->
        {:reply, :not_found, state}

      {:ok, task} ->
        if TaskState.terminal?(task) do
          persist_tasks(Map.delete(state.tasks, id), :ok, state)
        else
          {:reply, {:error, {:task_not_terminal, task.status}}, state}
        end
    end
  end

  def handle_call({:prune_terminal, older_than_ms}, _from, state) do
    horizon = DateTime.add(DateTime.utc_now(), -older_than_ms, :millisecond)
    expired = Enum.filter(state.tasks, fn {_id, task} -> prunable?(task, horizon) end)

    case expired do
      [] ->
        {:reply, {:ok, []}, state}

      expired ->
        ids = Enum.map(expired, &elem(&1, 0))
        persist_tasks(Map.drop(state.tasks, ids), {:ok, ids}, state)
    end
  end

  defp persist_task(task, state),
    do: persist_tasks(Map.put(state.tasks, task.id, task), :ok, state)

  defp persist_tasks(tasks, reply, state) do
    case adapter_call(state.adapter, :put_checkpoint, [@store_key, tasks, state.opts]) do
      :ok ->
        {:reply, reply, %{state | tasks: tasks}}

      {:error, {:commit_outcome_unknown, _reason} = ambiguity} ->
        {:stop, ambiguity, {:error, ambiguity}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      other ->
        {:reply, {:error, {:invalid_storage_response, other}}, state}
    end
  end

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, reason}}
  end

  defp summary(%TaskState{} = task) do
    %{
      id: task.id,
      node: task.node,
      status: task.status,
      terminal?: TaskState.terminal?(task),
      result: task.result,
      error: task.error,
      updated_at: task.updated_at
    }
  end

  defp recoverable(%TaskState{} = task) do
    %{
      id: task.id,
      node: task.node,
      status: task.status,
      terminal?: TaskState.terminal?(task),
      updated_at: task.updated_at
    }
  end

  defp prunable?(%TaskState{} = task, horizon) do
    TaskState.terminal?(task) and older_than?(task.updated_at, horizon)
  end

  # An unparsable timestamp is not evidence of age. Retain it rather than delete
  # durable state on a guess.
  defp older_than?(updated_at, horizon) do
    case DateTime.from_iso8601(updated_at) do
      {:ok, timestamp, _offset} -> DateTime.compare(timestamp, horizon) == :lt
      _error -> false
    end
  end

  # Load checks the shape of the checkpoint, not the runnability of what is in it.
  # This process is the head of a `rest_for_one` tree: refusing to start takes the whole
  # node with it, so a single task written by a newer build — or by a build that allowed
  # something this one does not — must not be able to decide that no task boots. A task
  # that cannot build a request is failed by name when it tries; see `Coding.Task`.
  defp valid_tasks?(tasks) do
    Enum.all?(tasks, fn
      {id, %TaskState{id: id}} when is_binary(id) -> true
      _other -> false
    end)
  end

  # Writes are gated: a checkpoint this build accepts must be one it can run.
  defp creatable_task?(%TaskState{id: id} = task),
    do: is_binary(id) and TaskState.requestable?(task)

  # A terminal task is the exception the gate has to make. It never builds another
  # request, and refusing it would leave a task that stopped being requestable mid-run
  # unable to record its own ending: no waiter answered, no workspace released.
  defp storable_task?(%TaskState{} = task),
    do: creatable_task?(task) or (is_binary(task.id) and TaskState.terminal?(task))
end
