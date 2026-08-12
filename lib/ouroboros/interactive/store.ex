defmodule Ouroboros.Interactive.Store do
  @moduledoc "Serialized, atomic persistence for interactive session state."

  use GenServer

  alias Ouroboros.Interactive.State

  @store_key {:ouroboros, :interactive_sessions, 1}

  @type recoverable :: %{
          id: String.t(),
          node: node(),
          status: State.status(),
          terminal?: boolean(),
          updated_at: String.t()
        }

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @spec create(State.t(), GenServer.server()) :: :ok | {:error, term()}
  def create(%State{} = state, server \\ __MODULE__), do: GenServer.call(server, {:create, state})

  @spec put(State.t(), GenServer.server()) :: :ok | {:error, term()}
  def put(%State{} = state, server \\ __MODULE__), do: GenServer.call(server, {:put, state})

  @spec get(String.t(), GenServer.server()) :: {:ok, State.t()} | :not_found | {:error, term()}
  def get(id, server \\ __MODULE__), do: GenServer.call(server, {:get, id})

  @spec list(GenServer.server()) :: [State.t()]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc """
  Returns the projection recovery needs, computed inside the store process.

  Each entry is `%{id:, node:, status:, terminal?:, updated_at:}`. Recovery runs on a
  one-second tick, and deep-copying every retained event list and turn map on every
  tick is the cost this exists to avoid.
  """
  @spec list_recoverable(GenServer.server()) :: [recoverable()]
  def list_recoverable(server \\ __MODULE__), do: GenServer.call(server, :list_recoverable)

  @doc "Deletes one terminal session. Non-terminal sessions are refused."
  @spec delete(String.t(), GenServer.server()) :: :ok | :not_found | {:error, term()}
  def delete(id, server \\ __MODULE__), do: GenServer.call(server, {:delete, id})

  @doc "Deletes terminal sessions whose last transition is older than `older_than_ms`."
  @spec prune_terminal(non_neg_integer(), GenServer.server()) ::
          {:ok, [String.t()]} | {:error, term()}
  def prune_terminal(older_than_ms, server \\ __MODULE__)

  def prune_terminal(older_than_ms, server)
      when is_integer(older_than_ms) and older_than_ms >= 0 do
    GenServer.call(server, {:prune_terminal, older_than_ms})
  end

  def prune_terminal(older_than_ms, _server), do: {:error, {:invalid_retention, older_than_ms}}

  @impl true
  def init(opts) do
    with true <- is_list(opts) and Keyword.keyword?(opts),
         storage <-
           Keyword.get_lazy(opts, :storage, fn ->
             Application.get_env(
               :ouroboros,
               :interactive_storage,
               {Jido.Storage.ETS, table: :ouroboros_interactive}
             )
           end),
         key <- Keyword.get(opts, :key, @store_key),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage) do
      case adapter_call(adapter, :get_checkpoint, [key, adapter_opts]) do
        :not_found ->
          {:ok, %{adapter: adapter, opts: adapter_opts, key: key, sessions: %{}}}

        {:ok, sessions} when is_map(sessions) ->
          load_sessions(sessions, adapter, adapter_opts, key)

        {:ok, _invalid} ->
          {:stop, :invalid_interactive_checkpoint}

        {:error, reason} ->
          {:stop, {:interactive_checkpoint_unreadable, reason}}

        other ->
          {:stop, {:invalid_storage_response, other}}
      end
    else
      false -> {:stop, :invalid_interactive_store_options}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:create, %State{} = session}, _from, state) do
    cond do
      not State.valid?(session) -> {:reply, {:error, :invalid_interactive_session}, state}
      Map.has_key?(state.sessions, session.id) -> {:reply, {:error, :already_exists}, state}
      true -> persist(Map.put(state.sessions, session.id, session), state)
    end
  end

  def handle_call({:put, %State{} = session}, _from, state) do
    if State.valid?(session),
      do: persist(Map.put(state.sessions, session.id, session), state),
      else: {:reply, {:error, :invalid_interactive_session}, state}
  end

  def handle_call({:get, id}, _from, state) do
    reply =
      case Map.fetch(state.sessions, id) do
        {:ok, session} -> {:ok, session}
        :error -> :not_found
      end

    {:reply, reply, state}
  end

  def handle_call(:list, _from, state) do
    sessions = state.sessions |> Map.values() |> Enum.sort_by(& &1.created_at, :desc)
    {:reply, sessions, state}
  end

  def handle_call(:list_recoverable, _from, state) do
    {:reply, Enum.map(state.sessions, fn {_id, session} -> recoverable(session) end), state}
  end

  def handle_call({:delete, id}, _from, state) do
    case Map.fetch(state.sessions, id) do
      :error ->
        {:reply, :not_found, state}

      {:ok, session} ->
        if State.terminal?(session) do
          persist(Map.delete(state.sessions, id), state)
        else
          {:reply, {:error, {:session_not_terminal, session.status}}, state}
        end
    end
  end

  def handle_call({:prune_terminal, older_than_ms}, _from, state) do
    horizon = DateTime.add(DateTime.utc_now(), -older_than_ms, :millisecond)
    expired = Enum.filter(state.sessions, fn {_id, session} -> prunable?(session, horizon) end)

    case expired do
      [] ->
        {:reply, {:ok, []}, state}

      expired ->
        ids = Enum.map(expired, &elem(&1, 0))
        persist(Map.drop(state.sessions, ids), state, {:ok, ids})
    end
  end

  defp load_sessions(sessions, adapter, adapter_opts, key) do
    if Enum.all?(sessions, fn {id, session} ->
         is_binary(id) and match?(%State{id: ^id}, session) and State.valid?(session)
       end) do
      {:ok, %{adapter: adapter, opts: adapter_opts, key: key, sessions: sessions}}
    else
      {:stop, :invalid_interactive_checkpoint}
    end
  end

  defp persist(sessions, state, reply \\ :ok) do
    case adapter_call(state.adapter, :put_checkpoint, [state.key, sessions, state.opts]) do
      :ok -> {:reply, reply, %{state | sessions: sessions}}
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, {:error, {:invalid_storage_response, other}}, state}
    end
  end

  defp recoverable(%State{} = session) do
    %{
      id: session.id,
      node: session.node,
      status: session.status,
      terminal?: State.terminal?(session),
      updated_at: session.updated_at
    }
  end

  defp prunable?(%State{} = session, horizon) do
    State.terminal?(session) and older_than?(session.updated_at, horizon)
  end

  # An unparsable timestamp is not evidence of age. Retain it rather than delete
  # durable state on a guess.
  defp older_than?(updated_at, horizon) do
    case DateTime.from_iso8601(updated_at) do
      {:ok, timestamp, _offset} -> DateTime.compare(timestamp, horizon) == :lt
      _error -> false
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_interactive_storage, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:invalid_interactive_storage, kind, reason}}
  end

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, reason}}
  end
end
