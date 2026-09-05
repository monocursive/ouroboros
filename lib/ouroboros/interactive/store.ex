defmodule Ouroboros.Interactive.Store do
  @moduledoc "Serialized, per-session atomic persistence for interactive session state."

  use GenServer

  alias Ouroboros.Interactive.State
  alias Ouroboros.Storage.Records

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
      repo =
        Records.new(
          adapter,
          adapter_opts,
          key,
          %{
            invalid: :invalid_interactive_checkpoint,
            unreadable: :interactive_checkpoint_unreadable,
            migration: :interactive_checkpoint_migration_failed,
            quarantine: :interactive_quarantine_failed
          },
          :session
        )

      case Records.load(repo, &decode_session/2) do
        {:ok, sessions} -> {:ok, %{repo: repo, sessions: sessions}}
        {:error, reason} -> {:stop, reason}
      end
    else
      false -> {:stop, :invalid_interactive_store_options}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:create, %State{} = session}, _from, state) do
    cond do
      not State.valid?(session) ->
        {:reply, {:error, :invalid_interactive_session}, state}

      Map.has_key?(state.sessions, session.id) ->
        {:reply, {:error, :already_exists}, state}

      true ->
        persist_session(session, state)
    end
  end

  def handle_call({:put, %State{} = session}, _from, state) do
    if State.storable?(session),
      do: persist_session(session, state),
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
          drop_sessions([id], :ok, state)
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
        drop_sessions(ids, {:ok, ids}, state)
    end
  end

  defp persist_session(session, state) do
    sessions = Map.put(state.sessions, session.id, session)

    Records.reply(Records.put(state.repo, state.sessions, session.id, session), :ok, state, %{
      state
      | sessions: sessions
    })
  end

  defp drop_sessions(ids, reply, state) do
    sessions = Map.drop(state.sessions, ids)

    Records.reply(Records.drop(state.repo, state.sessions, ids), reply, state, %{
      state
      | sessions: sessions
    })
  end

  defp decode_session(id, %State{id: id} = session) when is_binary(id) do
    if State.loadable?(session), do: {:ok, session}, else: :error
  end

  defp decode_session(_id, _session), do: :error

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
end
