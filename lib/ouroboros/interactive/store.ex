defmodule Ouroboros.Interactive.Store do
  @moduledoc "Serialized, per-session atomic persistence for interactive session state."

  use GenServer

  require Logger

  alias Ouroboros.Interactive.State

  @store_key {:ouroboros, :interactive_sessions, 1}
  @index_version 2

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

        {:ok, %{version: @index_version, ids: ids}} ->
          load_index(ids, adapter, adapter_opts, key)

        # Version 1 stored every session under one checkpoint. Load and migrate it once;
        # subsequent event checkpoints rewrite only the session that changed.
        {:ok, sessions} when is_map(sessions) ->
          load_legacy_sessions(sessions, adapter, adapter_opts, key)

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
      not State.valid?(session) ->
        {:reply, {:error, :invalid_interactive_session}, state}

      Map.has_key?(state.sessions, session.id) ->
        {:reply, {:error, :already_exists}, state}

      true ->
        sessions = Map.put(state.sessions, session.id, session)

        case put_session(session, state) do
          :ok ->
            case put_index(sessions, state) do
              :ok ->
                {:reply, :ok, %{state | sessions: sessions}}

              {:error, {:commit_outcome_unknown, _reason} = ambiguity} ->
                {:stop, ambiguity, {:error, ambiguity}, state}

              {:error, reason} ->
                _ = delete_session_checkpoint(session.id, state)
                {:reply, {:error, reason}, state}
            end

          {:error, reason} ->
            persistence_error(reason, state)
        end
    end
  end

  # `storable?/1` is `valid?/1` plus the one exception a terminal session needs: it never
  # builds another request, so a session that stopped being requestable mid-run can still
  # record the honest ending it just decided. Creation stays on the strict gate.
  def handle_call({:put, %State{} = session}, _from, state) do
    if State.storable?(session) do
      sessions = Map.put(state.sessions, session.id, session)
      new? = not Map.has_key?(state.sessions, session.id)

      case put_session(session, state) do
        :ok when not new? ->
          {:reply, :ok, %{state | sessions: sessions}}

        :ok ->
          case put_index(sessions, state) do
            :ok ->
              {:reply, :ok, %{state | sessions: sessions}}

            {:error, {:commit_outcome_unknown, _reason} = ambiguity} ->
              {:stop, ambiguity, {:error, ambiguity}, state}

            {:error, reason} ->
              _ = delete_session_checkpoint(session.id, state)
              {:reply, {:error, reason}, state}
          end

        {:error, reason} ->
          persistence_error(reason, state)
      end
    else
      {:reply, {:error, :invalid_interactive_session}, state}
    end
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
          sessions = Map.delete(state.sessions, id)

          case put_index(sessions, state) do
            :ok ->
              _ = delete_session_checkpoint(id, state)
              {:reply, :ok, %{state | sessions: sessions}}

            {:error, reason} ->
              persistence_error(reason, state)
          end
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
        sessions = Map.drop(state.sessions, ids)

        case put_index(sessions, state) do
          :ok ->
            Enum.each(ids, &delete_session_checkpoint(&1, state))
            {:reply, {:ok, ids}, %{state | sessions: sessions}}

          {:error, reason} ->
            persistence_error(reason, state)
        end
    end
  end

  # Load checks shape, not runnability: one unrequestable session must not veto its peers.
  defp load_legacy_sessions(sessions, adapter, adapter_opts, key) do
    if valid_sessions?(sessions) do
      state = %{adapter: adapter, opts: adapter_opts, key: key, sessions: sessions}

      with :ok <- put_all_sessions(sessions, state),
           :ok <- put_index(sessions, state) do
        {:ok, state}
      else
        {:error, reason} -> {:stop, {:interactive_checkpoint_migration_failed, reason}}
      end
    else
      {:stop, :invalid_interactive_checkpoint}
    end
  end

  # A corrupt *index* is this store's own state and fails closed. One unreadable session
  # is not: halting there refuses to boot the whole interactive plane — and, under
  # `rest_for_one`, everything started after it — over a single session nobody can read
  # anyway. The bad session is quarantined instead: logged by id, dropped from the
  # rebuilt index, and left on disk for whoever wants to look at it.
  defp load_index(ids, adapter, adapter_opts, key) when is_list(ids) do
    if ids == Enum.uniq(ids) and Enum.all?(ids, &is_binary/1) do
      state = %{adapter: adapter, opts: adapter_opts, key: key, sessions: %{}}

      {sessions, quarantined} =
        Enum.reduce(ids, {%{}, []}, fn id, {sessions, quarantined} ->
          case load_session(id, adapter, adapter_opts, key) do
            {:ok, session} -> {Map.put(sessions, id, session), quarantined}
            {:error, reason} -> {sessions, [{id, reason} | quarantined]}
          end
        end)

      state = %{state | sessions: sessions}

      case quarantined do
        [] ->
          {:ok, state}

        quarantined ->
          Enum.each(quarantined, fn {id, reason} ->
            Logger.error(
              "interactive session #{id} could not be loaded (#{inspect(reason)}); " <>
                "quarantining it and continuing with the sessions that survived"
            )
          end)

          case put_index(sessions, state) do
            :ok -> {:ok, state}
            {:error, reason} -> {:stop, {:interactive_quarantine_failed, reason}}
          end
      end
    else
      {:stop, :invalid_interactive_checkpoint}
    end
  end

  defp load_index(_ids, _adapter, _adapter_opts, _key),
    do: {:stop, :invalid_interactive_checkpoint}

  defp load_session(id, adapter, adapter_opts, key) do
    case adapter_call(adapter, :get_checkpoint, [session_key(key, id), adapter_opts]) do
      {:ok, %{^id => %State{id: ^id} = session}} ->
        if State.loadable?(session),
          do: {:ok, session},
          else: {:error, :invalid_interactive_session}

      {:error, reason} ->
        {:error, {:interactive_checkpoint_unreadable, reason}}

      _missing_or_invalid ->
        {:error, :invalid_interactive_checkpoint}
    end
  end

  defp valid_sessions?(sessions) do
    Enum.all?(sessions, fn {id, session} ->
      is_binary(id) and match?(%State{id: ^id}, session) and State.loadable?(session)
    end)
  end

  defp put_all_sessions(sessions, state) do
    Enum.reduce_while(sessions, :ok, fn {_id, session}, :ok ->
      case put_session(session, state) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp put_session(%State{id: id} = session, state),
    do: put_checkpoint(session_key(state.key, id), %{id => session}, state)

  defp put_index(sessions, state) do
    ids = sessions |> Map.keys() |> Enum.sort()
    put_checkpoint(state.key, %{version: @index_version, ids: ids}, state)
  end

  defp put_checkpoint(key, value, state) do
    case adapter_call(state.adapter, :put_checkpoint, [key, value, state.opts]) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_storage_response, other}}
    end
  end

  defp delete_session_checkpoint(id, state),
    do: adapter_call(state.adapter, :delete_checkpoint, [session_key(state.key, id), state.opts])

  defp session_key(key, id), do: {key, :session, @index_version, id}

  defp persistence_error({:commit_outcome_unknown, _reason} = ambiguity, state),
    do: {:stop, ambiguity, {:error, ambiguity}, state}

  defp persistence_error(reason, state), do: {:reply, {:error, reason}, state}

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
