defmodule Ouroboros.Interactive.Store do
  @moduledoc "Serialized, per-session atomic persistence for interactive session state."

  use GenServer

  alias Ouroboros.Interactive.State
  alias Ouroboros.Maintenance.Epoch
  alias Ouroboros.Storage.Records

  @store_key {:ouroboros, :interactive_sessions, 1}

  @type recoverable :: %{
          id: String.t(),
          node: node(),
          status: State.status(),
          runtime_id: String.t() | nil,
          runtime_generation: String.t() | nil,
          runtime_cursor: non_neg_integer(),
          terminal?: boolean(),
          removed_provider?: boolean(),
          updated_at: String.t()
        }

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @spec create(State.t(), GenServer.server()) :: :ok | {:error, term()}
  def create(%State{} = state, server \\ __MODULE__), do: GenServer.call(server, {:create, state})

  @doc "Atomically creates or matches an imported session across logical and source IDs."
  def create_import(%State{} = session, server \\ __MODULE__),
    do: GenServer.call(server, {:create_import, session})

  @doc "Atomically updates one handoff reservation only while its expected intent matches."
  def prepare_handoff(id, expected_intent, provider_session_id, server \\ __MODULE__),
    do:
      GenServer.call(
        server,
        {:prepare_handoff, id, expected_intent, provider_session_id},
        :infinity
      )

  @spec put(State.t(), GenServer.server()) :: :ok | {:error, term()}
  def put(%State{} = state, server \\ __MODULE__) do
    # Durable serialization of a long retained transcript can exceed GenServer.call's
    # default. Backpressure the coordinator instead of killing it and detaching subscribers.
    # Catching exits here also keeps the full State out of a caller crash report.
    GenServer.call(server, {:put, state}, :infinity)
  catch
    :exit, _reason -> {:error, :interactive_store_unavailable}
  end

  @spec get(String.t(), GenServer.server()) :: {:ok, State.t()} | :not_found | {:error, term()}
  def get(id, server \\ __MODULE__), do: GenServer.call(server, {:get, id})

  @spec list(GenServer.server()) :: [State.t()]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc """
  Returns the projection recovery needs, computed inside the store process.

  Each entry contains routing, runtime identity, terminal/provider flags and updated_at.
  Recovery runs on a
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
               {Ouroboros.Storage.ETS, table: :ouroboros_interactive}
             )
           end),
         key <- Keyword.get(opts, :key, @store_key),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage),
         {:ok, epoch_server} <- epoch_server(opts) do
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
        {:ok, sessions} ->
          state = %{repo: repo, sessions: sessions, epoch_server: epoch_server, pending: %{}}

          case reconcile_epoch(state) do
            {:ok, state} -> {:ok, state}
            {:error, reason} -> {:stop, reason}
          end

        {:error, reason} ->
          {:stop, reason}
      end
    else
      false -> {:stop, :invalid_interactive_store_options}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:create, %State{} = session}, _from, state) do
    import_owner = imported_source_owner(state.sessions, session)

    cond do
      not State.valid?(session) ->
        {:reply, {:error, :invalid_interactive_session}, state}

      import_owner != nil and import_owner != session.id ->
        {:reply, {:error, {:native_checkpoint_owned, import_owner}}, state}

      Map.has_key?(state.sessions, session.id) ->
        {:reply, {:error, :already_exists}, state}

      true ->
        persist_session(:create, session.id, session, :ok, state)
    end
  end

  def handle_call({:create_import, %State{} = session}, _from, state) do
    source =
      get_in(session, [Access.key(:imported_from), Access.key(:source_provider_session_id)])

    case {Map.get(state.sessions, session.id), imported_source(state.sessions, source)} do
      {nil, nil} ->
        if State.valid?(session),
          do: persist_session(:create_import, session.id, session, :ok, state),
          else: {:reply, {:error, :invalid_interactive_session}, state}

      {%State{} = existing, _} ->
        if same_import?(existing, session),
          do: {:reply, {:ok, existing, :existing}, state},
          else: {:reply, {:error, {:session_id_conflict, session.id}}, state}

      {nil, %State{} = existing} ->
        if same_import?(existing, session),
          do: {:reply, {:ok, existing, :existing}, state},
          else: {:reply, {:error, {:native_checkpoint_owned, existing.id}}, state}
    end
  end

  def handle_call({:prepare_handoff, id, expected_intent, provider_session_id}, _from, state) do
    case Map.get(state.sessions, id) do
      %State{status: :preparing, handoff_intent: ^expected_intent} = child ->
        prepared = %{
          child
          | status: :starting,
            provider_session_id: provider_session_id,
            handoff_intent: Map.put(expected_intent, :status, :prepared)
        }

        persist_session(:prepare_handoff, payload_digest(prepared), prepared, :ok, state)

      %State{} ->
        {:reply, {:error, {:handoff_id_conflict, id}}, state}

      nil ->
        {:reply, {:error, :handoff_reservation_missing}, state}
    end
  end

  def handle_call({:put, %State{} = session}, _from, state) do
    import_owner = imported_source_owner(state.sessions, session)

    cond do
      import_owner != nil and import_owner != session.id ->
        {:reply, {:error, {:native_checkpoint_owned, import_owner}}, state}

      State.storable?(session) ->
        persist_session(:put, payload_digest(%{session.id => session}), session, :ok, state)

      true ->
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
        delivery = delivery_state(session)

        cond do
          not State.terminal?(session) ->
            {:reply, {:error, {:session_not_terminal, session.status}}, state}

          delivery == :pending ->
            {:reply, {:error, :session_delivery_pending}, state}

          delivery == :unknown ->
            {:reply, {:error, :session_delivery_unknown}, state}

          delivery == :uncheckpointed ->
            {:reply, {:error, :session_delivery_uncheckpointed}, state}

          true ->
            desired = Map.delete(state.sessions, id)
            drop_sessions(:delete, payload_digest(desired), [id], :ok, state)
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
        desired = Map.drop(state.sessions, ids)
        drop_sessions(:prune, payload_digest(desired), ids, {:ok, ids}, state)
    end
  end

  defp imported_source_owner(sessions, session) do
    source =
      case Map.get(session, :imported_from) do
        %{source_provider_session_id: imported} ->
          imported

        _ ->
          Map.get(session, :provider_session_id) ||
            get_in(session, [Access.key(:options), :provider_session_id])
      end

    if is_binary(source) do
      Enum.find_value(sessions, fn {id, existing} ->
        provenance = Map.get(existing, :imported_from)
        if provenance && provenance.source_provider_session_id == source, do: id
      end)
    end
  end

  defp imported_source(sessions, source) do
    Enum.find_value(sessions, fn {_id, existing} ->
      provenance = Map.get(existing, :imported_from)

      if existing.provider_session_id == source or
           (provenance && provenance.source_provider_session_id == source),
         do: existing
    end)
  end

  defp same_import?(left, right) do
    get_in(left, [Access.key(:imported_from), Access.key(:fingerprint)]) ==
      get_in(right, [Access.key(:imported_from), Access.key(:fingerprint)])
  end

  defp persist_session(_kind, _identity, session, reply, %{epoch_server: nil} = state) do
    sessions = Map.put(state.sessions, session.id, session)

    Records.reply(Records.put(state.repo, state.sessions, session.id, session), reply, state, %{
      state
      | sessions: sessions
    })
  end

  defp persist_session(kind, identity, session, reply, state) do
    sessions = Map.put(state.sessions, session.id, session)

    epoch_mutation(kind, identity, sessions, reply, state, fn ->
      Records.put(state.repo, state.sessions, session.id, session)
    end)
  end

  defp drop_sessions(_kind, _identity, ids, reply, %{epoch_server: nil} = state) do
    sessions = Map.drop(state.sessions, ids)

    Records.reply(Records.drop(state.repo, state.sessions, ids), reply, state, %{
      state
      | sessions: sessions
    })
  end

  defp drop_sessions(kind, identity, ids, reply, state) do
    sessions = Map.drop(state.sessions, ids)

    epoch_mutation(kind, identity, sessions, reply, state, fn ->
      Records.drop(state.repo, state.sessions, ids)
    end)
  end

  defp epoch_mutation(kind, identity, desired, reply, state, publish) do
    digest = payload_digest(desired)
    write_id = write_id(kind, identity)

    cond do
      state.pending != %{} and Map.get(state.pending, write_id) != digest ->
        {:reply, {:error, :interactive_epoch_pending}, state}

      true ->
        reserve_and_publish(write_id, digest, desired, reply, state, publish)
    end
  end

  defp reserve_and_publish(write_id, digest, desired, reply, state, publish) do
    case epoch_call(fn -> Epoch.reserve(write_id, digest, state.epoch_server) end) do
      {:ok, {:ok, reservation}} ->
        with {:ok, durable} <- load_sessions(state.repo) do
          cond do
            durable == desired ->
              commit_epoch(reservation, desired, reply, state)

            durable == state.sessions ->
              publish_and_commit(publish, reservation, desired, reply, state)

            true ->
              stop_unknown(:interactive_records_changed_outside_store, state)
          end
        else
          {:error, reason} -> stop_unknown({:interactive_records_unreadable, reason}, state)
        end

      {:ok, {:error, reason}} ->
        {:reply, {:error, {:maintenance_epoch, reason}}, state}

      {:ok, other} ->
        stop_unknown({:invalid_epoch_response, other}, state)

      {:uncertain, reason} ->
        stop_unknown({:epoch_reserve_outcome_unknown, reason}, state)
    end
  end

  defp publish_and_commit(publish, reservation, desired, reply, state) do
    case publish.() do
      :ok ->
        commit_epoch(reservation, desired, reply, state)

      {:error, {:commit_outcome_unknown, _} = reason} ->
        stop_unknown(reason, state)

      {:error, reason} ->
        reconcile_failed_publish(reservation, desired, reply, reason, state)

      other ->
        stop_unknown({:invalid_storage_response, other}, state)
    end
  end

  defp reconcile_failed_publish(reservation, desired, reply, publish_reason, state) do
    case load_sessions(state.repo) do
      {:ok, ^desired} ->
        commit_epoch(reservation, desired, reply, state)

      {:ok, durable} when durable == state.sessions ->
        case epoch_call(fn ->
               Epoch.abort(reservation, :payload_absence_confirmed, state.epoch_server)
             end) do
          {:ok, :ok} -> {:reply, {:error, publish_reason}, state}
          {:ok, {:error, reason}} -> stop_unknown({:epoch_abort_failed, reason}, state)
          {:ok, other} -> stop_unknown({:invalid_epoch_response, other}, state)
          {:uncertain, reason} -> stop_unknown({:epoch_abort_outcome_unknown, reason}, state)
        end

      {:ok, _other} ->
        stop_unknown(:interactive_payload_outcome_unknown, state)

      {:error, reason} ->
        stop_unknown({:interactive_payload_observation_failed, reason}, state)
    end
  end

  defp commit_epoch(reservation, desired, reply, state) do
    case epoch_call(fn -> Epoch.commit(reservation, state.epoch_server) end) do
      {:ok, :ok} ->
        {:reply, reply,
         %{state | sessions: desired, pending: Map.delete(state.pending, reservation.write_id)}}

      {:ok, {:error, reason}} ->
        stop_unknown({:epoch_commit_failed, reason}, state)

      {:ok, other} ->
        stop_unknown({:invalid_epoch_response, other}, state)

      {:uncertain, reason} ->
        stop_unknown({:epoch_commit_outcome_unknown, reason}, state)
    end
  end

  defp reconcile_epoch(%{epoch_server: nil} = state), do: {:ok, state}

  defp reconcile_epoch(state) do
    digest = payload_digest(state.sessions)

    case epoch_call(fn -> Epoch.observe(state.epoch_server) end) do
      {:ok, %{pending: pending}} when is_list(pending) ->
        Enum.reduce_while(pending, {:ok, state}, fn reservation, {:ok, acc} ->
          if reservation.payload_digest == digest do
            case epoch_call(fn ->
                   Epoch.commit(Map.delete(reservation, :status), acc.epoch_server)
                 end) do
              {:ok, :ok} -> {:cont, {:ok, acc}}
              result -> {:halt, {:error, {:interactive_epoch_reconcile_failed, result}}}
            end
          else
            {:cont,
             {:ok,
              %{
                acc
                | pending: Map.put(acc.pending, reservation.write_id, reservation.payload_digest)
              }}}
          end
        end)

      {:ok, other} ->
        {:error, {:invalid_epoch_observation, other}}

      {:uncertain, reason} ->
        {:error, {:maintenance_epoch_unavailable, reason}}
    end
  end

  defp load_sessions(repo), do: Records.load(repo, &decode_session/2)

  # This is the exact logical Records payload: every decoded session and the authoritative
  # membership represented by the map. `:deterministic` fixes map ordering before SHA-256.
  defp payload_digest(sessions) do
    sessions
    |> :erlang.term_to_binary([:deterministic])
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp write_id(kind, identity) do
    encoded = :erlang.term_to_binary({kind, identity}, [:deterministic])
    hash = :crypto.hash(:sha256, encoded) |> Base.encode16(case: :lower)
    "interactive-store/v1/#{kind}/#{hash}"
  end

  defp epoch_call(fun) do
    {:ok, fun.()}
  catch
    :exit, reason -> {:uncertain, reason}
  end

  defp stop_unknown(reason, state),
    do: {:stop, {:interactive_store_epoch_uncertain, reason}, {:error, reason}, state}

  defp epoch_server(opts) do
    configured = Keyword.get(opts, :epoch_server, :auto)
    data_dir = Application.get_env(:ouroboros, :data_dir)
    storage = Keyword.get(opts, :storage)
    durable? = match?({Ouroboros.Storage.DurableFile, _}, storage)

    case configured do
      :auto ->
        if durable? and Process.whereis(Epoch) do
          {:ok, Epoch}
        else
          if durable? and is_binary(data_dir) and data_dir != "",
            do: {:error, :maintenance_epoch_required},
            else: {:ok, nil}
        end

      nil ->
        if durable? and is_binary(data_dir) and data_dir != "",
          do: {:error, :maintenance_epoch_required},
          else: {:ok, nil}

      server ->
        {:ok, server}
    end
  end

  defp decode_session(id, session), do: Ouroboros.Storage.SessionMigration.decode(id, session)

  defp recoverable(%State{} = session) do
    %{
      id: session.id,
      node: session.node,
      status: session.status,
      runtime_id: session.runtime_id,
      runtime_generation: session.runtime_generation,
      runtime_cursor: session.runtime_cursor,
      terminal?: State.terminal?(session),
      # A record whose provider this build no longer serves is not recovered: there is
      # nothing to resume, and starting a coordinator for it every restart would leave one
      # read-only holder per removed-provider record on every node. It gets a coordinator
      # only when a verb is served against it. See docs/proposals/core.md §3 D2.
      removed_provider?: State.removed_provider(session) != nil,
      updated_at: session.updated_at
    }
  end

  defp prunable?(%State{} = session, horizon) do
    State.terminal?(session) and older_than?(session.updated_at, horizon) and
      delivery_state(session) == :settled
  end

  defp delivery_state(session),
    do:
      Ouroboros.Session.Delivery.state(
        session.runtime_id,
        session.runtime_generation,
        session.runtime_cursor
      )

  # An unparsable timestamp is not evidence of age. Retain it rather than delete
  # durable state on a guess.
  defp older_than?(updated_at, horizon) do
    case DateTime.from_iso8601(updated_at) do
      {:ok, timestamp, _offset} -> DateTime.compare(timestamp, horizon) == :lt
      _error -> false
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Ouroboros.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_interactive_storage, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:invalid_interactive_storage, kind, reason}}
  end
end
