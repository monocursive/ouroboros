defmodule Ouroboros.InteractiveSession do
  @moduledoc """
  Durable, distribution-aware interactive coding sessions.

  The upstream Harness owns provider transports and active processes. Ouroboros
  owns durable session/turn intent, redacted replay, workspace admission, crash
  reattachment, and node-aware routing.
  """

  alias Ouroboros.Interactive.{Ref, State, Store, Task}

  @type session :: Ref.t() | String.t()

  @turn_options [:attachments, :reasoning_effort, :output_schema, :metadata, :provider_options]

  # Control-plane operations (info/replay/subscribe/steer/respond_approval/interrupt/
  # close/kill) are bounded so one wedged coordinator cannot freeze every caller.
  # `await/3` is the deliberate exception: it threads the caller's own timeout, and the
  # transport is given that timeout plus a margin so the local waiter, not the
  # transport, decides when to stop waiting.
  @default_call_timeout 30_000
  @remote_margin_ms 5_000

  # A human approval is the one control-plane call whose latency is a person's. The three
  # ceilings are layered so that the innermost one answers: the coordinator denies at 13
  # minutes, this transport stops waiting at 14, and the gateway kills the task at 15.
  @approval_request_timeout 14 * 60 * 1_000

  @doc "Starts or adopts a caller-independent interactive coding session."
  @spec start(keyword()) :: {:ok, Ref.t()} | {:error, term()}
  def start(opts \\ [])

  def start(opts) when is_list(opts) do
    case start_for_gateway(opts) do
      {:created, %Ref{}, reason} -> {:error, reason}
      result -> result
    end
  end

  def start(_opts), do: {:error, :invalid_options}

  @doc false
  @spec start_for_gateway(keyword()) ::
          {:ok, Ref.t()} | {:created, Ref.t(), term()} | {:error, term()}
  def start_for_gateway(opts) when is_list(opts) do
    if valid_options?(opts) do
      id = Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0)

      with {:ok, session} <- State.new(id, opts),
           {:ok, persisted} <- create_or_match(session) do
        ref = Ref.new(id)

        case persisted.status do
          status when status in [:failed, :lost] ->
            {:created, ref, {:session_start_failed, persisted.error}}

          status when status in [:closed, :cancelled] ->
            {:ok, ref}

          _active ->
            case ensure_coordinator(id) do
              {:ok, pid} ->
                # Readiness waits for provider start-up, whose latency is legitimately
                # unbounded, so it keeps the long wait rather than the control-plane
                # bound. The request already exists durably at this point. Preserve that
                # fact when provider/workspace readiness fails so the gateway can open
                # the failed session instead of making a same-id client reconcile
                # forever. A coordinator whose readiness never settles — a store that
                # keeps refusing checkpoints, for instance — answers this call itself
                # at the readiness deadline with `{:session_start_unresolved, id}`,
                # so a caller here cannot wait forever on a session that can no
                # longer report anything.
                case safe_call(pid, :ready, :infinity) do
                  {:ok, _state} -> {:ok, ref}
                  {:error, reason} -> {:created, ref, reason}
                end

              {:error, reason} ->
                {:created, ref, reason}
            end
        end
      else
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :invalid_options}
    end
  end

  def start_for_gateway(_opts), do: {:error, :invalid_options}

  @doc "Starts an interactive session on a selected connected node."
  @spec start_on(node(), keyword()) :: {:ok, Ref.t()} | {:error, term()}
  def start_on(owner, opts \\ [])

  def start_on(owner, opts) when is_atom(owner) and not is_nil(owner) do
    case route(owner, __MODULE__, :start, [opts]) do
      {:ok, %Ref{} = ref} -> {:ok, %{ref | node: owner}}
      other -> other
    end
  end

  def start_on(_owner, _opts), do: {:error, :invalid_owner}

  @doc false
  @spec start_for_gateway_on(node(), keyword()) ::
          {:ok, Ref.t()} | {:created, Ref.t(), term()} | {:error, term()}
  def start_for_gateway_on(owner, opts \\ [])

  def start_for_gateway_on(owner, opts) when is_atom(owner) and not is_nil(owner) do
    case route(owner, __MODULE__, :start_for_gateway, [opts]) do
      {:ok, %Ref{} = ref} -> {:ok, %{ref | node: owner}}
      {:created, %Ref{} = ref, reason} -> {:created, %{ref | node: owner}, reason}
      other -> other
    end
  end

  def start_for_gateway_on(_owner, _opts), do: {:error, :invalid_owner}

  @doc "Returns a durable public session snapshot."
  def info(session), do: call(session, :info)

  @doc "Lists local durable interactive sessions."
  def list do
    Store.list()
    |> Enum.filter(&(&1.node == node()))
    |> Enum.map(&State.public/1)
  end

  @doc "Atomically subscribes the caller and returns events after an exclusive cursor."
  def subscribe(session, opts \\ []) do
    with :ok <- validate_options(opts, [:cursor]) do
      call(session, {:subscribe, self(), Keyword.get(opts, :cursor, 0)})
    end
  end

  @doc "Stops live event delivery to the caller."
  def unsubscribe(session), do: call(session, {:unsubscribe, self()})

  @doc "Replays retained redacted events after an exclusive cursor."
  def replay(session, opts \\ []) do
    with :ok <- validate_options(opts, [:cursor, :limit]) do
      call(session, {:replay, Keyword.get(opts, :cursor, 0), Keyword.get(opts, :limit, 100)})
    end
  end

  @doc "Starts an immediate turn. A caller-supplied id makes dispatch idempotent."
  def send_message(session, input, opts \\ []) do
    send_turn(session, :message, input, opts)
  end

  @doc "Queues a follow-up turn with durable, idempotent intent."
  def follow_up(session, input, opts \\ []) do
    send_turn(session, :follow_up, input, opts)
  end

  @doc "Waits for one logical turn; waiter timeout never interrupts provider work."
  def await(session, turn_id, timeout \\ :infinity) do
    with {:ok, id, owner} <- session_identity(session),
         :ok <- validate_turn_id(turn_id),
         :ok <- validate_timeout(timeout) do
      request_ref = make_ref()

      if owner == node() do
        local_await(id, turn_id, request_ref, timeout)
      else
        route(
          owner,
          __MODULE__,
          :local_await,
          [id, turn_id, request_ref, timeout],
          transport_timeout(timeout)
        )
      end
    end
  end

  @doc false
  def local_await(id, turn_id, request_ref, timeout) do
    with :ok <- validate_id(id),
         :ok <- validate_turn_id(turn_id),
         true <- is_reference(request_ref) || {:error, :invalid_request_reference},
         :ok <- validate_timeout(timeout),
         {:ok, pid} <- ensure_coordinator(id) do
      try do
        GenServer.call(pid, {:await_turn, request_ref, turn_id}, timeout)
      catch
        :exit, {:timeout, _call} ->
          GenServer.cast(pid, {:cancel_await, request_ref})
          {:error, :timeout}

        :exit, reason ->
          {:error, {:session_call_failed, reason}}
      end
    end
  end

  @doc "Steers an active native provider turn when its transport supports steering."
  def steer(session, input, opts \\ []) do
    with :ok <- validate_options(opts, @turn_options) do
      call(session, {:steer, input, opts})
    end
  end

  @doc "Responds to a normalized provider approval request."
  def respond_approval(session, request_id, response) do
    if is_binary(request_id) and String.trim(request_id) != "",
      do: call(session, {:respond_approval, request_id, response}),
      else: {:error, :invalid_request_id}
  end

  @doc """
  Asks this session's owner for a human decision on a tool call the provider cannot ask
  about itself.

  The one caller today is `ouro mcp-serve`, the stdio MCP server Claude Code is given as
  its `--permission-prompt-tool`. The coordinator mints the request id, records the
  question durably, consults the permission engine, and blocks until
  `respond_approval/3` names that id or its own deadline passes.

  Waits under a ceiling of its own — one minute above the coordinator's, one minute below
  the gateway's — so the answer a caller receives is the runtime's denial rather than a
  transport that stopped listening. A caller that gives up first tells the coordinator so,
  exactly as `await/3` does, and the row is closed as a denial rather than left open.
  """
  @spec request_approval(session(), map()) :: {:ok, map()} | {:error, term()}
  def request_approval(session, request) when is_map(request) do
    with {:ok, id, owner} <- session_identity(session) do
      request_ref = make_ref()

      if owner == node() do
        local_request_approval(id, request_ref, request, @approval_request_timeout)
      else
        route(
          owner,
          __MODULE__,
          :local_request_approval,
          [id, request_ref, request, @approval_request_timeout],
          transport_timeout(@approval_request_timeout)
        )
      end
    end
  end

  def request_approval(_session, _request), do: {:error, :invalid_approval_request}

  @doc false
  def local_request_approval(id, request_ref, request, timeout) do
    with :ok <- validate_id(id),
         true <- is_reference(request_ref) || {:error, :invalid_request_reference},
         true <- is_map(request) || {:error, :invalid_approval_request},
         :ok <- validate_timeout(timeout),
         {:ok, pid} <- ensure_coordinator(id) do
      try do
        GenServer.call(pid, {:request_approval, request_ref, request}, timeout)
      catch
        :exit, {:timeout, _call} ->
          GenServer.cast(pid, {:cancel_approval, request_ref})
          {:error, :timeout}

        :exit, reason ->
          {:error, {:session_call_failed, reason}}
      end
    end
  end

  @doc "Interrupts an active turn without closing the provider session."
  def interrupt(session, turn_id \\ :active)

  def interrupt(session, :active), do: call(session, {:interrupt, :active})

  def interrupt(session, turn_id) when is_binary(turn_id) do
    with :ok <- validate_turn_id(turn_id), do: call(session, {:interrupt, turn_id})
  end

  def interrupt(_session, _turn_id), do: {:error, :invalid_turn_id}

  @doc "Closes the provider session gracefully."
  def close(session), do: call(session, :close)

  @doc "Forcibly cancels the provider session."
  def kill(session), do: call(session, :kill)

  @doc """
  Deletes a terminal session's durable record.

  Live sessions must be closed or killed first. The coordinator is stopped before the
  checkpoint is removed so a retiring process cannot write the session back.
  """
  @spec delete(session()) :: :ok | :not_found | {:error, term()}
  def delete(session) do
    with {:ok, id, owner} <- session_identity(session) do
      if owner == node() do
        local_delete(id)
      else
        route(owner, __MODULE__, :local_delete, [id], call_timeout())
      end
    end
  end

  @doc false
  def local_delete(id) do
    with :ok <- validate_id(id) do
      case Store.get(id) do
        :not_found ->
          :not_found

        {:error, reason} ->
          {:error, {:storage_error, reason}}

        {:ok, %State{node: owner}} when owner != node() ->
          {:error, {:wrong_owner, owner}}

        {:ok, %State{} = session} ->
          if State.terminal?(session) do
            stop_local_coordinator(id)
            Store.delete(id)
          else
            {:error, {:session_not_terminal, session.status}}
          end
      end
    end
  end

  @doc false
  def local_call(id, message) do
    with :ok <- validate_id(id),
         {:ok, pid} <- ensure_coordinator(id),
         do: safe_call(pid, message, call_timeout())
  end

  defp create_or_match(session) do
    case Store.create(session) do
      :ok ->
        {:ok, session}

      {:error, :already_exists} ->
        case Store.get(session.id) do
          {:ok, existing} ->
            if same_request?(existing, session),
              do: {:ok, existing},
              else: {:error, {:session_id_conflict, session.id}}

          other ->
            {:error, {:existing_session_unavailable, other}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp same_request?(left, right) do
    immutable = [:id, :node, :provider, :workspace_mode, :event_limit, :options]

    Map.take(left, immutable) == Map.take(right, immutable) and
      canonical_workspace(left.workspace) == canonical_workspace(right.workspace)
  end

  defp call(session, message) do
    with {:ok, id, owner} <- session_identity(session) do
      if owner == node(),
        do: local_call(id, message),
        else: route(owner, __MODULE__, :local_call, [id, message], call_timeout())
    end
  end

  defp stop_local_coordinator(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        _ = DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)
        :ok

      _absent ->
        :ok
    end
  end

  defp ensure_coordinator(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        {:ok, pid}

      nil ->
        case Store.get(id) do
          {:ok, %State{node: owner}} when owner == node() ->
            case DynamicSupervisor.start_child(Ouroboros.Interactive.TaskSupervisor, {Task, id}) do
              {:ok, pid} -> {:ok, pid}
              {:error, {:already_started, pid}} -> {:ok, pid}
              {:error, reason} -> {:error, reason}
            end

          {:ok, %State{node: owner}} ->
            {:error, {:wrong_owner, owner}}

          :not_found ->
            {:error, :not_found}

          {:error, reason} ->
            {:error, {:storage_error, reason}}
        end
    end
  end

  defp safe_call(pid, message, timeout) do
    try do
      GenServer.call(pid, message, timeout)
    catch
      :exit, {:timeout, _call} -> {:error, :timeout}
      :exit, reason -> {:error, {:session_call_failed, reason}}
    end
  end

  # Starting a session remotely keeps an unbounded transport: it has no
  # caller-supplied timeout to thread, and provider start-up latency is legitimately
  # unbounded.
  defp route(owner, module, function, arguments, timeout \\ :infinity) do
    cond do
      owner == node() -> apply(module, function, arguments)
      owner not in Node.list() -> {:error, {:owner_unavailable, owner}}
      true -> :erpc.call(owner, module, function, arguments, timeout)
    end
  catch
    :error, {:erpc, reason} when reason in [:noconnection, :timeout] ->
      {:error, {:owner_unavailable, owner, reason}}

    kind, reason ->
      {:error, {:remote_call_failed, owner, kind, reason}}
  end

  defp call_timeout do
    case Application.get_env(:ouroboros, :session_call_timeout, @default_call_timeout) do
      :infinity -> :infinity
      timeout when is_integer(timeout) and timeout > 0 -> timeout
      _invalid -> @default_call_timeout
    end
  end

  # `await/3` validates the timeout before routing, so only these two shapes reach here.
  defp transport_timeout(:infinity), do: :infinity
  defp transport_timeout(timeout) when is_integer(timeout), do: timeout + @remote_margin_ms

  defp validate_timeout(:infinity), do: :ok
  defp validate_timeout(timeout) when is_integer(timeout) and timeout >= 0, do: :ok
  defp validate_timeout(timeout), do: {:error, {:invalid_timeout, timeout}}

  defp send_turn(session, mode, input, opts) do
    with :ok <- validate_options(opts, [:id | @turn_options]),
         id = Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0),
         :ok <- validate_turn_id(id) do
      call(session, {:send_turn, mode, id, input, Keyword.delete(opts, :id)})
    end
  end

  defp validate_options(opts, allowed) when is_list(opts) do
    cond do
      not Keyword.keyword?(opts) ->
        {:error, :invalid_options}

      Keyword.keys(opts) != Enum.uniq(Keyword.keys(opts)) ->
        {:error, :duplicate_options}

      unknown = Enum.find(Keyword.keys(opts), &(&1 not in allowed)) ->
        {:error, {:unknown_option, unknown}}

      true ->
        :ok
    end
  end

  defp validate_options(_opts, _allowed), do: {:error, :invalid_options}

  defp valid_options?(opts) when is_list(opts) do
    Keyword.keyword?(opts) and Keyword.keys(opts) == Enum.uniq(Keyword.keys(opts))
  end

  defp session_identity(%Ref{id: id, node: owner}) do
    with :ok <- validate_id(id),
         true <- (is_atom(owner) and not is_nil(owner)) || {:error, :invalid_owner},
         do: {:ok, id, owner}
  end

  defp session_identity(id) when is_binary(id) do
    with :ok <- validate_id(id), do: {:ok, id, node()}
  end

  defp session_identity(_session), do: {:error, :invalid_session}

  defp validate_id(id) when is_binary(id) do
    if String.trim(id) == "", do: {:error, :invalid_session_id}, else: :ok
  end

  defp validate_id(_id), do: {:error, :invalid_session_id}

  defp validate_turn_id(id) when is_binary(id) do
    if String.trim(id) == "", do: {:error, :invalid_turn_id}, else: :ok
  end

  defp validate_turn_id(_id), do: {:error, :invalid_turn_id}

  defp canonical_workspace(workspace) do
    case Ouroboros.Workspace.Path.canonicalize(workspace) do
      {:ok, canonical} -> canonical
      {:error, _reason} -> workspace
    end
  end
end
