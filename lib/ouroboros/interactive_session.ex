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

  @doc "Starts or adopts a caller-independent interactive coding session."
  @spec start(keyword()) :: {:ok, Ref.t()} | {:error, term()}
  def start(opts \\ [])

  def start(opts) when is_list(opts) do
    if valid_options?(opts) do
      id = Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0)

      with {:ok, session} <- State.new(id, opts),
           :ok <- create_or_match(session),
           {:ok, pid} <- ensure_coordinator(id) do
        case safe_call(pid, :ready) do
          {:ok, _state} -> {:ok, Ref.new(id)}
          {:error, reason} -> {:error, reason}
        end
      else
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :invalid_options}
    end
  end

  def start(_opts), do: {:error, :invalid_options}

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
        route(owner, __MODULE__, :local_await, [id, turn_id, request_ref, timeout])
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

  @doc false
  def local_call(id, message) do
    with :ok <- validate_id(id), {:ok, pid} <- ensure_coordinator(id), do: safe_call(pid, message)
  end

  defp create_or_match(session) do
    case Store.create(session) do
      :ok ->
        :ok

      {:error, :already_exists} ->
        case Store.get(session.id) do
          {:ok, existing} ->
            if same_request?(existing, session),
              do: :ok,
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
        else: route(owner, __MODULE__, :local_call, [id, message])
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

  defp safe_call(pid, message) do
    try do
      GenServer.call(pid, message, :infinity)
    catch
      :exit, reason -> {:error, {:session_call_failed, reason}}
    end
  end

  defp route(owner, module, function, arguments) do
    cond do
      owner == node() -> apply(module, function, arguments)
      owner not in Node.list() -> {:error, {:owner_unavailable, owner}}
      true -> :erpc.call(owner, module, function, arguments, :infinity)
    end
  catch
    :error, {:erpc, reason} when reason in [:noconnection, :timeout] ->
      {:error, {:owner_unavailable, owner, reason}}

    kind, reason ->
      {:error, {:remote_call_failed, owner, kind, reason}}
  end

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
