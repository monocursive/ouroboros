defmodule Ouroboros.CodingSession do
  @moduledoc """
  Supervised, provider-neutral coding runs with durable task state and replay.

  A `%Ouroboros.Coding.TaskRef{}` carries the node-local Harness ownership needed
  to route calls safely across Erlang distribution. Passing a bare task ID is a
  deliberate local-node convenience.
  """

  alias Jido.Harness.ApprovalResponse
  alias Ouroboros.Coding.{Store, Task, TaskRef, TaskState}

  @type task :: TaskRef.t() | String.t()

  # Control-plane operations (info/replay/subscribe/unsubscribe/cancel) are bounded so
  # one wedged coordinator cannot freeze every caller, cancellation included. `await/2`
  # is the deliberate exception: it threads the caller's own timeout, and the transport
  # is given that timeout plus a margin so the local waiter, not the transport, decides.
  @immutable_request_fields [
    :id,
    :node,
    :objective,
    :provider,
    :workspace_mode,
    :origin_digest,
    :event_limit,
    :options,
    # G1. A task adopted under an id that already belongs to a different conversation is
    # a different request, not the same one retried.
    :parent
  ]

  @doc "Starts a detached coding task on the local node."
  @spec start(String.t(), keyword()) :: {:ok, TaskRef.t()} | {:error, term()}
  def start(objective, opts \\ []) when is_binary(objective) and is_list(opts) do
    case start_for_gateway(objective, opts) do
      {:created, %TaskRef{}, reason} -> {:error, reason}
      result -> result
    end
  end

  @doc false
  @spec start_for_gateway(String.t(), keyword()) ::
          {:ok, TaskRef.t()} | {:created, TaskRef.t(), term()} | {:error, term()}
  def start_for_gateway(objective, opts \\ []) when is_binary(objective) and is_list(opts) do
    id = Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0)

    with {:ok, requested} <- TaskState.new(id, objective, opts),
         {:ok, task} <- create_or_match(requested) do
      ref = TaskRef.new(id)

      case task.status do
        status when status in [:failed, :lost] ->
          {:created, ref, task.error || {:task_start_failed, status}}

        status when status in [:completed, :cancelled] ->
          {:ok, ref}

        _active ->
          case ensure_coordinator(id) do
            {:ok, _pid} ->
              {:ok, ref}

            {:error, reason} ->
              case fail_unstarted_task(task, reason) do
                {:error, failure} -> {:created, ref, failure}
              end
          end
      end
    end
  end

  @doc "Starts a detached coding task on a connected BEAM node."
  @spec start_on(node(), String.t(), keyword()) :: {:ok, TaskRef.t()} | {:error, term()}
  def start_on(owner, objective, opts \\ []) when is_atom(owner) do
    route(owner, __MODULE__, :start, [objective, opts])
  end

  @doc false
  @spec start_for_gateway_on(node(), String.t(), keyword()) ::
          {:ok, TaskRef.t()} | {:created, TaskRef.t(), term()} | {:error, term()}
  def start_for_gateway_on(owner, objective, opts \\ []) when is_atom(owner) do
    route(owner, __MODULE__, :start_for_gateway, [objective, opts])
  end

  @doc "Returns a durable task snapshot."
  @spec info(task()) :: {:ok, TaskState.t()} | {:error, term()}
  def info(task), do: call(task, :info)

  @doc "Lists durable tasks owned by the local node."
  @spec list() :: [TaskState.t()]
  def list do
    Store.list()
    |> Enum.filter(&(&1.node == node()))
    |> Enum.map(&TaskState.public/1)
  end

  @doc """
  The workspaces of the coding tasks this node holds, for the code-intelligence admission.

  Same contract as `Ouroboros.InteractiveSession.workspaces/0`: a task's workspace is
  already where this node runs an agent with a shell, so a language server rooted there
  adds no capability the task lacks. Deleting the task withdraws the admission.
  """
  @spec workspaces() :: [Path.t()]
  def workspaces do
    Store.list()
    |> Enum.filter(&(&1.node == node()))
    |> Enum.map(& &1.workspace)
    |> Enum.filter(&is_binary/1)
    |> Enum.uniq()
  end

  @doc "Returns retained events whose sequence is greater than `:cursor`."
  @spec replay(task(), keyword()) :: {:ok, [Ouroboros.Coding.Event.t()]} | {:error, term()}
  def replay(task, opts \\ []) do
    cursor = Keyword.get(opts, :cursor, 0)
    limit = Keyword.get(opts, :limit, 100)
    call(task, {:replay, cursor, limit})
  end

  @doc "Atomically subscribes the caller and returns its persisted backlog."
  @spec subscribe(task(), keyword()) :: {:ok, [Ouroboros.Coding.Event.t()]} | {:error, term()}
  def subscribe(task, opts \\ []) do
    cursor = Keyword.get(opts, :cursor, 0)
    call(task, {:subscribe, self(), cursor})
  end

  @doc "Stops delivering task events to the caller."
  @spec unsubscribe(task()) :: :ok | {:error, term()}
  def unsubscribe(task), do: call(task, {:unsubscribe, self()})

  @doc "Waits for terminal durable task state without cancelling on timeout."
  @spec await(task(), timeout()) :: {:ok, TaskState.t()} | {:error, term()}
  def await(task, timeout \\ :infinity) do
    request_ref = make_ref()
    owner = owner(task)
    id = id(task)

    if owner == node() do
      local_await(id, request_ref, timeout)
    else
      route(
        owner,
        __MODULE__,
        :local_await,
        [id, request_ref, timeout],
        transport_timeout(timeout)
      )
    end
  end

  @doc false
  def local_await(id, _request_ref, 0) do
    with {:ok, %TaskState{} = task} <- local_call(id, :info) do
      if TaskState.terminal?(task), do: {:ok, task}, else: {:error, :timeout}
    end
  end

  def local_await(id, request_ref, timeout) do
    with :ok <- validate_timeout(timeout),
         {:ok, pid} <- ensure_coordinator(id) do
      try do
        GenServer.call(pid, {:await, request_ref}, timeout)
      catch
        :exit, {:timeout, _call} ->
          GenServer.cast(pid, {:cancel_await, request_ref})
          {:error, :timeout}

        :exit, reason ->
          {:error, {:task_call_failed, reason}}
      end
    end
  end

  @doc "Requests cancellation; inspect or await the final state afterward."
  @spec cancel(task()) :: :ok | {:error, term()}
  def cancel(task), do: call(task, :cancel)

  @doc "Validates and durably responds to a Native coding-run approval request."
  @spec respond_approval(task(), String.t(), map()) :: :ok | {:error, term()}
  def respond_approval(task, request_id, response) do
    with true <- is_binary(request_id) and String.trim(request_id) != "",
         true <- is_map(response),
         actor when actor in [:human, :headless, :automation] <-
           Map.get(response, :actor, :human),
         {:ok, approval} <-
           ApprovalResponse.new(
             Map.take(response, [:decision, :scope, :reason, :provider_options])
           ) do
      call(task, {:respond_approval, request_id, approval, actor})
    else
      false -> {:error, :invalid_approval_response}
      {:error, reason} -> {:error, {:invalid_approval_response, reason}}
      invalid -> {:error, {:invalid_approval_actor, invalid}}
    end
  end

  @doc """
  Deletes a terminal coding task's durable record.

  Live tasks must be cancelled first. The coordinator is stopped before the checkpoint is
  removed so a retiring process cannot write the task back.
  """
  @spec delete(task()) :: :ok | :not_found | {:error, term()}
  def delete(task) do
    owner = owner(task)
    id = id(task)

    if owner == node() do
      local_delete(id)
    else
      route(owner, __MODULE__, :local_delete, [id], call_timeout())
    end
  end

  @doc false
  def local_delete(id) when is_binary(id) do
    case Store.get(id) do
      :not_found ->
        :not_found

      {:error, reason} ->
        {:error, {:storage_error, reason}}

      {:ok, %TaskState{node: owner}} when owner != node() ->
        {:error, {:wrong_owner, owner}}

      {:ok, %TaskState{} = task} ->
        if TaskState.terminal?(task) do
          stop_local_coordinator(id)
          Store.delete(id)
        else
          {:error, {:task_not_terminal, task.status}}
        end
    end
  end

  @doc false
  def local_call(id, message) do
    with {:ok, pid} <- ensure_coordinator(id) do
      GenServer.call(pid, message, call_timeout())
    end
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, reason -> {:error, {:task_call_failed, reason}}
  end

  defp stop_local_coordinator(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        _ = DynamicSupervisor.terminate_child(Ouroboros.Coding.TaskSupervisor, pid)
        :ok

      _absent ->
        :ok
    end
  end

  defp call(task, message) do
    owner = owner(task)
    id = id(task)

    if owner == node() do
      local_call(id, message)
    else
      route(owner, __MODULE__, :local_call, [id, message], call_timeout())
    end
  end

  # A caller-generated ID is the start idempotency key. `Store.create/1` is serialized,
  # so concurrent starts elect exactly one durable request; every loser may adopt it only
  # when the normalized immutable intent is identical. Mutable run state — status,
  # cursor, events, Harness IDs, timestamps, results, and workspace lease — never enters
  # the comparison.
  defp create_or_match(requested) do
    case Store.create(requested) do
      :ok ->
        {:ok, requested}

      {:error, :already_exists} ->
        case Store.get(requested.id) do
          {:ok, existing} ->
            if same_request?(existing, requested),
              do: {:ok, existing},
              else: {:error, {:task_id_conflict, requested.id}}

          other ->
            {:error, {:existing_task_unavailable, other}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp same_request?(left, right) do
    Map.take(left, @immutable_request_fields) == Map.take(right, @immutable_request_fields) and
      canonical_workspace(left.workspace) == canonical_workspace(right.workspace)
  end

  defp ensure_coordinator(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        {:ok, pid}

      nil ->
        case Store.get(id) do
          {:ok, %TaskState{node: owner}} when owner == node() ->
            case DynamicSupervisor.start_child(Ouroboros.Coding.TaskSupervisor, {Task, id}) do
              {:ok, pid} -> {:ok, pid}
              {:error, {:already_started, pid}} -> {:ok, pid}
              {:error, reason} -> {:error, reason}
            end

          {:ok, %TaskState{node: owner}} ->
            {:error, {:wrong_owner, owner}}

          :not_found ->
            {:error, :not_found}

          {:error, reason} ->
            {:error, {:storage_error, reason}}
        end
    end
  end

  # Starting a task remotely keeps an unbounded transport: it has no caller-supplied
  # timeout to thread, and provider start-up latency is legitimately unbounded.
  defp route(owner, module, function, arguments, timeout \\ :infinity),
    do: Ouroboros.Session.Routing.route(owner, module, function, arguments, timeout)

  defp call_timeout, do: Ouroboros.Session.Routing.call_timeout()
  defp transport_timeout(timeout), do: Ouroboros.Session.Routing.transport_timeout(timeout)

  defp canonical_workspace(workspace) do
    case Ouroboros.Workspace.Path.canonicalize(workspace) do
      {:ok, canonical} -> canonical
      {:error, _reason} -> workspace
    end
  end

  defp fail_unstarted_task(task, reason) do
    case Store.get(task.id) do
      {:ok, %TaskState{status: :failed, error: {:workspace_admission_failed, _reason} = error}} ->
        {:error, error}

      _other ->
        redacted = Jido.Harness.Redaction.redact(reason)

        failed = %{
          task
          | status: :failed,
            error: {:coordinator_start_failed, redacted},
            updated_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        case Store.put(failed) do
          :ok ->
            {:error, {:coordinator_start_failed, redacted}}

          {:error, store_reason} ->
            {:error,
             {:coordinator_start_failed, redacted, {:failure_checkpoint_failed, store_reason}}}
        end
    end
  end

  defp validate_timeout(:infinity), do: :ok
  defp validate_timeout(timeout) when is_integer(timeout) and timeout > 0, do: :ok
  defp validate_timeout(timeout), do: {:error, {:invalid_timeout, timeout}}

  defp owner(%TaskRef{node: owner}), do: owner
  defp owner(id) when is_binary(id), do: node()

  defp id(%TaskRef{id: id}), do: id
  defp id(id) when is_binary(id), do: id
end
