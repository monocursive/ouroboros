defmodule Ouroboros.Team.Server.State do
  @moduledoc false

  @enforce_keys [
    :id,
    :coordinator_id,
    :coordinator_pid,
    :coordinator_monitor,
    :status,
    :created_at,
    :updated_at,
    :store
  ]
  defstruct @enforce_keys ++
              [
                workers: %{},
                delegations: %{},
                waiters: %{},
                waiter_monitors: %{},
                cleanup_agents?: true,
                durability: :ephemeral_checkpoint,
                backoff: %{},
                start_deadlines: %{}
              ]
end

defmodule Ouroboros.Team.Server do
  @moduledoc """
  Supervised execution owner for an Ouroboros team.

  Coding runs are detached from request callers. Subscription is atomic: the
  server registers for live `CodingSession` events and receives the persisted
  backlog in the same call, then deduplicates both paths with a cursor. A terminal
  event is only progress evidence; final delivery begins after `CodingSession.info/1`
  exposes a persisted terminal result.

  A serializable aggregate checkpoint is committed before accepted membership,
  delegation, cancellation, cursor, and delivery transitions become visible to
  callers. Runtime PIDs and waiter capabilities never enter that checkpoint.
  Abnormal process failure is recovered by the supervisor without cancelling the
  detached run; orderly shutdown first closes the aggregate so it cannot resurrect.
  Recovery therefore never compensates a coding task it merely failed to resubscribe
  to: a rejected cursor or unreachable owner degrades the delegation to completion
  polling with the error recorded. Only a fresh `delegate/4` request fails fast.

  Transport ambiguity during startup is not a durable failure. Because the coding
  task ID is deterministic, an unreachable owner keeps the delegation `:starting`
  and retries with backoff until `:delegation_start_retry_ms` elapses; the durable
  failure then records that provider-side work may exist unconfirmed.

  Local workers use Jido's logical parent/child machinery. Jido 2.3.3 validates
  adopted children with a local-only `Process.alive?/1` guard, so remote PIDs
  cannot be adopted honestly. Remote workers instead retain the coordinator ID
  in their inspectable Mesh agent state and are marked `:mesh_remote` in both
  runtime and coordinator projections.
  """

  use GenServer

  require Logger

  alias Ouroboros.Agent.Coordinator
  alias Ouroboros.AgentProfile
  alias Ouroboros.Coding.{Event, TaskRef, TaskState}
  alias Ouroboros.Coding.Store, as: CodingStore
  alias Ouroboros.Team.Server.State
  alias Ouroboros.Team.Snapshot
  alias Ouroboros.Team.Snapshot.{Delegation, Worker}
  alias Ouroboros.Team.Store
  alias Ouroboros.Team.Signals.{TaskDelegated, TaskFinalized, TeamStarted, WorkerAdded}
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @completion_check_ms 25
  @delivery_retry_ms 50
  @backoff_cap_ms 5_000
  @default_start_retry_ms 300_000
  @mesh_visibility_timeout_ms 2_000
  @worker_reconcile_ms 250
  @terminal_statuses [:completed, :failed, :cancelled, :lost]
  @server_options [:id, :coordinator_id, :cleanup_agents, :store]
  @worker_options [:role, :node]
  @registry Ouroboros.Team.Registry

  def child_spec(opts) do
    # Team IDs become coordinator IDs in the cluster-wide Mesh namespace. A VM-local
    # integer alone can collide with the same default allocated on another machine, so
    # generated IDs carry the stable BEAM owner. Explicit durable IDs remain byte-for-byte
    # unchanged for restart and snapshot recovery.
    team_id = Keyword.get_lazy(opts, :id, &default_team_id/0)

    %{
      id: Keyword.get(opts, :supervisor_id, {__MODULE__, team_id}),
      start: {__MODULE__, :start_link, [Keyword.put(opts, :id, team_id)]},
      restart: :transient,
      type: :worker
    }
  end

  def start_link(opts) when is_list(opts) do
    with true <- Keyword.keyword?(opts),
         {:ok, team_id} <- required_id(opts) do
      GenServer.start_link(__MODULE__, opts, name: via(team_id))
    else
      false -> {:error, :invalid_team_options}
      {:error, reason} -> {:error, reason}
    end
  end

  def start_link(_opts), do: {:error, :invalid_team_options}

  @doc false
  def build_delegated_task_state(id, objective, opts) when is_list(opts) do
    workspace = Keyword.get(opts, :workspace, File.cwd!())

    with {:ok, canonical_workspace} <- canonical_workspace(workspace) do
      TaskState.new(id, objective, Keyword.put(opts, :workspace, canonical_workspace))
    end
  end

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    with :ok <- validate_options(opts),
         {:ok, team_id} <- required_id(opts),
         {:ok, coordinator_id} <- coordinator_id(opts, team_id),
         :ok <- validate_cleanup_agents(opts),
         store <- Keyword.get(opts, :store, Store),
         {:ok, snapshot} <- load_or_create_snapshot(store, opts, team_id, coordinator_id),
         :ok <- ensure_recoverable(snapshot) do
      case restore_runtime(snapshot, store) do
        {:ok, state} ->
          {:ok, state, {:continue, :reconcile}}

        {:error, reason} ->
          {:stop, fence_deterministic_startup_failure(store, snapshot, reason)}
      end
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_continue(:reconcile, state) do
    transition_info(reconcile_delegations(state), state, :team_reconciliation_failed)
  end

  @impl true
  def handle_call(:state, _from, state), do: {:reply, public_state(state), state}

  def handle_call(:coordinator_state, _from, state) do
    reply =
      with pid when is_pid(pid) <- Ouroboros.Mesh.whereis(state.coordinator_id),
           :ok <- verify_coordinator_owner(pid, state.id, state.coordinator_id) do
        safe_agent_state(pid)
      else
        nil -> {:error, {:coordinator_not_found, state.coordinator_id}}
        {:error, reason} -> {:error, reason}
      end

    {:reply, reply, state}
  end

  def handle_call({:add_worker, _worker_id, _opts}, _from, %State{status: :closing} = state) do
    {:reply, {:error, :team_closing}, state}
  end

  def handle_call({:add_worker, worker_id, opts}, _from, state) do
    case add_worker(state, worker_id, opts) do
      {:ok, worker, state} -> {:reply, {:ok, worker}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(
        {:delegate, _worker_id, _objective, _opts},
        _from,
        %State{status: :closing} = state
      ) do
    {:reply, {:error, :team_closing}, state}
  end

  def handle_call({:delegate, worker_id, objective, opts}, _from, state) do
    case delegate(state, worker_id, objective, opts) do
      {:ok, delegation, state} -> {:reply, {:ok, public_delegation(delegation)}, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:cancel, delegation_id}, _from, state) when is_binary(delegation_id) do
    case request_cancellation(state, delegation_id) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:cancel, _delegation_id}, _from, state) do
    {:reply, {:error, :invalid_delegation_id}, state}
  end

  def handle_call(:close, _from, state) do
    case begin_close(state) do
      {:ok, %State{status: :closed} = state} ->
        {:stop, :normal, :ok, state}

      {:ok, state} ->
        {:reply, :ok, state}

      {:accepted, reason, state} ->
        {:stop, {:team_close_checkpoint_failed, reason}, :ok, state}

      {:error, reason} ->
        {:reply, {:error, {:team_close_checkpoint_failed, reason}}, state}
    end
  end

  def handle_call({:await, delegation_id, _request_ref}, _from, state)
      when not is_binary(delegation_id) do
    {:reply, {:error, :invalid_delegation_id}, state}
  end

  def handle_call({:await, delegation_id, request_ref}, from, state) do
    case Map.fetch(state.delegations, delegation_id) do
      :error ->
        {:reply, {:error, :not_found}, state}

      {:ok, %Delegation{delivery: :delivered} = delegation} ->
        {:reply, {:ok, public_delegation(delegation)}, state}

      {:ok, _delegation} ->
        monitor = Process.monitor(elem(from, 0))
        waiter = {from, monitor}
        delegation_waiters = Map.get(state.waiters, delegation_id, %{})

        state = %{
          state
          | waiters:
              Map.put(
                state.waiters,
                delegation_id,
                Map.put(delegation_waiters, request_ref, waiter)
              ),
            waiter_monitors: Map.put(state.waiter_monitors, monitor, {delegation_id, request_ref})
        }

        {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:cancel_await, delegation_id, request_ref}, state) do
    {:noreply, drop_waiter(state, delegation_id, request_ref)}
  end

  @impl true
  def handle_info({:ouroboros_coding_event, task_id, %Event{} = event}, state) do
    case delegation_id_for_task(state, task_id) do
      nil ->
        {:noreply, state}

      delegation_id ->
        case consume_event(state, delegation_id, event) do
          {:ok, state} ->
            if Event.terminal?(event), do: schedule_completion_check(delegation_id, 0)
            {:noreply, state}

          {:error, reason} ->
            {:stop, {:team_checkpoint_failed, reason}, state}
        end
    end
  end

  def handle_info({:check_completion, delegation_id}, state) do
    transition_info(check_completion(state, delegation_id), state)
  end

  def handle_info({:deliver_terminal, delegation_id}, state) do
    transition_info(deliver_terminal(state, delegation_id), state)
  end

  def handle_info({:retry_cancel, delegation_id}, state) do
    transition_info(propagate_cancellation(state, delegation_id), state)
  end

  def handle_info({:retry_start, delegation_id}, state) do
    transition_info(resume_delegation_start(state, delegation_id), state)
  end

  # Cluster.Monitor retains topology churn and broadcasts it to every live local team.
  # Durable membership is not revoked by a disconnect: on rejoin, recreate or adopt the
  # exact logical workers assigned to that owner. Repeated nodeup events and monitor
  # restarts are safe because Mesh identity and the stored owner fence every adoption.
  def handle_info({:ouroboros_cluster, :nodeup, owner}, state) when is_atom(owner) do
    Process.send_after(self(), {:reconcile_workers, owner}, @worker_reconcile_ms)
    {:noreply, state}
  end

  def handle_info({:ouroboros_cluster, :nodedown, _owner}, state), do: {:noreply, state}

  def handle_info({:reconcile_workers, owner}, state) when is_atom(owner) do
    case reconcile_workers_on(state, owner) do
      {:ok, state} ->
        {:noreply, reset_backoff(state, {:worker_reconcile, owner})}

      {:retry, reason, state} ->
        {delay, state} = next_backoff(state, {:worker_reconcile, owner}, @worker_reconcile_ms)
        Process.send_after(self(), {:reconcile_workers, owner}, delay)

        Logger.debug(
          "team #{state.id} is waiting to restore workers on #{owner}: " <>
            inspect(reason, limit: 10, printable_limit: 200)
        )

        {:noreply, state}

      {:error, reason, state} ->
        Logger.error(
          "team #{state.id} could not reconcile workers on #{owner}: " <>
            inspect(reason, limit: 10, printable_limit: 200)
        )

        {:noreply, state}
    end
  end

  def handle_info(
        {:DOWN, monitor, :process, pid, reason},
        %State{coordinator_monitor: monitor, coordinator_pid: pid} = state
      ) do
    {:stop, {:coordinator_down, reason}, state}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    {:noreply, drop_waiter_by_monitor(state, monitor)}
  end

  # Team.Server has no linked execution children; its only normal link is its
  # OTP supervisor. Infrastructure shutdown is recoverable and must never be
  # interpreted as a user-requested durable close.
  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %State{status: :closed, cleanup_agents?: true} = state),
    do: cleanup_runtime(state)

  def terminate(_reason, _state), do: :ok

  defp cleanup_runtime(state) do
    Enum.each(state.delegations, fn {_delegation_id, delegation} ->
      if delegation.delivery != :delivered do
        cancel_owned_detached(delegation)
      end
    end)

    Enum.each(state.workers, fn {_worker_id, worker} ->
      _ = stop_exact(worker.pid)
    end)

    with pid when is_pid(pid) <- Ouroboros.Mesh.whereis(state.coordinator_id),
         :ok <- verify_coordinator_owner(pid, state.id, state.coordinator_id) do
      _ = stop_exact(pid)
    end

    :ok
  end

  defp add_worker(state, worker_id, opts)
       when is_binary(worker_id) and is_list(opts) do
    if Keyword.keyword?(opts) do
      case Enum.find(Keyword.keys(opts), &(&1 not in @worker_options)) do
        nil -> add_validated_worker(state, worker_id, opts)
        option -> {:error, {:unknown_worker_option, option}}
      end
    else
      {:error, :invalid_worker_options}
    end
  end

  defp add_worker(_state, _worker_id, _opts), do: {:error, :invalid_worker_options}

  defp add_validated_worker(state, worker_id, opts) do
    role = Keyword.get(opts, :role, "worker")
    worker_node = Keyword.get(opts, :node, node())

    cond do
      String.trim(worker_id) == "" ->
        {:error, :invalid_worker_id}

      Map.has_key?(state.workers, worker_id) ->
        {:error, {:worker_already_added, worker_id}}

      not is_binary(role) or String.trim(role) == "" ->
        {:error, :invalid_worker_role}

      not is_atom(worker_node) ->
        {:error, :invalid_worker_node}

      true ->
        # A named `:node` is a placement decision this server records durably, so the
        # target is checked before the worker exists rather than after a remote start
        # fails for an unnamed reason.
        with :ok <- validate_worker_node(worker_node),
             {:ok, pid} <-
               Ouroboros.Mesh.start_agent_on(worker_node, worker_id,
                 role: role,
                 parent_id: state.coordinator_id
               ) do
          finish_add_worker(state, worker_id, worker_node, role, pid)
        end
    end
  end

  defp validate_worker_node(worker_node) do
    case Ouroboros.Cluster.ensure_placeable(worker_node) do
      :ok -> :ok
      {:error, reason} -> {:error, {:invalid_worker_node, worker_node, reason}}
    end
  end

  defp delegate(state, worker_id, objective, opts)
       when is_binary(worker_id) and is_binary(objective) and is_list(opts) do
    if Keyword.keyword?(opts) do
      with {:ok, worker} <- fetch_worker(state, worker_id),
           :ok <- validate_objective(objective),
           {:ok, delegation_id} <- delegation_id(opts),
           coding_task_id = Snapshot.coding_task_id(state.id, delegation_id),
           coding_node <- Keyword.get(opts, :coding_node, worker.node),
           :ok <- validate_coding_node(coding_node),
           {:ok, fingerprint, durable_coding_options} <-
             request_fingerprint(worker_id, objective, coding_task_id, coding_node, opts) do
        case delegation_identity(state, delegation_id, fingerprint) do
          {:existing, delegation} ->
            {:ok, delegation, state}

          :new ->
            with :ok <- ensure_worker_available(state, worker_id) do
              durable_coding_options =
                Map.put(
                  durable_coding_options,
                  :origin_digest,
                  origin_digest(state.id, delegation_id, fingerprint)
                )

              assign_and_start(
                state,
                worker,
                delegation_id,
                coding_task_id,
                objective,
                coding_node,
                fingerprint,
                durable_coding_options
              )
            else
              {:error, reason} -> {:error, reason, state}
            end

          {:error, reason} ->
            {:error, reason, state}
        end
      else
        {:error, reason} -> {:error, reason, state}
      end
    else
      {:error, :invalid_delegation, state}
    end
  end

  defp delegate(state, _worker_id, _objective, _opts),
    do: {:error, :invalid_delegation, state}

  defp consume_event(state, delegation_id, %Event{} = event) do
    next_state = consume_event_without_checkpoint(state, delegation_id, event)

    if next_state == state do
      {:ok, state}
    else
      checkpoint(next_state)
    end
  end

  defp consume_event_without_checkpoint(state, delegation_id, %Event{} = event) do
    case Map.fetch(state.delegations, delegation_id) do
      {:ok, %Delegation{cursor: cursor}} when event.sequence > cursor ->
        delegation = Map.fetch!(state.delegations, delegation_id)

        delegation = %{
          delegation
          | cursor: event.sequence,
            event_count: delegation.event_count + 1,
            last_event: event,
            updated_at: timestamp()
        }

        %{state | delegations: Map.put(state.delegations, delegation_id, delegation)}

      _duplicate_or_unknown ->
        state
    end
  end

  defp check_completion(state, delegation_id) do
    case Map.fetch(state.delegations, delegation_id) do
      :error ->
        {:ok, state}

      {:ok, %Delegation{delivery: :delivered}} ->
        {:ok, state}

      {:ok, %Delegation{} = delegation} ->
        # The durable Coding store is the terminal source of truth. Calling the
        # coordinator here with an infinite timeout lets a suspended or wedged
        # coding process block this Team server, including a queued `close/1`
        # request whose only job is to checkpoint cancellation intent. One
        # verified checkpoint read per tick serves both ownership and progress,
        # so a busy store is polled once rather than twice.
        case verified_coding_task(delegation) do
          {:ok, %TaskState{status: status} = task} when status in @terminal_statuses ->
            delegation = %{
              delegation
              | status: status,
                result: task.result,
                error: task.error,
                delivery: :delivering,
                delivery_error: nil,
                updated_at: timestamp()
            }

            case checkpoint(put_delegation(state, delegation)) do
              {:ok, state} ->
                send(self(), {:deliver_terminal, delegation_id})
                notify_parent(delegation, task)
                {:ok, reset_backoff(state, {:completion, delegation_id})}

              {:error, reason} ->
                {:error, reason}
            end

          {:ok, %TaskState{}} ->
            schedule_completion_check(delegation_id, @completion_check_ms)
            {:ok, reset_backoff(state, {:completion, delegation_id})}

          {:error, reason} ->
            checkpoint_completion_error(state, delegation, delegation_id, reason)
        end
    end
  end

  # G1. The seam where a conversation learns its delegation ended. Deliberately after the
  # terminal status is checkpointed and deliberately fire-and-forget: this team's delivery
  # to its own worker is the obligation, and a parent conversation that is closed, on an
  # unreachable node, or simply not running must never hold it up or fail it. The parent's
  # copy is a hint that follows the record checkpointed just above, and
  # `interactive.delegations` reads *this* record rather than that copy when it wants the
  # truth.
  defp notify_parent(%Delegation{} = delegation, %TaskState{} = task) do
    case Map.get(task, :parent) do
      %{plane: :interactive, id: parent_id} when is_binary(parent_id) ->
        Ouroboros.InteractiveSession.note_delegation(
          Ouroboros.Interactive.Ref.new(parent_id, node_of(task)),
          delegation.id,
          delegation.status,
          result_digest(task.result)
        )

      _no_parent ->
        :ok
    end
  rescue
    _error -> :ok
  catch
    _kind, _reason -> :ok
  end

  # The conversation runs where its own record is, which is where the task was placed
  # from. A task whose node is somehow absent falls back to this one rather than guessing.
  defp node_of(%TaskState{node: owner}) when is_atom(owner) and not is_nil(owner), do: owner
  defp node_of(_task), do: node()

  # A digest, never the result. The result belongs to the child task's own record, and a
  # parent transcript that carried it would copy one plane's content into the other's log.
  defp result_digest(nil), do: nil

  defp result_digest(result) do
    :sha256
    |> :crypto.hash(:erlang.term_to_binary(result))
    |> Base.encode16(case: :lower)
    |> binary_slice(0, 32)
  end

  # A partitioned owner or a busy store would otherwise checkpoint the whole team
  # aggregate at every retry. Only a changed error term is durable news.
  defp checkpoint_completion_error(state, delegation, delegation_id, reason) do
    error = {:completion_check_failed, durable_error(reason)}
    {delay, state} = next_backoff(state, {:completion, delegation_id}, @delivery_retry_ms)
    schedule_completion_check(delegation_id, delay)

    if delegation.delivery_error == error do
      {:ok, state}
    else
      delegation = %{delegation | delivery_error: error, updated_at: timestamp()}
      checkpoint(put_delegation(state, delegation))
    end
  end

  defp request_cancellation(state, delegation_id) do
    case Map.fetch(state.delegations, delegation_id) do
      :error ->
        {:error, :not_found, state}

      {:ok, %Delegation{delivery: :delivered}} ->
        {:ok, state}

      {:ok, %Delegation{cancellation_requested_at: requested_at}}
      when is_binary(requested_at) ->
        case propagate_cancellation(state, delegation_id) do
          {:ok, state} -> {:ok, state}
          {:error, reason} -> {:error, reason, state}
        end

      {:ok, %Delegation{} = delegation} ->
        delegation = %{
          delegation
          | cancellation_requested_at: timestamp(),
            updated_at: timestamp()
        }

        case checkpoint(put_delegation(state, delegation)) do
          {:ok, state} ->
            # The durable request is accepted even if its first propagation
            # attempt fails. A retry is scheduled and recovery repeats it.
            case propagate_cancellation(state, delegation_id) do
              {:ok, state} -> {:ok, state}
              {:error, _reason} -> {:ok, state}
            end

          {:error, reason} ->
            {:error, {:cancellation_checkpoint_failed, reason}, state}
        end
    end
  end

  defp propagate_cancellation(state, delegation_id) do
    case Map.fetch(state.delegations, delegation_id) do
      {:ok, %Delegation{delivery: :delivered}} ->
        {:ok, state}

      {:ok, %Delegation{} = delegation} ->
        result =
          with :ok <- verify_coding_task_owner(delegation) do
            Ouroboros.CodingSession.cancel(delegation.task_ref)
          end

        case result do
          :ok ->
            schedule_completion_check(delegation_id, 0)
            {:ok, state}

          {:error, reason} ->
            redacted = durable_error(reason)

            delegation = %{
              delegation
              | delivery_error: {:cancellation_propagation_failed, redacted},
                updated_at: timestamp()
            }

            Process.send_after(self(), {:retry_cancel, delegation_id}, @delivery_retry_ms)
            checkpoint(put_delegation(state, delegation))
        end

      :error ->
        {:ok, state}
    end
  end

  defp deliver_terminal(state, delegation_id) do
    case Map.fetch(state.delegations, delegation_id) do
      {:ok, %Delegation{delivery: :delivering} = delegation} ->
        delivery = terminal_delivery(delegation)

        with {:ok, _worker_agent} <-
               Ouroboros.Mesh.complete_task(delegation.worker_id, delegation.id, delivery),
             {:ok, signal} <-
               TaskFinalized.new(
                 %{
                   delegation_id: delegation.id,
                   worker_id: delegation.worker_id,
                   status: delegation.status,
                   result: delegation.result,
                   error: delegation.error
                 },
                 subject: state.coordinator_id,
                 source: team_source(state.id)
               ),
             {:ok, _coordinator_agent} <- signal_coordinator(state, signal) do
          _ = unsubscribe_owned_coding_task(delegation)

          delegation = %{
            delegation
            | delivery: :delivered,
              delivery_error: nil,
              updated_at: timestamp()
          }

          case checkpoint(put_delegation(state, delegation)) do
            {:ok, state} ->
              state = reset_backoff(state, {:delivery, delegation_id})
              {:ok, reply_waiters(state, delegation)}

            {:error, reason} ->
              {:error, reason}
          end
        else
          {:error, reason} ->
            error = durable_error(reason)
            {delay, state} = next_backoff(state, {:delivery, delegation_id}, @delivery_retry_ms)
            Process.send_after(self(), {:deliver_terminal, delegation_id}, delay)

            if delegation.delivery_error == error do
              {:ok, state}
            else
              delegation = %{delegation | delivery_error: error, updated_at: timestamp()}
              checkpoint(put_delegation(state, delegation))
            end
        end

      _not_delivering ->
        {:ok, state}
    end
  end

  defp terminal_delivery(delegation) do
    %{
      coding_task_id: delegation.task_ref.id,
      coding_node: delegation.task_ref.node,
      status: delegation.status,
      result: delegation.result,
      error: delegation.error
    }
  end

  defp reply_waiters(state, delegation) do
    {waiters, all_waiters} = Map.pop(state.waiters, delegation.id, %{})

    waiter_monitors =
      Enum.reduce(waiters, state.waiter_monitors, fn {_request_ref, {from, monitor}}, monitors ->
        Process.demonitor(monitor, [:flush])
        GenServer.reply(from, {:ok, public_delegation(delegation)})
        Map.delete(monitors, monitor)
      end)

    %{state | waiters: all_waiters, waiter_monitors: waiter_monitors}
  end

  defp drop_waiter(state, delegation_id, request_ref) do
    case get_in(state.waiters, [delegation_id, request_ref]) do
      nil ->
        state

      {_from, monitor} ->
        Process.demonitor(monitor, [:flush])
        delegation_waiters = state.waiters[delegation_id] |> Map.delete(request_ref)

        waiters =
          if map_size(delegation_waiters) == 0,
            do: Map.delete(state.waiters, delegation_id),
            else: Map.put(state.waiters, delegation_id, delegation_waiters)

        %{
          state
          | waiters: waiters,
            waiter_monitors: Map.delete(state.waiter_monitors, monitor)
        }
    end
  end

  defp drop_waiter_by_monitor(state, monitor) do
    case Map.get(state.waiter_monitors, monitor) do
      nil -> state
      {delegation_id, request_ref} -> drop_waiter(state, delegation_id, request_ref)
    end
  end

  defp load_or_create_snapshot(store, opts, team_id, coordinator_id) do
    cleanup_agents? = Keyword.get(opts, :cleanup_agents, true)

    case store_call(store, :get, [team_id]) do
      :not_found ->
        snapshot = Snapshot.new(team_id, coordinator_id, cleanup_agents?)

        case store_call(store, :create, [snapshot]) do
          :ok ->
            {:ok, snapshot}

          {:error, :already_exists} ->
            load_or_create_snapshot(store, opts, team_id, coordinator_id)

          {:error, reason} ->
            {:error, {:team_checkpoint_create_failed, reason}}
        end

      {:ok, %Snapshot{} = snapshot} ->
        with true <- Snapshot.valid?(snapshot),
             :ok <- compatible_snapshot?(snapshot, opts, coordinator_id) do
          {:ok, snapshot}
        else
          false -> {:error, :invalid_team_snapshot}
          {:error, reason} -> {:error, reason}
        end

      {:ok, _invalid} ->
        {:error, :invalid_team_snapshot}

      {:error, reason} ->
        {:error, {:team_checkpoint_read_failed, reason}}
    end
  end

  defp compatible_snapshot?(snapshot, opts, coordinator_id) do
    cond do
      snapshot.coordinator_id != coordinator_id ->
        {:error,
         {:team_option_conflict, :coordinator_id, snapshot.coordinator_id, coordinator_id}}

      Keyword.has_key?(opts, :cleanup_agents) and
          snapshot.cleanup_agents? != Keyword.fetch!(opts, :cleanup_agents) ->
        {:error,
         {:team_option_conflict, :cleanup_agents, snapshot.cleanup_agents?,
          Keyword.fetch!(opts, :cleanup_agents)}}

      true ->
        :ok
    end
  end

  defp ensure_recoverable(%Snapshot{status: status}) when status in [:active, :closing], do: :ok
  defp ensure_recoverable(%Snapshot{status: :closed}), do: {:error, :team_closed}

  defp restore_runtime(snapshot, store) do
    with {:ok, coordinator_pid} <-
           start_or_adopt_coordinator(snapshot.coordinator_id, snapshot.id),
         {:ok, _agent} <-
           initialize_coordinator(coordinator_pid, snapshot.id, snapshot.coordinator_id),
         {:ok, durability} <- store_durability(store) do
      coordinator_monitor = Process.monitor(coordinator_pid)

      state = %State{
        id: snapshot.id,
        coordinator_id: snapshot.coordinator_id,
        coordinator_pid: coordinator_pid,
        coordinator_monitor: coordinator_monitor,
        status: snapshot.status,
        cleanup_agents?: snapshot.cleanup_agents?,
        workers: %{},
        delegations: snapshot.delegations,
        created_at: snapshot.created_at,
        updated_at: snapshot.updated_at,
        store: store,
        durability: durability
      }

      with {:ok, state} <- restore_workers(snapshot.workers, state),
           :ok <- restore_delegation_projections(state) do
        {:ok, state}
      end
    end
  end

  defp fence_deterministic_startup_failure(store, snapshot, reason) do
    if deterministic_coordinator_failure?(reason) do
      fenced = %{snapshot | status: :closed, updated_at: timestamp()}

      case store_call(store, :put, [fenced]) do
        :ok -> reason
        {:error, fence_reason} -> {:team_start_fence_failed, reason, fence_reason}
      end
    else
      reason
    end
  end

  defp deterministic_coordinator_failure?({kind, _coordinator_id, _actual, _expected})
       when kind in [:coordinator_owner_conflict, :coordinator_identity_conflict],
       do: true

  defp deterministic_coordinator_failure?(
         {:coordinator_module_conflict, _coordinator_id, _module}
       ),
       do: true

  defp deterministic_coordinator_failure?(_reason), do: false

  defp restore_workers(workers, state) do
    Enum.reduce_while(workers, {:ok, state}, fn {_worker_id, worker}, {:ok, state} ->
      case restore_worker(worker, state) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp restore_worker(%Worker{} = worker, state) do
    with {:ok, pid} <- start_or_adopt_worker(worker, state.coordinator_id),
         :ok <- await_mesh_visibility(worker.id, pid),
         {:ok, hierarchy} <- attach_worker(state, pid, worker.id, worker.node, worker.role) do
      runtime_worker = %{
        id: worker.id,
        pid: pid,
        node: worker.node,
        role: worker.role,
        hierarchy: hierarchy
      }

      next_state = %{state | workers: Map.put(state.workers, worker.id, runtime_worker)}
      _ = publish_worker_projection(next_state, runtime_worker)
      {:ok, next_state}
    end
  end

  defp start_or_adopt_worker(%Worker{} = worker, coordinator_id) do
    case Ouroboros.Mesh.whereis(worker.id) do
      pid when is_pid(pid) and node(pid) == worker.node ->
        {:ok, pid}

      pid when is_pid(pid) ->
        {:error, {:worker_owner_conflict, worker.id, worker.node, node(pid)}}

      nil ->
        case Ouroboros.Mesh.start_agent_on(worker.node, worker.id,
               role: worker.role,
               parent_id: coordinator_id
             ) do
          {:ok, pid} -> {:ok, pid}
          {:error, {:already_started, pid}} when is_pid(pid) -> {:ok, pid}
          {:error, reason} -> {:error, {:worker_restore_failed, worker.id, reason}}
        end
    end
  end

  defp reconcile_workers_on(state, owner) do
    assigned =
      state.workers
      |> Map.values()
      |> Enum.filter(&(&1.node == owner))

    if assigned == [] do
      {:ok, state}
    else
      worker_ids = assigned |> Enum.map(& &1.id) |> MapSet.new()

      case Ouroboros.Cluster.ensure_placeable(owner) do
        :ok ->
          case restore_assigned_workers(assigned, state) do
            {:ok, restored} ->
              restored
              |> restore_worker_delegations(worker_ids)
              |> worker_reconcile_result(restored)

            {:error, reason, restored} ->
              worker_reconcile_result({:error, reason}, restored)
          end

        {:error, reason} ->
          worker_reconcile_result({:error, reason}, state)
      end
    end
  end

  defp worker_reconcile_result(:ok, state), do: {:ok, state}

  defp worker_reconcile_result({:error, reason}, state) do
    if transient_worker_reconcile_error?(reason),
      do: {:retry, reason, state},
      else: {:error, reason, state}
  end

  defp restore_assigned_workers(workers, state) do
    Enum.reduce_while(workers, {:ok, state}, fn runtime_worker, {:ok, acc} ->
      durable_worker = %Worker{
        id: runtime_worker.id,
        node: runtime_worker.node,
        role: runtime_worker.role,
        hierarchy: runtime_worker.hierarchy
      }

      case restore_worker(durable_worker, acc) do
        {:ok, next} -> {:cont, {:ok, next}}
        {:error, reason} -> {:halt, {:error, reason, acc}}
      end
    end)
  end

  defp transient_worker_reconcile_error?(:node_not_connected), do: true
  defp transient_worker_reconcile_error?(:runtime_not_running), do: true
  defp transient_worker_reconcile_error?({:probe_failed, _reason}), do: true
  defp transient_worker_reconcile_error?({:mesh_visibility_timeout, _id, _owner}), do: true

  defp transient_worker_reconcile_error?({:worker_restore_failed, _id, reason}),
    do: transient_worker_reconcile_error?(reason)

  defp transient_worker_reconcile_error?({:placement_refused, _owner, reason}),
    do: transient_worker_reconcile_error?(reason)

  defp transient_worker_reconcile_error?({:remote_start_failed, _owner, _reason}), do: true

  defp transient_worker_reconcile_error?({:agent_state_call_failed, _owner, _kind, _reason}),
    do: true

  defp transient_worker_reconcile_error?({:agent_not_found, _id}), do: true
  defp transient_worker_reconcile_error?(_reason), do: false

  defp restore_delegation_projections(state) do
    with :ok <- restore_coordinator_delegations(state),
         :ok <- restore_worker_delegations(state) do
      :ok
    end
  end

  defp restore_coordinator_delegations(state) do
    state.delegations
    |> Enum.sort_by(fn {_id, delegation} -> {delegation.created_at, delegation.id} end)
    |> Enum.reduce_while(:ok, fn {_id, delegation}, :ok ->
      case restore_coordinator_delegation(state, delegation) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp restore_coordinator_delegation(state, delegation) do
    with :ok <- publish_delegated_projection(state, delegation) do
      if delegation.delivery == :delivered do
        publish_finalized_projection(state, delegation)
      else
        :ok
      end
    end
  end

  defp restore_worker_delegations(state), do: restore_worker_delegations(state, :all)

  defp restore_worker_delegations(state, worker_ids) do
    state.delegations
    |> Enum.group_by(fn {_id, delegation} -> delegation.worker_id end)
    |> Enum.filter(fn {worker_id, _delegations} ->
      worker_ids == :all or MapSet.member?(worker_ids, worker_id)
    end)
    |> Enum.reduce_while(:ok, fn {worker_id, delegations}, :ok ->
      case current_worker_delegation(delegations) do
        nil ->
          {:cont, :ok}

        delegation ->
          case restore_worker_delegation(state, worker_id, delegation) do
            :ok -> {:cont, :ok}
            {:error, reason} -> {:halt, {:error, reason}}
          end
      end
    end)
  end

  defp current_worker_delegation(delegations) do
    undelivered =
      Enum.filter(delegations, fn {_id, delegation} -> delegation.delivery != :delivered end)

    candidates = if undelivered == [], do: delegations, else: undelivered

    case candidates do
      [] ->
        nil

      values ->
        values
        |> Enum.max_by(fn {_id, delegation} -> delegation.updated_at || delegation.created_at end)
        |> elem(1)
    end
  end

  defp restore_worker_delegation(state, worker_id, delegation) do
    delegation_id = delegation.id

    with {:ok, ^delegation_id, _agent} <-
           Ouroboros.Mesh.assign_task(
             state.coordinator_id,
             worker_id,
             delegation.objective,
             task_id: delegation_id
           ) do
      if delegation.delivery == :delivered do
        case Ouroboros.Mesh.complete_task(
               worker_id,
               delegation_id,
               terminal_delivery(delegation)
             ) do
          {:ok, _agent} -> :ok
          {:error, reason} -> {:error, reason}
        end
      else
        :ok
      end
    end
  end

  defp reconcile_delegations(state) do
    Enum.reduce_while(state.delegations, {:ok, state}, fn {_id, delegation}, {:ok, state} ->
      case reconcile_delegation(state, delegation) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp reconcile_delegation(state, %Delegation{delivery: :delivered}), do: {:ok, state}

  defp reconcile_delegation(state, %Delegation{status: :starting} = delegation) do
    case start_assigned_coding(state, delegation, :recovery) do
      {:ok, delegation, state} ->
        if delegation.cancellation_requested_at != nil do
          send(self(), {:retry_cancel, delegation.id})
        end

        {:ok, state}

      {:error, _setup_reason, state} ->
        case Map.fetch(state.delegations, delegation.id) do
          {:ok, %Delegation{status: :failed}} -> {:ok, state}
          _other -> {:error, {:starting_delegation_recovery_failed, delegation.id}}
        end
    end
  end

  defp reconcile_delegation(state, %Delegation{} = delegation) do
    state_result =
      with :ok <- verify_coding_task_owner(delegation) do
        case Ouroboros.CodingSession.subscribe(delegation.task_ref, cursor: delegation.cursor) do
          {:ok, backlog} ->
            next_state =
              Enum.reduce(
                backlog,
                state,
                &consume_event_without_checkpoint(&2, delegation.id, &1)
              )

            if next_state == state, do: {:ok, state}, else: checkpoint(next_state)

          {:error, reason} ->
            delegation = %{
              delegation
              | delivery_error: {:resubscribe_failed, durable_error(reason)}
            }

            checkpoint(put_delegation(state, delegation))
        end
      else
        {:error, reason} ->
          delegation = %{
            delegation
            | delivery_error: {:resubscribe_failed, durable_error(reason)}
          }

          checkpoint(put_delegation(state, delegation))
      end

    with {:ok, state} <- state_result do
      delegation = Map.fetch!(state.delegations, delegation.id)

      cond do
        delegation.cancellation_requested_at != nil ->
          send(self(), {:retry_cancel, delegation.id})

        delegation.delivery == :delivering ->
          send(self(), {:deliver_terminal, delegation.id})

        true ->
          schedule_completion_check(delegation.id, 0)
      end

      {:ok, state}
    end
  end

  defp start_or_adopt_coordinator(coordinator_id, team_id) do
    case Ouroboros.Mesh.start_agent(coordinator_id,
           agent: Coordinator,
           role: "coordinator"
         ) do
      {:ok, pid} ->
        {:ok, pid}

      {:error, {:already_started, pid}} ->
        with :ok <- verify_coordinator_candidate(pid, team_id, coordinator_id) do
          {:ok, pid}
        end

      {:error, reason} ->
        {:error, {:coordinator_start_failed, reason}}
    end
  end

  defp initialize_coordinator(pid, team_id, coordinator_id) do
    with {:ok, signal} <-
           TeamStarted.new(
             %{team_id: team_id, coordinator_id: coordinator_id},
             subject: coordinator_id,
             source: team_source(team_id)
           ) do
      Jido.AgentServer.call(pid, signal)
    end
  end

  defp verify_coordinator_candidate(pid, team_id, coordinator_id) do
    case Jido.AgentServer.state(pid) do
      {:ok,
       %{
         agent_module: Coordinator,
         agent: %{state: %{team_id: nil, coordinator_id: nil}}
       }} ->
        :ok

      {:ok,
       %{
         agent_module: Coordinator,
         agent: %{state: %{team_id: ^team_id, coordinator_id: ^coordinator_id}}
       }} ->
        :ok

      {:ok, %{agent_module: Coordinator, agent: %{state: %{team_id: owner}}}}
      when owner != team_id ->
        {:error, {:coordinator_owner_conflict, coordinator_id, owner, team_id}}

      {:ok,
       %{
         agent_module: Coordinator,
         agent: %{state: %{team_id: ^team_id, coordinator_id: actual_coordinator_id}}
       }} ->
        {:error, {:coordinator_identity_conflict, team_id, actual_coordinator_id, coordinator_id}}

      {:ok, %{agent_module: agent_module}} ->
        {:error, {:coordinator_module_conflict, coordinator_id, agent_module}}

      {:error, reason} ->
        {:error, {:coordinator_owner_verification_failed, coordinator_id, reason}}
    end
  catch
    kind, reason ->
      {:error, {:coordinator_owner_verification_failed, coordinator_id, kind, reason}}
  end

  defp verify_coordinator_owner(pid, team_id, coordinator_id) do
    case Jido.AgentServer.state(pid) do
      {:ok,
       %{
         agent_module: Coordinator,
         agent: %{state: %{team_id: ^team_id, coordinator_id: ^coordinator_id}}
       }} ->
        :ok

      {:ok, %{agent_module: Coordinator, agent: %{state: %{team_id: owner}}}} ->
        {:error, {:coordinator_owner_conflict, coordinator_id, owner, team_id}}

      {:ok, %{agent_module: agent_module}} ->
        {:error, {:coordinator_module_conflict, coordinator_id, agent_module}}

      {:error, reason} ->
        {:error, {:coordinator_owner_verification_failed, coordinator_id, reason}}
    end
  catch
    kind, reason ->
      {:error, {:coordinator_owner_verification_failed, coordinator_id, kind, reason}}
  end

  defp publish_worker_projection(state, worker) do
    with {:ok, signal} <-
           WorkerAdded.new(
             %{
               worker_id: worker.id,
               worker_node: Atom.to_string(worker.node),
               role: worker.role,
               hierarchy: worker.hierarchy
             },
             subject: state.coordinator_id,
             source: team_source(state.id)
           ),
         {:ok, _agent} <- signal_coordinator(state, signal) do
      :ok
    end
  end

  defp publish_delegated_projection(state, delegation) do
    with {:ok, signal} <-
           TaskDelegated.new(
             %{
               delegation_id: delegation.id,
               worker_id: delegation.worker_id,
               objective: delegation.objective,
               coding_task_id: delegation.task_ref.id,
               coding_node: Atom.to_string(delegation.task_ref.node)
             },
             subject: state.coordinator_id,
             source: team_source(state.id)
           ),
         {:ok, _agent} <- signal_coordinator(state, signal) do
      :ok
    end
  end

  defp publish_finalized_projection(state, delegation) do
    with {:ok, signal} <-
           TaskFinalized.new(
             %{
               delegation_id: delegation.id,
               worker_id: delegation.worker_id,
               status: delegation.status,
               result: delegation.result,
               error: delegation.error
             },
             subject: state.coordinator_id,
             source: team_source(state.id)
           ),
         {:ok, _agent} <- signal_coordinator(state, signal) do
      :ok
    end
  end

  defp signal_coordinator(state, signal) do
    case Ouroboros.Mesh.whereis(state.coordinator_id) do
      pid when is_pid(pid) ->
        with :ok <- verify_coordinator_owner(pid, state.id, state.coordinator_id) do
          Jido.AgentServer.call(pid, signal)
        end

      nil ->
        {:error, {:coordinator_not_found, state.coordinator_id}}
    end
  end

  defp finish_add_worker(state, worker_id, worker_node, role, pid) do
    result =
      with :ok <- await_mesh_visibility(worker_id, pid),
           {:ok, hierarchy} <- attach_worker(state, pid, worker_id, worker_node, role) do
        worker = %{
          id: worker_id,
          pid: pid,
          node: worker_node,
          role: role,
          hierarchy: hierarchy
        }

        next_state = %{state | workers: Map.put(state.workers, worker_id, worker)}

        with {:ok, next_state} <- checkpoint(next_state) do
          # Projection failure does not revoke durable membership. Recovery
          # deterministically replays WorkerAdded.
          _ = publish_worker_projection(next_state, worker)
          {:ok, worker, next_state}
        end
      end

    case result do
      {:ok, _worker, _state} = success ->
        success

      {:error, reason} ->
        stop_result = stop_exact(pid)
        {:error, {:worker_setup_failed, reason, %{stop_worker: stop_result}}}
    end
  end

  defp attach_worker(state, pid, worker_id, worker_node, role) do
    coordinator_pid = Ouroboros.Mesh.whereis(state.coordinator_id)

    ownership =
      if is_pid(coordinator_pid),
        do: verify_coordinator_owner(coordinator_pid, state.id, state.coordinator_id),
        else: {:error, {:coordinator_not_found, state.coordinator_id}}

    cond do
      not is_pid(coordinator_pid) ->
        {:error, {:coordinator_not_found, state.coordinator_id}}

      ownership != :ok ->
        ownership

      node(pid) != node(coordinator_pid) ->
        # Jido 2.3.3's adopt_child/4 calls Process.alive?/1, which rejects a
        # remote PID. Keep this relationship explicit rather than pretending it
        # is represented in Jido's local child table.
        {:ok, :mesh_remote}

      true ->
        case Jido.AgentServer.adopt_child(
               coordinator_pid,
               pid,
               {:worker, worker_id},
               %{team_id: state.id, role: role, node: worker_node}
             ) do
          {:ok, ^pid} ->
            {:ok, :jido_child}

          {:error, {:tag_in_use, {:worker, ^worker_id}}} ->
            existing_child?(coordinator_pid, worker_id, pid)

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp existing_child?(coordinator_pid, worker_id, expected_pid) do
    case safe_agent_state(coordinator_pid) do
      {:ok, %{children: %{{:worker, ^worker_id} => %{pid: ^expected_pid}}}} ->
        {:ok, :jido_child}

      {:ok, %{children: %{{:worker, ^worker_id} => %{pid: other_pid}}}} ->
        {:error, {:worker_tag_claimed, worker_id, other_pid}}

      {:ok, _state} ->
        {:error, {:worker_tag_inconsistent, worker_id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp await_mesh_visibility(worker_id, expected_pid) do
    deadline = System.monotonic_time(:millisecond) + @mesh_visibility_timeout_ms
    do_await_mesh_visibility(worker_id, expected_pid, deadline)
  end

  defp do_await_mesh_visibility(worker_id, expected_pid, deadline) do
    if expected_pid in Ouroboros.Mesh.members(worker_id) do
      :ok
    else
      if System.monotonic_time(:millisecond) >= deadline do
        {:error, {:mesh_visibility_timeout, worker_id, node(expected_pid)}}
      else
        Process.sleep(10)
        do_await_mesh_visibility(worker_id, expected_pid, deadline)
      end
    end
  end

  defp stop_exact(pid) when node(pid) == node(), do: Ouroboros.Jido.stop_agent(pid)

  defp stop_exact(pid) do
    :erpc.call(node(pid), Ouroboros.Jido, :stop_agent, [pid])
  catch
    kind, reason -> {:error, {:exact_remote_stop_failed, node(pid), kind, reason}}
  end

  defp assign_and_start(
         state,
         worker,
         delegation_id,
         coding_task_id,
         objective,
         coding_node,
         fingerprint,
         coding_options
       ) do
    case Ouroboros.Mesh.assign_task(state.coordinator_id, worker.id, objective,
           task_id: delegation_id
         ) do
      {:ok, ^delegation_id, _agent} ->
        checkpoint_and_start_delegation(
          state,
          worker,
          delegation_id,
          coding_task_id,
          objective,
          coding_node,
          fingerprint,
          coding_options
        )

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp checkpoint_and_start_delegation(
         state,
         worker,
         delegation_id,
         coding_task_id,
         objective,
         coding_node,
         fingerprint,
         coding_options
       ) do
    now = timestamp()

    delegation = %Delegation{
      id: delegation_id,
      worker_id: worker.id,
      objective: objective,
      task_ref: TaskRef.new(coding_task_id, coding_node),
      coding_options: coding_options,
      request_fingerprint: fingerprint,
      status: :starting,
      created_at: now,
      updated_at: now
    }

    case checkpoint(put_delegation(state, delegation)) do
      {:ok, state} ->
        start_assigned_coding(state, delegation, :fresh)

      {:error, reason} ->
        failed_delivery = %{
          coding_task_id: coding_task_id,
          coding_node: coding_node,
          status: :failed,
          result: nil,
          error: {:delegation_setup_failed, :team_checkpoint, durable_error(reason)}
        }

        _ = Ouroboros.Mesh.complete_task(worker.id, delegation_id, failed_delivery)
        {:error, {:delegation_checkpoint_failed, reason}, state}
    end
  end

  defp start_assigned_coding(state, delegation, mode) do
    case ensure_coding_task(delegation) do
      {:ok, %TaskRef{} = task_ref} ->
        subscribe_assigned_coding(state, %{delegation | task_ref: task_ref}, mode)

      {:error, reason} ->
        if ambiguous_start?(reason) do
          retry_delegation_start(state, delegation, reason)
        else
          fail_durable_delegation(state, delegation, :coding_start, reason)
        end
    end
  end

  defp resume_delegation_start(state, delegation_id) do
    case Map.fetch(state.delegations, delegation_id) do
      {:ok, %Delegation{status: :starting, delivery: delivery} = delegation}
      when delivery != :delivered ->
        case start_assigned_coding(state, delegation, :recovery) do
          {:ok, delegation, state} ->
            if delegation.cancellation_requested_at != nil do
              send(self(), {:retry_cancel, delegation.id})
            end

            {:ok, state}

          {:error, _setup_reason, state} ->
            case Map.fetch(state.delegations, delegation_id) do
              {:ok, %Delegation{status: :failed}} -> {:ok, state}
              _other -> {:error, {:delegation_start_retry_failed, delegation_id}}
            end
        end

      _other ->
        {:ok, state}
    end
  end

  # `CodingSession.start_on/3` is idempotent for this caller because the coding
  # task ID is deterministic. An unreachable owner therefore proves nothing about
  # whether provider work began, and must not become an unretryable `:failed`.
  defp retry_delegation_start(state, delegation, reason) do
    {deadline, state} = start_deadline(state, delegation.id)

    if System.monotonic_time(:millisecond) >= deadline do
      fail_durable_delegation(state, delegation, :coding_start_unconfirmed, reason)
    else
      error = {:coding_start_unconfirmed, durable_error(reason)}
      {delay, state} = next_backoff(state, {:start, delegation.id}, @delivery_retry_ms)
      Process.send_after(self(), {:retry_start, delegation.id}, delay)

      if delegation.delivery_error == error do
        {:ok, delegation, state}
      else
        delegation = %{delegation | delivery_error: error, updated_at: timestamp()}

        case checkpoint(put_delegation(state, delegation)) do
          {:ok, state} -> {:ok, delegation, state}
          {:error, reason} -> {:error, {:delegation_progress_checkpoint_failed, reason}, state}
        end
      end
    end
  end

  defp ambiguous_start?({:owner_unavailable, _owner}), do: true
  defp ambiguous_start?({:owner_unavailable, _owner, _reason}), do: true
  defp ambiguous_start?({:remote_call_failed, _owner, _kind, _reason}), do: true
  defp ambiguous_start?(_reason), do: false

  defp ensure_coding_task(delegation) do
    case Ouroboros.CodingSession.info(delegation.task_ref) do
      {:ok, %TaskState{}} ->
        with :ok <- verify_coding_task_owner(delegation) do
          {:ok, delegation.task_ref}
        end

      {:error, :not_found} ->
        start_coding_task(delegation)

      {:error, {:owner_unavailable, _owner} = reason} ->
        {:error, reason}

      {:error, {:owner_unavailable, _owner, _erpc_reason} = reason} ->
        {:error, reason}

      {:error, _reason} ->
        # A coordinator may have been created between the lookup and this
        # branch. The stable ID makes start idempotent: a matching live task
        # returns `{:ok, ref}` rather than `:already_exists`.
        start_coding_task(delegation)
    end
  end

  defp start_coding_task(delegation) do
    options = coding_options_from_snapshot(delegation)

    Ouroboros.CodingSession.start_on(
      delegation.task_ref.node,
      delegation.objective,
      options
    )
  end

  defp coding_options_from_snapshot(delegation) do
    fixed = [
      id: delegation.task_ref.id,
      workspace: delegation.coding_options.workspace,
      workspace_mode: delegation.coding_options.workspace_mode,
      provider: delegation.coding_options.provider,
      event_limit: delegation.coding_options.event_limit,
      origin_digest: delegation.coding_options.origin_digest,
      parent: Map.get(delegation.coding_options, :parent)
    ]

    options =
      delegation.coding_options.options
      |> apply_prompt_inputs(Map.get(delegation.coding_options, :prompt_inputs, %{}))
      |> Map.to_list()

    Keyword.merge(options, fixed)
  end

  defp subscribe_assigned_coding(state, delegation, mode) do
    with :ok <- verify_coding_task_owner(delegation) do
      case Ouroboros.CodingSession.subscribe(delegation.task_ref, cursor: delegation.cursor) do
        {:ok, backlog} ->
          publish_delegation(state, delegation, backlog)

        # The task is verified as ours and alive. A pruned cursor or an
        # unavailable owner is a delivery problem, never grounds for recovery to
        # compensate a healthy provider run.
        {:error, reason} when mode == :recovery ->
          degrade_to_completion_polling(state, delegation, reason)

        {:error, reason} ->
          fail_durable_delegation(state, delegation, :coding_subscribe, reason)
      end
    else
      {:error, reason} ->
        fail_durable_delegation(state, delegation, :coding_identity, reason)
    end
  end

  defp degrade_to_completion_polling(state, delegation, reason) do
    delegation = %{
      delegation
      | status: :running,
        delivery_error: {:resubscribe_failed, durable_error(reason)},
        updated_at: timestamp()
    }

    case checkpoint(put_delegation(state, delegation)) do
      {:ok, state} ->
        schedule_completion_check(delegation.id, 0)
        {:ok, delegation, forget_start(state, delegation.id)}

      {:error, reason} ->
        {:error, {:delegation_progress_checkpoint_failed, reason}, state}
    end
  end

  defp publish_delegation(state, delegation, backlog) do
    delegation = %{delegation | status: :running, updated_at: timestamp()}
    next_state = put_delegation(state, delegation)

    next_state =
      Enum.reduce(backlog, next_state, &consume_event_without_checkpoint(&2, delegation.id, &1))

    case checkpoint(next_state) do
      {:ok, next_state} ->
        next_state = forget_start(next_state, delegation.id)
        delegation = Map.fetch!(next_state.delegations, delegation.id)
        schedule_completion_check(delegation.id, 0)

        case publish_delegated_projection(next_state, delegation) do
          :ok ->
            {:ok, delegation, next_state}

          {:error, reason} ->
            redacted = durable_error(reason)
            delegation = %{delegation | delivery_error: {:projection_reconcile_failed, redacted}}

            case checkpoint(put_delegation(next_state, delegation)) do
              {:ok, next_state} -> {:ok, delegation, next_state}
              {:error, checkpoint_reason} -> {:error, checkpoint_reason, next_state}
            end
        end

      {:error, reason} ->
        {:error, {:delegation_progress_checkpoint_failed, reason}, state}
    end
  end

  defp fail_durable_delegation(state, delegation, stage, reason) do
    redacted = durable_error(reason)
    error = setup_failure(stage, redacted, compensate_owned_coding_task(delegation))

    delegation = %{
      delegation
      | status: :failed,
        error: error,
        delivery: :delivering,
        delivery_error: nil,
        updated_at: timestamp()
    }

    case checkpoint(put_delegation(state, delegation)) do
      {:ok, state} ->
        send(self(), {:deliver_terminal, delegation.id})
        {:error, error, forget_start(state, delegation.id)}

      {:error, checkpoint_reason} ->
        {:error, setup_checkpoint_failure(error, checkpoint_reason), state}
    end
  end

  defp setup_checkpoint_failure({:delegation_setup_failed, stage, redacted}, reason),
    do: {:delegation_setup_failed, stage, redacted, {:failure_checkpoint_failed, reason}}

  defp setup_checkpoint_failure(
         {:delegation_setup_failed, stage, redacted, compensation},
         reason
       ),
       do:
         {:delegation_setup_failed, stage, redacted,
          {compensation, {:failure_checkpoint_failed, reason}}}

  # A task that is foreign or absent is correctly left alone. A compensation that
  # could not run at all is different, and is recorded rather than implied.
  defp setup_failure(
         stage,
         redacted,
         {:error, {:compensation_unavailable, _reason} = unavailable}
       ),
       do: {:delegation_setup_failed, stage, redacted, unavailable}

  defp setup_failure(stage, redacted, _compensation),
    do: {:delegation_setup_failed, stage, redacted}

  defp coding_options(opts, coding_task_id) do
    opts
    |> Keyword.drop([:coding_node])
    |> Keyword.put(:id, coding_task_id)
  end

  defp delegation_id(opts) do
    id = Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0)
    if is_binary(id) and String.trim(id) != "", do: {:ok, id}, else: {:error, :invalid_id}
  end

  defp fetch_worker(state, worker_id) do
    case Map.fetch(state.workers, worker_id) do
      {:ok, worker} -> {:ok, worker}
      :error -> {:error, {:worker_not_found, worker_id}}
    end
  end

  defp delegation_identity(state, delegation_id, fingerprint) do
    case Map.fetch(state.delegations, delegation_id) do
      :error ->
        :new

      {:ok, %Delegation{request_fingerprint: ^fingerprint} = delegation} ->
        {:existing, delegation}

      {:ok, %Delegation{}} ->
        {:error, {:delegation_id_conflict, delegation_id}}
    end
  end

  defp request_fingerprint(worker_id, objective, coding_task_id, coding_node, opts) do
    coding_options = coding_options(opts, coding_task_id)

    with :ok <- portable_prompt_options(coding_options),
         {:ok, task} <- task_state_on(coding_node, coding_task_id, objective, coding_options) do
      request = %{
        worker_id: worker_id,
        objective: objective,
        coding_node: coding_node,
        coding_options: durable_coding_options(task, coding_options)
      }

      plain_request = plain_terms(request)

      cond do
        not portable_request?(request) ->
          {:error, :non_durable_delegation_options}

        # Redaction turns every struct it walks into a plain map, so comparing it against
        # a request that carries one would always differ. Compare like with like: the
        # same struct-free projection redaction itself would produce.
        Jido.Harness.Redaction.redact(plain_request) != plain_request ->
          {:error, :secret_bearing_delegation_options}

        true ->
          fingerprint =
            request
            |> :erlang.term_to_binary([:deterministic])
            |> then(&:crypto.hash(:sha256, &1))
            |> Base.encode16(case: :lower)

          {:ok, fingerprint, request.coding_options}
      end
    end
  rescue
    # Everything this function inspects is prompt or profile text. An exception message
    # is built from the term that raised — `Protocol.UndefinedError` inspects it in full —
    # so only the exception type is reported. The error term reaches callers, logs, and
    # durable delegation records; none of them are a place for prompt content.
    error -> {:error, {:invalid_delegation_options, error.__struct__}}
  end

  # TaskState validates prompt/profile text before it constructs the durable request. Keep
  # Team's older authority-boundary error stable by rejecting runtime-only values first;
  # secret-bearing binaries still flow through normalization and the redaction check below.
  defp portable_prompt_options(coding_options) do
    coding_options
    |> Keyword.take([:system_prompt, :agent_profile])
    |> portable_request?()
    |> case do
      true -> :ok
      false -> {:error, :non_durable_delegation_options}
    end
  end

  # Relative paths belong to the execution machine, not the coordinator. Constructing
  # TaskState there makes its cwd, symlink resolution, provider defaults, and prompt
  # assembly the same ones the eventual coding task will use.
  defp task_state_on(owner, id, objective, opts) when owner == node(),
    do: build_delegated_task_state(id, objective, opts)

  defp task_state_on(owner, id, objective, opts) do
    :erpc.call(owner, __MODULE__, :build_delegated_task_state, [id, objective, opts], 30_000)
  catch
    :error, {:erpc, reason} when reason in [:noconnection, :timeout] ->
      {:error, {:owner_unavailable, owner, reason}}

    kind, reason ->
      {:error, {:remote_task_normalization_failed, owner, kind, durable_error(reason)}}
  end

  defp canonical_workspace(workspace) when is_binary(workspace) do
    case WorkspacePath.canonicalize(workspace) do
      {:ok, canonical} -> {:ok, canonical}
      {:error, _reason} -> {:error, {:invalid_workspace, Path.expand(workspace)}}
    end
  end

  defp canonical_workspace(workspace), do: {:error, {:invalid_workspace, workspace}}

  # A delegated task must carry the same prompt identity as the identical local task.
  # `TaskState` compiles the profile into `options.system_prompt` and drops the profile
  # itself, so the compiled text alone would arrive at the owner as a *session* prompt and
  # be wrapped a second time — a different prompt, a different digest, no
  # `metadata.ouroboros_prompt`. The assembler's inputs travel beside the compiled
  # options, never inside them: assembly is deterministic, so the owner re-runs it and
  # reproduces byte-identical options, which is what task identity is verified against.
  defp durable_coding_options(task, coding_options) do
    durable = %{
      workspace: task.workspace,
      workspace_mode: task.workspace_mode,
      provider: task.provider,
      event_limit: task.event_limit,
      options: task.options,
      # G1. Persisted here or the request is silently lost: a delegation restarted from
      # its snapshot rebuilds the coding task from this map alone, and a child that came
      # back without its parent would be a conversation's work with nothing linking it.
      parent: Map.get(task, :parent)
    }

    case Keyword.get(coding_options, :agent_profile) do
      %AgentProfile{} = profile ->
        Map.put(durable, :prompt_inputs, prompt_inputs(profile, coding_options))

      _no_profile ->
        durable
    end
  end

  defp prompt_inputs(profile, coding_options) do
    case Keyword.get(coding_options, :system_prompt) do
      nil -> %{agent_profile: profile}
      session_prompt -> %{agent_profile: profile, system_prompt: session_prompt}
    end
  end

  defp apply_prompt_inputs(options, %{agent_profile: %AgentProfile{} = profile} = inputs) do
    options
    |> Map.put(:agent_profile, profile)
    |> put_session_prompt(Map.get(inputs, :system_prompt))
  end

  defp apply_prompt_inputs(options, _inputs), do: options

  # An absent session prompt has to be absent again, not left as the compiled profile
  # text the owner would then treat as this session's own instructions.
  defp put_session_prompt(options, nil), do: Map.delete(options, :system_prompt)
  defp put_session_prompt(options, prompt), do: Map.put(options, :system_prompt, prompt)

  # Mirrors the traversal `Jido.Harness.Redaction` performs: structs become plain maps,
  # map values and list elements are walked, keys and every other term are left alone.
  defp plain_terms(term) when is_struct(term), do: term |> Map.from_struct() |> plain_terms()

  defp plain_terms(term) when is_map(term),
    do: Map.new(term, fn {key, value} -> {key, plain_terms(value)} end)

  defp plain_terms(term) when is_list(term), do: Enum.map(term, &plain_terms/1)
  defp plain_terms(term), do: term

  defp origin_digest(team_id, delegation_id, request_fingerprint) do
    {:ouroboros_team_delegation, team_id, delegation_id, request_fingerprint,
     :crypto.strong_rand_bytes(32)}
    |> :erlang.term_to_binary([:deterministic])
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp portable_request?(term) when is_pid(term) or is_port(term) or is_reference(term), do: false
  defp portable_request?(term) when is_function(term), do: false

  # A struct satisfies `is_map/1` but implements no `Enumerable`, so it has to be
  # decomposed before the map clause walks it. An agent profile is the struct that
  # actually travels here; enumerating one raised `Protocol.UndefinedError`, and the
  # rescue below then carried the inspected profile into the returned error term.
  defp portable_request?(term) when is_struct(term) do
    term |> Map.from_struct() |> portable_request?()
  end

  defp portable_request?(term) when is_map(term) do
    Enum.all?(term, fn {key, value} ->
      not authority_key?(key) and portable_request?(key) and portable_request?(value)
    end)
  end

  defp portable_request?(term) when is_list(term) do
    if Keyword.keyword?(term) do
      Enum.all?(term, fn {key, value} -> not authority_key?(key) and portable_request?(value) end)
    else
      Enum.all?(term, &portable_request?/1)
    end
  end

  defp portable_request?(term) when is_tuple(term) do
    term |> Tuple.to_list() |> Enum.all?(&portable_request?/1)
  end

  defp portable_request?(_term), do: true

  defp authority_key?(key) when is_atom(key), do: authority_key?(Atom.to_string(key))

  defp authority_key?(key) when is_binary(key) do
    key
    |> String.downcase()
    |> then(fn normalized ->
      Enum.any?(
        ["token", "secret", "password", "credential", "api_key", "capability"],
        &String.contains?(normalized, &1)
      )
    end)
  end

  defp authority_key?(_key), do: false

  defp ensure_worker_available(state, worker_id) do
    case Enum.find(state.delegations, fn {_delegation_id, delegation} ->
           delegation.worker_id == worker_id and delegation.delivery != :delivered
         end) do
      {delegation_id, _delegation} ->
        {:error, {:worker_busy, worker_id, delegation_id}}

      nil ->
        :ok
    end
  end

  defp validate_objective(objective) do
    if String.trim(objective) == "", do: {:error, :invalid_objective}, else: :ok
  end

  defp validate_coding_node(coding_node) when is_atom(coding_node) do
    case Ouroboros.Cluster.ensure_placeable(coding_node) do
      :ok -> :ok
      {:error, reason} -> {:error, {:invalid_coding_node, coding_node, reason}}
    end
  end

  defp validate_coding_node(_coding_node), do: {:error, :invalid_coding_node}

  defp validate_options(opts) do
    case Enum.find(Keyword.keys(opts), &(&1 not in (@server_options ++ [:supervisor_id]))) do
      nil -> :ok
      option -> {:error, {:unknown_option, option}}
    end
  end

  defp coordinator_id(opts, team_id) do
    case Keyword.get(opts, :coordinator_id, team_id <> ":coordinator") do
      id when is_binary(id) ->
        if String.trim(id) == "", do: {:error, :invalid_coordinator_id}, else: {:ok, id}

      _other ->
        {:error, :invalid_coordinator_id}
    end
  end

  defp validate_cleanup_agents(opts) do
    case Keyword.get(opts, :cleanup_agents, true) do
      value when is_boolean(value) -> :ok
      _other -> {:error, :invalid_cleanup_agents}
    end
  end

  defp checkpoint(%State{} = state) do
    state = %{state | updated_at: timestamp()}

    case store_call(state.store, :put, [to_snapshot(state)]) do
      :ok -> {:ok, state}
      {:error, reason} -> {:error, reason}
    end
  end

  defp begin_close(%State{status: :closed} = state), do: {:ok, state}

  defp begin_close(%State{} = state) do
    requested_at = timestamp()

    delegations =
      Map.new(state.delegations, fn {id, delegation} ->
        delegation =
          if delegation.delivery != :delivered and delegation.cancellation_requested_at == nil do
            %{
              delegation
              | cancellation_requested_at: requested_at,
                updated_at: requested_at
            }
          else
            delegation
          end

        {id, delegation}
      end)

    case checkpoint(%{state | status: :closing, delegations: delegations}) do
      {:ok, state} ->
        Enum.each(state.delegations, fn {delegation_id, delegation} ->
          if delegation.delivery != :delivered, do: send(self(), {:retry_cancel, delegation_id})
        end)

        case finish_close_if_ready(state) do
          {:ok, state} -> {:ok, state}
          {:error, reason} -> {:accepted, reason, state}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp finish_close_if_ready(%State{status: :closing} = state) do
    if Enum.all?(state.delegations, fn {_id, delegation} ->
         delegation.delivery == :delivered
       end) do
      checkpoint(%{state | status: :closed})
    else
      {:ok, state}
    end
  end

  defp finish_close_if_ready(%State{} = state), do: {:ok, state}

  defp to_snapshot(state) do
    workers =
      Map.new(state.workers, fn {id, worker} ->
        {id,
         %Worker{
           id: worker.id,
           node: worker.node,
           role: worker.role,
           hierarchy: worker.hierarchy
         }}
      end)

    %Snapshot{
      id: state.id,
      coordinator_id: state.coordinator_id,
      status: state.status,
      cleanup_agents?: state.cleanup_agents?,
      workers: workers,
      delegations: state.delegations,
      created_at: state.created_at,
      updated_at: state.updated_at
    }
  end

  defp store_call(store, function, arguments) do
    apply(Store, function, arguments ++ [store])
  rescue
    error -> {:error, {:team_store_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:team_store_unavailable, kind, reason}}
  end

  defp store_durability(store) do
    case store_call(store, :durability, []) do
      level when level in [:ephemeral_checkpoint, :durable_checkpoint, :synced_checkpoint] ->
        {:ok, level}

      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, {:invalid_team_store_durability, other}}
    end
  end

  defp transition_info(result, previous),
    do: transition_info(result, previous, :team_checkpoint_failed)

  defp transition_info({:ok, state}, previous, failure_tag) do
    case finish_close_if_ready(state) do
      {:ok, %State{status: :closed} = state} -> {:stop, :normal, state}
      {:ok, state} -> {:noreply, state}
      {:error, reason} -> {:stop, {failure_tag, reason}, previous}
    end
  end

  defp transition_info({:error, reason}, previous, failure_tag) do
    {:stop, {failure_tag, reason}, previous}
  end

  defp durable_error(term) when is_pid(term), do: {:runtime_pid, node(term)}
  defp durable_error(term) when is_port(term), do: :runtime_port
  defp durable_error(term) when is_reference(term), do: :runtime_reference
  defp durable_error(term) when is_function(term), do: :runtime_function

  defp durable_error(%_{} = term), do: term |> Map.from_struct() |> durable_error()

  # Redaction is key-aware for maps and would be lost by decomposing one here, so
  # it runs first and this pass only removes runtime authority from the result.
  defp durable_error(term) when is_map(term) do
    term
    |> Jido.Harness.Redaction.redact()
    |> Map.new(fn {key, value} -> {durable_error(key), durable_error(value)} end)
  end

  defp durable_error(term) when is_list(term), do: Enum.map(term, &durable_error/1)

  defp durable_error(term) when is_tuple(term) do
    term |> Tuple.to_list() |> Enum.map(&durable_error/1) |> List.to_tuple()
  end

  defp durable_error(term), do: Jido.Harness.Redaction.redact(term)

  defp required_id(opts) do
    case Keyword.fetch(opts, :id) do
      {:ok, id} when is_binary(id) ->
        if String.trim(id) == "", do: {:error, :invalid_team_id}, else: {:ok, id}

      _ ->
        {:error, :invalid_team_id}
    end
  end

  defp default_team_id do
    "#{node()}:team:#{System.unique_integer([:positive, :monotonic])}"
  end

  defp put_delegation(state, delegation) do
    %{state | delegations: Map.put(state.delegations, delegation.id, delegation)}
  end

  defp schedule_completion_check(delegation_id, delay) do
    Process.send_after(self(), {:check_completion, delegation_id}, delay)
  end

  # Retry pacing is runtime scheduling, not durable domain state, so it is held in
  # memory only. A restart honestly restarts the bound.
  defp next_backoff(state, key, base) do
    delay = Map.get(state.backoff, key, base)
    {delay, %{state | backoff: Map.put(state.backoff, key, min(delay * 2, @backoff_cap_ms))}}
  end

  defp reset_backoff(state, key), do: %{state | backoff: Map.delete(state.backoff, key)}

  defp start_deadline(state, delegation_id) do
    case Map.fetch(state.start_deadlines, delegation_id) do
      {:ok, deadline} ->
        {deadline, state}

      :error ->
        deadline = System.monotonic_time(:millisecond) + start_retry_ms()

        {deadline,
         %{state | start_deadlines: Map.put(state.start_deadlines, delegation_id, deadline)}}
    end
  end

  defp forget_start(state, delegation_id) do
    state
    |> reset_backoff({:start, delegation_id})
    |> Map.update!(:start_deadlines, &Map.delete(&1, delegation_id))
  end

  defp start_retry_ms do
    case Application.get_env(:ouroboros, :delegation_start_retry_ms, @default_start_retry_ms) do
      value when is_integer(value) and value >= 0 -> value
      _other -> @default_start_retry_ms
    end
  end

  defp safe_agent_state(pid) do
    Jido.AgentServer.state(pid)
  catch
    kind, reason -> {:error, {:agent_state_call_failed, node(pid), kind, reason}}
  end

  defp public_state(state) do
    %{
      id: state.id,
      node: node(),
      coordinator_id: state.coordinator_id,
      workers:
        Map.new(state.workers, fn {id, worker} ->
          visible? =
            Enum.any?(Ouroboros.Mesh.members(id), fn pid ->
              node(pid) == worker.node
            end)

          {id, worker |> Map.delete(:pid) |> Map.put(:available?, visible?)}
        end),
      delegations:
        Map.new(state.delegations, fn {id, value} -> {id, public_delegation(value)} end),
      waiter_count: Enum.sum(Enum.map(state.waiters, fn {_id, waiters} -> map_size(waiters) end)),
      status: state.status,
      durability: state.durability,
      process_restart_safe?: true,
      # Only a synced adapter commits through the page cache, so a file-backed
      # checkpoint survives a BEAM restart but is not a power-loss claim.
      host_restart_safe?: state.durability == :synced_checkpoint
    }
  end

  defp public_delegation(%Delegation{} = delegation) do
    delegation
    |> Map.from_struct()
    |> Map.delete(:coding_options)
  end

  defp delegation_id_for_task(state, coding_task_id) do
    Enum.find_value(state.delegations, fn {delegation_id, delegation} ->
      if delegation.task_ref.id == coding_task_id, do: delegation_id
    end)
  end

  defp verify_coding_task_owner(%Delegation{} = delegation) do
    with {:ok, %TaskState{}} <- verified_coding_task(delegation), do: :ok
  end

  defp verified_coding_task(%Delegation{} = delegation) do
    case coding_store_get(delegation.task_ref) do
      {:ok, %TaskState{} = task} ->
        expected = %{
          id: delegation.task_ref.id,
          node: delegation.task_ref.node,
          objective: delegation.objective,
          workspace: delegation.coding_options.workspace,
          workspace_mode: delegation.coding_options.workspace_mode,
          provider: delegation.coding_options.provider,
          event_limit: delegation.coding_options.event_limit,
          origin_digest: delegation.coding_options.origin_digest,
          options: delegation.coding_options.options,
          parent: Map.get(delegation.coding_options, :parent)
        }

        actual = %{
          id: task.id,
          node: task.node,
          objective: task.objective,
          workspace: task.workspace,
          workspace_mode: task.workspace_mode,
          provider: task.provider,
          event_limit: task.event_limit,
          origin_digest: Map.get(task, :origin_digest),
          options: task.options,
          parent: Map.get(task, :parent)
        }

        if actual == expected do
          {:ok, task}
        else
          {:error, {:coding_task_owner_conflict, delegation.task_ref.id}}
        end

      :not_found ->
        {:error, {:coding_task_not_found, delegation.task_ref.id}}

      {:error, reason} ->
        {:error, {:coding_task_owner_verification_failed, delegation.task_ref.id, reason}}
    end
  end

  # A busy local Coding.Store answers a 5s GenServer call late. That timeout is a
  # delivery problem, not grounds for taking this team's control plane down.
  defp coding_store_get(%TaskRef{id: id, node: owner}) when owner == node() do
    CodingStore.get(id)
  catch
    kind, reason -> {:error, {:local_store_unavailable, kind, reason}}
  end

  defp coding_store_get(%TaskRef{id: id, node: owner}) do
    :erpc.call(owner, CodingStore, :get, [id])
  catch
    kind, reason -> {:error, {:remote_store_unavailable, owner, kind, reason}}
  end

  defp compensate_owned_coding_task(%Delegation{} = delegation) do
    case verify_coding_task_owner(delegation) do
      :ok ->
        _ = Ouroboros.CodingSession.unsubscribe(delegation.task_ref)
        Ouroboros.CodingSession.cancel(delegation.task_ref)

      {:error, {:coding_task_owner_conflict, _id}} ->
        :ok

      {:error, {:coding_task_not_found, _id}} ->
        :ok

      {:error, reason} ->
        {:error, {:compensation_unavailable, durable_error(reason)}}
    end
  end

  defp unsubscribe_owned_coding_task(%Delegation{} = delegation) do
    with :ok <- verify_coding_task_owner(delegation) do
      Ouroboros.CodingSession.unsubscribe(delegation.task_ref)
    end
  end

  defp cancel_owned_detached(%Delegation{} = delegation) do
    spawn(fn ->
      with :ok <- verify_coding_task_owner(delegation) do
        _ = Ouroboros.CodingSession.cancel(delegation.task_ref)
      end
    end)

    :ok
  end

  defp via(team_id), do: {:via, Registry, {@registry, team_id}}

  defp timestamp, do: DateTime.utc_now() |> DateTime.to_iso8601()
  defp team_source(team_id), do: "/ouroboros/teams/" <> URI.encode(team_id)
end
