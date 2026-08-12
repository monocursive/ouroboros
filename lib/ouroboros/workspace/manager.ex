defmodule Ouroboros.Workspace.Manager do
  @moduledoc """
  Node-local workspace admission and lease ownership.

  The manager is intentionally an admission primitive, not a distributed lock.
  A cluster scheduler must route every lease for a physical filesystem through
  one authority (or add a consensus-backed authority) before treating these
  guarantees as cross-node guarantees.
  """

  use GenServer

  alias Ouroboros.Workspace.{Lease, Path}

  defmodule Entry do
    @moduledoc false
    @enforce_keys [:kind, :lease, :owner_pid, :owner_monitor, :capability_digest]
    defstruct @enforce_keys
  end

  defmodule Reservation do
    @moduledoc false
    @enforce_keys [:kind, :lease]
    defstruct @enforce_keys
  end

  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :id, Keyword.get(opts, :name, __MODULE__)),
      start: {__MODULE__, :start_link, [Keyword.delete(opts, :id)]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {name, init_opts} = Keyword.pop(opts, :name, __MODULE__)

    if is_nil(name) do
      GenServer.start_link(__MODULE__, init_opts)
    else
      GenServer.start_link(__MODULE__, init_opts, name: name)
    end
  end

  @impl true
  def init(opts) do
    configured_roots =
      Keyword.get_lazy(opts, :allowed_roots, fn ->
        Application.get_env(:ouroboros, :workspace_allowed_roots, [])
      end)

    with {:ok, allowed_roots} <- canonical_allowed_roots(configured_roots),
         {:ok, reservations} <- recovery_reservations(opts, allowed_roots) do
      {:ok,
       %{
         allowed_roots: allowed_roots,
         leases: %{},
         reservations: reservations,
         monitors: %{},
         released: %{}
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:validate_root, root}, _from, state) do
    {:reply, authorize_root(root, state.allowed_roots), state}
  end

  def handle_call({:acquire, root, task_id, mode, kind}, {owner_pid, _tag}, state) do
    with :ok <- validate_task_id(task_id),
         :ok <- validate_mode(mode),
         :ok <- validate_owner_kind(kind),
         :ok <- validate_managed_task_id(kind, task_id),
         {:ok, canonical_root} <- authorize_root(root, state.allowed_roots),
         :ok <-
           validate_reservation(
             state.reservations,
             task_id,
             canonical_root,
             mode,
             kind,
             owner_pid
           ),
         [] <- conflicting_claims(canonical_root, mode, kind, task_id, state) do
      {lease, capability, entry} = new_entry(canonical_root, task_id, mode, kind, owner_pid)

      next_state = %{
        state
        | leases: Map.put(state.leases, lease.id, entry),
          reservations: Map.delete(state.reservations, reservation_key(kind, task_id)),
          monitors: Map.put(state.monitors, entry.owner_monitor, lease.id)
      }

      {:reply, {:ok, lease, capability}, next_state}
    else
      [_ | _] = conflicts ->
        public_conflicts = Enum.map(conflicts, &Lease.to_map/1)
        {:reply, {:error, {:workspace_conflict, public_conflicts}}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:release, lease_id, capability}, {caller_pid, _tag}, state) do
    case Map.fetch(state.leases, lease_id) do
      {:ok, entry} ->
        if authorized_release?(entry, caller_pid, capability) do
          {:reply, :ok, release_active(state, lease_id, entry, true)}
        else
          {:reply, {:error, :not_lease_owner}, state}
        end

      :error ->
        release_tombstone(state, lease_id, caller_pid, capability)
    end
  end

  def handle_call({:status, lease_id}, _from, state) do
    reply =
      case Map.fetch(state.leases, lease_id) do
        {:ok, entry} ->
          {:ok, %{status: :active, lease: Lease.to_map(entry.lease)}}

        :error ->
          case Enum.find_value(state.reservations, fn {_task_id, reservation} ->
                 if reservation.lease.id == lease_id, do: reservation.lease
               end) do
            %Lease{} = lease -> {:ok, %{status: :reserved, lease: Lease.to_map(lease)}}
            nil -> released_status(state.released, lease_id)
          end
      end

    {:reply, reply, state}
  end

  def handle_call(:list, _from, state) do
    leases =
      state
      |> all_claims()
      |> Enum.map(&Lease.to_map/1)
      |> Enum.sort_by(&{&1.acquired_at, &1.id})

    {:reply, leases, state}
  end

  def handle_call(:summary, _from, state) do
    reply = %{
      allowed_roots: state.allowed_roots,
      active_lease_count: map_size(state.leases),
      recovery_reservation_count: map_size(state.reservations),
      leases:
        state
        |> all_claims()
        |> Enum.map(&Lease.to_map/1)
        |> Enum.sort_by(&{&1.acquired_at, &1.id})
    }

    {:reply, reply, state}
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, owner_pid, _reason}, state) do
    case Map.pop(state.monitors, monitor) do
      {nil, _monitors} ->
        {:noreply, state}

      {lease_id, monitors} ->
        case Map.pop(state.leases, lease_id) do
          {nil, _leases} ->
            {:noreply, %{state | monitors: monitors}}

          {entry, leases} ->
            next_state = %{state | leases: leases, monitors: monitors}
            {:noreply, reserve_or_release(next_state, lease_id, entry, owner_pid)}
        end
    end
  end

  defp canonical_allowed_roots(roots) when is_list(roots) and roots != [] do
    roots
    |> Enum.reduce_while({:ok, []}, fn root, {:ok, acc} ->
      case Path.canonicalize(root) do
        {:ok, canonical} -> {:cont, {:ok, [canonical | acc]}}
        {:error, reason} -> {:halt, {:error, {:invalid_allowed_root, root, reason}}}
      end
    end)
    |> case do
      {:ok, canonical} -> {:ok, canonical |> Enum.uniq() |> Enum.sort()}
      error -> error
    end
  end

  defp canonical_allowed_roots(roots), do: {:error, {:invalid_allowed_roots, roots}}

  defp validate_task_id(task_id) when is_binary(task_id) and byte_size(task_id) > 0, do: :ok
  defp validate_task_id(task_id), do: {:error, {:invalid_task_id, task_id}}

  defp validate_mode(mode) when mode in [:exclusive, :shared_read], do: :ok
  defp validate_mode(mode), do: {:error, {:invalid_lease_mode, mode}}

  defp validate_owner_kind(kind) when kind in [:generic, :coding, :interactive], do: :ok
  defp validate_owner_kind(kind), do: {:error, {:invalid_workspace_owner_kind, kind}}

  defp validate_managed_task_id(:interactive, "interactive:" <> session_id)
       when byte_size(session_id) > 0,
       do: :ok

  defp validate_managed_task_id(:interactive, task_id),
    do: {:error, {:invalid_interactive_workspace_task_id, task_id}}

  defp validate_managed_task_id(_kind, _task_id), do: :ok

  defp authorize_root(root, allowed_roots) do
    with {:ok, canonical} <- Path.canonicalize(root) do
      if Enum.any?(allowed_roots, &Path.within?(canonical, &1)) do
        {:ok, canonical}
      else
        {:error, {:workspace_outside_allowed_roots, canonical, allowed_roots}}
      end
    end
  end

  defp conflicting_claims(root, mode, kind, task_id, state) do
    requested_key = reservation_key(kind, task_id)
    conflicting_claims(root, mode, requested_key, state)
  end

  defp conflicting_claims(root, mode, requested_key, state) do
    active = Enum.map(state.leases, fn {_id, entry} -> entry.lease end)

    reserved =
      state.reservations
      |> Enum.reject(fn {key, _reservation} ->
        not is_nil(requested_key) and key == requested_key
      end)
      |> Enum.map(fn {_id, reservation} -> reservation.lease end)

    (active ++ reserved)
    |> Enum.filter(fn lease ->
      Path.overlap?(root, lease.root) and
        not (mode == :shared_read and lease.mode == :shared_read)
    end)
    |> Enum.sort_by(&{&1.acquired_at, &1.id})
  end

  defp all_claims(state) do
    active = Enum.map(state.leases, fn {_id, entry} -> entry.lease end)
    reserved = Enum.map(state.reservations, fn {_id, reservation} -> reservation.lease end)
    active ++ reserved
  end

  defp validate_reservation(reservations, task_id, root, mode, requested_kind, owner_pid) do
    case reservation_key(requested_kind, task_id) do
      nil ->
        :ok

      key ->
        validate_reservation_key(
          reservations,
          key,
          task_id,
          root,
          mode,
          requested_kind,
          owner_pid
        )
    end
  end

  defp validate_reservation_key(
         reservations,
         key,
         task_id,
         root,
         mode,
         requested_kind,
         owner_pid
       ) do
    case Map.fetch(reservations, key) do
      {:ok, %{kind: kind, lease: %{root: ^root, mode: ^mode}}} when kind == requested_kind ->
        if registered_recovery_owner?(kind, task_id, owner_pid) do
          :ok
        else
          {:error, {:workspace_recovery_owner_mismatch, task_id}}
        end

      {:ok, _reservation} ->
        {:error, {:workspace_recovery_reservation_mismatch, task_id}}

      :error ->
        :ok
    end
  end

  defp reservation_key(:coding, task_id), do: {:coding, task_id}

  defp reservation_key(:interactive, "interactive:" <> session_id),
    do: {:interactive, session_id}

  defp reservation_key(:interactive, _task_id), do: nil

  defp reservation_key(:generic, _task_id), do: nil

  defp registered_recovery_owner?(kind, task_id, owner_pid) do
    {registry, registry_id} =
      case kind do
        :coding ->
          {Ouroboros.Coding.Registry, task_id}

        :interactive ->
          {Ouroboros.Interactive.Registry, String.replace_prefix(task_id, "interactive:", "")}
      end

    try do
      Registry.lookup(registry, registry_id) == [{owner_pid, nil}]
    catch
      :exit, _reason -> false
    end
  end

  defp recovery_reservations(opts, allowed_roots) do
    if Keyword.get(opts, :recover_reservations, false) do
      with {:ok, coding} <- safe_recovery_states(Ouroboros.Coding.Store),
           {:ok, interactive} <- safe_recovery_states(Ouroboros.Interactive.Store) do
        coding_claims =
          Enum.flat_map(coding, fn
            %Ouroboros.Coding.TaskState{} = task ->
              if task.node == node() and not Ouroboros.Coding.TaskState.terminal?(task),
                do: [{:coding, task.id, task.workspace, task.workspace_mode}],
                else: []

            _other ->
              []
          end)

        interactive_claims =
          Enum.flat_map(interactive, fn
            %Ouroboros.Interactive.State{} = session ->
              if session.node == node() and not Ouroboros.Interactive.State.terminal?(session),
                do: [
                  {:interactive, "interactive:" <> session.id, session.workspace,
                   session.workspace_mode}
                ],
                else: []

            _other ->
              []
          end)

        build_reservations(coding_claims ++ interactive_claims, allowed_roots)
      end
    else
      {:ok, %{}}
    end
  end

  defp safe_recovery_states(store) do
    try do
      case store.list() do
        states when is_list(states) -> {:ok, states}
        {:error, reason} -> {:error, {:workspace_recovery_store_unavailable, store, reason}}
        other -> {:error, {:invalid_workspace_recovery_store, store, other}}
      end
    catch
      :exit, reason -> {:error, {:workspace_recovery_store_unavailable, store, reason}}
    end
  end

  defp build_reservations(claims, allowed_roots) do
    Enum.reduce_while(claims, {:ok, %{}}, fn {kind, task_id, root, mode}, {:ok, acc} ->
      with :ok <- validate_mode(mode),
           {:ok, canonical} <- authorize_root(root, allowed_roots),
           key when not is_nil(key) <- reservation_key(kind, task_id),
           false <- Map.has_key?(acc, key) do
        lease = recovery_lease(task_id, canonical, mode)

        conflicts =
          acc
          |> Map.values()
          |> Enum.map(& &1.lease)
          |> Enum.filter(fn existing ->
            Path.overlap?(canonical, existing.root) and
              not (mode == :shared_read and existing.mode == :shared_read)
          end)

        if conflicts == [] do
          {:cont, {:ok, Map.put(acc, key, %Reservation{kind: kind, lease: lease})}}
        else
          {:halt, {:error, {:conflicting_workspace_recovery_state, task_id}}}
        end
      else
        true ->
          {:halt, {:error, {:duplicate_workspace_recovery_task, task_id}}}

        {:error, reason} ->
          {:halt, {:error, {:invalid_workspace_recovery_state, task_id, reason}}}
      end
    end)
  end

  defp recovery_lease(task_id, root, mode) do
    %Lease{
      id: "recovery-" <> random_id(),
      root: root,
      task_id: task_id,
      mode: mode,
      owner: %{id: random_id(), node: node(), type: :local_process},
      acquired_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }
  end

  defp new_entry(root, task_id, mode, kind, owner_pid) do
    lease_id = random_id()
    capability = random_capability()
    monitor = Process.monitor(owner_pid)

    lease = %Lease{
      id: lease_id,
      root: root,
      task_id: task_id,
      mode: mode,
      owner: %{id: random_id(), node: node(owner_pid), type: :local_process},
      acquired_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    entry = %Entry{
      kind: kind,
      lease: lease,
      owner_pid: owner_pid,
      owner_monitor: monitor,
      capability_digest: capability_digest(capability)
    }

    {lease, capability, entry}
  end

  defp release_active(state, lease_id, entry, demonitor?) do
    if demonitor?, do: Process.demonitor(entry.owner_monitor, [:flush])

    next_state = %{
      state
      | leases: Map.delete(state.leases, lease_id),
        monitors: Map.delete(state.monitors, entry.owner_monitor)
    }

    reserve_or_release(next_state, lease_id, entry, entry.owner_pid)
  end

  defp reserve_or_release(state, lease_id, %Entry{kind: :generic} = entry, owner_pid) do
    add_tombstone(state, lease_id, entry, owner_pid)
  end

  defp reserve_or_release(state, _lease_id, %Entry{} = entry, _owner_pid) do
    if durable_owner_nonterminal_or_unknown?(entry.kind, entry.lease) do
      reservation = %Reservation{kind: entry.kind, lease: entry.lease}
      key = reservation_key(entry.kind, entry.lease.task_id)

      state
      |> add_tombstone(entry.lease.id, entry, entry.owner_pid)
      |> Map.update!(:reservations, &Map.put(&1, key, reservation))
    else
      add_tombstone(state, entry.lease.id, entry, entry.owner_pid)
    end
  end

  defp durable_owner_nonterminal_or_unknown?(:coding, lease) do
    durable_state_nonterminal_or_unknown?(
      safe_store_get(Ouroboros.Coding.Store, lease.task_id),
      &Ouroboros.Coding.TaskState.terminal?/1
    )
  end

  defp durable_owner_nonterminal_or_unknown?(:interactive, lease) do
    session_id = String.replace_prefix(lease.task_id, "interactive:", "")

    durable_state_nonterminal_or_unknown?(
      safe_store_get(Ouroboros.Interactive.Store, session_id),
      &Ouroboros.Interactive.State.terminal?/1
    )
  end

  defp durable_state_nonterminal_or_unknown?({:ok, durable}, terminal?),
    do: not terminal?.(durable)

  defp durable_state_nonterminal_or_unknown?(:not_found, _terminal?), do: false
  defp durable_state_nonterminal_or_unknown?({:error, _reason}, _terminal?), do: true

  defp safe_store_get(store, id) do
    try do
      store.get(id)
    rescue
      error -> {:error, {:store_exception, Exception.message(error)}}
    catch
      kind, reason -> {:error, {:store_failure, kind, reason}}
    end
  end

  defp add_tombstone(state, lease_id, entry, owner_pid) do
    tombstone = %{
      owner_pid: owner_pid,
      capability_digest: entry.capability_digest,
      released_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    Map.update!(state, :released, &Map.put(&1, lease_id, tombstone))
  end

  defp release_tombstone(state, lease_id, caller_pid, capability) do
    case Map.fetch(state.released, lease_id) do
      {:ok, tombstone} ->
        if authorized_release?(tombstone, caller_pid, capability) do
          {:reply, :ok, state}
        else
          {:reply, {:error, :not_lease_owner}, state}
        end

      :error ->
        {:reply, {:error, :lease_not_found}, state}
    end
  end

  defp released_status(released, lease_id) do
    case Map.fetch(released, lease_id) do
      {:ok, tombstone} ->
        {:ok, %{id: lease_id, status: :released, released_at: tombstone.released_at}}

      :error ->
        {:error, :lease_not_found}
    end
  end

  defp authorized_release?(entry, caller_pid, capability) do
    entry.owner_pid == caller_pid or valid_capability?(entry.capability_digest, capability)
  end

  defp valid_capability?(_expected, nil), do: false

  defp valid_capability?(expected, capability) when is_binary(capability) do
    :crypto.hash_equals(expected, capability_digest(capability))
  end

  defp valid_capability?(_expected, _capability), do: false

  defp capability_digest(capability), do: :crypto.hash(:sha256, capability)

  defp random_id do
    18
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp random_capability do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end
end
