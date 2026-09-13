defmodule Ouroboros.Maintenance.Fence do
  @moduledoc """
  Node-local cooperative maintenance admission fence.

  This process is the target-owned half of the P4 controller contract. It serializes
  operation leases with fence entry, closes admission before obtaining and revalidating
  an authoritative maintenance barrier, and persists the resulting inventory identity
  before reporting success. It is not an updater, lifecycle controller, or
  hostile-same-UID security boundary.
  """

  use GenServer

  alias Ouroboros.Maintenance.{Barrier, NativeInventory}

  @filename "maintenance-fence.json"
  @max_id_bytes 128
  @default_barrier_timeout 30_000
  @digest ~r/\A[0-9a-f]{64}\z/

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  def acquire(operation_id, session_id, server \\ __MODULE__),
    do: acquire_admission(operation_id, session_id, :current, server)

  def acquire_admission(operation_id, session_id, generation \\ :current, server \\ __MODULE__),
    do: GenServer.call(server, {:acquire, operation_id, session_id, generation})

  def release(token, server \\ __MODULE__), do: GenServer.call(server, {:release, token})

  def validate_admission(token, session_id, server \\ __MODULE__),
    do: GenServer.call(server, {:validate, token, session_id})

  def queue_turn(token, turn_id, server \\ __MODULE__),
    do: GenServer.call(server, {:queue_turn, token, turn_id})

  def enter(transaction_id, expected_generation, server \\ __MODULE__),
    do: GenServer.call(server, {:enter, transaction_id, expected_generation}, :infinity)

  def inspect(server \\ __MODULE__), do: GenServer.call(server, :inspect)

  def release_fence(transaction_id, generation, server \\ __MODULE__),
    do: GenServer.call(server, {:release_fence, transaction_id, generation}, :infinity)

  @impl true
  def init(opts) do
    path = marker_path(Keyword.get(opts, :data_dir, Application.get_env(:ouroboros, :data_dir)))

    base = %{
      path: path,
      mode: :open,
      generation: 0,
      marker: nil,
      leases: %{},
      participant_revision: 0,
      entry: nil,
      native_release: nil,
      barrier: Keyword.get(opts, :barrier, {Barrier, :freeze}),
      barrier_opts: Keyword.get(opts, :barrier_opts, []),
      barrier_timeout: Keyword.get(opts, :barrier_timeout, @default_barrier_timeout)
    }

    with :ok <- valid_barrier_timeout(base.barrier_timeout) do
      case load_marker(path) do
        {:ok, marker} ->
          {:ok, %{base | mode: :fenced, generation: marker["generation"], marker: marker}}

        :not_found ->
          {:ok, base}

        {:error, reason} ->
          {:stop, {:maintenance_fence_unavailable, reason}}
      end
    else
      {:error, reason} -> {:stop, {:maintenance_fence_unavailable, reason}}
    end
  end

  @impl true
  def handle_call({:acquire, operation_id, session_id, expected_generation}, _from, state) do
    with :ok <- valid_id(operation_id),
         :ok <- valid_id(session_id),
         :ok <- matching_generation(expected_generation, state.generation),
         :open <- state.mode do
      case Map.get(state.leases, operation_id) do
        nil ->
          token = %{
            operation_id: operation_id,
            session_id: session_id,
            generation: state.generation,
            capability: make_ref()
          }

          next = %{
            state
            | leases: Map.put(state.leases, operation_id, token),
              participant_revision: state.participant_revision + 1
          }

          {:reply, {:ok, token}, next}

        %{session_id: ^session_id} = token ->
          {:reply, {:ok, token}, state}

        _conflict ->
          {:reply, {:error, :operation_id_conflict}, state}
      end
    else
      mode when mode in [:closing, :fenced] -> {:reply, {:error, :maintenance_fenced}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:release, token}, _from, state) do
    case Map.get(state.leases, token[:operation_id]) do
      ^token ->
        next = %{
          state
          | leases: Map.delete(state.leases, token.operation_id),
            participant_revision: state.participant_revision + 1
        }

        {:reply, :ok, next}

      nil ->
        {:reply, :stale, state}

      _ ->
        {:reply, {:error, :not_lease_owner}, state}
    end
  end

  def handle_call({:validate, token, session_id}, _from, state) do
    case Map.get(state.leases, token[:operation_id]) do
      ^token when token.session_id == session_id and token.generation == state.generation ->
        {:reply, :ok, state}

      nil ->
        {:reply, {:error, :stale_admission}, state}

      _ ->
        {:reply, {:error, :invalid_admission}, state}
    end
  end

  def handle_call({:queue_turn, token, turn_id}, _from, state) do
    with :ok <- valid_id(turn_id) do
      case Map.get(state.leases, token[:operation_id]) do
        ^token when token.generation == state.generation and state.mode == :open ->
          {:reply, :ok, state}

        nil ->
          {:reply, {:error, :stale_admission}, state}

        _ ->
          {:reply, {:error, :invalid_admission}, state}
      end
    else
      {:error, _reason} -> {:reply, {:error, :invalid_turn_id}, state}
    end
  end

  def handle_call({:enter, transaction_id, expected}, from, state) do
    cond do
      valid_id(transaction_id) != :ok ->
        {:reply, {:error, :invalid_transaction_id}, state}

      state.mode == :fenced ->
        {:reply, {:error, :already_fenced}, state}

      state.mode == :closing ->
        {:reply, {:error, :already_closing}, state}

      expected != state.generation ->
        {:reply, {:error, {:stale_generation, state.generation}}, state}

      map_size(state.leases) != 0 ->
        {:reply, {:error, {:active_admission, map_size(state.leases)}}, state}

      true ->
        fence_generation = state.generation + 1
        attempt = make_ref()
        maintenance_token = make_ref()
        parent = self()
        barrier = state.barrier
        barrier_opts = Keyword.put(state.barrier_opts, :maintenance_token, maintenance_token)

        {pid, monitor} =
          spawn_monitor(fn ->
            result = freeze_and_revalidate(barrier, fence_generation, barrier_opts)
            send(parent, {:barrier_result, attempt, result})
          end)

        timer = Process.send_after(self(), {:barrier_timeout, attempt}, state.barrier_timeout)

        entry = %{
          attempt: attempt,
          from: from,
          transaction_id: transaction_id,
          generation: fence_generation,
          participant_revision: state.participant_revision,
          pid: pid,
          monitor: monitor,
          timer: timer,
          maintenance_token: maintenance_token
        }

        {:noreply, %{state | mode: :closing, entry: entry}}
    end
  end

  def handle_call(:inspect, _from, state) do
    marker = state.marker
    transaction_id = (marker && marker["transaction_id"]) || closing_transaction(state.entry)

    {:reply,
     %{
       state: state.mode,
       generation: state.generation,
       active_admissions: map_size(state.leases),
       transaction_id: transaction_id
     }, state}
  end

  def handle_call({:release_fence, transaction_id, generation}, _from, state) do
    case state.marker do
      %{"transaction_id" => ^transaction_id, "generation" => ^generation} ->
        with :ok <- Barrier.release(state.native_release),
             :ok <- remove_marker(state.path) do
          {:reply, :ok, %{state | mode: :open, marker: nil, native_release: nil}}
        else
          {:error, reason} -> {:reply, {:error, {:fence_release_unknown, reason}}, state}
        end

      _ ->
        {:reply, {:error, :fence_identity_mismatch}, state}
    end
  end

  @impl true
  def handle_info(
        {:barrier_result, attempt, result},
        %{entry: %{attempt: attempt} = entry} = state
      ) do
    Process.cancel_timer(entry.timer)
    Process.demonitor(entry.monitor, [:flush])

    case complete_entry(result, entry, state) do
      {:ok, marker, native_release} ->
        GenServer.reply(entry.from, {:ok, marker})

        {:noreply,
         %{
           state
           | mode: :fenced,
             marker: marker,
             generation: marker["generation"],
             entry: nil,
             native_release: native_release
         }}

      {:error, reason} ->
        release_precommit(entry, result)
        GenServer.reply(entry.from, {:error, reason})
        {:noreply, %{state | mode: :open, entry: nil}}
    end
  end

  def handle_info({:barrier_result, _attempt, _result}, state), do: {:noreply, state}

  def handle_info({:barrier_timeout, attempt}, %{entry: %{attempt: attempt} = entry} = state) do
    Process.exit(entry.pid, :kill)
    Process.demonitor(entry.monitor, [:flush])
    _ = NativeInventory.release_all(entry.generation, entry.maintenance_token)
    GenServer.reply(entry.from, {:error, :barrier_timeout})
    {:noreply, %{state | mode: :open, entry: nil}}
  end

  def handle_info({:barrier_timeout, _attempt}, state), do: {:noreply, state}

  def handle_info(
        {:DOWN, monitor, :process, _pid, reason},
        %{entry: %{monitor: monitor} = entry} = state
      ) do
    Process.cancel_timer(entry.timer)
    _ = NativeInventory.release_all(entry.generation, entry.maintenance_token)
    GenServer.reply(entry.from, {:error, {:barrier_unavailable, reason}})
    {:noreply, %{state | mode: :open, entry: nil}}
  end

  def handle_info({:DOWN, _monitor, :process, _pid, _reason}, state), do: {:noreply, state}

  defp complete_entry({:ok, barrier}, entry, state) do
    with :ok <- revalidate_entry(entry, state),
         :ok <- Barrier.revalidate(barrier),
         {:ok, marker} <- marker(entry, barrier),
         :ok <- persist(state.path, marker) do
      {:ok, marker, barrier[:native_release]}
    else
      {:error, {:fence_persist_failed, _reason} = reason} -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  defp complete_entry({:error, reason}, _entry, _state), do: {:error, {:barrier_refused, reason}}

  defp release_precommit(_entry, {:ok, %{native_release: release}}),
    do: Barrier.release(release)

  defp release_precommit(entry, _result),
    do: NativeInventory.release_all(entry.generation, entry.maintenance_token)

  defp revalidate_entry(entry, state) do
    cond do
      state.mode != :closing -> {:error, :fence_state_changed}
      state.generation != entry.generation - 1 -> {:error, {:stale_generation, state.generation}}
      state.participant_revision != entry.participant_revision -> {:error, :participants_changed}
      map_size(state.leases) != 0 -> {:error, :participants_changed}
      true -> :ok
    end
  end

  defp marker(entry, %{snapshot: snapshot, write_epoch: write_epoch}) do
    with %{generation: generation, token: snapshot_id, digest: inventory_digest} <- snapshot,
         true <- generation == entry.generation,
         true <- valid_digest?(snapshot_id),
         true <- valid_digest?(inventory_digest),
         true <- is_integer(write_epoch) and write_epoch >= 0 do
      {:ok,
       %{
         "schema" => 1,
         "transaction_id" => entry.transaction_id,
         "generation" => entry.generation,
         "state" => "fenced",
         "snapshot_id" => snapshot_id,
         "inventory_digest" => inventory_digest,
         "write_epoch" => write_epoch
       }}
    else
      _ -> {:error, :invalid_barrier_snapshot}
    end
  end

  defp marker(_entry, _barrier), do: {:error, :invalid_barrier_snapshot}

  defp freeze_and_revalidate(barrier, generation, opts) do
    with {:ok, first} <- invoke_barrier(barrier, generation, opts),
         :ok <- valid_barrier(first, generation),
         {:ok, second} <- invoke_barrier(barrier, generation, opts),
         :ok <- valid_barrier(second, generation),
         true <- barrier_identity(first) == barrier_identity(second) do
      {:ok, first}
    else
      false -> {:error, :participants_changed}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_barrier_snapshot}
    end
  catch
    kind, reason -> {:error, {:barrier_callback_failed, kind, reason}}
  end

  defp invoke_barrier(fun, generation, opts) when is_function(fun, 2), do: fun.(generation, opts)
  defp invoke_barrier(fun, generation, _opts) when is_function(fun, 1), do: fun.(generation)

  defp invoke_barrier({module, function}, generation, opts),
    do: apply(module, function, [generation, opts])

  defp invoke_barrier(_barrier, _generation, _opts), do: {:error, :invalid_barrier_callback}

  defp valid_barrier(%{snapshot: snapshot, write_epoch: epoch}, generation) do
    case snapshot do
      %{generation: ^generation, token: token, digest: digest, root_digest: root, total: total}
      when is_integer(epoch) and epoch >= 0 and is_integer(total) and total >= 0 ->
        if valid_digest?(token) and valid_digest?(digest) and valid_digest?(root),
          do: :ok,
          else: {:error, :invalid_barrier_snapshot}

      _ ->
        {:error, :invalid_barrier_snapshot}
    end
  end

  defp valid_barrier(_barrier, _generation), do: {:error, :invalid_barrier_snapshot}

  defp barrier_identity(barrier) do
    snapshot = barrier.snapshot
    {snapshot.token, snapshot.digest, snapshot.root_digest, snapshot.total, barrier.write_epoch}
  end

  defp closing_transaction(nil), do: nil
  defp closing_transaction(entry), do: entry.transaction_id

  defp marker_path(nil), do: nil
  defp marker_path(data_dir) when is_binary(data_dir), do: Path.join(data_dir, @filename)

  defp valid_id(value) when is_binary(value) do
    if value != "" and byte_size(value) <= @max_id_bytes and String.valid?(value),
      do: :ok,
      else: {:error, :invalid_id}
  end

  defp valid_id(_), do: {:error, :invalid_id}

  defp matching_generation(:current, _generation), do: :ok
  defp matching_generation(generation, generation) when is_integer(generation), do: :ok
  defp matching_generation(_expected, current), do: {:error, {:stale_generation, current}}

  defp valid_barrier_timeout(value) when is_integer(value) and value > 0, do: :ok
  defp valid_barrier_timeout(_value), do: {:error, :invalid_barrier_timeout}
  defp valid_digest?(value), do: is_binary(value) and value =~ @digest

  defp load_marker(nil), do: :not_found

  defp load_marker(path) do
    case File.read(path) do
      {:ok, bytes} ->
        with {:ok, marker} <- Jason.decode(bytes),
             true <- valid_marker?(marker) do
          {:ok, marker}
        else
          _ -> {:error, :invalid_marker}
        end

      {:error, :enoent} ->
        :not_found

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp valid_marker?(marker) do
    is_map(marker) and map_size(marker) == 7 and marker["schema"] == 1 and
      marker["state"] == "fenced" and valid_id(marker["transaction_id"]) == :ok and
      is_integer(marker["generation"]) and marker["generation"] > 0 and
      valid_digest?(marker["snapshot_id"]) and valid_digest?(marker["inventory_digest"]) and
      is_integer(marker["write_epoch"]) and marker["write_epoch"] >= 0
  end

  defp persist(nil, _marker), do: {:error, {:fence_persist_failed, :no_data_dir}}

  defp persist(path, marker) do
    dir = Path.dirname(path)
    temp = path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    with :ok <- File.mkdir_p(dir),
         :ok <- File.write(temp, Jason.encode!(marker), [:exclusive, :sync]),
         :ok <- File.chmod(temp, 0o600),
         :ok <- File.rename(temp, path),
         :ok <- sync_dir(dir) do
      :ok
    else
      {:error, reason} ->
        _ = File.rm(temp)
        {:error, {:fence_persist_failed, reason}}
    end
  end

  defp remove_marker(nil), do: {:error, :no_data_dir}

  defp remove_marker(path) do
    with :ok <- File.rm(path), :ok <- sync_dir(Path.dirname(path)), do: :ok
  end

  defp sync_dir(dir) do
    with {:ok, device} <- :file.open(String.to_charlist(dir), [:read, :raw, :directory]),
         :ok <- :file.sync(device),
         :ok <- :file.close(device) do
      :ok
    end
  end
end
