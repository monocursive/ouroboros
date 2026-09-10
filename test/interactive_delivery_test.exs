defmodule Ouroboros.InteractiveDeliveryTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log

  alias Ouroboros.Interactive.{Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Provider.Native.Output
  alias Ouroboros.Session
  alias Ouroboros.Storage.DurableFile
  alias Ouroboros.Test.{ControlledModel, NativeConfig}

  defmodule CheckpointGate do
    @moduledoc false
    def get_checkpoint(key, opts), do: DurableFile.get_checkpoint(key, opts[:storage])
    def delete_checkpoint(key, opts), do: DurableFile.delete_checkpoint(key, opts[:storage])

    def put_checkpoint(key, value, opts) do
      gate = Agent.get(opts[:gate], & &1)
      candidate = if is_map(value), do: Map.get(value, gate.id)

      if is_map(candidate) and candidate.cursor > gate.floor and gate.mode != :open do
        case gate.mode do
          :fail ->
            send(gate.test, {:j2_checkpoint_refused, candidate.cursor})
            {:error, :j2_disk_full}

          phase when phase in [:before_write, :after_write] ->
            store = self()
            Agent.update(opts[:gate], &%{&1 | mode: :open, blocked: store})

            if phase == :after_write,
              do: :ok = DurableFile.put_checkpoint(key, value, opts[:storage])

            send(gate.test, {:j2_checkpoint_blocked, phase, self(), candidate.cursor})

            action =
              receive do
                {:j2_release_checkpoint, action} -> action
              after
                15_000 -> :refuse
              end

            Agent.update(opts[:gate], &%{&1 | blocked: nil})

            case action do
              :commit when phase == :before_write ->
                DurableFile.put_checkpoint(key, value, opts[:storage])

              :commit ->
                :ok

              :refuse ->
                {:error, :j2_disk_full}

              :unknown ->
                {:error, {:commit_outcome_unknown, :j2_directory_sync_unknown}}
            end
        end
      else
        DurableFile.put_checkpoint(key, value, opts[:storage])
      end
    end
  end

  setup do
    root = Path.join(System.tmp_dir!(), "j2-delivery-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)
    id = "j2-delivery-#{System.unique_integer([:positive])}"
    original_store = :sys.get_state(Store)
    old_storage = Application.get_env(:ouroboros, :interactive_storage)
    old_dir = Application.get_env(:ouroboros, :native_data_dir)
    old_config = NativeConfig.snapshot()
    storage = [path: Path.join(root, "interactive")]
    owner = self()

    {:ok, gate} =
      Agent.start(fn -> %{id: id, test: owner, floor: 0, mode: :open, blocked: nil} end)

    repo = %{original_store.repo | adapter: CheckpointGate, opts: [storage: storage, gate: gate]}
    :sys.replace_state(Store, fn state -> %{state | repo: repo, sessions: %{}} end)
    Application.put_env(:ouroboros, :interactive_storage, {DurableFile, storage})
    Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "native"))
    NativeConfig.configure(%{native: %{test_pid: self()}})

    on_exit(fn ->
      if Process.alive?(gate) do
        blocked =
          Agent.get_and_update(gate, fn state -> {state.blocked, %{state | mode: :open}} end)

        if is_pid(blocked), do: send(blocked, {:j2_release_checkpoint, :commit})
      end

      if pid = Task.whereis(id),
        do: DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      for {_child, pid, _type, _modules} <-
            DynamicSupervisor.which_children(Ouroboros.SessionTransportSupervisor) do
        case Session.info(pid) do
          {:ok, %{logical_id: ^id}} ->
            DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, pid)

          _ ->
            :ok
        end
      end

      :sys.replace_state(Store, fn _ -> original_store end)
      restore(:interactive_storage, old_storage)
      restore(:native_data_dir, old_dir)
      NativeConfig.configure(old_config)
      if Process.alive?(gate), do: Agent.stop(gate)
      File.rm_rf!(root)
    end)

    {:ok, ref} = InteractiveSession.start(id: id, workspace: workspace, runtime_exposure: false)
    {:ok, turn} = InteractiveSession.send_message(ref, "one admitted turn", id: "#{id}-turn")
    assert_receive {:ouroboros_test_model_started, _, _, producer}, 3_000

    session =
      eventually(fn ->
        {:ok, state} = Store.get(id)
        if Enum.any?(state.events, &(&1.type == :turn_started)), do: state
      end)

    {:ok, info} = Session.info(session.runtime_id)
    eventually(fn -> native_meta(info.pid).acked == session.runtime_cursor end)
    Agent.update(gate, &%{&1 | floor: session.cursor})
    {:ok, _backlog} = InteractiveSession.subscribe(ref, cursor: session.cursor)

    %{
      id: id,
      ref: ref,
      turn: turn,
      producer: producer,
      gate: gate,
      storage: storage,
      original: session,
      native: info.pid,
      runtime_id: info.runtime_id
    }
  end

  test "a blocked checkpoint exposes no output, acknowledgement or terminal waiter outcome",
       ctx do
    Agent.update(ctx.gate, &%{&1 | mode: :before_write})
    emit_marker(ctx.producer)
    assert_receive {:j2_checkpoint_blocked, :before_write, store, cursor}, 3_000
    assert cursor > ctx.original.cursor
    waiter = waiter(ctx)
    ControlledModel.emit(ctx.producer, :usage, %{input_tokens: 7, output_tokens: 3})
    ControlledModel.finish(ctx.producer)
    eventually(fn -> native_meta(ctx.native).cursor > cursor end)

    assert native_meta(ctx.native).acked == ctx.original.runtime_cursor
    assert stored(ctx).cursor == ctx.original.cursor
    refute_receive {:ouroboros_interactive_event, _, _}, 100
    refute_receive {:j2_waiter, {:ok, %{status: :completed}}}, 100

    send(store, {:j2_release_checkpoint, :commit})
    assert_receive {:j2_waiter, {:ok, %{status: :completed}}}, 3_000
    assert Process.alive?(ctx.native)
    assert is_pid(waiter)
  end

  test "a refused checkpoint retains the batch and folds usage only after a later successful commit",
       ctx do
    Agent.update(ctx.gate, &%{&1 | mode: :fail})
    ControlledModel.emit(ctx.producer, :usage, %{input_tokens: 7, output_tokens: 3})
    ControlledModel.finish(ctx.producer)
    waiter(ctx)
    assert_receive {:j2_checkpoint_refused, _}, 3_000
    assert native_meta(ctx.native).acked == ctx.original.runtime_cursor
    assert stored(ctx).cursor == ctx.original.cursor
    refute_receive {:ouroboros_interactive_event, _, _}, 100
    refute_receive {:j2_waiter, {:ok, %{status: :completed}}}, 100

    Agent.update(ctx.gate, &%{&1 | mode: :open})
    assert_receive {:j2_waiter, {:ok, %{status: :completed}}}, 3_000
    {:ok, state} = Store.get(ctx.id)
    assert state.usage.total_tokens == 10
    assert Enum.count(state.events, &(&1.type == :turn_completed)) == 1
    eventually(fn -> native_meta(ctx.native).acked == state.runtime_cursor end)
  end

  for phase <- [:before_write, :after_write] do
    test "a coordinator crash #{phase} reattaches the same runtime and counts a redrained batch once",
         ctx do
      phase = unquote(phase)
      Agent.update(ctx.gate, &%{&1 | mode: phase})
      ControlledModel.emit(ctx.producer, :usage, %{input_tokens: 7, output_tokens: 3})
      ControlledModel.finish(ctx.producer)
      assert_receive {:j2_checkpoint_blocked, ^phase, store, _cursor}, 3_000
      old = Task.whereis(ctx.id)
      monitor = Process.monitor(old)
      Process.exit(old, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^old, :killed}, 3_000
      assert Process.alive?(ctx.native)
      assert native_meta(ctx.native).acked == ctx.original.runtime_cursor
      send(store, {:j2_release_checkpoint, :commit})

      completed =
        eventually(fn ->
          case InteractiveSession.info(ctx.ref) do
            {:ok, state} ->
              if state.turns[ctx.turn.id].status == :completed do
                {:ok, stored} = Store.get(ctx.id)
                stored
              end

            _ ->
              nil
          end
        end)

      assert Task.whereis(ctx.id) != old
      assert completed.runtime_id == ctx.runtime_id
      assert completed.usage.total_tokens == 10
      assert Enum.count(completed.events, &(&1.type == :turn_completed)) == 1
      assert length(Enum.uniq_by(completed.events, & &1.sequence)) == length(completed.events)
      refute_receive {:ouroboros_test_model_started, _, _, _}, 100
      eventually(fn -> native_meta(ctx.native).acked == completed.runtime_cursor end)
    end
  end

  test "a crash after acknowledgement replays durable usage without executing another model turn",
       ctx do
    ControlledModel.emit(ctx.producer, :usage, %{input_tokens: 7, output_tokens: 3})
    ControlledModel.finish(ctx.producer)
    assert {:ok, %{status: :completed}} = InteractiveSession.await(ctx.ref, ctx.turn.id, 3_000)
    {:ok, before} = Store.get(ctx.id)
    eventually(fn -> native_meta(ctx.native).acked == before.runtime_cursor end)
    old = Task.whereis(ctx.id)
    Process.exit(old, :kill)

    after_restart =
      eventually(fn ->
        if Task.whereis(ctx.id) != old do
          case InteractiveSession.info(ctx.ref) do
            {:ok, _state} ->
              {:ok, stored} = Store.get(ctx.id)
              stored

            _ ->
              nil
          end
        end
      end)

    assert after_restart.runtime_id == before.runtime_id
    assert after_restart.usage == before.usage
    assert Enum.map(after_restart.events, & &1.id) == Enum.map(before.events, & &1.id)
    refute_receive {:ouroboros_test_model_started, _, _, _}, 100
  end

  test "an uncertain commit stops dependent execution and publishes none of the uncertain batch",
       ctx do
    Agent.update(ctx.gate, &%{&1 | mode: :after_write})
    emit_marker(ctx.producer)
    assert_receive {:j2_checkpoint_blocked, :after_write, store, _cursor}, 3_000
    assert stored(ctx).cursor > ctx.original.cursor
    assert native_meta(ctx.native).acked == ctx.original.runtime_cursor
    refute_receive {:ouroboros_interactive_event, _, _}, 100
    monitor = Process.monitor(ctx.native)
    send(store, {:j2_release_checkpoint, :unknown})
    assert_receive {:DOWN, ^monitor, :process, _, _}, 3_000
    eventually(fn -> is_pid(Process.whereis(Store)) and Process.whereis(Store) != store end)
    refute_receive {:ouroboros_interactive_event, _, %{payload: %{"kind" => "j2_barrier"}}}, 100
    refute_receive {:ouroboros_test_model_started, _, _, _}, 200
  end

  test "a refused resume checkpoint retries adoption of the same idle replacement", ctx do
    Agent.update(ctx.gate, &%{&1 | mode: :fail})
    Process.exit(ctx.native, :kill)
    assert_receive {:j2_checkpoint_refused, _cursor}, 3_000

    replacement =
      eventually(fn ->
        Enum.find(Session.list(), &(&1.logical_id == ctx.id and &1.runtime_id != ctx.runtime_id))
      end)

    assert replacement.state == :idle
    assert {:ok, %{runtime_id: old_id}} = Store.get(ctx.id)
    assert old_id == ctx.runtime_id
    Agent.update(ctx.gate, &%{&1 | mode: :open})

    resumed =
      eventually(fn ->
        {:ok, session} = Store.get(ctx.id)
        if session.runtime_id == replacement.runtime_id and session.status == :idle, do: session
      end)

    assert resumed.resumes == 1
    assert Enum.count(resumed.events, &(&1.payload["kind"] == "resumed")) == 1
    assert Enum.count(Session.list(), &(&1.logical_id == ctx.id)) == 1
    refute_receive {:ouroboros_test_model_started, _, _, _}, 100
    assert :ok = InteractiveSession.close(ctx.ref)
    eventually(fn -> Session.info(replacement.runtime_id) == {:error, :not_found} end)
  end

  test "kill during a refused resume adoption also retires the retained replacement", ctx do
    Agent.update(ctx.gate, &%{&1 | mode: :fail})
    Process.exit(ctx.native, :kill)
    assert_receive {:j2_checkpoint_refused, _cursor}, 3_000

    replacement =
      eventually(fn ->
        Enum.find(Session.list(), &(&1.logical_id == ctx.id and &1.runtime_id != ctx.runtime_id))
      end)

    assert {:error, :not_found} = InteractiveSession.kill(ctx.ref)
    assert {:ok, %{close_intent: :kill}} = Store.get(ctx.id)
    Agent.update(ctx.gate, &%{&1 | mode: :open})

    eventually(fn ->
      {:ok, session} = Store.get(ctx.id)

      session.status == :cancelled and
        Session.info(replacement.runtime_id) == {:error, :not_found}
    end)

    refute_receive {:ouroboros_test_model_started, _, _, _}, 100
    assert Enum.count(Session.list(), &(&1.logical_id == ctx.id)) == 0
  end

  test "a slow subscriber receives one resync and is detached before its mailbox can grow", ctx do
    slow =
      spawn(fn ->
        receive do
          :release -> :ok
        end
      end)

    on_exit(fn -> Process.exit(slow, :kill) end)

    assert {:ok, _} =
             GenServer.call(Task.whereis(ctx.id), {:subscribe, slow, ctx.original.cursor})

    for i <- 1..1000, do: send(slow, {:already_queued, i})
    emit_marker(ctx.producer)
    eventually(fn -> not Map.has_key?(:sys.get_state(Task.whereis(ctx.id)).subscribers, slow) end)
    assert {:message_queue_len, 1001} = Process.info(slow, :message_queue_len)
    assert {:messages, messages} = Process.info(slow, :messages)
    assert Enum.count(messages, &match?({:ouroboros_interactive_resync, _, _}, &1)) == 1
    for _ <- 1..20, do: emit_marker(ctx.producer)
    ControlledModel.finish(ctx.producer)
    assert {:ok, %{status: :completed}} = InteractiveSession.await(ctx.ref, ctx.turn.id, 3_000)
    assert {:message_queue_len, 1001} = Process.info(slow, :message_queue_len)
    assert {:ok, events} = InteractiveSession.replay(ctx.ref, cursor: ctx.original.cursor)
    assert Enum.count(events, &(&1.payload["kind"] == "j2_barrier")) == 21
  end

  defp emit_marker(producer),
    do: ControlledModel.emit(producer, :provider_event, %{"kind" => "j2_barrier"})

  defp waiter(ctx) do
    owner = self()

    spawn(fn ->
      send(owner, {:j2_waiter, InteractiveSession.await(ctx.ref, ctx.turn.id, 5_000)})
    end)
  end

  defp stored(ctx) do
    key = {{:ouroboros, :interactive_sessions, 1}, :session, 2, ctx.id}
    {:ok, records} = DurableFile.get_checkpoint(key, ctx.storage)
    records[ctx.id]
  end

  defp native_meta(pid) do
    owner = self()
    ref = make_ref()

    :sys.replace_state(pid, fn state ->
      send(owner, {ref, Output.snapshot(state.output) |> Map.take([:acked, :cursor, :count])})
      state
    end)

    receive do
      {^ref, meta} -> meta
    after
      1000 -> flunk("no native output state")
    end
  end

  defp eventually(fun, attempts \\ 300)
  defp eventually(_fun, 0), do: flunk("condition did not settle")

  defp eventually(fun, attempts) do
    case fun.() do
      value when value not in [false, nil] ->
        value

      _ ->
        Process.sleep(10)
        eventually(fun, attempts - 1)
    end
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
