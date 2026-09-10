defmodule Ouroboros.InteractiveTerminalAckTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log

  alias Ouroboros.Interactive.{Event, State, Store, Task}
  alias Ouroboros.Session
  alias Ouroboros.Test.NativeModelScript

  defmodule RetainedTerminal do
    use GenServer
    alias Ouroboros.Session.RuntimeInfo

    def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

    def init(opts) do
      {:ok, _} = Registry.register(Ouroboros.SessionRegistry, {:runtime, opts.runtime_id}, nil)
      {:ok, Map.merge(opts, %{attempts: 0})}
    end

    def handle_call(:runtime_info, _from, state) do
      {:reply, {:ok, info(state)}, state}
    end

    def handle_call({:attach, coordinator, cursor}, {coordinator, _}, state) do
      send(state.test, {:terminal_attach, cursor})

      attachment = %{
        runtime_id: state.runtime_id,
        generation: state.generation,
        token: make_ref()
      }

      {:reply, {:ok, attachment, info(state)}, state}
    end

    def handle_call({:ack, _attachment, cursor}, _from, %{attempts: 0} = state) do
      send(state.test, {:terminal_ack_refused, cursor})
      {:reply, {:error, :injected_ack_failure}, %{state | attempts: 1}}
    end

    def handle_call({:ack, _attachment, cursor}, _from, state) do
      send(state.test, {:terminal_ack_recovered, cursor})
      {:stop, :normal, :ok, state}
    end

    def handle_call(other, _from, state) do
      send(state.test, {:unexpected_terminal_operation, other})
      {:reply, {:error, :unexpected_operation}, state}
    end

    defp info(state) do
      %RuntimeInfo{
        runtime_id: state.runtime_id,
        session_id: state.runtime_id,
        logical_id: state.logical_id,
        generation: state.generation,
        state: :closed,
        status: :closed,
        output_cursor: state.cursor,
        output_high_water: state.cursor,
        pid: self()
      }
    end
  end

  setup do
    root = Path.join(System.tmp_dir!(), "terminal-ack-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    original_dir = Application.get_env(:ouroboros, :native_data_dir)
    original_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "native"))
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      restore(:native_data_dir, original_dir)
      restore(:native_model_module, original_model)
      File.rm_rf!(root)
    end)

    %{root: root, id: "terminal-ack-#{System.unique_integer([:positive])}"}
  end

  test "coordinator restart releases the real native terminal checkpointed before its ack", ctx do
    {model, model_agent} = NativeModelScript.start([])
    {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, ctx.id, nil)
    {:ok, runtime_id} = Session.open(ctx.id, %{cwd: ctx.root, model: model})
    {:ok, attachment, info} = Session.attach(runtime_id, self(), 0)
    :ok = Session.close(runtime_id)
    {:ok, events, _} = Session.drain(attachment, 0, 500)
    cursor = List.last(events).sequence
    {:ok, base} = State.new(ctx.id, workspace: ctx.root, runtime_exposure: false)

    session = %{
      base
      | status: :closed,
        runtime_id: runtime_id,
        runtime_generation: info.generation,
        runtime_cursor: cursor,
        cursor: cursor,
        provider_session_id: info.provider_session_id,
        events: Enum.map(events, &Event.from_execution(ctx.id, &1))
    }

    :ok = Store.create(session)
    on_exit(fn -> cleanup(ctx.id, info.pid) end)
    assert Process.alive?(info.pid)
    Registry.unregister(Ouroboros.Interactive.Registry, ctx.id)
    monitor = Process.monitor(info.pid)

    {:ok, _coordinator} =
      DynamicSupervisor.start_child(Ouroboros.Interactive.TaskSupervisor, {Task, ctx.id})

    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 2_000
    assert {:ok, ^session} = Store.get(ctx.id)
    assert NativeModelScript.call_count(model_agent) == 0
  end

  test "terminal acknowledgement failure retries without rewriting history or dispatching execution",
       ctx do
    runtime_id = "runtime-terminal-retry-#{System.unique_integer([:positive])}"
    generation = "terminal-generation"

    {:ok, retained} =
      RetainedTerminal.start_link(%{
        runtime_id: runtime_id,
        logical_id: ctx.id,
        generation: generation,
        cursor: 7,
        test: self()
      })

    {:ok, base} = State.new(ctx.id, workspace: ctx.root, runtime_exposure: false)

    session = %{
      base
      | status: :closed,
        runtime_id: runtime_id,
        runtime_generation: generation,
        runtime_cursor: 7,
        cursor: 7
    }

    :ok = Store.create(session)
    on_exit(fn -> cleanup(ctx.id, retained) end)

    {:ok, coordinator} =
      DynamicSupervisor.start_child(Ouroboros.Interactive.TaskSupervisor, {Task, ctx.id})

    assert_receive {:terminal_ack_refused, 7}, 1_000
    assert Process.alive?(coordinator)
    assert {:ok, ^session} = Store.get(ctx.id)
    assert_receive {:terminal_ack_recovered, 7}, 2_000
    refute_receive {:unexpected_terminal_operation, _}, 50
    assert {:ok, ^session} = Store.get(ctx.id)
  end

  test "terminal recovery cannot acknowledge a replacement generation", ctx do
    runtime_id = "runtime-terminal-stale-#{System.unique_integer([:positive])}"

    {:ok, replacement} =
      RetainedTerminal.start_link(%{
        runtime_id: runtime_id,
        logical_id: ctx.id,
        generation: "new-generation",
        cursor: 7,
        test: self()
      })

    {:ok, base} = State.new(ctx.id, workspace: ctx.root, runtime_exposure: false)

    session = %{
      base
      | status: :closed,
        runtime_id: runtime_id,
        runtime_generation: "old-generation",
        runtime_cursor: 7,
        cursor: 7
    }

    :ok = Store.create(session)
    on_exit(fn -> cleanup(ctx.id, replacement) end)

    {:ok, coordinator} =
      DynamicSupervisor.start_child(Ouroboros.Interactive.TaskSupervisor, {Task, ctx.id})

    monitor = Process.monitor(coordinator)
    assert_receive {:DOWN, ^monitor, :process, ^coordinator, :normal}, 2_000
    refute_receive {:terminal_attach, _}, 50
    refute_receive {:terminal_ack_refused, _}, 50
    assert Process.alive?(replacement)
    assert {:ok, ^session} = Store.get(ctx.id)
  end

  defp cleanup(id, runtime) do
    if pid = Task.whereis(id),
      do: DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

    if Process.alive?(runtime), do: Process.exit(runtime, :kill)
    Store.delete(id)
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
