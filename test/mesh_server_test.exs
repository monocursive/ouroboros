defmodule Ouroboros.Capability.MeshServerReference do
  @behaviour Ouroboros.Mesh.Agent
  @impl true
  def init_state(initial), do: {:ok, Map.merge(%{count: 0}, initial)}
  @impl true
  def handle_message(%{body: {:block, observer}}, state, context) do
    send(observer, {:handler_started, self(), context})

    receive do
      :continue -> {:ok, %{state | count: state.count + 1}}
    end
  end

  def handle_message(%{body: :fail}, _state, _context), do: {:error, :deliberate_failure}
  def handle_message(%{body: {:replace, next}}, _state, _context), do: {:ok, next}
  def handle_message(_message, state, _context), do: {:ok, %{state | count: state.count + 1}}
end

defmodule Ouroboros.Capability.RetiredContractReference do
  # A historical extension with only the retired constructor surface must never run.
  def new, do: raise("unsupported contract executed")
end

defmodule Ouroboros.MeshServerTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Mesh
  alias Ouroboros.Capability.MeshServerReference, as: Reference

  test "only the owned callback contract is startable" do
    assert {:error, {:unsupported_agent_contract, Ouroboros.Capability.RetiredContractReference}} =
             Mesh.start_agent(id(), agent: Ouroboros.Capability.RetiredContractReference)
  end

  test "malformed directly constructed envelopes fail without restarting or changing state" do
    id = start()
    owner = Mesh.whereis(id)

    for data <- [[1], [{:from, "test"}, :malformed], %{from: self()}] do
      message = %Ouroboros.Signals.AgentMessage{
        id: Ouroboros.ID.generate!(),
        type: "ouroboros.agent.message",
        source: "/test",
        data: data
      }

      assert {:error, _} = Ouroboros.Mesh.Server.call(owner, message, 1_000)
      assert Mesh.whereis(id) == owner
      assert {:ok, %{agent: %{state: %{count: 0}}}} = Mesh.state(id)
    end

    assert {:ok, %{state: %{count: 1}}} = Mesh.send_message("test", id, :increment)
  end

  test "healthy concurrent starts serialize to one owner" do
    id = id()
    on_exit(fn -> Mesh.stop_agent(id) end)

    results =
      1..12
      |> Task.async_stream(fn _ -> Mesh.start_agent(id, agent: Reference) end,
        max_concurrency: 12
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert [{:ok, owner}] = Enum.filter(results, &match?({:ok, _}, &1))
    assert Enum.count(results, &(&1 == {:error, {:already_started, owner}})) == 11
    assert Mesh.members(id) == [owner]
  end

  test "one handler runs while bounded admission and committed-state inspection remain responsive" do
    id = start(max_queue_size: 1)
    observer = self()
    first = Task.async(fn -> Mesh.send_message("test", id, {:block, observer}) end)
    assert_receive {:handler_started, worker, %{id: ^id, server_pid: server}}, 1_000
    assert server == Mesh.whereis(id)
    refute server == worker
    second = Task.async(fn -> Mesh.send_message("test", id, :increment) end)
    eventually(fn -> :sys.get_state(server).queue_size == 1 end)
    assert {:ok, %{agent: %{state: %{count: 0}}}} = Mesh.state(id)
    assert {:error, :queue_overflow} = Mesh.send_message("test", id, :overflow)
    send(worker, :continue)
    assert {:ok, %{state: %{count: 1}}} = Task.await(first)
    assert {:ok, %{state: %{count: 2}}} = Task.await(second)
  end

  test "timeouts do not resend or discard an executed transition, and failures keep committed state" do
    id = start()
    observer = self()
    caller = Task.async(fn -> Mesh.send_message("test", id, {:block, observer}, timeout: 25) end)
    assert_receive {:handler_started, worker, _}, 1_000
    assert {:error, {:agent_call_failed, :exit, {:timeout, _}}} = Task.await(caller)
    send(worker, :continue)
    eventually(fn -> match?({:ok, %{agent: %{state: %{count: 1}}}}, Mesh.state(id)) end)
    assert {:error, :deliberate_failure} = Mesh.send_message("test", id, :fail)
    assert {:ok, %{agent: %{state: %{count: 1}}}} = Mesh.state(id)

    assert {:ok, %{state: %{answer: %{fresh: true}}}} =
             Mesh.send_message("test", id, {:replace, %{answer: %{fresh: true}}})

    assert {:ok, %{state: %{answer: %{other: true}}}} =
             Mesh.send_message("test", id, {:replace, %{answer: %{other: true}}})
  end

  test "forced owner death kills its active task and restarts one fresh registered owner" do
    id = start()
    observer = self()
    caller = Task.async(fn -> Mesh.send_message("test", id, {:block, observer}) end)
    assert_receive {:handler_started, worker, %{server_pid: owner}}, 1_000
    monitor = Process.monitor(worker)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 1_000
    assert {:error, {:agent_call_failed, :exit, _}} = Task.await(caller)
    eventually(fn -> match?([pid] when pid != owner, Mesh.members(id)) end)
    assert {:ok, %{agent: %{state: %{count: 0}}}} = Mesh.state(id)
  end

  test "explicit stop cancels an active handler without restarting its owner" do
    id = start()
    observer = self()
    caller = Task.async(fn -> Mesh.send_message("test", id, {:block, observer}) end)
    assert_receive {:handler_started, worker, _}, 1_000
    monitor = Process.monitor(worker)
    assert :ok = Mesh.stop_agent(id)
    assert_receive {:DOWN, ^monitor, :process, ^worker, _}, 1_000
    assert {:error, {:agent_call_failed, :exit, _}} = Task.await(caller)
    eventually(fn -> Mesh.members(id) == [] end)
  end

  test "the configured failure threshold restarts from initialized state" do
    id = start(error_policy: {:max_errors, 2})
    owner = Mesh.whereis(id)
    assert {:error, :deliberate_failure} = Mesh.send_message("test", id, :fail)
    assert Mesh.whereis(id) == owner
    assert {:error, :deliberate_failure} = Mesh.send_message("test", id, :fail)
    eventually(fn -> match?([pid] when pid != owner, Mesh.members(id)) end)
  end

  defp start(opts \\ []) do
    id = id()
    assert {:ok, _} = Mesh.start_agent(id, [agent: Reference] ++ opts)
    on_exit(fn -> Mesh.stop_agent(id) end)
    id
  end

  defp id, do: "mesh-owned-#{System.unique_integer([:positive])}"
  defp eventually(fun, attempts \\ 200)
  defp eventually(_fun, 0), do: flunk("condition did not become true")

  defp eventually(fun, attempts) do
    if fun.(),
      do: :ok,
      else:
        (
          Process.sleep(10)
          eventually(fun, attempts - 1)
        )
  end
end
