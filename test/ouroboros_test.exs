defmodule OuroborosTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh

  test "starts a supervised agent and routes typed messages and tasks" do
    id = unique_id("worker")

    assert {:ok, pid} = Mesh.start_agent(id, role: "reviewer")
    assert Mesh.whereis(id) == pid
    assert {:error, {:already_started, ^pid}} = Mesh.start_agent(id)

    assert {:ok, agent} = Mesh.send_message("root", id, %{text: "hello"})
    assert agent.state.messages_received == 1
    assert agent.state.last_message.body == %{text: "hello"}

    assert {:ok, task_id, agent} = Mesh.assign_task("root", id, "inspect the repository")
    assert agent.state.status == :working
    assert agent.state.current_task == task_id
    assert agent.state.objective == "inspect the repository"

    assert {:ok, agent} = Mesh.complete_task(id, task_id, %{files_reviewed: 3})
    assert agent.state.status == :completed
    assert agent.state.last_answer == %{files_reviewed: 3}

    assert :ok = Mesh.stop_agent(id)
    assert_eventually(fn -> Mesh.whereis(id) == nil end)
  end

  test "missing logical agents fail explicitly" do
    id = unique_id("missing")
    assert {:error, {:agent_not_found, ^id}} = Mesh.state(id)
    assert {:error, {:agent_not_found, ^id}} = Mesh.send_message("root", id, :hello)
  end

  test "status distinguishes disabled planes from unavailable or empty planes" do
    status = Ouroboros.status()

    assert status.availability.coding == :available
    assert status.availability.interactive == :available
    assert status.availability.teams == :available
    assert status.availability.orchestration == :available
    assert status.availability.effect_ledger == :available
    assert status.availability.hot_upgrade == :available
    assert status.availability.release == :available
    assert status.availability.control == :disabled
    assert is_list(status.coding_tasks)
    assert is_list(status.control.runs)
    assert status.effect_ledger.durability == :ephemeral_checkpoint
    assert is_integer(status.effect_ledger.retained)
    assert is_integer(status.effect_ledger.in_flight)
    refute Map.has_key?(status.control, :enabled)
    assert status.forge.signer in [:deny, :local, :remote, :other, :unknown]
    assert is_boolean(status.forge.admit_possible?)
    assert is_integer(status.forge.live_count)
    assert is_list(status.forge.live)
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"

  defp assert_eventually(fun, attempts \\ 50)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(10)
      assert_eventually(fun, attempts - 1)
    end
  end
end
