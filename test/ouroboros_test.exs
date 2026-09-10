defmodule OuroborosTest.Agent do
  @moduledoc false

  use Jido.Agent,
    name: "ouroboros_test_agent",
    description: "A minimal mesh agent, so the lifecycle claims below need no runtime plane",
    schema: [
      role: [type: :string, default: "reviewer"],
      messages_received: [type: :non_neg_integer, default: 0],
      last_message: [type: :any, default: nil]
    ]
end

defmodule OuroborosTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh

  setup do
    previous = Application.get_env(:ouroboros, :mesh_allowed_agent_modules)
    Application.put_env(:ouroboros, :mesh_allowed_agent_modules, [OuroborosTest.Agent])

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ouroboros, :mesh_allowed_agent_modules)
        value -> Application.put_env(:ouroboros, :mesh_allowed_agent_modules, value)
      end
    end)

    :ok
  end

  test "starts a supervised agent under one logical id and stops it" do
    id = unique_id("agent")

    assert {:ok, pid} = Mesh.start_agent(id, agent: OuroborosTest.Agent, role: "reviewer")
    assert Mesh.whereis(id) == pid
    assert {:error, {:already_started, ^pid}} = Mesh.start_agent(id, agent: OuroborosTest.Agent)

    assert {:ok, server_state} = Mesh.state(id)
    assert server_state.agent.state.role == "reviewer"

    assert :ok = Mesh.stop_agent(id)
    assert_eventually(fn -> Mesh.whereis(id) == nil end)
  end

  test "missing logical agents fail explicitly" do
    id = unique_id("missing")
    assert {:error, {:agent_not_found, ^id}} = Mesh.state(id)
    assert {:error, {:agent_not_found, ^id}} = Mesh.send_message("root", id, :hello)
  end

  test "status reports each plane this build runs" do
    status = Ouroboros.status()

    assert status.availability.cluster == :available
    assert status.availability.mesh == :available
    assert status.availability.interactive == :available
    assert status.availability.effect_ledger == :available
    assert is_list(status.interactive_sessions)
    assert status.effect_ledger.durability == :ephemeral_checkpoint
    assert is_integer(status.effect_ledger.retained)
    assert is_integer(status.effect_ledger.in_flight)
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
