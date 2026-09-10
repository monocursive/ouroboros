defmodule Ouroboros.DistributionTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Capability.DistributionReference
  alias Ouroboros.Mesh

  test "routes a typed agent message to a supervised mesh process on an OS peer" do
    ensure_distributed!()

    peer_name = String.to_atom("ouroboros_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, peer_node} =
             :peer.start(%{name: peer_name, args: args, wait_boot: 15_000})

    on_exit(fn -> :peer.stop(peer) end)

    storage = {Ouroboros.Storage.ETS, table: peer_name}

    :ok =
      :erpc.call(peer_node, Application, :put_env, [:ouroboros, :interactive_storage, storage])

    assert {:ok, _applications} =
             :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    id = "distributed-worker-#{System.unique_integer([:positive])}"

    assert {:ok, pid} =
             Mesh.start_agent_on(peer_node, id,
               agent: DistributionReference,
               role: "remote reviewer"
             )

    assert node(pid) == peer_node

    assert_eventually(fn -> Mesh.whereis(id) == pid end)

    assert {:ok, agent} = Mesh.send_message("root", id, %{kind: :review, path: "mix.exs"})
    assert agent.state.messages_received == 1
    assert agent.state.last_message.body == %{kind: :review, path: "mix.exs"}

    assert :ok = Mesh.stop_agent(id)
    assert_eventually(fn -> Mesh.whereis(id) == nil end)
  end

  test "a connected node without the runtime fails placement instead of exiting the caller" do
    ensure_distributed!()

    peer_name = String.to_atom("ouroboros_bare_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, peer_node} =
             :peer.start(%{name: peer_name, args: args, wait_boot: 15_000})

    on_exit(fn -> :peer.stop(peer) end)

    # The peer is connected and can load the code, but never started :ouroboros. It can
    # therefore answer a role probe — the module is on its path — and answers honestly
    # that the runtime is not running, which is what placement refuses on.
    id = "bare-peer-worker-#{System.unique_integer([:positive])}"

    assert {:error, {:placement_refused, ^peer_node, :runtime_not_running}} =
             Mesh.start_agent_on(peer_node, id, agent: DistributionReference)

    assert Mesh.whereis(id) == nil

    # Disabling role placement checks cannot bypass mesh protocol/runtime admission.
    previous = Application.get_env(:ouroboros, :placement_role_check, true)
    Application.put_env(:ouroboros, :placement_role_check, false)
    on_exit(fn -> Application.put_env(:ouroboros, :placement_role_check, previous) end)

    assert {:error, {:placement_refused, ^peer_node, :runtime_not_running}} =
             Mesh.start_agent_on(peer_node, id, agent: DistributionReference)

    assert Mesh.whereis(id) == nil
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_root_#{System.unique_integer([:positive])}")
      assert {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end

  defp assert_eventually(fun, attempts \\ 100)
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
