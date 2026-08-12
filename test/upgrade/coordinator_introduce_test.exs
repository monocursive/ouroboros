defmodule Ouroboros.Upgrade.CoordinatorIntroduceTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Test.UpgradeCounter
  alias Ouroboros.Upgrade.{Artifact, Coordinator}

  @module Ouroboros.Capability.CoordinatedIntroduction

  setup do
    ensure_distributed!()

    peer_name = String.to_atom("ouroboros_introduce_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, peer_node} =
             :peer.start(%{name: peer_name, args: args, wait_boot: 15_000})

    on_exit(fn -> :peer.stop(peer) end)

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :upgrade_trust_policy,
        [allow_unsigned: true]
      ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :coding_storage,
        {Jido.Storage.ETS, table: peer_name}
      ])

    assert {:ok, _applications} =
             :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    on_exit(fn -> unload_everywhere([node()]) end)

    {:ok, peer_node: peer_node}
  end

  test "a failed health check leaves an introduced module absent on every node",
       %{peer_node: peer_node} do
    nodes = [node(), peer_node]
    binary = compile_capability!()

    assert versions(nodes) == %{node() => 1, peer_node => 1}
    assert_absent(nodes)

    assert {:error, unhealthy} =
             Coordinator.deploy(introduce_artifact!(binary), nodes,
               health_check: {UpgradeCounter, :version, []},
               health_expected: :never_matches
             )

    assert unhealthy.outcome == :health_failed
    assert unhealthy.recovery == :complete

    for target <- nodes do
      assert unhealthy.node_receipts[target].commit == :committed
      assert unhealthy.node_receipts[target].health == {:failed, 1}
      assert unhealthy.node_receipts[target].recovery == :rolled_back
    end

    # Compensating a bad introduction means the module is gone, not merely retired.
    assert_absent(nodes)

    assert {:ok, statuses} = Coordinator.status(nodes)
    assert Enum.all?(statuses, fn {_target, status} -> status.mode == :ready end)
    assert Enum.all?(statuses, fn {_target, status} -> status.rollback_receipts == [] end)

    # The same artifact shape, deployed with a check it can pass, is live on both nodes
    # and still reversible from the deployment receipt alone.
    assert {:ok, deployed} =
             Coordinator.deploy(introduce_artifact!(binary), nodes,
               health_check: {UpgradeCounter, :version, []},
               health_expected: 1
             )

    assert deployed.outcome == :committed
    assert live_everywhere(nodes) == %{node() => :world, peer_node => :world}

    assert {:ok, rolled_back} = Coordinator.rollback(deployed)
    assert rolled_back.outcome == :rolled_back
    assert rolled_back.recovery == :complete
    assert_absent(nodes)

    unload_everywhere(nodes)
  end

  defp introduce_artifact!(binary) do
    assert {:ok, artifact} =
             Artifact.build([{@module, binary, disposition: :introduce}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    artifact
  end

  defp compile_capability! do
    source = """
    defmodule #{inspect(@module)} do
      @vsn 1
      def hello, do: :world
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{@module, binary}] = Code.compile_string(source, "coordinated_capability.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    unload_everywhere([node()])
    binary
  end

  defp unload_everywhere(nodes) do
    for target <- nodes, reachable?(target) do
      call(target, :code, :delete, [@module])
      call(target, :code, :soft_purge, [@module])
    end

    :ok
  end

  defp assert_absent(nodes) do
    for target <- nodes do
      assert call(target, :code, :which, [@module]) == :non_existing
      assert call(target, :code, :get_object_code, [@module]) == :error
    end

    :ok
  end

  defp live_everywhere(nodes) do
    Map.new(nodes, &{&1, call(&1, @module, :hello, [])})
  end

  defp versions(nodes) do
    Map.new(nodes, &{&1, call(&1, UpgradeCounter, :version, [])})
  end

  defp reachable?(target), do: target == node() or Node.ping(target) == :pong

  defp call(target, module, function, arguments) when target == node() do
    apply(module, function, arguments)
  end

  defp call(target, module, function, arguments) do
    :erpc.call(target, module, function, arguments)
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_introduce_root_#{System.unique_integer([:positive])}")
      assert {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end
end
