defmodule Ouroboros.Upgrade.CoordinatorTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Test.UpgradeCounter
  alias Ouroboros.Upgrade.{Artifact, Coordinator}

  setup do
    ensure_distributed!()

    peer_name = String.to_atom("ouroboros_upgrade_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, peer_node} =
             :peer.start(%{name: peer_name, args: args, wait_boot: 15_000})

    on_exit(fn -> :peer.stop(peer) end)

    storage = {Jido.Storage.ETS, table: peer_name}
    :ok = :erpc.call(peer_node, Application, :put_env, [:ouroboros, :coding_storage, storage])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :upgrade_trust_policy,
        [allow_unsigned: true]
      ])

    assert {:ok, _applications} =
             :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    old_binary = object_code!(UpgradeCounter)

    on_exit(fn ->
      restore_v1(node(), old_binary)

      if Node.ping(peer_node) == :pong do
        restore_v1(peer_node, old_binary)
      end
    end)

    {:ok, peer_node: peer_node, old_binary: old_binary}
  end

  test "coordinates a real local and peer deployment, health compensation, and rollback",
       %{peer_node: peer_node, old_binary: old_binary} do
    nodes = [node(), peer_node]
    {:ok, abort_counter} = start_supervised({UpgradeCounter, 1}, id: :abort_counter)

    # A node-local validation failure after another node prepares must abort the
    # successful prepare before any code becomes visible.
    artifact = artifact!(old_binary)

    assert {:error, aborted} =
             Coordinator.deploy(artifact, nodes,
               migrations: %{
                 node() => [{UpgradeCounter, abort_counter}],
                 peer_node => :invalid
               }
             )

    assert aborted.outcome == :prepare_failed
    assert aborted.node_receipts[node()].recovery == :aborted
    assert aborted.node_receipts[peer_node].prepare == :failed
    assert versions(nodes) == %{node() => 1, peer_node => 1}

    assert {:ok, statuses} = Coordinator.status(nodes)
    assert statuses[node()].prepared == []
    assert statuses[peer_node].prepared == []

    # The v2 fixture deliberately rejects one node's state migration. The remote
    # executor rolls itself back; the coordinator compensates the committed local
    # node using its retained receipt.
    {:ok, local_counter} = start_supervised({UpgradeCounter, 7})

    assert {:ok, remote_counter} =
             :erpc.call(peer_node, GenServer, :start, [UpgradeCounter, 11, []])

    artifact = artifact!(old_binary)

    migrations = %{
      node() => [{UpgradeCounter, local_counter, :ok}],
      peer_node => [{UpgradeCounter, remote_counter, :fail}]
    }

    healthy_migrations = %{
      node() => [{UpgradeCounter, local_counter, :ok}],
      peer_node => [{UpgradeCounter, remote_counter, :ok}]
    }

    assert {:error, compensated} = Coordinator.deploy(artifact, nodes, migrations: migrations)
    assert compensated.outcome == :commit_failed
    assert compensated.recovery == :complete
    assert compensated.node_receipts[node()].recovery == :rolled_back
    assert compensated.node_receipts[peer_node].recovery == :rolled_back
    assert versions(nodes) == %{node() => 1, peer_node => 1}
    assert UpgradeCounter.value(local_counter) == {1, 7}
    assert :erpc.call(peer_node, UpgradeCounter, :value, [remote_counter]) == {1, 11}

    # Health checks happen only after every commit. A failed check compensates all
    # nodes and retains the check result in each node receipt.
    artifact = artifact!(old_binary)

    assert {:error, unhealthy} =
             Coordinator.deploy(artifact, nodes,
               migrations: healthy_migrations,
               health_check: {UpgradeCounter, :version, []},
               health_expected: 3
             )

    assert unhealthy.outcome == :health_failed
    assert unhealthy.recovery == :complete
    assert unhealthy.node_receipts[node()].health == {:failed, 2}
    assert unhealthy.node_receipts[peer_node].health == {:failed, 2}
    assert versions(nodes) == %{node() => 1, peer_node => 1}

    artifact = artifact!(old_binary)

    assert {:ok, deployed} =
             Coordinator.deploy(artifact, nodes,
               migrations: healthy_migrations,
               health_check: {UpgradeCounter, :version, []},
               health_expected: 2
             )

    assert deployed.atomic? == false
    assert deployed.outcome == :committed
    assert deployed.recovery == :not_needed
    assert versions(nodes) == %{node() => 2, peer_node => 2}

    assert {:ok, rolled_back} = Coordinator.rollback(deployed)
    assert rolled_back.outcome == :rolled_back
    assert rolled_back.recovery == :complete
    assert versions(nodes) == %{node() => 1, peer_node => 1}

    assert {:error, unavailable} = Coordinator.rollback(rolled_back)
    assert unavailable.outcome == :rollback_unavailable
    assert unavailable.recovery == :not_available
  end

  test "promotes all node receipts and makes fast rollback unavailable",
       %{peer_node: peer_node, old_binary: old_binary} do
    nodes = [node(), peer_node]
    {:ok, local_counter} = start_supervised({UpgradeCounter, 5})

    assert {:ok, remote_counter} =
             :erpc.call(peer_node, GenServer, :start, [UpgradeCounter, 6, []])

    migrations = %{
      node() => [{UpgradeCounter, local_counter}],
      peer_node => [{UpgradeCounter, remote_counter}]
    }

    artifact = artifact!(old_binary)

    assert {:ok, deployed} = Coordinator.deploy(artifact, nodes, migrations: migrations)
    assert {:ok, promoted} = Coordinator.promote(deployed)
    assert promoted.outcome == :promoted
    assert promoted.recovery == :not_available

    for target <- nodes do
      assert promoted.node_receipts[target].executor_receipt == nil
      assert promoted.node_receipts[target].recovery == :promoted_no_rollback
    end

    assert versions(nodes) == %{node() => 2, peer_node => 2}
    assert {:ok, statuses} = Coordinator.status(promoted)
    assert statuses[node()].rollback_receipts == []
    assert statuses[peer_node].rollback_receipts == []

    assert {:error, unavailable} = Coordinator.promote(promoted)
    assert unavailable.outcome == :promotion_unavailable
    assert unavailable.recovery == :not_available

    assert {:error, rollback_unavailable} = Coordinator.rollback(promoted)
    assert rollback_unavailable.outcome == :rollback_unavailable

    # A promoted fast patch cannot be undone through its discarded receipt.
    # Restore the fixture through a new, higher-epoch deployment so the default
    # executor's durable expected-module journal agrees with the code left for
    # later tests. Loading the v1 binary behind the executor's back would
    # correctly quarantine it on the next application restart.
    [promoted_beam] = artifact.modules
    current_binary = promoted_beam.binary

    assert {:ok, restore_artifact} =
             Artifact.build(
               [
                 {UpgradeCounter, old_binary, old_binary: current_binary, stateful: true}
               ],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, restored} =
             Coordinator.deploy(restore_artifact, nodes, migrations: migrations)

    assert {:ok, _restored_permanently} = Coordinator.promote(restored)
    assert versions(nodes) == %{node() => 1, peer_node => 1}
  end

  test "rejects malformed coordinator options without touching executors",
       %{peer_node: peer_node, old_binary: old_binary} do
    nodes = [node(), peer_node]
    artifact = artifact!(old_binary)

    assert {:error, empty} = Coordinator.deploy(artifact, [])
    assert empty.outcome == :validation_failed
    assert empty.recovery == :unchanged
    assert empty.node_receipts == %{}

    assert {:error, %{coordinator: :empty_node_list}} = Coordinator.status([])

    for options <- [
          [:not_a_keyword],
          [max_concurrency: 0],
          [prepare_timeout: -1],
          [abort_timeout: :infinity],
          [prepare_options: %{}],
          [commit_options: [:not_a_keyword]],
          [rollback_options: [process_timeout: 0]],
          [migrations: []]
        ] do
      assert {:error, invalid} = Coordinator.deploy(artifact, nodes, options)
      assert invalid.outcome == :validation_failed
      assert invalid.recovery == :unchanged
    end

    assert versions(nodes) == %{node() => 1, peer_node => 1}

    assert {:error, %{coordinator: {:invalid_option, :status_timeout, 0}}} =
             Coordinator.status(nodes, status_timeout: 0)

    disconnected = String.to_atom("missing@localhost")

    assert {:error, %{coordinator: {:disconnected_nodes, [^disconnected]}}} =
             Coordinator.status([disconnected])
  end

  defp artifact!(old_binary) do
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [
                 {UpgradeCounter, new_binary,
                  old_binary: old_binary,
                  stateful: true,
                  migration_extra: {:one_of, [nil, :ok, :fail]}}
               ],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    artifact
  end

  defp versions(nodes) do
    Map.new(nodes, fn
      target when target == node() -> {target, UpgradeCounter.version()}
      target -> {target, :erpc.call(target, UpgradeCounter, :version, [])}
    end)
  end

  defp object_code!(module) do
    {^module, binary, _filename} = :code.get_object_code(module)
    binary
  end

  defp compile_v2!(old_binary) do
    source = """
    defmodule Ouroboros.Test.UpgradeCounter do
      @vsn 2
      use GenServer

      def start_link(initial), do: GenServer.start_link(__MODULE__, initial)
      def value(pid), do: GenServer.call(pid, :value)
      def version, do: 2

      @impl true
      def init(initial), do: {:ok, %{schema_vsn: 2, count: initial}}

      @impl true
      def handle_call(:value, _from, state), do: {:reply, {state.schema_vsn, state.count}, state}

      @impl true
      def code_change(1, _state, :fail), do: {:error, :deliberate_test_failure}

      def code_change(1, state, _extra) do
        {:ok, %{state | schema_vsn: 2, count: state.count * 2}}
      end

      def code_change({:down, 2}, state, _extra) do
        {:ok, %{state | schema_vsn: 1, count: div(state.count, 2)}}
      end
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{UpgradeCounter, binary}] = Code.compile_string(source, "upgrade_counter_coordinator_v2.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    restore_v1(node(), old_binary)
    binary
  end

  defp restore_v1(target, old_binary) when target == node() do
    assert :code.soft_purge(UpgradeCounter)

    assert {:module, UpgradeCounter} =
             :code.load_binary(UpgradeCounter, ~c"upgrade_counter_v1.beam", old_binary)

    assert :code.soft_purge(UpgradeCounter)
    :ok
  end

  defp restore_v1(target, old_binary) do
    assert :erpc.call(target, :code, :soft_purge, [UpgradeCounter])

    assert {:module, UpgradeCounter} =
             :erpc.call(target, :code, :load_binary, [
               UpgradeCounter,
               ~c"upgrade_counter_v1.beam",
               old_binary
             ])

    assert :erpc.call(target, :code, :soft_purge, [UpgradeCounter])
    :ok
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_upgrade_root_#{System.unique_integer([:positive])}")
      assert {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end
end
