defmodule Ouroboros.Upgrade.CoordinatorRecoveryTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Test.UpgradeCounter
  alias Ouroboros.Upgrade.Coordinator.{DeploymentReceipt, NodeReceipt}
  alias Ouroboros.Upgrade.{Artifact, Coordinator, NodeExecutor}

  setup do
    on_exit(fn ->
      :code.soft_purge(UpgradeCounter)
      :code.load_file(UpgradeCounter)
      :code.soft_purge(UpgradeCounter)
    end)

    :ok
  end

  test "an ambiguous prepare releases its reservation instead of wedging the node" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile!(old_binary, 2)
    artifact = artifact!(new_binary, old_binary)

    # A suspended executor still receives the prepare and still holds the reservation it
    # creates. The caller only learns that its reply never arrived, which is exactly the
    # ambiguity a lost transport reply produces.
    executor = Process.whereis(NodeExecutor)
    assert :ok = :sys.suspend(executor)
    on_exit(fn -> if Process.alive?(executor), do: :sys.resume(executor) end)

    spawn(fn ->
      Process.sleep(300)
      :sys.resume(executor)
    end)

    assert {:error, deployment} = Coordinator.deploy(artifact, [node()], prepare_timeout: 50)

    node_receipt = deployment.node_receipts[node()]
    assert deployment.outcome == :prepare_failed
    assert node_receipt.prepare == :unknown
    assert match?({:prepare, {:transport, _reason}}, node_receipt.error)

    # The reservation is provably gone, so this node is unchanged rather than ambiguous.
    assert node_receipt.recovery == :aborted
    assert deployment.recovery == :complete
    assert UpgradeCounter.version() == 1

    status = NodeExecutor.status()
    assert status.prepared == []
    assert Enum.any?(status.operations, &(&1.operation == :abort and &1.outcome == :aborted))

    # Without the release the node would answer :upgrade_in_progress until it was killed.
    assert {:ok, token} = NodeExecutor.prepare(artifact!(new_binary, old_binary))
    assert :ok = NodeExecutor.abort(token)
  end

  test "a promote that quarantines a node outranks a partial promotion in the receipt" do
    old_binary = object_code!(UpgradeCounter)
    second_binary = compile!(old_binary, 2)

    assert {:ok, deployed} =
             Coordinator.deploy(artifact!(second_binary, old_binary), [node()])

    assert {:ok, _promoted} = Coordinator.promote(deployed)
    assert UpgradeCounter.version() == 2

    # A process parked inside the version being retired is what makes a soft purge
    # refuse, which is the promote failure that quarantines an executor.
    third_binary = compile!(second_binary, 3)
    observer = register_observer!()
    # `block/1` only exists in the hot-loaded version, never in the compiled fixture.
    blocker = spawn(fn -> apply(UpgradeCounter, :block, [observer]) end)
    assert_receive {:blocked, ^blocker}, 5_000

    assert {:ok, deployed} =
             Coordinator.deploy(artifact!(third_binary, second_binary), [node()])

    assert UpgradeCounter.version() == 3

    assert {:error, failed} = Coordinator.promote(partially_promoted(deployed))

    node_receipt = failed.node_receipts[node()]
    assert node_receipt.recovery == :quarantined

    assert match?(
             {:promote, {:promote_failed, {:retired_code_in_use, UpgradeCounter}, _required}},
             node_receipt.error
           )

    # One node promoted irreversibly and one is quarantined. Reporting only the
    # irreversibility hides the node whose state is unknown.
    assert failed.outcome == :promotion_partial
    assert failed.recovery == :quarantined
    assert NodeExecutor.status().mode == :quarantined

    send(blocker, :release)
    wait_until_dead!(blocker)

    assert :ok = NodeExecutor.reconcile_quarantine()
    assert NodeExecutor.status().mode == :ready

    assert {:ok, rolled_back} = Coordinator.rollback(deployed)
    assert rolled_back.recovery == :complete
    assert UpgradeCounter.version() == 2

    # Leave the fixture where every other test expects it, through the executor rather
    # than behind its back, so its expected-module journal stays true.
    assert {:ok, restored} =
             Coordinator.deploy(artifact!(old_binary, second_binary), [node()])

    assert {:ok, _permanent} = Coordinator.promote(restored)
    assert UpgradeCounter.version() == 1
  end

  # Stands in for a second node that promoted before this one failed: its receipt was
  # discarded, so only the still-retained node is contacted again.
  defp partially_promoted(%DeploymentReceipt{} = receipt) do
    promoted = :"already-promoted@nowhere"

    %{
      receipt
      | nodes: receipt.nodes ++ [promoted],
        node_receipts:
          Map.put(receipt.node_receipts, promoted, %NodeReceipt{
            node: promoted,
            prepare: :prepared,
            commit: :committed,
            recovery: :promoted_no_rollback
          })
    }
  end

  defp artifact!(binary, old_binary) do
    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    artifact
  end

  defp object_code!(module) do
    {^module, binary, _filename} = :code.get_object_code(module)
    binary
  end

  defp register_observer! do
    name = String.to_atom("upgrade_promote_observer_#{System.unique_integer([:positive])}")
    Process.register(self(), name)
    on_exit(fn -> if Process.whereis(name) == self(), do: Process.unregister(name) end)
    name
  end

  defp wait_until_dead!(pid) do
    reference = Process.monitor(pid)
    assert_receive {:DOWN, ^reference, :process, ^pid, _reason}, 5_000
    :ok
  end

  defp compile!(previous_binary, version) do
    source = """
    defmodule Ouroboros.Test.UpgradeCounter do
      @vsn #{version}
      use GenServer

      def start_link(initial), do: GenServer.start_link(__MODULE__, initial)
      def value(pid), do: GenServer.call(pid, :value)
      def version, do: #{version}

      def block(observer) do
        send(Process.whereis(observer), {:blocked, self()})

        receive do
          :release -> :ok
        end
      end

      @impl true
      def init(initial), do: {:ok, %{schema_vsn: #{version}, count: initial}}

      @impl true
      def handle_call(:value, _from, state), do: {:reply, {state.schema_vsn, state.count}, state}

      @impl true
      def code_change(_old_vsn, state, _extra), do: {:ok, state}
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{UpgradeCounter, binary}] = Code.compile_string(source, "upgrade_counter_recovery.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    # Compiling loads. Put the declared base back so the artifact's preimage is the code
    # this node is actually running.
    assert :code.soft_purge(UpgradeCounter)

    assert {:module, UpgradeCounter} =
             :code.load_binary(UpgradeCounter, ~c"upgrade_counter_recovery.beam", previous_binary)

    assert :code.soft_purge(UpgradeCounter)
    binary
  end
end
