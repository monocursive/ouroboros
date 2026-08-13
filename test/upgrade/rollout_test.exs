defmodule Ouroboros.Upgrade.RolloutTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Forge
  alias Ouroboros.Upgrade.Forge.{Signer, Source}
  alias Ouroboros.Upgrade.Rollout
  alias Ouroboros.Upgrade.Rollout.Registry

  @echo Ouroboros.Capability.Echo
  @faulty Ouroboros.Capability.FaultyEcho
  @signer "forge-rollout-signer"

  setup do
    ensure_distributed!()

    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
    configure_signer!(private_key)

    nodes = [start_app_peer!(public_key), start_app_peer!(public_key)]

    on_exit(fn ->
      for module <- [@echo, @faulty], do: unload(module)
    end)

    {:ok, nodes: nodes}
  end

  test "the rollout registry is supervised by the application" do
    assert is_pid(Process.whereis(Registry))
    assert Registry.durability() == :ephemeral_checkpoint
    assert is_list(Registry.list())
  end

  test "forges a capability from source and runs it live on every node", %{nodes: nodes} do
    assert {:ok, signed} = forge!(@echo, echo_source(), echo_test_source(), nodes)

    # Provenance travels inside the signed manifest, so a reviewer can tell which source
    # and which passing test run produced these bytes.
    assert signed.signature.signer == @signer
    assert byte_size(signed.signature.value) == 64
    assert signed.metadata.forge.author == "test-agent"
    assert signed.metadata.forge.test_report.failures == 0
    assert signed.metadata.forge.test_report.total == 1
    assert signed.metadata.forge.peer_runtime.distributed == false
    assert [%{module: @echo, disposition: :introduce}] = signed.modules

    # Nothing has been loaded anywhere yet, this VM included.
    assert_absent(nodes ++ [node()], @echo)

    assert {:ok, rollout} = Rollout.deploy(signed, @echo, nodes)
    assert rollout.state == :live
    assert rollout.nodes == nodes
    assert rollout.epoch == signed.epoch

    assert {:ok, entry} = Registry.get(signed.id)
    assert entry.state == :live
    assert entry.module == @echo
    assert entry.source_sha256 == signed.metadata.forge.source_sha256
    assert entry.test_report.total == 1
    assert Enum.any?(Registry.live(), &(&1.artifact_id == signed.id))

    # The capability is loaded on both target nodes and on neither of them was it
    # compiled: the only thing that crossed the wire was a verified, signed BEAM.
    for target <- nodes do
      assert :erpc.call(target, :code, :which, [@echo]) ==
               ~c"ouroboros://capability/#{inspect(@echo)}"
    end

    # It is not loaded on the node that forged and coordinated it, which never needed it.
    assert :code.which(@echo) == :non_existing

    # A brand-new module, started as a real mesh agent on both nodes, answering a real
    # typed signal sent from a third node that has never loaded its code.
    [first, second] = nodes
    assert {:ok, first_pid} = Mesh.start_agent_on(first, "cap-echo-1", agent: @echo)
    assert {:ok, second_pid} = Mesh.start_agent_on(second, "cap-echo-2", agent: @echo)
    assert node(first_pid) == first
    assert node(second_pid) == second

    on_exit(fn ->
      Mesh.stop_agent("cap-echo-1")
      Mesh.stop_agent("cap-echo-2")
    end)

    # Mesh visibility across nodes is eventually consistent by design, so the coordinating
    # node waits to see the remote agents rather than assuming a `:pg` broadcast has
    # already arrived.
    await_visible!("cap-echo-1", first)
    await_visible!("cap-echo-2", second)

    assert {:ok, agent} = Mesh.send_message("rollout-test", "cap-echo-1", "ping-one")
    assert agent.state.last_message.body == "ping-one"
    assert agent.state.messages_received == 1

    assert {:ok, other} = Mesh.send_message("rollout-test", "cap-echo-2", "ping-two")
    assert other.state.last_message.body == "ping-two"
  end

  test "a capability that fails its probe is rolled back everywhere", %{nodes: nodes} do
    assert {:ok, signed} = forge!(@faulty, faulty_source(), faulty_test_source(), nodes)

    # The capability's own tests pass. What it cannot do is answer a message, which is
    # exactly what the probe asks of it on the node that just loaded it.
    assert signed.metadata.forge.test_report.failures == 0

    assert {:error, {:rolled_back, outcome}} = Rollout.deploy(signed, @faulty, nodes)

    assert outcome.state == :rolled_back
    assert outcome.deployment.outcome == :health_failed
    assert outcome.deployment.recovery == :complete

    for target <- nodes do
      receipt = outcome.deployment.node_receipts[target]
      assert receipt.commit == :committed
      assert match?({:failed, {:error, {:probe_failed, @faulty, _reason}}}, receipt.health)
      assert receipt.recovery == :rolled_back
    end

    assert {:ok, entry} = Registry.get(signed.id)
    assert entry.state == :rolled_back
    assert entry.detail.recovery == :complete
    refute Enum.any?(Registry.live(), &(&1.artifact_id == signed.id))

    # Compensating an introduction means the module is gone, not retired: the name is
    # free again on every node, and starting an agent from it now fails.
    assert_absent(nodes, @faulty)

    for target <- nodes do
      assert {:error, _reason} =
               Mesh.start_agent_on(target, "cap-faulty-#{target}", agent: @faulty)
    end

    # The nodes are ready, not quarantined: a clean rollback leaves nothing to reconcile.
    assert {:ok, statuses} = Ouroboros.Upgrade.Coordinator.status(nodes)
    assert Enum.all?(statuses, fn {_target, status} -> status.mode == :ready end)
    assert Enum.all?(statuses, fn {_target, status} -> status.rollback_receipts == [] end)
  end

  test "the forge cannot forge itself out of the protected set", %{nodes: nodes} do
    # The namespace check refuses it before anything is compiled...
    assert {:error, {:source_rejected, {:invalid_module_name, "Ouroboros.Upgrade.Forge.Sneak"}}} =
             Forge.forge(
               source!(
                 Ouroboros.Upgrade.Forge.Sneak,
                 "defmodule Ouroboros.Upgrade.Forge.Sneak do\n  def sneak, do: :ok\nend\n",
                 nil
               ),
               nodes: nodes,
               signer_id: @signer,
               storage: ets_storage()
             )

    # ...and a hand-built artifact that skips the forge entirely is still refused by the
    # verifier on the loading node, which is where the protected set actually lives.
    binary = compile_locally!(Ouroboros.Upgrade.Forge.Sneak)

    {:ok, artifact} =
      Ouroboros.Upgrade.Artifact.build(
        [{Ouroboros.Upgrade.Forge.Sneak, binary, disposition: :introduce}],
        epoch: System.unique_integer([:positive, :monotonic])
      )

    assert {:error, {:immutable_control_module, Ouroboros.Upgrade.Forge.Sneak}} =
             Ouroboros.Upgrade.Verifier.verify(artifact, allow_unsigned: true)

    unload(Ouroboros.Upgrade.Forge.Sneak)
  end

  test "an unsigned capability is refused by the nodes that would load it", %{nodes: nodes} do
    Application.put_env(:ouroboros, :forge_signer, Signer.Deny)

    assert {:error, {:signing_failed, :signing_denied}} =
             forge!(@echo, echo_source(), echo_test_source(), nodes)

    assert_absent(nodes ++ [node()], @echo)
  end

  defp forge!(module, source, test_source, nodes) do
    Forge.forge(source!(module, source, test_source),
      nodes: nodes,
      signer_id: @signer,
      storage: ets_storage()
    )
  end

  defp source!(module, source, test_source) do
    {:ok, record} =
      Source.new(module: module, source: source, test_source: test_source, author: "test-agent")

    record
  end

  defp echo_source do
    """
    defmodule #{inspect(@echo)} do
      @vsn 1

      use Jido.Agent,
        name: "ouroboros_capability_echo",
        description: "A capability agent forged at runtime that echoes what it is told",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          messages_received: [type: :non_neg_integer, default: 0]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]
    end
    """
  end

  defp echo_test_source do
    """
    defmodule Ouroboros.Capability.EchoTest do
      use ExUnit.Case, async: false

      test "starts empty and declares its identity" do
        agent = #{inspect(@echo)}.new()
        assert agent.name == "ouroboros_capability_echo"
        assert agent.state.messages_received == 0
      end
    end
    """
  end

  defp faulty_source do
    """
    defmodule #{inspect(@faulty)} do
      @vsn 1

      use Jido.Agent,
        name: "ouroboros_capability_faulty_echo",
        description: "A capability agent whose message handler always fails",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          messages_received: [type: :non_neg_integer, default: 0]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]

      @impl true
      def on_before_cmd(_agent, _action) do
        raise "forged capability handler is broken"
      end
    end
    """
  end

  defp faulty_test_source do
    """
    defmodule Ouroboros.Capability.FaultyEchoTest do
      use ExUnit.Case, async: false

      test "compiles and declares its identity" do
        assert #{inspect(@faulty)}.new().name == "ouroboros_capability_faulty_echo"
      end
    end
    """
  end

  defp configure_signer!(private_key) do
    previous_signer = Application.get_env(:ouroboros, :forge_signer)
    previous_id = Application.get_env(:ouroboros, :forge_signer_id)

    Application.put_env(:ouroboros, :forge_signer, {Signer.Local, private_key: private_key})
    Application.put_env(:ouroboros, :forge_signer_id, @signer)

    on_exit(fn ->
      restore_env(:forge_signer, previous_signer)
      restore_env(:forge_signer_id, previous_id)
    end)
  end

  defp restore_env(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore_env(key, value), do: Application.put_env(:ouroboros, key, value)

  defp compile_locally!(module) do
    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)

    [{^module, binary}] =
      Code.compile_string(
        "defmodule #{inspect(module)} do\n  def sneak, do: :ok\nend\n",
        "sneak.ex"
      )

    Code.put_compiler_option(:ignore_module_conflict, previous)
    unload(module)
    binary
  end

  defp await_visible!(id, expected_node, attempts \\ 100) do
    case Mesh.whereis(id) do
      pid when is_pid(pid) and node(pid) == expected_node ->
        pid

      _other when attempts > 0 ->
        Process.sleep(25)
        await_visible!(id, expected_node, attempts - 1)

      other ->
        flunk("agent #{id} never became visible on #{expected_node}, saw #{inspect(other)}")
    end
  end

  defp assert_absent(nodes, module) do
    for target <- nodes do
      assert call(target, :code, :which, [module]) == :non_existing
      assert call(target, :code, :get_object_code, [module]) == :error
    end

    :ok
  end

  defp call(target, module, function, arguments) when target == node() do
    apply(module, function, arguments)
  end

  defp call(target, module, function, arguments) do
    :erpc.call(target, module, function, arguments)
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end

  defp ets_storage do
    {Jido.Storage.ETS,
     table: String.to_atom("rollout_epoch_#{System.unique_integer([:positive])}")}
  end

  # Every peer trusts exactly one signer and nothing unsigned, so the artifact is admitted
  # by its signature rather than by a permissive development policy.
  defp start_app_peer!(public_key) do
    peer_name = String.to_atom("ouroboros_rollout_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    {:ok, peer, peer_node} = :peer.start(%{name: peer_name, args: args, wait_boot: 20_000})
    on_exit(fn -> :peer.stop(peer) end)

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :upgrade_trust_policy,
        [allow_unsigned: false, trusted_signers: %{@signer => public_key}]
      ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :coding_storage,
        {Jido.Storage.ETS, table: peer_name}
      ])

    {:ok, _applications} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])
    peer_node
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_rollout_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end
end
