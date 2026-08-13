defmodule Ouroboros.Upgrade.RolloutTest do
  use ExUnit.Case, async: false

  # Every test boots two full-application peer VMs in `setup`, and most bodies boot one
  # or two more forge build peers. Each wait in that path is bounded on an explicit
  # condition — node booted, application started — but its wall-clock cost scales with
  # machine load, and under a loaded scheduler the default 60s per-test ceiling fires
  # mid-setup (ExUnit.TimeoutError inside `:peer.start` or the `ensure_all_started`
  # erpc) while every underlying wait is still making progress. The ceiling stays
  # bounded so a wedged peer still fails the test; it is sized to the workload.
  @moduletag timeout: 180_000

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

    {:ok, nodes: nodes, private_key: private_key}
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

    # An artifact that declared no evaluation criteria was evaluated against none, and
    # the record says so rather than implying a gate that never ran.
    refute Map.has_key?(signed.metadata.forge, :eval)
    assert entry.eval_report == nil
    assert rollout.eval_report == nil

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

  test "signed evaluation criteria gate promotion on every node", %{nodes: nodes} do
    assert {:ok, signed} =
             forge!(@echo, echo_source(), echo_test_source(), nodes, eval: eval_spec())

    # The criteria are inside the signed manifest, next to the provenance and covered by
    # the same signature as the bytes they judge.
    assert signed.metadata.forge.eval.budget_ms == 5_000
    assert length(signed.metadata.forge.eval.probes) == 2
    assert signed.metadata.forge.eval.required == :all

    assert {:ok, rollout} = Rollout.deploy(signed, @echo, nodes)
    assert rollout.state == :live

    # Every target ran the spec against a throwaway instance of the code it had just
    # committed, and the record carries what each of them found.
    assert %{nodes: reports} = rollout.eval_report
    assert Map.keys(reports) |> Enum.sort() == Enum.sort(nodes)

    for target <- nodes do
      report = reports[target]
      assert report.outcome == :passed
      assert report.node == target
      assert report.passed == 2
      assert report.failed == 0
      assert report.failures == []
      assert report.satisfied?
      assert is_integer(report.total_ms)
    end

    assert rollout.eval_report.compare == false
    assert rollout.eval_report.champion == nil

    assert rollout.eval_report.spec == %{
             probes: 2,
             required: :all,
             budget_ms: 5_000,
             max_latency_ms: 2_000
           }

    assert {:ok, entry} = Registry.get(signed.id)
    assert entry.state == :live
    assert entry.eval_report.nodes[hd(nodes)].satisfied?
    assert entry.detail.eval == rollout.eval_report

    for target <- nodes do
      assert :erpc.call(target, :code, :which, [@echo]) ==
               ~c"ouroboros://capability/#{inspect(@echo)}"
    end
  end

  test "a capability that fails its evaluation is rolled back everywhere", %{nodes: nodes} do
    # The capability is healthy: it starts, it answers, it passes its probe. What it does
    # not do is satisfy the criteria the artifact was signed with, which is the whole
    # difference between a system that can modify itself and one that can improve.
    unsatisfiable = %{
      probes: [%{input: "anything", expect: {:equals, "a thing this capability never says"}}],
      budget_ms: 5_000
    }

    assert {:ok, signed} =
             forge!(@echo, echo_source(), echo_test_source(), nodes, eval: unsatisfiable)

    assert {:error, {:rolled_back, outcome}} = Rollout.deploy(signed, @echo, nodes)

    assert outcome.state == :rolled_back
    assert outcome.deployment.outcome == :rolled_back
    assert outcome.deployment.recovery == :complete

    for target <- nodes do
      report = outcome.eval_report.nodes[target]
      assert report.outcome == :failed
      assert report.passed == 0
      assert [%{index: 0, reason: {:not_equal, _rendered}}] = report.failures

      assert outcome.deployment.node_receipts[target].health == {:passed, :ok}
      assert outcome.deployment.node_receipts[target].recovery == :rolled_back
    end

    assert {:ok, entry} = Registry.get(signed.id)
    assert entry.state == :rolled_back
    assert entry.detail.stage == :evaluate
    assert entry.eval_report.nodes[hd(nodes)].satisfied? == false
    refute Enum.any?(Registry.live(), &(&1.artifact_id == signed.id))

    # Compensation is real, not bookkeeping: the module is gone from every node again.
    assert_absent(nodes, @echo)

    assert {:ok, statuses} = Ouroboros.Upgrade.Coordinator.status(nodes)
    assert Enum.all?(statuses, fn {_target, status} -> status.mode == :ready end)
  end

  test "an evaluation nobody could run is quarantined, never rolled back", %{nodes: nodes} do
    assert {:ok, signed} =
             forge!(@echo, echo_source(), echo_test_source(), nodes, eval: eval_spec())

    # A node that never answered the evaluation is not a node that failed it. The code
    # is withdrawn anyway, and the *record* refuses to claim a clean withdrawal, exactly
    # as it refuses to claim a rollback nobody proved.
    ghost = :ouroboros_rollout_ghost@nowhere

    # The ghost's ambiguity comes from unreachability — `:erpc` refuses the connection
    # immediately — not from this deadline, so the deadline is sized for the *real*
    # nodes: tight enough to bound the test, generous enough that a loaded host does
    # not turn their honest evaluations into a second ambiguity.
    assert {:error, {:quarantined, outcome}} =
             Rollout.deploy(signed, @echo, nodes,
               eval_nodes: nodes ++ [ghost],
               eval_timeout: 15_000
             )

    assert outcome.state == :quarantined
    assert outcome.eval_report.nodes[ghost].outcome == :ambiguous
    assert outcome.eval_report.nodes[hd(nodes)].outcome == :passed

    assert {:ok, entry} = Registry.get(signed.id)
    assert entry.state == :quarantined
    assert entry.detail.stage == :evaluate
    refute Enum.any?(Registry.live(), &(&1.artifact_id == signed.id))

    # The nodes themselves are fine and say so. The quarantine is about the evidence,
    # and clearing it is an operator's judgement rather than a retry.
    assert_absent(nodes, @echo)
    assert {:ok, statuses} = Ouroboros.Upgrade.Coordinator.status(nodes)
    assert Enum.all?(statuses, fn {_target, status} -> status.mode == :ready end)
  end

  test "a spec this build could not run stops the rollout before it starts", %{nodes: nodes} do
    assert {:error, {:invalid_eval_spec, {:probe_input_not_portable, 0}}} =
             Forge.forge(source!(@echo, echo_source(), echo_test_source()),
               nodes: nodes,
               signer_id: @signer,
               storage: ets_storage(),
               eval: %{probes: [%{input: self(), expect: :any_reply}]}
             )

    assert {:ok, signed} = forge!(@echo, echo_source(), echo_test_source(), nodes)

    # An override is refused on the same terms, and refused before the `:deploying`
    # checkpoint: a rollout nobody could evaluate never becomes a record of one.
    before = length(Registry.list())

    assert {:error, {:invalid_eval_spec, :probes_required}} =
             Rollout.deploy(signed, @echo, nodes, eval: %{probes: []})

    assert {:error, :comparison_requires_eval_spec} =
             Rollout.deploy(signed, @echo, nodes, compare: true)

    assert length(Registry.list()) == before
    assert Registry.get(signed.id) == :not_found
    assert_absent(nodes ++ [node()], @echo)
  end

  test "a challenger that regresses the probe set is rolled back with both reports", context do
    %{nodes: nodes, private_key: private_key} = context
    {champion, challenger} = champion_and_challenger!(nodes, private_key, slow_echo_source())

    assert {:ok, _live} = Rollout.deploy(champion, @echo, nodes)

    # A replacement is admitted only through the comparison path, because promoting a new
    # version of a live capability without measuring the one it displaces throws away the
    # only baseline that will ever exist.
    assert {:error, {:not_an_introduction, @echo, :replace}} =
             Rollout.deploy(challenger, @echo, nodes)

    assert {:error, {:rolled_back, outcome}} =
             Rollout.deploy(challenger, @echo, nodes, compare: true)

    assert outcome.state == :rolled_back
    assert outcome.eval_report.compare == true
    assert outcome.eval_report.regression_budget == 1.2

    for target <- nodes do
      champion_report = outcome.eval_report.champion[target]
      challenger_report = outcome.eval_report.nodes[target]

      # The challenger is not broken. It answers every probe the champion answered, and
      # takes long enough doing it that the probe set says so.
      assert champion_report.satisfied?
      assert challenger_report.satisfied?
      assert challenger_report.passed == champion_report.passed
      assert challenger_report.regressed
      assert challenger_report.outcome == :failed
      assert challenger_report.total_ms > champion_report.total_ms
    end

    assert {:ok, entry} = Registry.get(challenger.id)
    assert entry.state == :rolled_back
    assert entry.detail.stage == :evaluate
    assert is_map(entry.eval_report.champion)

    # The champion is still live and still the version that is running.
    for target <- nodes do
      assert :erpc.call(target, :code, :which, [@echo]) ==
               ~c"ouroboros://capability/#{inspect(@echo)}"

      assert :erpc.call(target, @echo, :module_info, [:md5]) == hd(champion.modules).md5
    end
  end

  test "a challenger that holds its own replaces the champion", context do
    %{nodes: nodes, private_key: private_key} = context
    {champion, challenger} = champion_and_challenger!(nodes, private_key, revised_echo_source())

    assert {:ok, _live} = Rollout.deploy(champion, @echo, nodes)

    # The budget is deliberately loose. Wall-clock over two probes on a shared VM is not
    # a measurement worth tightening, and a test that pretended otherwise would be
    # asserting something this gate cannot honestly deliver.
    assert {:ok, rollout} =
             Rollout.deploy(challenger, @echo, nodes, compare: true, regression_budget: 10.0)

    assert rollout.state == :live
    assert rollout.eval_report.compare == true

    for target <- nodes do
      report = rollout.eval_report.nodes[target]
      assert report.outcome == :passed
      refute report.regressed
      assert report.passed == rollout.eval_report.champion[target].passed
    end

    assert {:ok, entry} = Registry.get(challenger.id)
    assert entry.state == :live
    assert is_map(entry.eval_report.champion)

    # The running code is the challenger's, and it is the challenger the registry calls
    # live while the champion's own record is untouched.
    for target <- nodes do
      assert :erpc.call(target, @echo, :module_info, [:md5]) == hd(challenger.modules).md5
    end

    assert {:ok, champion_entry} = Registry.get(champion.id)
    assert champion_entry.state == :live
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

  defp forge!(module, source, test_source, nodes, extra \\ []) do
    Forge.forge(
      source!(module, source, test_source),
      Keyword.merge(
        [nodes: nodes, signer_id: @signer, storage: ets_storage()],
        extra
      )
    )
  end

  # A capability upgrade is a `:replace` beam for a module that is already live, which is
  # not something the forge builds: `Forge.forge/2` only introduces. So the challenger is
  # assembled here from the forge's compiled bytes, with the champion's binary as the
  # pre-image, and signed with the same key every peer trusts. The pre-image identity has
  # to be capturable on this node, which is why the champion is loaded here and unloaded
  # again immediately: this VM is not a deployment target and must not look like one.
  defp champion_and_challenger!(nodes, private_key, challenger_source) do
    {:ok, champion} = forge!(@echo, echo_source(), echo_test_source(), nodes, eval: eval_spec())
    {:ok, forged} = forge!(@echo, challenger_source, echo_test_source(), nodes)

    champion_binary = hd(champion.modules).binary
    filename = "ouroboros://capability/#{inspect(@echo)}"

    {:module, @echo} =
      :code.load_binary(@echo, String.to_charlist(filename), champion_binary)

    {:ok, artifact} =
      Ouroboros.Upgrade.Artifact.build(
        [
          {@echo, hd(forged.modules).binary,
           disposition: :replace,
           old_binary: champion_binary,
           filename: filename,
           old_filename: filename}
        ],
        # Both artifacts are forged before either is deployed, so the epoch allocator sees
        # the same empty targets twice. The number a real forge would allocate after the
        # champion committed is stamped here instead: a challenger's epoch is above the
        # version it replaces or the target refuses it.
        epoch: champion.epoch + 1,
        metadata: %{forge: %{eval: eval_spec_normalized()}}
      )

    unload(@echo)

    {champion, Ouroboros.Upgrade.Artifact.sign(artifact, @signer, private_key)}
  end

  defp eval_spec_normalized do
    {:ok, spec} = Ouroboros.Upgrade.Rollout.Evaluation.validate(eval_spec())
    spec
  end

  # Two probes against one throwaway instance: the first says the capability echoed what
  # it was sent, the second says it kept count while doing so.
  defp eval_spec do
    %{
      probes: [
        %{input: %{op: "ping"}, expect: {:contains, "ping"}},
        %{input: "second", expect: {:state_matches, :messages_received, 2}}
      ],
      budget_ms: 5_000,
      max_latency_ms: 2_000,
      required: :all
    }
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

  # Same answers, more of everyone's time: the probe set cannot tell these two apart on
  # behaviour, only on what they cost to run.
  defp slow_echo_source do
    """
    defmodule #{inspect(@echo)} do
      @vsn 2

      use Jido.Agent,
        name: "ouroboros_capability_echo",
        description: "A capability agent that echoes what it is told, slowly",
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
      def on_before_cmd(agent, action) do
        Process.sleep(150)
        {:ok, agent, action}
      end
    end
    """
  end

  defp revised_echo_source do
    """
    defmodule #{inspect(@echo)} do
      @vsn 2

      use Jido.Agent,
        name: "ouroboros_capability_echo",
        description: "A capability agent forged at runtime, revised",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          messages_received: [type: :non_neg_integer, default: 0],
          revision: [type: :non_neg_integer, default: 2]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]
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

  # 400 x 25ms: cross-node `:pg` propagation is typically milliseconds, but this is an
  # eventual-consistency wait and a loaded scheduler stretches it; the ceiling exists to
  # catch an agent that will never appear, not to race the propagation.
  defp await_visible!(id, expected_node, attempts \\ 400) do
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

    # `wait_boot` is a hang guard, not a pacing assumption: a healthy boot takes about a
    # second, and a loaded scheduler can honestly take tens of seconds. It stays inside
    # the module's 180s ceiling so a genuinely wedged peer is still a bounded failure.
    {:ok, peer, peer_node} = :peer.start(%{name: peer_name, args: args, wait_boot: 60_000})
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
