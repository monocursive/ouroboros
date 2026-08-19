defmodule Ouroboros.AgentEffectsTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Control.Grants
  alias Ouroboros.Mesh

  alias Ouroboros.Signals.{
    EffectDelegateTask,
    EffectDeployCapability,
    EffectForgeCapability,
    EffectSendMessage,
    EffectStartAgent,
    EffectStopAgent
  }

  alias Ouroboros.Team
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Upgrade.Forge.Signer
  alias Ouroboros.Upgrade.Rollout.Registry

  @provider :ouroboros_test
  @capability Ouroboros.Capability.EffectLoop
  @signer "effect-surface-signer"

  test "the effect actions are declared by the agent that routes them" do
    actions = Ouroboros.Agent.Worker.actions()

    for action <- Ouroboros.Agent.Effects.actions() do
      assert action in actions
    end

    for {type, action} <- Ouroboros.Agent.Effects.signal_routes() do
      assert {type, action} in Ouroboros.Agent.Worker.signal_routes()
    end
  end

  describe "deny by default" do
    test "an ungranted agent is refused every effect and keeps running" do
      {actor, pid} = start_actor!("ungranted")
      target = unique_id("never-started")

      signal!(pid, EffectStartAgent, %{
        from: actor,
        agent_id: target,
        module: Ouroboros.Agent.Worker
      })

      signal!(pid, EffectDelegateTask, %{
        from: actor,
        team: unique_id("never-reached-team"),
        worker_id: unique_id("never-reached-worker"),
        objective: "do something expensive"
      })

      signal!(pid, EffectForgeCapability, %{
        from: actor,
        module: @capability,
        source: capability_source()
      })

      for effect <- [:start_agent, :delegate, :forge] do
        entry = await_effect!(pid, effect)
        assert entry.status == :denied
        assert entry.principal == actor
        assert {:effect_denied, ^effect, {:not_granted, _attempt}} = entry.error
      end

      # Refusal is an error directive, not a crash, and nothing reached the world.
      assert Process.alive?(pid)
      assert Mesh.whereis(target) == nil
      assert :code.which(@capability) == :non_existing
      assert agent_state(pid).forged == []
      assert agent_state(pid).effects_in_flight == []
    end

    test "a signal cannot spend another agent's grants by claiming its name" do
      {privileged, _privileged_pid} = start_actor!("privileged")
      {spoofer, spoofer_pid} = start_actor!("spoofer")
      target = unique_id("spoofed-worker")

      assert {:ok, _grant} =
               Grants.grant(privileged, :start_agent, modules: [Ouroboros.Agent.Worker])

      # The signal says it is from the agent that holds the grant. The acting principal
      # is read from the receiving agent's own server-side identity, so the claim buys
      # nothing.
      signal!(spoofer_pid, EffectStartAgent, %{
        from: privileged,
        agent_id: target,
        module: Ouroboros.Agent.Worker
      })

      entry = await_effect!(spoofer_pid, :start_agent)
      assert entry.status == :denied
      assert entry.principal == spoofer
      assert entry.claimed_from == privileged
      assert Mesh.whereis(target) == nil
    end
  end

  describe "mesh effects" do
    test "a granted start_agent starts a real agent and still obeys the mesh allow-list" do
      {actor, pid} = start_actor!("starter")
      target = unique_id("started-worker")

      assert {:ok, _grant} =
               Grants.grant(actor, :start_agent, modules: [Ouroboros.Agent.Worker, Kernel])

      signal!(pid, EffectStartAgent, %{
        from: actor,
        agent_id: target,
        module: Ouroboros.Agent.Worker,
        role: "assistant"
      })

      entry = await_effect!(pid, :start_agent)
      assert entry.status == :ok
      assert entry.result == %{agent_id: target, module: Ouroboros.Agent.Worker, node: node()}
      on_exit(fn -> Mesh.stop_agent(target) end)

      assert is_pid(Mesh.whereis(target))
      assert local_state(target).role == "assistant"

      # The grant admits `Kernel`; the mesh's own namespace allow-list is a second gate
      # the effect surface does not get to remove.
      denied = unique_id("kernel-agent")
      signal!(pid, EffectStartAgent, %{from: actor, agent_id: denied, module: Kernel})

      failure = await_effect!(pid, :start_agent)
      assert failure.status == :failed
      assert failure.error == {:effect_failed, :start_agent, {:agent_module_not_allowed, Kernel}}
      assert Mesh.whereis(denied) == nil
    end

    test "a granted send_message round-trips and carries the principal, not the claim" do
      {actor, pid} = start_actor!("sender")
      {peer, _peer_pid} = start_actor!("peer")

      assert {:ok, _grant} = Grants.grant(actor, :send_message, agents: [peer])

      signal!(pid, EffectSendMessage, %{
        from: "somebody-else",
        to: peer,
        body: %{request: "inspect mix.exs"}
      })

      entry = await_effect!(pid, :send_message)
      assert entry.status == :ok
      assert entry.result == %{to: peer, from: actor, messages_received: 1}
      assert entry.claimed_from == "somebody-else"

      peer_state = local_state(peer)
      assert peer_state.messages_received == 1
      assert peer_state.last_message.body == %{request: "inspect mix.exs"}
      assert peer_state.last_message.from == actor
    end

    test "a granted stop_agent stops exactly what it is allowed to stop" do
      {actor, pid} = start_actor!("stopper")
      {allowed, _allowed_pid} = start_actor!("disposable")
      {protected, _protected_pid} = start_actor!("protected")

      assert {:ok, _grant} = Grants.grant(actor, :stop_agent, agents: [allowed])

      signal!(pid, EffectStopAgent, %{from: actor, agent_id: protected})
      denied = await_effect!(pid, :stop_agent)
      assert denied.status == :denied
      assert is_pid(Mesh.whereis(protected))

      signal!(pid, EffectStopAgent, %{from: actor, agent_id: allowed})
      stopped = await_effect!(pid, :stop_agent)
      assert stopped.status == :ok
      assert stopped.result == %{agent_id: allowed}
      assert Mesh.whereis(allowed) == nil
    end
  end

  test "a granted delegate runs a real team delegation and lands its result in agent state" do
    harness!()

    {actor, pid} = start_actor!("delegator")
    team_id = unique_id("effect-team")
    worker_id = unique_id("effect-worker")
    objective = "review the effect surface"

    team = start_supervised!({Team.Server, id: team_id, cleanup_agents: true}, id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, _grant} = Grants.grant(actor, :delegate, teams: [team_id])

    signal!(pid, EffectDelegateTask, %{
      from: actor,
      team: team_id,
      worker_id: worker_id,
      objective: objective,
      options: [provider: @provider, workspace: File.cwd!()]
    })

    # The effect returned immediately, so this process is free to drive the provider run
    # the delegation started while the bounded runner waits for it.
    assert_receive {:ouroboros_test_adapter_started, _run_id, %RunRequest{prompt: prompt},
                    adapter},
                   5_000

    assert Ouroboros.Test.Prompt.wrapped?(prompt, objective)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "reviewed"})
    assert :ok = HarnessAdapter.finish(adapter)

    entry = await_effect!(pid, :delegate)
    assert entry.status == :ok
    assert entry.result.team == team_id
    assert entry.result.worker_id == worker_id
    assert entry.result.status == :completed
    assert entry.result.delivery == :delivered
    assert entry.result.result.text == "reviewed"

    # A team the agent was not granted is refused before the team is even looked up.
    signal!(pid, EffectDelegateTask, %{
      from: actor,
      team: unique_id("other-team"),
      worker_id: worker_id,
      objective: objective,
      options: [provider: @provider, workspace: File.cwd!()]
    })

    assert await_effect!(pid, :delegate).status == :denied
    assert :ok = Team.close(team)
  end

  @tag timeout: 300_000
  test "an agent forges, deploys, starts, and messages a capability, driven only by signals" do
    ensure_distributed!()
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)

    # The whole loop happens on one node, which is what makes it a loop: the agent that
    # forges the capability is the agent that deploys it, starts it, and talks to it.
    # That node is a peer rather than this VM only because a node executor reads its
    # trusted signers once, at boot, and this VM booted before the key existed.
    target = start_app_peer!(public_key)
    configure_signer!(target, {Signer.Local, private_key: private_key})

    actor = unique_id("self-improver")
    capability_agent = unique_id("forged-echo")
    assert {:ok, pid} = Mesh.start_agent_on(target, actor)

    grant!(target, actor, :forge, modules: [@capability])
    grant!(target, actor, :deploy, nodes: [target])
    grant!(target, actor, :start_agent, modules: [@capability])
    grant!(target, actor, :send_message, agents: [capability_agent])

    assert absent?(target, @capability)

    # 1. Source in, signed artifact out. The recorded author is the acting principal,
    #    which is the identity the agent server holds and not the one the signal claimed.
    signal!(pid, EffectForgeCapability, %{
      from: "some-other-agent",
      module: @capability,
      source: capability_source(),
      test_source: capability_test_source(),
      nodes: [target],
      signer_id: @signer
    })

    forged = await_effect!(pid, :forge, 2_400)
    assert forged.status == :ok, "forge failed: #{inspect(forged.error)}"
    assert forged.result.module == @capability
    assert forged.result.signer == @signer

    artifact_id = forged.result.artifact_id

    assert [%{artifact_id: ^artifact_id, artifact: artifact, module: @capability}] =
             agent_state(pid).forged

    assert artifact.metadata.forge.author == actor
    assert artifact.metadata.forge.test_report.failures == 0

    # The trail keeps a summary; the BEAM stays out of the audit line, and nothing is
    # loaded anywhere yet.
    refute Map.has_key?(forged.result, :artifact)
    assert absent?(target, @capability)

    # 2. Health-gated deploy of the artifact this agent forged, admitted by its
    #    signature rather than by a permissive development policy.
    signal!(pid, EffectDeployCapability, %{
      from: actor,
      artifact_id: artifact_id,
      nodes: [target]
    })

    deployed = await_effect!(pid, :deploy, 1_200)
    assert deployed.status == :ok, "deploy failed: #{inspect(deployed.error)}"

    assert deployed.result == %{
             artifact_id: artifact_id,
             module: @capability,
             epoch: artifact.epoch,
             nodes: [target],
             state: :live
           }

    assert {:ok, record} = :erpc.call(target, Registry, :get, [artifact_id])
    assert record.state == :live
    assert record.module == @capability

    assert :erpc.call(target, :code, :which, [@capability]) ==
             ~c"ouroboros://capability/#{inspect(@capability)}"

    # 3. Start the module that did not exist a moment ago as a real mesh agent.
    signal!(pid, EffectStartAgent, %{
      from: actor,
      agent_id: capability_agent,
      module: @capability
    })

    started = await_effect!(pid, :start_agent)
    assert started.status == :ok, "start failed: #{inspect(started.error)}"
    assert started.result == %{agent_id: capability_agent, module: @capability, node: target}

    # 4. Message it, and have it answer.
    signal!(pid, EffectSendMessage, %{from: actor, to: capability_agent, body: "hello, self"})

    messaged = await_effect!(pid, :send_message)
    assert messaged.status == :ok, "message failed: #{inspect(messaged.error)}"
    assert messaged.result == %{to: capability_agent, from: actor, messages_received: 1}

    assert {:ok, capability_state} = :erpc.call(target, Mesh, :state, [capability_agent])
    assert capability_state.agent.state.last_message.body == "hello, self"
    assert capability_state.agent.state.last_message.from == actor

    # Every step of the loop is on the record, in order, as this agent's own doing.
    trail = agent_state(pid).last_effects
    assert Enum.map(trail, & &1.effect) == [:send_message, :start_agent, :deploy, :forge]
    assert Enum.all?(trail, &(&1.status == :ok and &1.principal == actor))
    assert Enum.all?(trail, &is_binary(&1.settled_at))
    assert agent_state(pid).effects_in_flight == []

    # The same flow under the shipped production signer stops at the signature, which is
    # the gate that is supposed to stand between an agent and its own new code.
    configure_signer!(target, Signer.Deny)

    signal!(pid, EffectForgeCapability, %{
      from: actor,
      module: @capability,
      source: capability_source(),
      test_source: capability_test_source(),
      nodes: [target],
      signer_id: @signer
    })

    refused = await_effect!(pid, :forge, 2_400)
    assert refused.status == :failed
    assert refused.error == {:effect_failed, :forge, {:signing_failed, :signing_denied}}
    assert length(agent_state(pid).forged) == 1
  end

  defp start_actor!(prefix) do
    id = unique_id(prefix)
    assert {:ok, pid} = Mesh.start_agent(id)
    on_exit(fn -> Mesh.stop_agent(id) end)
    {id, pid}
  end

  defp signal!(server, module, data) do
    assert {:ok, signal} = module.new(data, source: "/ouroboros/test")
    assert {:ok, agent} = Jido.AgentServer.call(server, signal, 15_000)
    agent
  end

  defp agent_state(server) do
    assert {:ok, server_state} = Jido.AgentServer.state(server)
    server_state.agent.state
  end

  defp local_state(agent_id) do
    assert {:ok, server_state} = Mesh.state(agent_id)
    server_state.agent.state
  end

  # Effects settle asynchronously by design: the agent's own process is never the thing
  # waiting on a build peer or a provider run.
  defp await_effect!(server, effect, attempts \\ 200) do
    entry =
      server |> agent_state() |> Map.fetch!(:last_effects) |> Enum.find(&(&1.effect == effect))

    cond do
      is_map(entry) and entry.status != :started ->
        entry

      attempts > 0 ->
        Process.sleep(50)
        await_effect!(server, effect, attempts - 1)

      true ->
        flunk("effect #{effect} never settled: #{inspect(entry)}")
    end
  end

  defp grant!(target, principal, effect, constraints) do
    assert {:ok, _grant} =
             :erpc.call(target, Grants, :grant, [principal, effect, constraints])
  end

  defp configure_signer!(target, signer) do
    :ok = :erpc.call(target, Application, :put_env, [:ouroboros, :forge_signer, signer])
    :ok = :erpc.call(target, Application, :put_env, [:ouroboros, :forge_signer_id, @signer])
  end

  defp absent?(target, module) do
    :erpc.call(target, :code, :which, [module]) == :non_existing and
      :erpc.call(target, :code, :get_object_code, [module]) == :error and
      :code.which(module) == :non_existing
  end

  # A peer that trusts exactly one signer and nothing unsigned, configured the way an
  # operator configures a node: before it boots.
  defp start_app_peer!(public_key) do
    peer_name = String.to_atom("ouroboros_effect_peer_#{System.unique_integer([:positive])}")
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
      name = String.to_atom("ouroboros_effects_root_#{System.unique_integer([:positive])}")
      assert {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end

  defp harness! do
    cleanup_test_runs()
    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)

    journal_dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-effects-test-#{System.unique_integer([:positive, :monotonic])}"
      )

    providers = Map.put(map_or_empty(previous_providers), @provider, HarnessAdapter)

    provider_config =
      previous_provider_config
      |> map_or_empty()
      |> Map.put(@provider, %{test_pid: self(), retention: %{journal_dir: journal_dir}})

    Application.put_env(:jido_harness, :providers, providers)
    Application.put_env(:jido_harness, :provider_config, provider_config)

    on_exit(fn ->
      cleanup_test_runs()
      restore(:providers, previous_providers)
      restore(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
    end)
  end

  defp cleanup_test_runs do
    @provider
    |> then(&Run.list(providers: [&1]))
    |> Enum.each(fn info ->
      unless RunInfo.terminal?(info) do
        _ = Run.cancel(info.run_id)
        _ = Run.await(info.run_id, 1_000)
      end

      _ = Run.prune(info.run_id)
    end)
  end

  defp capability_source do
    """
    defmodule #{inspect(@capability)} do
      @vsn 1

      use Jido.Agent,
        name: "ouroboros_capability_effect_loop",
        description: "A capability agent forged through the agent effect surface",
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

  defp capability_test_source do
    """
    defmodule Ouroboros.Capability.EffectLoopTest do
      use ExUnit.Case, async: false

      test "starts empty and declares its identity" do
        agent = #{inspect(@capability)}.new()
        assert agent.name == "ouroboros_capability_effect_loop"
        assert agent.state.messages_received == 0
      end
    end
    """
  end

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore(key, value), do: Application.put_env(:jido_harness, key, value)

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"
end
