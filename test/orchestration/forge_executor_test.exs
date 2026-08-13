defmodule Ouroboros.Orchestration.ForgeExecutorTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Orchestration.{Execution, ForgeExecutor, Plan, Scheduler, Store, TestExecutor}
  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Forge.Signer
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Workspace

  # A real forge boots an isolated build peer, compiles, and runs the candidate's
  # tests before anything is deployed. That is minutes-scale work in the worst
  # case and must not be cut short by the default per-test deadline.
  @moduletag timeout: 300_000

  @capability Ouroboros.Capability.OrchestratedEcho
  @pending Ouroboros.Capability.InterruptedRollout
  @signer "orchestration-forge-signer"

  setup do
    {:ok, _applications} = Application.ensure_all_started(:jido)

    suffix = System.unique_integer([:positive])
    workspace = Path.join(System.tmp_dir!(), "ouroboros-forge-executor-#{suffix}")
    File.mkdir_p!(Path.join(workspace, "capabilities"))
    File.write!(Path.join(workspace, "capabilities/echo.ex"), capability_source(@capability))
    File.write!(Path.join(workspace, "capabilities/pending.ex"), capability_source(@pending))

    store = String.to_atom("forge_executor_store_#{suffix}")
    scheduler = String.to_atom("forge_executor_scheduler_#{suffix}")
    registry = String.to_atom("forge_executor_registry_#{suffix}")

    start_supervised!(
      {Store,
       name: store,
       storage: {Jido.Storage.ETS, table: String.to_atom("forge_executor_plans_#{suffix}")},
       key: {:forge_executor_test, suffix}}
    )

    start_supervised!(
      {Registry,
       name: registry,
       storage: {Jido.Storage.ETS, table: String.to_atom("forge_executor_rollouts_#{suffix}")}}
    )

    manager =
      start_supervised!(
        {Workspace,
         allowed_roots: [workspace], name: nil, id: {:forge_executor_workspace, suffix}}
      )

    {public_key, private_key} = configure_signer!()

    on_exit(fn ->
      File.rm_rf!(workspace)
      for module <- [@capability, @pending], do: unload(module)
    end)

    %{
      workspace: workspace,
      workspace_server: manager,
      store: store,
      scheduler: scheduler,
      registry: registry,
      epoch_storage: {Jido.Storage.ETS, table: String.to_atom("forge_executor_epochs_#{suffix}")},
      public_key: public_key,
      private_key: private_key
    }
  end

  test "a mixed plan runs a coding step, then forges and deploys the capability", context do
    ensure_distributed!()
    target = start_app_peer!(context.public_key)

    start_scheduler(context, nodes: [target])

    plan =
      plan!("self-improve", [
        %{id: "author", input: %{objective: "author the capability"}},
        %{
          id: "build",
          kind: :forge,
          dependencies: ["author"],
          input: %{module: inspect(@capability), source_path: "capabilities/echo.ex"}
        }
      ])

    assert {:ok, _submitted} = Scheduler.submit(context.scheduler, plan)

    # Dependency ordering: the forge step is not offered while its coding
    # dependency is unfinished.
    assert_receive {:execution_started, authoring}
    assert authoring.step_id == "author"
    assert authoring.kind == :coding

    assert {:ok, in_progress} = Scheduler.get(context.scheduler, "self-improve")
    assert in_progress.steps["build"].state == :pending
    assert Registry.history(@capability, context.registry) == []

    assert {:ok, _plan} =
             Scheduler.complete(
               context.scheduler,
               "self-improve",
               "author",
               authoring.token,
               :authored
             )

    completed = await_plan(context.scheduler, "self-improve", &(&1.status in terminal_statuses()))
    assert completed.status == :completed, inspect(completed.steps["build"].error)

    result = completed.steps["build"].result
    assert result.kind == :forge
    assert result.module == inspect(@capability)
    assert result.source_path == "capabilities/echo.ex"
    assert result.registry_state == :live
    assert result.nodes == [target]
    assert is_integer(result.epoch) and result.epoch > 0
    refute result.reattached?

    # The durable rollout record and the plan agree about what was deployed.
    assert [entry] = Registry.history(@capability, context.registry)
    assert entry.state == :live
    assert entry.artifact_id == result.artifact_id
    assert entry.epoch == result.epoch
    assert entry.source_sha256 == result.source_sha256

    # The capability is running on the target node and was never compiled or
    # loaded on the node that orchestrated it.
    assert :erpc.call(target, :code, :which, [@capability]) ==
             ~c"ouroboros://capability/#{inspect(@capability)}"

    assert :code.which(@capability) == :non_existing

    # A durable plan carries no runtime handles, whatever the executor learned.
    assert {:ok, persisted} = Store.get(context.store, "self-improve")
    refute persisted |> :erlang.term_to_binary() |> String.contains?("#PID")
    assert Plan.validate(persisted) == :ok

    {:ok, watermark} = Epoch.watermark(storage: context.epoch_storage)

    # A second offer of the same step reattaches to the live rollout: no second
    # build, no second deployment, and no second epoch.
    again =
      plan!("self-improve-again", [
        %{
          id: "build",
          kind: :forge,
          input: %{module: inspect(@capability), source_path: "capabilities/echo.ex"}
        }
      ])

    assert {:ok, _submitted} = Scheduler.submit(context.scheduler, again)

    reattached =
      await_plan(context.scheduler, "self-improve-again", &(&1.status in terminal_statuses()))

    assert reattached.status == :completed, inspect(reattached.steps["build"].error)
    reattached_result = reattached.steps["build"].result
    assert reattached_result.reattached?
    assert reattached_result.artifact_id == result.artifact_id
    assert reattached_result.epoch == result.epoch
    assert reattached_result.registry_state == :live

    assert [^entry] = Registry.history(@capability, context.registry)
    assert Epoch.watermark(storage: context.epoch_storage) == {:ok, watermark}

    # The same execution token offered again — what the scheduler does after an
    # owner crash — is answered identically and changes nothing durable.
    step = reattached.steps["build"]

    execution = %Execution{
      plan_id: reattached.id,
      step_id: step.id,
      token: step.execution_token,
      input: step.input,
      kind: :forge,
      attempt: step.attempt,
      state: :running,
      metadata: %{plan: reattached.metadata, step: step.metadata},
      recovered?: true
    }

    assert {:ok, owner} =
             ForgeExecutor.start(
               execution,
               context.scheduler,
               forge_options(context, nodes: [target])
             )

    ref = Process.monitor(owner)
    assert_receive {:DOWN, ^ref, :process, ^owner, _reason}, 30_000

    assert {:ok, unchanged} = Scheduler.get(context.scheduler, "self-improve-again")
    assert unchanged.version == reattached.version
    assert unchanged.steps["build"].result == reattached_result
    assert [^entry] = Registry.history(@capability, context.registry)
  end

  test "an interrupted rollout of the same module fails closed rather than deploying twice",
       context do
    assert {:ok, _entry} =
             Registry.deploying(
               %{
                 artifact_id: "interrupted-rollout",
                 module: @pending,
                 epoch: 41,
                 nodes: [node()]
               },
               context.registry
             )

    start_scheduler(context, nodes: [node()])

    plan =
      plan!("ambiguous", [
        %{
          id: "build",
          kind: :forge,
          input: %{module: inspect(@pending), source_path: "capabilities/pending.ex"}
        }
      ])

    assert {:ok, _submitted} = Scheduler.submit(context.scheduler, plan)
    failed = await_plan(context.scheduler, "ambiguous", &(&1.status in terminal_statuses()))

    assert failed.status == :failed

    assert failed.steps["build"].error ==
             {:forge_deploy_in_flight, inspect(@pending), "interrupted-rollout"}

    # Ambiguity is left exactly as it was found: one unsettled record, and no
    # code introduced anywhere.
    assert [checkpoint] = Registry.history(@pending, context.registry)
    assert checkpoint.state == :deploying
    assert checkpoint.artifact_id == "interrupted-rollout"
    assert :code.which(@pending) == :non_existing
  end

  test "a forge step whose source is missing fails without recording a rollout", context do
    start_scheduler(context, nodes: [node()])

    plan =
      plan!("missing-source", [
        %{
          id: "build",
          kind: :forge,
          input: %{module: inspect(@pending), source_path: "capabilities/absent.ex"}
        }
      ])

    assert {:ok, _submitted} = Scheduler.submit(context.scheduler, plan)
    failed = await_plan(context.scheduler, "missing-source", &(&1.status in terminal_statuses()))

    assert failed.status == :failed
    assert {:source_unreadable, "capabilities/absent.ex", :enoent} = failed.steps["build"].error
    assert Registry.history(@pending, context.registry) == []
  end

  defp start_scheduler(context, forge_opts) do
    start_supervised!(
      {Scheduler,
       name: context.scheduler,
       store: context.store,
       max_concurrency: 2,
       executors: %{
         coding: {TestExecutor, test_pid: self()},
         forge: {ForgeExecutor, forge_options(context, forge_opts)}
       }},
      restart: :temporary
    )
  end

  defp forge_options(context, opts) do
    [
      workspace: context.workspace,
      workspace_server: context.workspace_server,
      signer_id: @signer,
      registry: context.registry,
      epoch_storage: context.epoch_storage
    ] ++ opts
  end

  defp plan!(id, steps) do
    {:ok, plan} = Plan.new(id, steps)
    plan
  end

  defp terminal_statuses, do: [:completed, :failed, :blocked, :cancelled]

  defp capability_source(module) do
    """
    defmodule #{inspect(module)} do
      @vsn 1

      use Jido.Agent,
        name: "#{module |> Atom.to_string() |> String.replace(".", "_") |> String.downcase()}",
        description: "A capability forged by a durable orchestration plan",
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

  defp configure_signer! do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
    previous_signer = Application.get_env(:ouroboros, :forge_signer)
    previous_id = Application.get_env(:ouroboros, :forge_signer_id)

    Application.put_env(:ouroboros, :forge_signer, {Signer.Local, private_key: private_key})
    Application.put_env(:ouroboros, :forge_signer_id, @signer)

    on_exit(fn ->
      restore_env(:forge_signer, previous_signer)
      restore_env(:forge_signer_id, previous_id)
    end)

    {public_key, private_key}
  end

  defp restore_env(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore_env(key, value), do: Application.put_env(:ouroboros, key, value)

  # The target trusts exactly one signer and nothing unsigned, so the artifact is
  # admitted by its signature rather than by a permissive development policy.
  defp start_app_peer!(public_key) do
    peer_name =
      String.to_atom("ouroboros_forge_executor_peer_#{System.unique_integer([:positive])}")

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
      name = String.to_atom("ouroboros_forge_executor_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end

  defp await_plan(scheduler, id, predicate, attempts \\ 1_200)

  defp await_plan(scheduler, id, predicate, attempts) when attempts > 0 do
    case Scheduler.get(scheduler, id) do
      {:ok, plan} ->
        if predicate.(plan) do
          plan
        else
          Process.sleep(100)
          await_plan(scheduler, id, predicate, attempts - 1)
        end

      _other ->
        Process.sleep(100)
        await_plan(scheduler, id, predicate, attempts - 1)
    end
  end

  defp await_plan(_scheduler, id, _predicate, 0), do: flunk("plan #{id} never settled")
end
