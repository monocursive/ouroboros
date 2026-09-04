defmodule Ouroboros.Wasm.RolloutTwoNodeTest do
  use ExUnit.Case, async: false

  # Two full-application peer VMs per test, each spawning a real `ouro-wasm` as an OS child
  # and compiling a real component. Every wait below is bounded on an explicit condition,
  # but the wall-clock cost scales with machine load, and under a loaded scheduler the
  # default 60s per-test ceiling fires mid-setup while everything underneath is still
  # making progress. Sized like `test/upgrade/rollout_test.exs`, for the same reason.
  @moduletag timeout: 180_000

  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Forge.Signer
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Rollout
  alias Ouroboros.Wasm.Store

  # The claim W3 exists to make: **one artifact deploys on both nodes**. Lane B cannot say
  # that — a BEAM artifact is loadable on exactly one OTP/Elixir/architecture triple
  # (docs/WASM.md §3.3) — and this is the test that says it, against the real helper and a
  # real `wasm32-wasip2` component rather than a scripted reply.
  @guest Path.expand("../support/wasm/echo.wasm", __DIR__)
  @signer "wasm-two-node-key"
  @config ~s({"greeting":"hello"})

  @needs_live (cond do
                 not Wasm.available?() ->
                   [
                     skip:
                       "no ouro-wasm at #{Wasm.helper_path()}; run `make wasm` to prove a " <>
                         "deploy against the real helper rather than a fake one"
                   ]

                 not File.regular?(@guest) ->
                   [
                     skip:
                       "no acceptance guest at #{@guest}; run `make wasm-guest` (it needs " <>
                         "`rustup target add wasm32-wasip2`) to deploy a real component"
                   ]

                 true ->
                   []
               end)

  setup do
    ensure_distributed!()

    {public, secret} = :crypto.generate_key(:eddsa, :ed25519)
    peers = [start_app_peer!(public), start_app_peer!(public)]

    %{
      nodes: peers,
      secret: secret,
      public: public,
      registry: start_registry!(),
      epoch_storage: ets_storage()
    }
  end

  @tag @needs_live
  test "one signed component deploys, live, on both nodes", context do
    name = unique_name()
    id = start_id(name)
    artifact = artifact!(context, name: name, start: %{id: id, config: @config})

    # Snapshotted before the deploy so the assertion afterwards is about what this rollout
    # loaded, not about what a peer happened to boot with.
    loaded_before = Map.new(context.nodes, &{&1, loaded_modules(&1)})

    assert {:ok, outcome} = deploy(artifact, context)

    assert outcome.state == :live
    assert outcome.stage == :evaluate
    assert outcome.nodes == context.nodes
    assert outcome.component_sha256 == artifact.component_sha256

    # This node drove a deployment it is not a target of, so nothing here will restart the
    # wrapper at boot: the targets have the store and no registry entry, and this node has
    # the entry and no store. Reported rather than refused — see `Ouroboros.Wasm.Rollout`.
    refute node() in context.nodes
    assert outcome.warnings == [{:driver_not_a_target, node()}]

    # Both nodes staged it, probed it, evaluated it, and described it — the same document,
    # because a description is a property of the bytes (D17). Disagreement is a unit of
    # `agree_describe/1`; two live helpers of one sha cannot honestly disagree, and this is
    # the proof they agree.
    for target <- context.nodes do
      assert %{
               stage: :ok,
               probe: :ok,
               eval: %{satisfied?: true, passed: 2, failed: 0},
               describe: :described
             } = outcome.deployment[target]
    end

    assert outcome.eval_report.spec.probes == 2
    assert outcome.eval_report.spec.required == :all

    # Checkpoint v3, on the node that drove it.
    assert {:ok, entry} = Registry.get(artifact.id, context.registry)
    assert entry.state == :live
    assert entry.module == "wasm/" <> artifact.name
    assert entry.component_sha256 == artifact.component_sha256
    assert entry.epoch == artifact.epoch
    assert entry.nodes == context.nodes
    assert {:ok, document} = entry.describe
    assert document.name == "ouroboros-echo-guest"
    assert document.world == Wasm.world()

    # Both stores hold the bytes, under the sha, at the path each node derives from its own
    # data directory. Nothing was configured per node except the directory itself.
    for target <- context.nodes do
      assert {:ok, path} = call(target, Store, :path, [artifact.component_sha256, []])
      assert String.ends_with?(path, "sha256-#{artifact.component_sha256}.wasm")
      assert {:ok, bytes} = call(target, Store, :fetch, [artifact.component_sha256, []])
      assert bytes == File.read!(@guest)

      # And the signed manifest beside them, which is what makes a reboot recoverable.
      assert {:ok, manifest} = call(target, Store, :fetch_manifest, [artifact.id, []])
      assert manifest.component_sha256 == artifact.component_sha256
      assert manifest.signature.signer == @signer
    end

    # `protected_shas/1` names it, so no prune on this plane can evict a live component.
    assert {:ok, protected} = Store.protected_shas(registry: context.registry)
    assert MapSet.member?(protected, artifact.component_sha256)

    # The durable wrapper is running on one of the targets — a mesh id is claimed once
    # cluster-wide — and it answers as itself.
    assert %{id: ^id, node: host} = outcome.started
    assert host in context.nodes

    assert {:ok, agent} = call(host, Ouroboros.Mesh, :send_message, ["two-node", id, %{"a" => 1}])

    assert agent.state.last_answer == %{
             "echo" => %{"a" => 1},
             "config" => %{"greeting" => "hello"},
             "n" => 1
           }

    # Neither peer loaded any capability code to get here: identity is the digest, and
    # nothing about the artifact named a module. Asserted against what each peer's code
    # server actually holds, before and after — the whole point of lane W is that this
    # deployment is a file and a checkpoint, not a `:code.load_binary/3`.
    for target <- context.nodes do
      after_deploy = loaded_modules(target)

      assert capability_modules(after_deploy) == []
      assert capability_modules(MapSet.difference(after_deploy, loaded_before[target])) == []
    end
  end

  @tag @needs_live
  test "an eval spec the component cannot satisfy rolls back, with proof from both nodes",
       context do
    name = unique_name()
    id = start_id(name)

    artifact =
      artifact!(context,
        name: name,
        start: %{id: id, config: @config},
        eval: %{
          probes: [%{input: %{"greet" => "x"}, expect: {:equals, "a reply it will never send"}}],
          budget_ms: 15_000,
          required: :all
        }
      )

    assert {:error, {:rolled_back, outcome}} = deploy(artifact, context)

    assert outcome.state == :rolled_back
    assert outcome.stage == :evaluate
    assert outcome.started == nil

    for target <- context.nodes do
      evidence = outcome.deployment[target]

      # Every node staged and probed cleanly and then failed the gate that matters, and
      # every node proved it has nothing to withdraw. Only proof earns `:rolled_back`.
      assert evidence.stage == :ok
      assert evidence.probe == :ok
      assert evidence.eval.satisfied? == false
      assert evidence.recovery == :not_needed
    end

    assert {:ok, %{state: :rolled_back}} = Registry.get(artifact.id, context.registry)

    # Rollback is stop-and-mark. The bytes stay on both nodes, because rollback material
    # that never expires is the whole point of keeping them (§7.4).
    for target <- context.nodes do
      assert {:ok, _path} = call(target, Store, :path, [artifact.component_sha256, []])
      assert call(target, Ouroboros.Mesh, :whereis, [id]) == nil
    end
  end

  @tag @needs_live
  test "a node that does not answer in time quarantines, however healthy the other is",
       context do
    # A deadline is what a node going away mid-deploy looks like from here: nobody
    # answered. Expressed as a deadline rather than by killing a peer at a guessed moment,
    # so the invariant is proved rather than raced for.
    artifact = artifact!(context)

    assert {:error, {:quarantined, outcome}} = deploy(artifact, context, probe_timeout: 1)

    assert outcome.state == :quarantined
    assert outcome.stage == :probe
    assert outcome.started == nil

    # Every node staged fine; the probe is what nobody answered for.
    for target <- context.nodes do
      assert outcome.deployment[target].stage == :ok
      assert {:ambiguous, _reason} = outcome.deployment[target].probe
    end

    assert {:ok, %{state: :quarantined}} = Registry.get(artifact.id, context.registry)

    # Quarantined bytes are evidence: they are on both nodes and no prune may take them.
    for target <- context.nodes do
      assert {:ok, _path} = call(target, Store, :path, [artifact.component_sha256, []])
    end

    assert {:ok, protected} = Store.protected_shas(registry: context.registry)
    assert MapSet.member?(protected, artifact.component_sha256)
  end

  @tag @needs_live
  test "a peer that is gone is refused before any node is touched", context do
    [first, second] = context.nodes

    # Minted while both peers are still there — `Epoch.next/2` refuses to allocate above a
    # subset it can only partly read, which is its own half of this discipline.
    artifact = artifact!(context)

    :ok = :peer.stop(peer_of(second))
    await_disconnected!(second)

    assert {:error, {:disconnected_nodes, [^second]}} = deploy(artifact, context)

    # Nothing was checkpointed and nothing was staged: the refusal is before the register.
    assert Registry.list(context.registry) == []

    assert {:error, {:unknown_component, _sha}} =
             call(first, Store, :path, [artifact.component_sha256, []])
  end

  @tag @needs_live
  test "a component whose manifest the helper disagrees with quarantines both nodes",
       context do
    # Well-formed, correctly signed, and exactly these bytes — except that it declares no
    # imports while the component imports `log`. Only the helper can see that.
    artifact = artifact!(context, imports: [])

    assert {:error, {:quarantined, outcome}} = deploy(artifact, context)

    assert outcome.stage == :stage

    for target <- context.nodes do
      assert {:mismatch, {:component_mismatch, :imports, [], ["log"]}} =
               outcome.deployment[target].stage

      assert outcome.deployment[target].probe == :skipped
    end

    assert {:ok, %{state: :quarantined}} = Registry.get(artifact.id, context.registry)
  end

  ## Fixtures

  defp deploy(artifact, context, extra \\ []) do
    Rollout.deploy(
      artifact,
      File.read!(@guest),
      context.nodes,
      Keyword.merge(
        [
          registry: context.registry,
          trust_policy: [allow_unsigned: false, trusted_signers: %{@signer => context.public}]
        ],
        extra
      )
    )
  end

  # The epoch is allocated the way `Ouroboros.Upgrade.Forge` allocates one — before the
  # manifest exists, from the cluster the manifest will be deployed to — because it is
  # inside what gets signed.
  defp artifact!(context, attrs \\ []) do
    {:ok, epoch} = Epoch.next(context.nodes, storage: context.epoch_storage)

    {:ok, artifact} =
      Artifact.build(
        File.read!(@guest),
        Keyword.merge(
          [
            name: "greeter",
            author: "two-node-test",
            imports: ["log"],
            epoch: epoch,
            eval: passing_spec()
          ],
          attrs
        )
      )

    sign!(artifact, context.secret)
  end

  defp passing_spec do
    %{
      probes: [
        %{input: %{"greet" => "world"}, expect: {:state_matches, :messages_received, 1}},
        %{
          input: %{"greet" => "again"},
          expect:
            {:equals,
             %{
               "echo" => %{"greet" => "again"},
               "config" => %{"greeting" => "hello"},
               "n" => 2
             }}
        }
      ],
      budget_ms: 15_000,
      required: :all
    }
  end

  # The shipped dev signer, through the generic `sign/2` payload path. Lane W needs no new
  # signer callback: the payload it hands over is bytes like any other.
  defp sign!(artifact, secret) do
    payload = Artifact.signing_payload(artifact, @signer)
    {:ok, value} = Signer.Local.sign(payload, @signer, private_key: secret)
    {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: value})
    signed
  end

  ## Peers

  # Each peer trusts exactly one signer and nothing unsigned, resolves the helper this
  # machine built, and owns a data directory of its own — which is what makes its component
  # store a real one rather than a directory a test passed in.
  defp start_app_peer!(public_key) do
    peer_name = String.to_atom("ouroboros_wasm_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    # The OS pid is in the name because `System.unique_integer/1` restarts small in every
    # VM: two runs of this file collide on the same directory names, and a leftover 0700
    # directory from a crashed run — already holding this guest's sha — would silently
    # satisfy assertions about what a deploy staged. Removed first for the same reason.
    data_dir = Path.join(System.tmp_dir!(), "ouro-wasm-peer-#{:os.getpid()}-#{peer_name}")
    File.rm_rf!(data_dir)
    File.mkdir_p!(data_dir)
    # `Ouroboros.RuntimeOwner` refuses to claim a directory it did not find at 0700 and
    # will not chmod one itself. A test creating the directory has to hand it over correct.
    File.chmod!(data_dir, 0o700)
    on_exit(fn -> File.rm_rf(data_dir) end)

    {:ok, peer, peer_node} = :peer.start(%{name: peer_name, args: args, wait_boot: 60_000})
    on_exit(fn -> stop_peer(peer) end)
    Process.put({__MODULE__, :peer, peer_node}, peer)

    put_env!(peer_node, :upgrade_trust_policy,
      allow_unsigned: false,
      trusted_signers: %{@signer => public_key}
    )

    put_env!(peer_node, :data_dir, data_dir)
    put_env!(peer_node, :wasm, helper_path: Wasm.helper_path())
    put_env!(peer_node, :coding_storage, {Jido.Storage.ETS, table: peer_name})

    # A durable data directory is what makes each peer's component store the production
    # one — `Ouroboros.Wasm.Store.root/1` deriving it rather than a test handing one in.
    # Owning it means `Ouroboros.RuntimeOwner`, which demands the trusted `ouro`
    # process-incarnation helper outside a test environment. A fresh peer VM has never
    # heard of Mix, so it has to be told what it is; `Mix.env/1` is the same fact this VM
    # already carries, declared on the peer before its application starts.
    {:ok, _mix} = :erpc.call(peer_node, Application, :ensure_all_started, [:mix])
    :ok = :erpc.call(peer_node, Mix, :env, [:test])

    {:ok, _applications} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])
    peer_node
  end

  defp put_env!(peer_node, key, value) do
    :ok = :erpc.call(peer_node, Application, :put_env, [:ouroboros, key, value])
  end

  defp peer_of(peer_node), do: Process.get({__MODULE__, :peer, peer_node})

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    :exit, _reason -> :ok
  end

  # 400 x 25ms: a peer's disconnection reaches `Node.list/0` asynchronously, and the
  # ceiling exists to catch a peer that will never leave rather than to race the notice.
  defp await_disconnected!(target, attempts \\ 400)

  defp await_disconnected!(target, 0),
    do: flunk("#{target} is still connected: #{inspect(Node.list())}")

  defp await_disconnected!(target, attempts) do
    if target in Node.list() do
      Process.sleep(25)
      await_disconnected!(target, attempts - 1)
    else
      :ok
    end
  end

  defp loaded_modules(target),
    do: target |> call(:code, :all_loaded, []) |> Enum.map(&elem(&1, 0)) |> MapSet.new()

  # The namespace a forged BEAM capability would have to live in: the verifier's
  # introduce-prefix, the signer's namespace rule, and the mesh allow-list all name it.
  defp capability_modules(modules) do
    modules
    |> Enum.filter(&String.starts_with?(Atom.to_string(&1), "Elixir.Ouroboros.Capability."))
    |> Enum.sort()
  end

  defp call(target, module, function, arguments) when target == node(),
    do: apply(module, function, arguments)

  defp call(target, module, function, arguments),
    do: :erpc.call(target, module, function, arguments, 30_000)

  # A start id is `"wasm/" <> name` or it is nothing: the signer refuses any other, and
  # `Ouroboros.Wasm.Rollout.start_block/1` re-derives it rather than reading it.
  defp unique_name, do: "two-node-#{System.unique_integer([:positive])}"
  defp start_id(name), do: "wasm/" <> name

  defp start_registry! do
    name = String.to_atom("wasm_two_node_registry_#{System.unique_integer([:positive])}")
    {:ok, pid} = Registry.start_link(name: name, storage: ets_storage())

    on_exit(fn ->
      try do
        GenServer.stop(pid)
      catch
        :exit, _reason -> :ok
      end
    end)

    name
  end

  defp ets_storage do
    {Jido.Storage.ETS,
     table: String.to_atom("wasm_two_node_#{System.unique_integer([:positive])}")}
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_wasm_two_node_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end
end
