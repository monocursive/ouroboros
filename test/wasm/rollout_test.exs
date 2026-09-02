# Hoisted to the top level on purpose: the mesh admits `Ouroboros.Capability.*` and one named
# wrapper, and a `defmodule` nested in the test module would land under
# `Ouroboros.Wasm.RolloutTest.` and be refused as `agent_module_not_allowed`.
# A capability that starts instantly and then takes far longer than any deadline in this
# file to answer one message. That is what makes "the deadline fired while the throwaway
# agent was alive" a fact rather than a race.
defmodule Ouroboros.Capability.RolloutTestSlowProbe do
  @moduledoc false

  use Jido.Agent,
    name: "ouroboros_capability_rollout_slow_probe",
    description: "A capability that is slow to answer, so a probe deadline always fires",
    schema: [last_message: [type: :any, default: nil]],
    signal_routes: [{"ouroboros.agent.message", __MODULE__.Wait}]

  def actions, do: super() ++ [__MODULE__.Wait]

  defmodule Wait do
    @moduledoc false

    use Jido.Action,
      name: "rollout_slow_probe_wait",
      description: "Sleeps past any deadline this file sets, then echoes",
      schema: [
        from: [type: :string, required: true],
        body: [type: :any, required: true],
        correlation_id: [type: :string, required: true],
        causation_id: [type: :any, default: nil]
      ]

    @impl true
    def run(params, _context) do
      Process.sleep(3_000)
      {:ok, %{last_message: %{body: params.body}}}
    end
  end
end

defmodule Ouroboros.Wasm.RolloutTest do
  # Not async: the live half spawns the real helper as an OS child and starts mesh agents.
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Rollout.Probe
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Capability
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Rollout
  alias Ouroboros.Wasm.Store

  # One node is enough for everything except "one artifact deploys on both nodes", which
  # is `rollout_two_node_test.exs`'s job. What is proved here is the decision table: what
  # is refused before the checkpoint, what quarantines, what rolls back, and what runs.
  @guest Path.expand("../support/wasm/echo.wasm", __DIR__)
  @signer "wasm-rollout-test-key"

  @needs_live (cond do
                 not Wasm.available?() ->
                   [
                     skip:
                       "no ouro-wasm at #{Wasm.helper_path()}; run `make wasm` to deploy " <>
                         "against the real helper rather than asserting about a fake one"
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
    {public, secret} = :crypto.generate_key(:eddsa, :ed25519)
    trust_policy = [allow_unsigned: false, trusted_signers: %{@signer => public}]

    # A loading node reads its *own* trust policy; it is never told one by the node
    # deploying to it. So the target's policy is application environment here, exactly as
    # `test/upgrade/rollout_test.exs` puts it on each peer before starting the runtime —
    # and here the target happens to be this node. Safe because this case is `async: false`.
    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)
    Application.put_env(:ouroboros, :upgrade_trust_policy, trust_policy)
    on_exit(fn -> restore(:upgrade_trust_policy, previous) end)

    root = Path.join(System.tmp_dir!(), "ouro-wasm-rollout-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    %{secret: secret, root: root, registry: start_registry!(), trust_policy: trust_policy}
  end

  describe "the start spec" do
    test "names all six keys that decide what is being evaluated", context do
      artifact = artifact!(context, start: %{id: "wasm/greeter", config: ~s({"a":1})})

      state = Rollout.start_state(artifact, pool: :my_pool, store_root: "/tmp/x", limits: %{f: 1})

      # `Evaluation` merges a signed spec's `initial_state` *under* this one, so every key
      # a signed spec could otherwise choose has to be named here.
      assert Enum.sort(Map.keys(state)) == [
               :component,
               :config,
               :limits,
               :name,
               :pool,
               :store_root
             ]

      assert state.component == artifact.component_sha256
      assert state.name == artifact.name
      assert state.pool == :my_pool
      assert state.store_root == "/tmp/x"
      assert state.limits == %{f: 1}

      # The config a probe and an evaluation see is the signed one.
      assert state.config == ~s({"a":1})
    end

    test "defaults to the production pool, this node's store, and the configured bounds",
         context do
      state = Rollout.start_state(artifact!(context))

      assert state.pool == Pool
      assert state.store_root == nil
      assert state.limits == Wasm.capability_limits()

      # No start block means no config to honour, and `"{}"` rather than a guess.
      assert state.config == "{}"
    end

    test "a start block is derived from the manifest's own name, never read from it",
         context do
      assert Rollout.start_block(artifact!(context)) == nil

      assert Rollout.start_block(
               artifact!(context, name: "greeter", start: %{id: "wasm/greeter", config: "{}"})
             ) == %{id: "wasm/greeter", config: "{}"}

      # Everything the signer refuses, this refuses again: a reader that would rather trust
      # the signer than check is one bad manifest away from starting whatever it said. And
      # the id is *derived* here rather than read, so a manifest that was somehow signed
      # naming another capability's durable id still starts nothing.
      for start <- [
            %{id: "greeter", config: "{}"},
            %{id: "wasm/", config: "{}"},
            %{id: "wasm/greeter", config: %{}},
            %{id: 42, config: "{}"},
            %{id: "wasm/victim", config: "{}"},
            %{id: "wasm/greeter/../../etc/passwd", config: "{}"},
            "wasm/greeter",
            nil
          ] do
        assert Rollout.start_block(artifact!(context, name: "greeter", start: start)) == nil,
               "start_block read #{inspect(start)} for a component named greeter"
      end

      # The squat, from the other side: a *signed* manifest whose name is `evil` and whose
      # start block names `greeter`'s id. The signature is real; the id is still not this
      # component's, so nothing is started under it.
      squat = %{artifact!(context) | name: "evil"}
      assert Rollout.start_block(squat) == nil
    end
  end

  describe "everything refused before the checkpoint" do
    test "an unusable node list never reaches the register", context do
      artifact = artifact!(context)

      assert {:error, :empty_node_list} = deploy(artifact, [], context)
      assert {:error, {:invalid_nodes, _}} = deploy(artifact, ["not-a-node"], context)
      assert {:error, {:duplicate_nodes, _}} = deploy(artifact, [node(), node()], context)

      assert {:error, {:disconnected_nodes, [:"absent@127.0.0.1"]}} =
               deploy(artifact, [:"absent@127.0.0.1"], context)

      assert Registry.list(context.registry) == []
    end

    test "an artifact this node does not trust never reaches the register", context do
      assert {:error, :signature_required} = deploy(unsigned!(), [node()], context)

      assert {:error, {:untrusted_signer, @signer}} =
               deploy(artifact!(context), [node()], %{context | trust_policy: []})

      # And bytes that are not the ones that were signed — of exactly the right length, so
      # it is the digest and not the size doing the refusing.
      artifact = artifact!(context)
      swapped = String.replace_prefix(placeholder_bytes(), "\0asm", "\0ASM")
      assert byte_size(swapped) == artifact.size

      assert {:error, {:component_sha256_mismatch, _expected, _actual}} =
               Rollout.deploy(artifact, swapped, [node()], opts(context))

      assert {:error, {:component_size_mismatch, _expected, _actual}} =
               Rollout.deploy(artifact, "short", [node()], opts(context))

      assert Registry.list(context.registry) == []
    end

    test "an eval spec this build could not run never reaches the register", context do
      artifact = artifact!(context, eval: %{probes: []})

      assert {:error, {:invalid_eval_spec, :probes_required}} =
               deploy(artifact, [node()], context)

      assert Registry.list(context.registry) == []
    end

    test "a stale epoch is refused against what this register already deployed", context do
      # A live lane-W entry at epoch 50 is the watermark this plane enforces; lane B's
      # monotonicity is the node executor's, and lane W has none. The check itself lives
      # inside `Registry.deploying/2` so it cannot be raced; what this asserts is that a
      # caller still sees the reason and not the recording wrapper around it.
      seed_live!(context, 50)

      assert {:error, {:stale_epoch, 50, 50}} =
               deploy(artifact!(context, epoch: 50), [node()], context)

      assert {:error, {:stale_epoch, 49, 50}} =
               deploy(artifact!(context, epoch: 49), [node()], context)

      # 51 gets past the epoch gate and fails later, which is the point: the refusal moved.
      assert {:error, {_state, %{stage: :stage}}} =
               deploy(artifact!(context, epoch: 51), [node()], context)
    end

    test "two concurrent deploys at one epoch cannot both checkpoint", context do
      # The read-then-write this replaced: both callers read an empty register, both saw
      # their epoch as fresh against `highest = 0`, and both wrote a `:deploying` entry.
      # Racing *identical* epochs is what makes the assertion order-independent — whichever
      # message the register serializes first, the second one's epoch is no longer greater
      # than what it holds.
      results =
        [70_000, 70_000]
        |> Enum.map(fn epoch ->
          # Resolved here rather than inside the task: the bytes travel beside the manifest
          # through this case's process dictionary, and a task is a different process.
          artifact = artifact!(context, epoch: epoch)
          bytes = bytes_for(artifact)

          Task.async(fn ->
            Rollout.deploy(artifact, bytes, [node()], opts(context))
          end)
        end)
        |> Task.await_many(60_000)

      stale = Enum.filter(results, &match?({:error, {:stale_epoch, 70_000, 70_000}}, &1))

      assert length(stale) == 1
      assert [%{epoch: 70_000}] = Registry.list(context.registry)

      # And the sequential case reads the same, because it is the same decision.
      assert {:error, {:stale_epoch, 60_000, 70_000}} =
               deploy(artifact!(context, epoch: 60_000), [node()], context)
    end

    test "nothing below the checkpoint runs when the checkpoint is refused", context do
      # The invariant, tested by its absence: with the stage gate moved above
      # `Registry.deploying/2` the whole suite still passes, because every other test only
      # asserts what happens *after* a checkpoint that succeeded. This one refuses the
      # checkpoint and then asks the disk whether anything happened anyway.
      artifact = artifact!(context)

      {:ok, _seeded} =
        Registry.deploying(
          %{
            artifact_id: artifact.id,
            module: Ouroboros.Capability.AlreadyThere,
            epoch: 1,
            nodes: [node()]
          },
          context.registry
        )

      assert {:error, {:rollout_not_recorded, {:already_recorded, id}}} =
               deploy(artifact, [node()], context)

      assert id == artifact.id

      # No bytes were published, no manifest was written, and nothing was handed to a
      # helper — the store this deploy would have written into is empty.
      assert {:ok, []} = Store.list(root: context.root)

      assert {:error, {:unknown_manifest, ^id}} =
               Store.fetch_manifest(artifact.id, root: context.root)
    end

    test "a manifest that reached a terminal state cannot be re-deployed", context do
      # A retry is always a new manifest: the register refuses the duplicate id, and a new
      # id at the same epoch is refused for the number. Parity with lane B, whose register
      # refuses `{:already_recorded, _}` and whose retry is a re-forge.
      artifact = artifact!(context, epoch: 42_000)

      assert {:error, {:rolled_back, _outcome}} = deploy(artifact, [node()], context)
      assert {:ok, %{state: :rolled_back}} = Registry.get(artifact.id, context.registry)

      # The identical signed manifest: refused on its id.
      assert {:error, {:rollout_not_recorded, {:already_recorded, _id}}} =
               deploy(artifact, [node()], context)

      # A fresh id at the same epoch: refused on its number, because that number was spent.
      assert {:error, {:stale_epoch, 42_000, 42_000}} =
               deploy(artifact!(context, epoch: 42_000), [node()], context)

      # Only a higher epoch gets through the gate at all.
      assert {:error, {:rolled_back, _outcome}} =
               deploy(artifact!(context, epoch: 42_001), [node()], context)
    end
  end

  describe "the transport deadline" do
    test "a local gate is bounded exactly as a remote one is", context do
      _ = context

      # Before this, the local branch was a bare `apply/3` and ignored the deadline
      # entirely: a gate on this node could hang forever while every peer's was enforced.
      assert {:ambiguous, :timeout} =
               Rollout.bounded_call(node(), __MODULE__.SlowGate, :sleep, [500], 100)

      assert {:returned, :slept} =
               Rollout.bounded_call(node(), __MODULE__.SlowGate, :sleep, [1], 5_000)

      # A gate that raises is still ambiguity rather than an exception escaping into the
      # caller, on the local branch as on the remote one.
      assert {:ambiguous, {:error, _reason}} =
               Rollout.bounded_call(node(), __MODULE__.SlowGate, :boom, [], 5_000)
    end
  end

  defmodule SlowGate do
    @moduledoc false
    def sleep(ms) do
      Process.sleep(ms)
      :slept
    end

    def boom, do: raise("a gate that raises")
  end

  describe "a target verifies for itself" do
    test "an unsigned artifact its driver was told to accept is still refused here", context do
      # `deploy/4`'s `:trust_policy` is the *caller's* and is used once, for the pre-flight.
      # `stage/3`'s is this node's own, read from application environment on the node that
      # would load the component. That difference is the whole of a target's independence
      # from the node deploying to it, and nothing exercised it: every shipped case signs
      # its artifacts, so deleting `verified(artifact, bytes)` from `stage/3` changed no
      # outcome anywhere.
      unsigned = unsigned!()
      assert unsigned.signature == nil

      assert {:error, {state, outcome}} =
               deploy(unsigned, [node()], context,
                 trust_policy: [allow_unsigned: true],
                 start?: false
               )

      assert state == :rolled_back

      assert {:error, {:component_rejected, :signature_required}} =
               outcome.deployment[node()].stage

      # And nothing was published on the way to that refusal: the target refuses before it
      # writes, not after.
      assert {:ok, []} = Store.list(root: context.root)
      assert {:ok, %{state: :rolled_back}} = Registry.get(unsigned.id, context.registry)
    end
  end

  describe "compensation is proof, or it is quarantine" do
    test "a withdrawal no node proved is quarantine, never a rollback", context do
      # `proven_state/1` is the rule this module's own comment calls "the invariant the
      # whole module exists to preserve", and nothing built the shape that distinguishes
      # it: every shipped case withdrew from a node with nothing to withdraw, so forcing
      # the answer to `:rolled_back` changed no outcome.
      #
      # The shape that does distinguish it: a process holds the start id, reports this
      # component's sha when asked — so `withdraw/2` is obliged to stop it — and cannot be
      # stopped, because it is not one of the agent supervisor's children. That is what a
      # peer whose stop nobody could confirm looks like from here.
      name = unique_name()
      id = start_id(name)
      artifact = unsigned!(name: name, start: %{id: id, config: "{}"})

      holder = start_unstoppable_holder!(id, artifact.component_sha256)
      assert Rollout.holder_component(id) == artifact.component_sha256

      assert {:error, {:quarantined, outcome}} =
               deploy(artifact, [node()], context, trust_policy: [allow_unsigned: true])

      assert outcome.state == :quarantined
      assert outcome.deployment[node()].recovery == :quarantined
      assert {:ok, %{state: :quarantined}} = Registry.get(artifact.id, context.registry)

      # The control: the same clean failure, with nothing holding the id. Now every node
      # proves it has nothing to withdraw, and only that earns `:rolled_back`.
      Process.exit(holder, :kill)
      assert Mesh.whereis(id) == nil

      proved = unsigned!(name: name, start: %{id: id, config: "{}"})

      assert {:error, {:rolled_back, clean}} =
               deploy(proved, [node()], context, trust_policy: [allow_unsigned: true])

      assert clean.state == :rolled_back
      assert clean.deployment[node()].recovery == :not_needed
    end
  end

  describe "a gate killed at its deadline" do
    test "leaves no throwaway probe agent behind", context do
      _ = context

      # `bounded_call/5`'s local branch kills the task at the deadline, and `after` does
      # not run for an exit signal from outside — so `Probe.run/2`'s cleanup never ran and
      # its throwaway agent kept a cluster-wide mesh id (and, for a lane-W capability, a
      # helper instance) with nothing left that would ever stop it.
      before = probe_agent_ids()

      assert {:ambiguous, :timeout} =
               Rollout.bounded_call(
                 node(),
                 Probe,
                 :ready?,
                 [{Ouroboros.Capability.RolloutTestSlowProbe, %{}}],
                 250
               )

      assert await_probe_agents(before, 200) == before,
             "a killed probe left a throwaway agent behind: " <>
               inspect(probe_agent_ids() -- before)
    end
  end

  describe "against the real helper, on one node" do
    @tag @needs_live
    test "a signed component deploys, is registered at v3, and starts its wrapper", context do
      env = live_env(context)
      name = unique_name()
      id = start_id(name)
      artifact = guest!(context, name: name, start: %{id: id, config: ~s({"greeting":"hello"})})
      on_exit(fn -> Mesh.stop_agent(id) end)

      assert {:ok, outcome} = deploy(artifact, [node()], context, env)

      assert outcome.state == :live
      assert outcome.stage == :evaluate
      assert outcome.component_sha256 == artifact.component_sha256
      assert outcome.module == "wasm/" <> artifact.name
      assert outcome.nodes == [node()]

      assert %{stage: :ok, probe: :ok, eval: %{satisfied?: true, passed: 2}} =
               outcome.deployment[node()]

      assert outcome.eval_report.compare == false
      assert outcome.eval_report.spec.probes == 2
      assert outcome.eval_report.nodes[node()].satisfied? == true

      # The register carries the component sha, which is the whole of checkpoint v3.
      assert {:ok, entry} = Registry.get(artifact.id, context.registry)
      assert entry.state == :live
      assert entry.module == "wasm/" <> artifact.name
      assert entry.component_sha256 == artifact.component_sha256
      assert entry.epoch == artifact.epoch

      # And the sha is now protected from pruning, which is what W1 left ready.
      assert {:ok, protected} = Store.protected_shas(registry: context.registry)
      assert MapSet.member?(protected, artifact.component_sha256)

      # Bytes and manifest both survive on the node, which is what makes reboot survival
      # possible at all.
      assert {:ok, ^id} = started_id(outcome)
      assert {:ok, _bytes} = Store.fetch(artifact.component_sha256, root: context.root)
      assert {:ok, manifest} = Store.fetch_manifest(artifact.id, root: context.root)
      assert manifest.component_sha256 == artifact.component_sha256

      # The durable wrapper is running and answers, which is more than the probe proved.
      assert is_pid(Mesh.whereis(id))
      assert {:ok, _agent} = Mesh.send_message("rollout-test", id, %{"greet" => "world"})

      assert %{"echo" => %{"greet" => "world"}, "config" => %{"greeting" => "hello"}} =
               state(id).last_answer
    end

    @tag @needs_live
    test "an eval spec the guest cannot satisfy rolls back, with per-node proof", context do
      env = live_env(context)
      name = unique_name()
      id = start_id(name)
      on_exit(fn -> Mesh.stop_agent(id) end)

      artifact =
        guest!(context,
          name: name,
          start: %{id: id, config: "{}"},
          eval: %{
            probes: [%{input: %{"greet" => "x"}, expect: {:equals, "something else entirely"}}],
            budget_ms: 10_000,
            required: :all
          }
        )

      assert {:error, {:rolled_back, outcome}} = deploy(artifact, [node()], context, env)

      assert outcome.state == :rolled_back
      assert outcome.stage == :evaluate
      assert %{stage: :ok, probe: :ok, recovery: :not_needed} = outcome.deployment[node()]
      assert outcome.deployment[node()].eval.satisfied? == false
      assert outcome.started == nil

      # Rollback is stop-and-mark. Nothing was started, and nothing was deleted: the bytes
      # stay because rollback material that never expires is the point of the store.
      assert Mesh.whereis(id) == nil
      assert {:ok, _bytes} = Store.fetch(artifact.component_sha256, root: context.root)
      assert {:ok, %{state: :rolled_back}} = Registry.get(artifact.id, context.registry)
    end

    @tag @needs_live
    test "a helper that reads something other than the manifest quarantines", context do
      env = live_env(context)

      # A manifest that is entirely well-formed, correctly signed, and describes exactly
      # these bytes — except that it declares no imports while the component imports `log`.
      # Only the helper can see that, and it never "just links less".
      artifact = guest!(context, imports: [])

      assert {:error, {:quarantined, outcome}} = deploy(artifact, [node()], context, env)

      assert outcome.stage == :stage

      assert {:mismatch, {:component_mismatch, :imports, [], ["log"]}} =
               outcome.deployment[node()].stage

      assert outcome.deployment[node()].probe == :skipped

      assert {:ok, %{state: :quarantined}} = Registry.get(artifact.id, context.registry)

      # Quarantined bytes are evidence and are protected from pruning (§7.4).
      assert {:ok, protected} = Store.protected_shas(registry: context.registry)
      assert MapSet.member?(protected, artifact.component_sha256)
    end

    @tag @needs_live
    test "a node that cannot stage rolls back rather than quarantining", context do
      env = live_env(context)
      blocker = Path.join(context.root, "not-a-directory")
      File.write!(blocker, "")

      artifact = guest!(context)

      assert {:error, {:rolled_back, outcome}} =
               deploy(artifact, [node()], context, Keyword.put(env, :store_root, blocker))

      assert outcome.stage == :stage
      assert {:error, {:component_not_stored, _reason}} = outcome.deployment[node()].stage
      assert outcome.deployment[node()].recovery == :not_needed
      assert {:ok, %{state: :rolled_back}} = Registry.get(artifact.id, context.registry)
    end

    @tag @needs_live
    test "a start id held by another component is not a start", context do
      env = live_env(context)
      name = unique_name()
      id = start_id(name)
      on_exit(fn -> Mesh.stop_agent(id) end)

      # The squatter: a live wrapper for a *different* component, holding the id first. A
      # mesh id is claimed once cluster-wide, so the rollout's `start_agent` gets
      # `{:already_started, _}` — which used to be counted as a start, recorded under the
      # rollout's own sha, while something else entirely answered for the id.
      other_sha = String.duplicate("d", 64)

      {:ok, squatter} =
        Mesh.start_agent(id,
          agent: Capability,
          initial_state: %{
            component: other_sha,
            config: ~s({"greeting":"squatter"}),
            name: "squatter",
            limits: %{},
            pool: env[:pool],
            store_root: context.root
          }
        )

      # A component that passes every gate, whose manifest wants that same durable id.
      artifact = guest!(context, name: name, start: %{id: id, config: "{}"})
      refute artifact.component_sha256 == other_sha

      assert {:error, {:quarantined, outcome}} = deploy(artifact, [node()], context, env)

      assert outcome.state == :quarantined
      assert outcome.stage == :start
      assert outcome.started.id == id
      assert outcome.started.node == nil
      assert outcome.started.claimed_by == other_sha

      # Every gate passed; it is the name that was taken.
      assert %{stage: :ok, probe: :ok} = outcome.deployment[node()]

      assert {:ok, entry} = Registry.get(artifact.id, context.registry)
      assert entry.state == :quarantined
      assert entry.detail.start_id_claimed_by == other_sha

      # The squatter is untouched, which is the other half: a rollout that cannot have the
      # name does not take it away from whoever does.
      assert Mesh.whereis(id) == squatter
      assert state(id).component == other_sha
    end

    @tag @needs_live
    test "a driver that is not a target is warned about, not refused", context do
      env = live_env(context)
      name = unique_name()
      id = start_id(name)
      on_exit(fn -> Mesh.stop_agent(id) end)

      # This node *is* the only target here, so there is nothing to warn about.
      artifact = guest!(context, name: name, start: %{id: id, config: ~s({"greeting":"hello"})})
      assert {:ok, outcome} = deploy(artifact, [node()], context, env)
      assert outcome.warnings == []

      # The two-node case — a driver deploying to peers it is not one of — is where the
      # warning appears; `rollout_two_node_test.exs` asserts it against real peers.
    end

    @tag @needs_live
    test "the checkpoint is written before any effect", context do
      env = live_env(context)
      artifact = guest!(context, imports: [])

      refute File.exists?(Path.join(context.root, "sha256-#{artifact.component_sha256}.wasm"))

      assert {:error, {:quarantined, _outcome}} = deploy(artifact, [node()], context, env)

      # The entry exists even though the deployment never got past staging, which is what
      # "checkpoint before effect" buys: a crash mid-rollout leaves evidence there was one.
      assert {:ok, entry} = Registry.get(artifact.id, context.registry)
      assert entry.component_sha256 == artifact.component_sha256
    end
  end

  ## Fixtures

  defp deploy(artifact, nodes, context, extra \\ []) do
    Rollout.deploy(artifact, bytes_for(artifact), nodes, opts(context, extra))
  end

  defp opts(context, extra \\ []) do
    Keyword.merge(
      [
        registry: context.registry,
        trust_policy: context.trust_policy,
        store_root: context.root,
        start?: true
      ],
      extra
    )
  end

  # A pool speaking to the real helper, named so nothing else in the suite shares it.
  defp live_env(_context) do
    name = :"wasm_rollout_pool_#{System.unique_integer([:positive])}"
    {:ok, pid} = Pool.start(name: name, handshake_timeout_ms: 15_000)

    on_exit(fn ->
      if Process.alive?(pid) do
        try do
          GenServer.stop(pid, :normal, 5_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    [pool: pid]
  end

  defp artifact!(context, attrs \\ []) do
    build!(context, placeholder_bytes(), attrs)
  end

  defp guest!(context, attrs \\ []) do
    build!(
      context,
      File.read!(@guest),
      Keyword.put_new(attrs, :eval, %{
        probes: [
          %{input: %{"greet" => "world"}, expect: {:contains, "greet"}},
          %{input: %{"greet" => "again"}, expect: {:state_matches, :messages_received, 2}}
        ],
        budget_ms: 10_000,
        required: :all
      })
    )
  end

  defp build!(context, bytes, attrs) do
    {:ok, artifact} =
      Artifact.build(
        bytes,
        Keyword.merge(
          [name: "greeter", author: "test-agent", imports: ["log"], epoch: next_epoch()],
          attrs
        )
      )

    Process.put({__MODULE__, :bytes, artifact.id}, bytes)
    sign(artifact, context.secret)
  end

  defp unsigned!(attrs \\ []) do
    {:ok, artifact} =
      Artifact.build(
        placeholder_bytes(),
        Keyword.merge(
          [name: "greeter", author: "test-agent", epoch: next_epoch()],
          attrs
        )
      )

    Process.put({__MODULE__, :bytes, artifact.id}, placeholder_bytes())
    artifact
  end

  # A process that holds a start id, answers `Mesh.state/1` with this component's sha — so
  # `Rollout.withdraw/2` is obliged to stop it rather than leave it alone — and is not one
  # of the agent supervisor's children, so stopping it answers `{:error, :not_found}`.
  # "A wrapper this node could not confirm it stopped" is exactly the evidence a peer
  # timeout produces, and it is the only thing that earns `:quarantined` over
  # `:rolled_back` on the compensation path.
  defp start_unstoppable_holder!(id, component_sha256) do
    {:ok, pid} = GenServer.start(__MODULE__.UnstoppableHolder, component_sha256)
    :ok = Ouroboros.Mesh.Directory.register(id, pid)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    pid
  end

  defp probe_agent_ids do
    Mesh.list_agents()
    |> Enum.map(fn agent -> if is_map(agent), do: Map.get(agent, :id), else: agent end)
    |> Enum.filter(&(is_binary(&1) and String.starts_with?(&1, "ouroboros-probe-")))
    |> Enum.sort()
  end

  # The janitor stops the id after the killed process goes down, which is asynchronous.
  defp await_probe_agents(expected, 0),
    do: (probe_agent_ids() == expected && expected) || probe_agent_ids()

  defp await_probe_agents(expected, attempts) do
    if probe_agent_ids() == expected do
      expected
    else
      Process.sleep(20)
      await_probe_agents(expected, attempts - 1)
    end
  end

  defmodule UnstoppableHolder do
    @moduledoc false
    use GenServer

    @impl true
    def init(component_sha256), do: {:ok, component_sha256}

    @impl true
    def handle_call(:get_state, _from, sha),
      do: {:reply, {:ok, %{agent: %{state: %{component: sha}}}}, sha}
  end

  # The bytes travel beside the manifest, never inside it, so a test carries them the way
  # a caller would: alongside, keyed by the artifact they belong to.
  defp bytes_for(artifact), do: Process.get({__MODULE__, :bytes, artifact.id})

  defp sign(artifact, secret) do
    payload = Artifact.signing_payload(artifact, @signer)
    value = :crypto.sign(:eddsa, :none, payload, [secret, :ed25519])
    {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: value})
    signed
  end

  defp placeholder_bytes, do: "\0asm\x01\x00\x00\x00 not a real component"

  defp next_epoch, do: System.unique_integer([:positive, :monotonic]) + 1_000

  defp seed_live!(context, epoch) do
    id = "seeded-#{System.unique_integer([:positive])}"

    {:ok, _entry} =
      Registry.deploying(
        %{
          artifact_id: id,
          module: "wasm/seeded",
          epoch: epoch,
          nodes: [node()],
          component_sha256: String.duplicate("c", 64)
        },
        context.registry
      )

    {:ok, entry} = Registry.mark(id, :live, [], context.registry)
    entry
  end

  defp started_id(%{started: %{id: id}}), do: {:ok, id}
  defp started_id(other), do: {:error, other}

  defp state(id) do
    {:ok, server_state} = Mesh.state(id)
    server_state.agent.state
  end

  # A start id is `"wasm/" <> name` or it is nothing (docs/WASM.md §7.5): the signer
  # refuses any other, and `Rollout.start_block/1` re-derives it rather than reading it.
  # So a test that wants a durable id of its own asks for a component name of its own.
  defp unique_name, do: "rollout-test-#{System.unique_integer([:positive])}"
  defp start_id(name), do: "wasm/" <> name

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp start_registry! do
    name = String.to_atom("wasm_rollout_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("wasm_rollout_rollouts_#{System.unique_integer([:positive])}")}
      )

    on_exit(fn ->
      try do
        GenServer.stop(pid)
      catch
        :exit, _reason -> :ok
      end
    end)

    name
  end
end
