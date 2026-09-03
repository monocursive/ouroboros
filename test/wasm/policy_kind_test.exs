defmodule Ouroboros.Wasm.PolicyKindTest do
  @moduledoc """
  The manifest's `kind`, from the struct that carries it to the helper that enforces it
  (docs/WASM.md §8.2, D21, contract C7).

  Two worlds and one linker means the interesting question is not "does a policy component
  work" — `test/wasm/policy_acceptance_test.exs` answers that — but "can a set of bytes end up
  in the world its manifest did not claim". Every clause below is one place along that path.
  """

  # The stage half spawns the real helper as an OS child and moves `:upgrade_trust_policy`,
  # which every loading node reads out of application environment.
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Policy.Default, as: SigningPolicy
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.{Artifact, Bundle, LiveFixture, PolicyEngine, Pool, Rollout}
  alias Ouroboros.Wasm.{SandboxFixture, Store}

  @moduletag :capture_log

  @capability_guest Path.expand("../support/wasm/echo.wasm", __DIR__)
  @policy_guest Path.expand(
                  "../../tui/wasm/guest/examples/no-network-shell/target/wasm32-wasip2/release/no_network_shell.wasm",
                  __DIR__
                )

  # Any bytes with a component preamble: everything in the first three blocks is about the
  # manifest, and the manifest never parses what it describes.
  @bytes "\0asm\x0d\x00\x01\x00 a component nothing here runs"

  @policy_eval %{
    cases: [
      %{
        request: %{"tool" => "bash", "input" => %{"command" => "curl x"}},
        expect: %{decision: :deny}
      },
      %{request: %{"tool" => "bash", "input" => %{"command" => "ls"}}, expect: %{decision: :ask}}
    ],
    budget_ms: 5_000
  }

  @capability_eval %{
    probes: [%{input: %{"greet" => "world"}, expect: {:contains, "greet"}}],
    budget_ms: 5_000,
    required: :all
  }

  describe "the struct: a kind, and the world that follows from it" do
    test "the default is a capability, and the world follows the kind" do
      assert {:ok, capability} = build()
      assert capability.kind == :capability
      assert capability.world == Wasm.world()

      assert {:ok, policy} = build(kind: :policy)
      assert policy.kind == :policy
      assert policy.world == Wasm.policy_world()

      # Two packages, never one wider than the other.
      refute Wasm.world() == Wasm.policy_world()
    end

    test "a kind outside the closed set is refused, whatever it spells" do
      for kind <- [:hook, "policy", nil, :Policy, %{}] do
        assert {:error, {:invalid_component_kind, _rendered}} = build(kind: kind),
               "#{inspect(kind)} must not be a kind"
      end
    end

    test "the kind is in the signed manifest, so a signature covers it" do
      assert {:ok, capability} = build()
      assert {:ok, policy} = build(kind: :policy, id: capability.id, epoch: capability.epoch)

      assert Artifact.manifest(capability)[:kind] == :capability
      assert Artifact.manifest(policy)[:kind] == :policy

      # The whole point: the payload a signature is issued over differs. Delete `:kind` from
      # `Artifact.manifest/1` and these two become the same bytes, which is a signature over a
      # capability replayable as one over a policy.
      refute Artifact.signing_payload(capability, "signer") ==
               Artifact.signing_payload(policy, "signer")
    end
  end

  describe "the bundle envelope carries the kind, and holds it to the closed set" do
    test "a policy bundle round-trips as a policy" do
      {:ok, artifact} = build(kind: :policy)

      {:ok, signed} =
        Artifact.with_signature(artifact, %{signer: "s", value: :binary.copy("\0", 64)})

      {:ok, bundle} = Bundle.encode(signed, @bytes)

      assert {:ok, %{artifact: decoded, bytes: @bytes}} = Bundle.decode(bundle)
      assert decoded.kind == :policy
      assert decoded.world == Wasm.policy_world()
    end

    test "a manifest naming an atom this VM happens to hold is refused, not reconstructed" do
      # `:erlang.binary_to_term/2`'s `:safe` refuses to *create* an atom and hands back any atom
      # already interned, so `kind: :erlang` decodes perfectly well. The kind decides which of
      # two worlds these bytes are offered as, so it is held to the set before anything reads it.
      {:ok, artifact} = build(kind: :policy)

      forged =
        artifact
        |> Artifact.manifest()
        |> Map.put(:kind, :erlang)

      assert {:error, {:invalid_component_kind, _rendered}} = decode_manifest(forged)

      # And the same file with the kind put back is readable, so the refusal above is the kind
      # and not the surgery.
      assert {:ok, _decoded} = decode_manifest(Artifact.manifest(artifact))
    end
  end

  describe "the signing policy: the kind decides the world, the eval grammar and the start" do
    test "a policy manifest carrying the capability world is refused" do
      {:ok, artifact} = build(kind: :policy, world: Wasm.world(), eval: @policy_eval)

      assert {:refused, {:world_not_supported, world}} = evaluate(artifact)
      assert world == Wasm.world()

      # And the reverse, which is the direction that would have let a capability be signed
      # into the world the permission engine reads from.
      {:ok, artifact} = build(world: Wasm.policy_world(), eval: @capability_eval)
      assert {:refused, {:world_not_supported, _world}} = evaluate(artifact)
    end

    test "a policy manifest with no eval spec is refused, exactly as a capability's is" do
      {:ok, artifact} = build(kind: :policy, eval: nil)
      assert {:refused, :eval_spec_required} = evaluate(artifact)
    end

    test "a policy's eval spec is cases, and a capability's probe list is not one" do
      {:ok, artifact} = build(kind: :policy, eval: @policy_eval)
      assert {:ok, verdict} = evaluate(artifact)
      assert verdict.kind == :policy
      assert verdict.eval == :required_and_valid

      # The capability grammar, offered to a policy manifest. Two grammars because they judge
      # different things; validating one against the other's validator would refuse every
      # honest spec in the lane it was not written for.
      {:ok, artifact} = build(kind: :policy, eval: @capability_eval)
      assert {:refused, {:invalid_eval_spec, {:unknown_spec_keys, keys}}} = evaluate(artifact)
      assert :probes in keys

      # And the other way round.
      {:ok, artifact} = build(eval: @policy_eval)
      assert {:refused, {:invalid_eval_spec, _reason}} = evaluate(artifact)
    end

    test "a spec whose every case expects an allow certifies nothing" do
      # An `allow` is the one verdict this node does not honour by default, so a component can
      # satisfy such a spec on every target and still be the only thing it must never be. The
      # signed spec *is* the test story for this lane (D12), and a test story with no refusal in
      # it is a claim that the component said yes twice. Delete `certifies_a_refusal/1` and
      # this goes green on a spec that proves nothing.
      only_allows = %{
        cases: [
          %{request: %{"tool" => "read"}, expect: %{decision: :allow}},
          %{request: %{"tool" => "ls"}, expect: %{decision: :allow}}
        ]
      }

      assert {:error, {:invalid_eval_spec, :no_case_expects_a_refusal}} =
               PolicyEngine.validate_eval(only_allows)

      {:ok, artifact} = build(kind: :policy, eval: only_allows)
      assert {:refused, {:invalid_eval_spec, :no_case_expects_a_refusal}} = evaluate(artifact)

      # One refusal is enough, in either spelling.
      for refusal <- [:deny, :ask] do
        spec =
          put_in(only_allows.cases, [
            %{request: %{"tool" => "bash"}, expect: %{decision: refusal}}
          ])

        assert {:ok, _valid} = PolicyEngine.validate_eval(spec)
      end
    end

    test "a policy's cases are bounded and named" do
      for {spec, expected} <- [
            {%{cases: []}, :cases_required},
            {%{cases: [%{request: %{}, expect: %{decision: :maybe}}]},
             {:unknown_expected_decision, 0}},
            {%{cases: [%{request: "not a map", expect: %{decision: :deny}}]},
             {:case_request_not_a_map, 0}},
            {%{cases: [%{request: %{}, expect: %{decision: :deny}}], budget_ms: 0},
             {:invalid_budget_ms, "0"}},
            {%{cases: [%{request: %{}, expect: %{decision: :deny}}], flavour: :spicy},
             {:unknown_spec_keys, [:flavour]}}
          ] do
        assert {:error, {:invalid_eval_spec, ^expected}} = PolicyEngine.validate_eval(spec),
               "#{inspect(spec)} must be refused as #{inspect(expected)}"
      end

      too_many = %{cases: for(_ <- 1..21, do: %{request: %{}, expect: %{decision: :ask}})}

      assert {:error, {:invalid_eval_spec, {:too_many_cases, 21, 20}}} =
               PolicyEngine.validate_eval(too_many)
    end

    test "a policy component may not declare a start block" do
      # A start block is the claim "this runs continuously under this durable mesh id". A
      # policy has no wrapper agent and is reached only by the engine, so the id would be one
      # nothing ever starts.
      {:ok, artifact} =
        build(kind: :policy, eval: @policy_eval, start: %{id: "wasm/guard", config: "{}"})

      assert {:refused, {:invalid_start, :policy_components_do_not_start}} = evaluate(artifact)

      # The same block on a capability is exactly as legal as it always was.
      {:ok, artifact} =
        build(eval: @capability_eval, start: %{id: "wasm/guard", config: "{}"})

      assert {:ok, %{start: %{id: "wasm/guard"}}} = evaluate(artifact)
    end

    test "the verifier refuses a kind and a world that disagree, on the loading node too" do
      # The signer refuses this pair, and so does every node that reads the bundle — one build,
      # one linker contract, checked at both ends. Compare against `Wasm.world()` in
      # `Verifier.verify_world/1` and a policy manifest carrying the capability world verifies.
      {:ok, artifact} = build(kind: :policy, world: Wasm.world(), eval: @policy_eval)

      assert {:error, {:world_not_supported, world}} =
               Ouroboros.Wasm.Verifier.verify_manifest(artifact, allow_unsigned: true)

      assert world == Wasm.world()

      {:ok, artifact} = build(world: Wasm.policy_world(), eval: @capability_eval)

      assert {:error, {:world_not_supported, _world}} =
               Ouroboros.Wasm.Verifier.verify_manifest(artifact, allow_unsigned: true)

      # And a kind outside the closed set is refused before the world is even looked at: it
      # arrives from a manifest in a file, and `:safe` hands back any atom this VM holds.
      forged = %{artifact | kind: :erlang, world: Wasm.world()}

      assert {:error, {:invalid_component_kind, _rendered}} =
               Ouroboros.Wasm.Verifier.verify_manifest(forged, allow_unsigned: true)
    end

    test "the register carries the kind, and refuses one it does not implement" do
      # W15 review H3. The kind is recorded at deploy from the manifest the rollout verified, so
      # `Rollout.live/1` filters without opening a file per entry — and a caller naming a third
      # kind is refused rather than defaulted.
      registry = registry()

      {:ok, entry} =
        Registry.deploying(
          %{
            artifact_id: "policy-entry",
            module: "wasm/guard",
            epoch: epoch(),
            nodes: [node()],
            component_sha256: String.duplicate("a", 64),
            kind: :policy
          },
          registry
        )

      assert entry.kind == :policy

      {:ok, capability} =
        Registry.deploying(
          %{
            artifact_id: "capability-entry",
            module: "wasm/greeter",
            epoch: epoch(),
            nodes: [node()],
            component_sha256: String.duplicate("b", 64)
          },
          registry
        )

      # An unstated kind is the capability every entry written before W15 was.
      assert capability.kind == :capability

      assert {:error, {:invalid_attribute, :kind, _rendered}} =
               Registry.deploying(
                 %{
                   artifact_id: "third",
                   module: "wasm/other",
                   epoch: epoch(),
                   nodes: [node()],
                   component_sha256: String.duplicate("c", 64),
                   kind: :hook
                 },
                 registry
               )

      {:ok, _live} = Registry.mark("policy-entry", :live, [], registry)
      {:ok, _live} = Registry.mark("capability-entry", :live, [], registry)

      # And the listing filters on the row rather than on a file it opens per entry.
      capabilities = Rollout.live(registry: registry)
      policies = Rollout.live(registry: registry, kind: :policy)

      assert Enum.map(capabilities, & &1.module) == ["wasm/greeter"]
      assert Enum.map(policies, & &1.module) == ["wasm/guard"]
    end

    test "the name charset is the kind-independent one it always was" do
      for name <- ["Guard", "wasm/guard", "guard ", "../guard", String.duplicate("g", 65)] do
        assert {:error, {:invalid_component_name, _rendered}} = build(kind: :policy, name: name),
               "#{inspect(name)} must not be a component name"
      end

      assert {:ok, %Artifact{name: "no-network.shell_1"}} =
               build(kind: :policy, name: "no-network.shell_1")
    end
  end

  describe "the pool refuses a kind before it builds a frame" do
    test "an unrecognized kind is a named refusal on both load and instantiate" do
      # `lane:`'s posture, for the same reason: one of the two kinds is *not* the default any
      # more in the sense that matters — it decides which world a component is checked
      # against — so a caller whose kind this build does not know has said something this
      # build cannot honour either way. Refused here, before a frame exists and before any
      # process is named, which is why this needs no helper at all.
      for kind <- [:hook, "policy", nil, :Policy] do
        assert {:error, {:invalid_kind, ^kind}} =
                 Pool.load(String.duplicate("a", 64), "/nowhere.wasm", :no_such_pool, kind: kind)

        assert {:error, {:invalid_kind, ^kind}} =
                 Pool.instantiate(
                   "i",
                   String.duplicate("a", 64),
                   "{}",
                   Wasm.capability_limits(),
                   :no_such_pool,
                   kind: kind
                 )
      end
    end

    test "the world a kind requires is a total function with no third answer" do
      assert Wasm.world_for(:capability) == Wasm.world()
      assert Wasm.world_for(:policy) == Wasm.policy_world()
      assert Wasm.kinds() == [:capability, :policy]

      # Anything that is not `:policy` is the capability world, because a manifest read back
      # from a file predating W15 has no `kind` at all and is the capability it always was.
      assert Wasm.world_for(nil) == Wasm.world()
    end
  end

  describe "the helper is where a manifest meets the bytes" do
    @describetag LiveFixture.tag(@capability_guest)

    setup do
      LiveFixture.ensure!(@capability_guest)
      :ok
    end

    test "a policy-kind manifest over capability bytes is refused at stage" do
      # The whole of contract C7's enforcement, in one call. Nothing here parses the component
      # on the Elixir side: `Wasm.Rollout.stage/3` hands the helper the *manifest's* kind, and
      # the helper's world check is what says these bytes are not in that world.
      bytes = File.read!(@capability_guest)
      root = tmp_dir()

      {:ok, artifact} =
        Artifact.build(bytes,
          name: "misdeclared",
          epoch: epoch(),
          kind: :policy,
          imports: ["log"],
          author: "test",
          eval: @policy_eval
        )

      {:ok, signed} = sign(artifact)

      assert {:error, {:component_not_loaded, %{refusal: "unsupported_world"}}} =
               Rollout.stage(signed, bytes,
                 store_root: root,
                 epoch_registry: registry(),
                 pool: live_pool!(root)
               )

      # The bytes are in the store — staging publishes before it loads — and no instance and
      # no cached component came out of it.
      assert {:ok, _path} = Store.path(artifact.component_sha256, root: root)
    end

    @tag policy_guest: true
    test "the same bytes stage cleanly under the kind they are actually in" do
      if File.regular?(@policy_guest) do
        bytes = File.read!(@policy_guest)
        root = tmp_dir()

        {:ok, artifact} =
          Artifact.build(bytes,
            name: "no-network-shell",
            epoch: epoch(),
            kind: :policy,
            imports: ["log"],
            author: "test",
            eval: @policy_eval
          )

        {:ok, signed} = sign(artifact)

        assert {:ok, _evidence} =
                 Rollout.stage(signed, bytes,
                   store_root: root,
                   epoch_registry: registry(),
                   pool: live_pool!(root)
                 )

        # And a capability manifest over those same bytes is refused, which is the other
        # direction of the same check.
        {:ok, wrong} =
          Artifact.build(bytes,
            name: "no-network-shell",
            epoch: epoch(),
            imports: ["log"],
            author: "test",
            eval: @capability_eval
          )

        {:ok, wrong} = sign(wrong)

        assert {:error, {:component_not_loaded, %{refusal: "unsupported_world"}}} =
                 Rollout.stage(wrong, bytes,
                   store_root: root,
                   epoch_registry: registry(),
                   pool: live_pool!(root)
                 )
      else
        # `make wasm-examples` builds it; without it this half is not checked, and under
        # `OUROBOROS_REQUIRE_WASM` that is a failure rather than a silence.
        refute LiveFixture.required?(),
               "OUROBOROS_REQUIRE_WASM is set and there is no #{@policy_guest}; " <>
                 "run `make wasm-examples`"
      end
    end
  end

  ## helpers

  defp build(attrs \\ []) do
    metadata =
      %{author: "test-agent"}
      |> put_present(:eval, Keyword.get(attrs, :eval, @capability_eval))
      |> put_present(:start, Keyword.get(attrs, :start))

    base = [
      name: "guard",
      epoch: 4_242,
      imports: ["log"],
      metadata: metadata
    ]

    Artifact.build(@bytes, Keyword.merge(base, Keyword.drop(attrs, [:eval, :start])))
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  # The signing policy, asked directly. `component_bytes` is what a real request carries and
  # what the recomputation reads; there is no signer and no key involved in any of this.
  defp evaluate(artifact) do
    SigningPolicy.evaluate(artifact, %{component_bytes: @bytes, requester: node()})
  end

  # A manifest term through the bundle's own decode path, which is where a file somebody else
  # wrote is read. Built by hand because `Bundle.encode/2` will not write a manifest this build
  # would refuse — which is the point of writing one here.
  defp decode_manifest(manifest) do
    envelope =
      JSON.encode!(%{
        "bundle" => 2,
        "manifest" => Base.encode64(:erlang.term_to_binary(manifest, [:deterministic])),
        "signer" => "s",
        "signature" => Base.encode64(:binary.copy("\0", 64))
      })

    bundle =
      "OUROWASM" <>
        <<2::8, byte_size(envelope)::32, 0::32, byte_size(@bytes)::32>> <> envelope <> @bytes

    Bundle.decode(bundle)
  end

  # A signature this node will accept, by pointing its trust policy at a key made here. The
  # subject of these tests is the world check at stage, not the signature, so this is the
  # smallest thing that gets past `Wasm.Verifier`.
  defp sign(artifact) do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, signer_seed())
    signer = "wasm-policy-kind-test-key"

    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)

    Application.put_env(:ouroboros, :upgrade_trust_policy,
      allow_unsigned: false,
      trusted_signers: %{signer => public}
    )

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ouroboros, :upgrade_trust_policy)
        value -> Application.put_env(:ouroboros, :upgrade_trust_policy, value)
      end
    end)

    value =
      :crypto.sign(
        :eddsa,
        :none,
        Artifact.signing_payload(artifact, signer),
        [private, :ed25519]
      )

    Artifact.with_signature(artifact, %{signer: signer, value: value})
  end

  # One seed per test process, so the trust policy this test installs is the one it signed
  # under whatever order the suite runs in.
  defp signer_seed do
    case Process.get(__MODULE__) do
      nil ->
        seed = :crypto.strong_rand_bytes(32)
        Process.put(__MODULE__, seed)
        seed

      seed ->
        seed
    end
  end

  defp registry do
    name = String.to_atom("wasm_policy_kind_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table:
             String.to_atom("wasm_policy_kind_rollouts_#{System.unique_integer([:positive])}")}
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

  defp epoch, do: System.unique_integer([:positive, :monotonic]) + 1_000_000

  # W16. A pool of this suite's own, told where `root` is, rather than the node's singleton:
  # the helper is spawned under the OS sandbox now and reads only the roots it is named, and
  # a singleton spawned by some earlier suite would have been named somebody else's.
  defp live_pool!(root) do
    name = :"wasm_kind_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start([name: name, handshake_timeout_ms: 15_000] ++ SandboxFixture.pool_opts(root))

    on_exit(fn ->
      if Process.alive?(pid) do
        try do
          GenServer.stop(pid, :normal, 5_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    pid
  end

  defp tmp_dir do
    dir = Path.join(System.tmp_dir!(), "ouro-wasm-kind-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end
end
