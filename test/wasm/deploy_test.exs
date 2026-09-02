defmodule Ouroboros.Wasm.DeployTest do
  # Not async: the live half spawns the real helper as an OS child, starts mesh agents, and
  # moves `:upgrade_trust_policy` — which every loading node reads from application
  # environment, because a target is never told which signers to trust.
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Deploy
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Store
  alias Ouroboros.Wasm.Upload

  @moduletag :capture_log

  @guest Path.expand("../support/wasm/echo.wasm", __DIR__)
  @signer "wasm-deploy-test-key"

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

  @eval %{
    probes: [
      %{input: %{"greet" => "world"}, expect: {:contains, "greet"}},
      %{input: %{"greet" => "again"}, expect: {:state_matches, :messages_received, 2}}
    ],
    budget_ms: 10_000,
    required: :all
  }

  setup do
    tmp = Path.join(System.tmp_dir!(), "ouro-wasm-deploy-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)

    seed = :crypto.strong_rand_bytes(32)
    key_path = Path.join(tmp, "signer.key")
    File.write!(key_path, seed)
    File.chmod!(key_path, 0o600)

    service =
      start_supervised!(
        {Service,
         [
           name: nil,
           key_path: key_path,
           signer_id: @signer,
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("wasm_deploy_journal_#{System.unique_integer([:positive])}")}
         ]},
        id: {Service, System.unique_integer([:positive])}
      )

    {:ok, %{public_key: public}} = Service.public_info(service)
    trust_policy = [allow_unsigned: false, trusted_signers: %{@signer => public}]

    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)
    Application.put_env(:ouroboros, :upgrade_trust_policy, trust_policy)
    on_exit(fn -> restore(:upgrade_trust_policy, previous) end)

    %{
      service: service,
      trust_policy: trust_policy,
      public: public,
      tmp: tmp,
      uploads: Path.join(tmp, "uploads"),
      store_root: Path.join(tmp, "store"),
      registry: start_registry!()
    }
  end

  describe "wasm.sign's plane" do
    test "a node with no signing service refuses by name rather than by silence",
         context do
      upload = upload!(context, "\0asm\x01\x00\x00\x00 not really a component")

      # No `:signing_service`, no `:signing_node`, and no service registered under the
      # module's own name on this node. "This node cannot sign" and "this signer said no"
      # need different operator responses, so they are different answers.
      previous = Application.get_env(:ouroboros, :signing_node)
      Application.delete_env(:ouroboros, :signing_node)
      on_exit(fn -> restore(:signing_node, previous) end)

      assert {:error, :no_signing_service} =
               Deploy.sign(
                 %{
                   upload: upload,
                   name: "greeter",
                   author: "test-agent",
                   imports: [],
                   epoch: 4_000,
                   eval: @eval
                 },
                 upload_root: context.uploads
               )

      # And the bytes are still staged: a refusal that consumed the upload would make the
      # operator re-transfer sixteen mebibytes to learn the same thing twice.
      assert {:ok, _bytes} = Upload.take(upload, root: context.uploads)
    end

    test "a signed manifest comes back as a bundle prefix, and the journal says so",
         context do
      bytes = "\0asm\x01\x00\x00\x00 a component this test never runs"
      upload = upload!(context, bytes)

      assert {:ok, receipt} = sign(context, upload, epoch: 4_100)

      assert receipt.name == "greeter"
      assert receipt.epoch == 4_100
      assert receipt.component_sha256 == Artifact.digest(bytes)
      assert receipt.size == byte_size(bytes)
      assert receipt.world == Wasm.world()
      assert receipt.imports == []
      assert receipt.signer == @signer
      assert receipt.start_id == "wasm/greeter"
      assert receipt.extension == ".ouro-wasm"

      prefix = Base.decode64!(receipt.bundle_prefix)
      assert receipt.bundle_bytes == byte_size(prefix) + byte_size(bytes)

      # The client's whole job: append the bytes it uploaded. It composes no manifest and
      # implements no format.
      assert {:ok, %{artifact: artifact, bytes: ^bytes}} =
               Bundle.verify(prefix <> bytes, context.trust_policy)

      assert artifact.id == receipt.artifact_id

      # Journalled before it was answered, like every other signing decision.
      assert {:ok, decisions} = Service.decisions(context.service)
      entry = List.last(decisions)
      assert entry.decision == :issued
      assert entry.lane == :wasm
      assert entry.artifact_id == receipt.artifact_id
      assert entry.signer_id == @signer
      assert [%{module: "wasm/greeter", disposition: :component}] = entry.modules
    end

    test "the whole signing policy applies, and a refusal is journalled too", context do
      upload = upload!(context, "\0asm\x01\x00\x00\x00 component")

      # D12: lane W's signer requires an eval spec by default, because there is no
      # BuildPeer behind a component and the signed spec is the test story.
      assert {:error, {:signing_refused, :eval_spec_required}} =
               sign(context, upload, epoch: 4_200, eval: nil)

      assert {:ok, decisions} = Service.decisions(context.service)
      assert List.last(decisions).decision == :refused

      # And a manifest the policy cannot admit for any other reason is refused the same
      # way: an import outside the world's one.
      upload = upload!(context, "\0asm\x01\x00\x00\x00 component")

      assert {:error, {:signing_refused, {:import_not_in_world, "socket"}}} =
               sign(context, upload, epoch: 4_201, imports: ["socket"])
    end

    test "the start id is derived from the name and is not a field a caller may name",
         context do
      upload = upload!(context, "\0asm\x01\x00\x00\x00 component")

      assert {:ok, receipt} = sign(context, upload, epoch: 4_300, name: "vet")
      assert receipt.start_id == "wasm/vet"

      prefix = Base.decode64!(receipt.bundle_prefix)
      {:ok, %{artifact: artifact}} = Bundle.decode(prefix <> "\0asm\x01\x00\x00\x00 component")
      assert artifact.metadata.start == %{id: "wasm/vet", config: "{}"}
    end

    test "an epoch nobody named is allocated rather than guessed", context do
      upload = upload!(context, "\0asm\x01\x00\x00\x00 component")

      assert {:ok, receipt} = sign(context, upload, epoch: nil)
      assert is_integer(receipt.epoch) and receipt.epoch > 0
    end

    test "an unknown or unfinished upload is refused before anything is built", context do
      {:ok, %{upload: half}} = Upload.append(nil, 0, "half", false, root: context.uploads)

      assert {:error, {:unknown_upload, _}} =
               sign(context, String.duplicate("0", 32), epoch: 4_400)

      assert {:error, {:upload_incomplete, ^half}} = sign(context, half, epoch: 4_401)
    end
  end

  describe "wasm.deploy's plane, before anything is written" do
    test "a bundle nobody signed is refused with the store and the helper untouched",
         context do
      # There is no such thing as a bundle with *no* signature — the format has the field
      # and `Bundle.encode/2` refuses to write one without it — so the shape an attacker
      # can actually produce is a bundle signed by somebody nobody trusts. That is what
      # this builds, and the refusal names the signer rather than the absence.
      bundle = unsigned_bundle(context)

      before = store_snapshot(context)
      pool_before = pool_snapshot()

      assert {:error, {:untrusted_signer, "nobody"}} = deploy(context, upload!(context, bundle))

      # Delete the `Bundle.verify/2` call from `Deploy.deploy/3` and these three go red:
      # the bytes reach `Rollout.deploy/4`, which writes a `:deploying` checkpoint before
      # its own verification refuses them, and stages toward the helper.
      assert store_snapshot(context) == before
      assert Registry.list(context.registry) == []
      assert pool_snapshot() == pool_before
    end

    test "a bundle whose bytes were swapped for others of the same length is refused",
         context do
      bytes = "\0asm\x01\x00\x00\x00 a component this test never runs"
      {:ok, receipt} = sign(context, upload!(context, bytes), epoch: 4_500)
      prefix = Base.decode64!(receipt.bundle_prefix)

      swapped = String.duplicate("z", byte_size(bytes))
      assert byte_size(swapped) == byte_size(bytes)

      before = store_snapshot(context)
      pool_before = pool_snapshot()

      assert {:error, {:component_sha256_mismatch, _expected, _actual}} =
               deploy(context, upload!(context, prefix <> swapped))

      assert store_snapshot(context) == before
      assert Registry.list(context.registry) == []
      assert pool_snapshot() == pool_before
    end

    test "a signer this node does not trust is refused, and the file is otherwise perfect",
         context do
      bytes = "\0asm\x01\x00\x00\x00 a component this test never runs"
      {:ok, receipt} = sign(context, upload!(context, bytes), epoch: 4_600)
      bundle = Base.decode64!(receipt.bundle_prefix) <> bytes

      # The same bundle, read by a node whose policy names no signers at all. The policy is
      # the *reading* node's, always: a deployment never carries one.
      before = store_snapshot(context)

      assert {:error, {:untrusted_signer, @signer}} =
               deploy(context, upload!(context, bundle), trust_policy: [allow_unsigned: false])

      assert store_snapshot(context) == before
      assert Registry.list(context.registry) == []
    end

    test "a file that is not one of these is refused by its framing", context do
      before = store_snapshot(context)

      assert {:error, :not_a_bundle} =
               deploy(context, upload!(context, "just some bytes, more than seventeen of them"))

      assert {:error, {:truncated_bundle, 4}} = deploy(context, upload!(context, "OURO"))
      assert store_snapshot(context) == before
    end
  end

  describe "against the real helper, end to end" do
    @tag @needs_live
    test "sign, bundle, deploy, talk to it, roll it back", context do
      pool = live_pool!()
      name = "deploy-test-#{System.unique_integer([:positive])}"
      id = "wasm/" <> name
      on_exit(fn -> Mesh.stop_agent(id) end)

      bytes = File.read!(@guest)

      # 1. Sign. The imports are read off the component by the helper rather than declared,
      #    because a wrong list is a quarantine and not a warning.
      assert {:ok, receipt} =
               sign(context, upload!(context, bytes),
                 name: name,
                 epoch: nil,
                 imports: nil,
                 pool: pool,
                 start_config: ~s({"greeting":"hello"})
               )

      assert receipt.imports == ["log"]
      assert receipt.start_id == id

      # 2. Bundle: the node's prefix, the operator's bytes.
      bundle = Base.decode64!(receipt.bundle_prefix) <> bytes

      # 3. Deploy.
      assert {:ok, outcome} = deploy(context, upload!(context, bundle), pool: pool)

      assert outcome.state == :live
      assert outcome.stage == :evaluate
      assert outcome.name == name
      assert outcome.module == id
      assert outcome.component_sha256 == receipt.component_sha256
      assert outcome.nodes == [Atom.to_string(node())]
      assert outcome.started.id == id
      assert outcome.started.node == Atom.to_string(node())
      assert outcome.warnings == []

      evidence = outcome.deployment[Atom.to_string(node())]
      assert evidence.stage == %{outcome: :ok, detail: nil}
      assert evidence.probe == %{outcome: :ok, detail: nil}
      assert evidence.eval.outcome == :passed
      assert evidence.eval.passed == 2
      assert outcome.eval.required == "all"
      assert outcome.eval.probes == 2

      # 4. The mesh agent is real and answers.
      assert is_pid(Mesh.whereis(id))
      assert {:ok, _agent} = Mesh.send_message("deploy-test", id, %{"greet" => "world"})

      assert %{"echo" => %{"greet" => "world"}, "config" => %{"greeting" => "hello"}} =
               state(id).last_answer

      # 5. Roll back: the wrapper is gone, the entry is marked, the bytes stay.
      assert {:ok, rolled} = Deploy.rollback(name, registry: context.registry)

      assert rolled.state == :rolled_back
      assert rolled.name == name
      assert rolled.start_id == id
      assert rolled.artifact_id == receipt.artifact_id
      assert rolled.recovery == %{Atom.to_string(node()) => :rolled_back}

      assert Mesh.whereis(id) == nil
      assert {:ok, entry} = Registry.get(receipt.artifact_id, context.registry)
      assert entry.state == :rolled_back

      # D6: rollback is stop and mark. The material to redeploy from never left.
      assert {:ok, _bytes} = Store.fetch(receipt.component_sha256, root: context.store_root)

      assert {:ok, _manifest} =
               Store.fetch_manifest(receipt.artifact_id, root: context.store_root)
    end
  end

  describe "wasm.rollback's plane" do
    test "a name with no live lane-W entry is not found", context do
      assert {:error, {:no_live_rollout, "greeter"}} =
               Deploy.rollback("greeter", registry: context.registry)
    end

    test "a name outside the manifest charset is refused before any lookup", context do
      for hostile <- ["../etc", "Greeter", "", String.duplicate("a", 65), "wasm/greeter"] do
        assert {:error, {:invalid_component_name, _}} =
                 Deploy.rollback(hostile, registry: context.registry)
      end
    end

    # Delete `withdraw/2`'s `holder_component(id) == component_sha256` comparison and this
    # goes red: the rollback would stop a process merely because it holds a name.
    test "a wrapper running some other component is left alone and reported unchanged",
         context do
      name = "squatted-#{System.unique_integer([:positive])}"
      id = "wasm/" <> name
      ours = String.duplicate("a", 64)
      theirs = String.duplicate("b", 64)

      seed_live!(context, name, ours)
      pid = start_holder!(id, theirs)

      assert {:ok, outcome} = Deploy.rollback(name, registry: context.registry)

      assert outcome.recovery == %{Atom.to_string(node()) => :unchanged}
      assert outcome.state == :rolled_back
      assert Process.alive?(pid)
    end

    test "a lane-B rollout is not a lane-W rollout and is never found here", context do
      {:ok, entry} =
        Registry.deploying(
          %{
            artifact_id: "beam-#{System.unique_integer([:positive])}",
            module: Ouroboros.Capability.Nothing,
            epoch: 9_100,
            nodes: [node()]
          },
          context.registry
        )

      {:ok, _live} = Registry.mark(entry.artifact_id, :live, [], context.registry)

      assert {:error, {:no_live_rollout, "nothing"}} =
               Deploy.rollback("nothing", registry: context.registry)
    end
  end

  ## Helpers

  defp sign(context, upload, attrs) do
    attrs = Map.new(attrs)

    base = %{
      upload: upload,
      name: Map.get(attrs, :name, "greeter"),
      author: "test-agent",
      imports: [],
      start_config: "{}",
      eval: @eval
    }

    attrs =
      base
      |> Map.merge(attrs)
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    Deploy.sign(attrs,
      signing_service: context.service,
      upload_root: context.uploads,
      pool: Map.get(attrs, :pool, Pool)
    )
  end

  defp deploy(context, upload, extra \\ []) do
    Deploy.deploy(
      upload,
      [node()],
      Keyword.merge(
        [
          upload_root: context.uploads,
          registry: context.registry,
          store_root: context.store_root,
          trust_policy: context.trust_policy
        ],
        extra
      )
    )
  end

  defp upload!(context, bytes) do
    {:ok, %{upload: id}} = Upload.append(nil, 0, bytes, true, root: context.uploads)
    id
  end

  # A bundle whose manifest nobody signed. Built by hand because `Bundle.encode/2` refuses
  # to write one — which is itself the point: an unsigned bundle only exists if somebody
  # made it on purpose.
  defp unsigned_bundle(_context) do
    bytes = "\0asm\x01\x00\x00\x00 an unsigned component"

    {:ok, artifact} =
      Artifact.build(bytes, name: "greeter", epoch: 9_000, author: "nobody", imports: [])

    envelope =
      JSON.encode!(%{
        "bundle" => 1,
        "manifest" => Base.encode64(:erlang.term_to_binary(Artifact.manifest(artifact))),
        "signer" => "nobody",
        "signature" => Base.encode64(:binary.copy("\0", 64))
      })

    "OUROWASM" <>
      <<1::8, byte_size(envelope)::32, byte_size(bytes)::32>> <> envelope <> bytes
  end

  # What the store holds, as a set. Compared before and after a refusal, because "nothing
  # was written" is the claim and a listing is how it is checked.
  defp store_snapshot(context) do
    case Store.list(root: context.store_root) do
      {:ok, entries} -> entries |> Enum.map(&{&1.kind, &1.sha256}) |> Enum.sort()
      {:error, reason} -> reason
    end
  end

  # What this node's helper pool is doing. A refused deploy must not advance it: no spawn,
  # no component admitted, no instance stood up. `:absent` is a node that runs no pool at
  # all, which is a posture and not a fault.
  defp pool_snapshot do
    case Process.whereis(Pool) do
      nil -> :absent
      pid -> pid |> Pool.status() |> Map.take([:phase, :instances, :owned, :hook_components])
    end
  end

  defp live_pool! do
    name = :"wasm_deploy_pool_#{System.unique_integer([:positive])}"
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

    pid
  end

  defp seed_live!(context, name, sha) do
    id = "seed-#{System.unique_integer([:positive])}"

    {:ok, _entry} =
      Registry.deploying(
        %{
          artifact_id: id,
          module: "wasm/" <> name,
          epoch: System.unique_integer([:positive, :monotonic]) + 9_000,
          nodes: [node()],
          component_sha256: sha
        },
        context.registry
      )

    {:ok, entry} = Registry.mark(id, :live, [], context.registry)
    entry
  end

  # A process that holds a mesh id and answers `Mesh.state/1` with some *other* component's
  # sha, which is exactly what a squatter looks like to `Rollout.withdraw/2`.
  defp start_holder!(id, sha) do
    {:ok, pid} = GenServer.start(__MODULE__.Holder, sha)
    :ok = Mesh.Directory.register(id, pid)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    pid
  end

  defmodule Holder do
    @moduledoc false
    use GenServer

    @impl true
    def init(sha), do: {:ok, sha}

    @impl true
    def handle_call(:get_state, _from, sha),
      do: {:reply, {:ok, %{agent: %{state: %{component: sha}}}}, sha}
  end

  defp state(id) do
    {:ok, server_state} = Mesh.state(id)
    server_state.agent.state
  end

  defp start_registry! do
    name = String.to_atom("wasm_deploy_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("wasm_deploy_rollouts_#{System.unique_integer([:positive])}")}
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

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
