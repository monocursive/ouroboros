defmodule Ouroboros.Wasm.DeployTest do
  # Not async: the live half spawns the real helper as an OS child, starts mesh agents, and
  # moves `:upgrade_trust_policy` — which every loading node reads from application
  # environment, because a target is never told which signers to trust.
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Deploy
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Rollout
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

    table = String.to_atom("wasm_deploy_rollouts_#{System.unique_integer([:positive])}")
    registry = start_registry!(table)

    %{
      service: service,
      trust_policy: trust_policy,
      public: public,
      tmp: tmp,
      uploads: Path.join(tmp, "uploads"),
      store_root: Path.join(tmp, "store"),
      registry: registry,
      registry_table: table
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
                   eval: @eval
                 },
                 upload_root: context.uploads
               )

      # The upload is consumed first, before anything that can refuse. A staged blob that
      # outlived its own refusal is one a client could re-present without limit — and every
      # bound below the signer (its policy, its rate limit, its journal) sits downstream of
      # that. Re-transferring is the cost, and it is the client's.
      assert {:error, {:unknown_upload, ^upload}} = Upload.take(upload, root: context.uploads)
    end

    test "a signed manifest comes back as a bundle prefix, and the journal says so",
         context do
      bytes = "\0asm\x01\x00\x00\x00 a component this test never runs"
      upload = upload!(context, bytes)

      assert {:ok, receipt} = sign(context, upload)

      assert receipt.name == "greeter"
      assert is_integer(receipt.epoch) and receipt.epoch > 0
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
               sign(context, upload, eval: nil)

      assert {:ok, decisions} = Service.decisions(context.service)
      assert List.last(decisions).decision == :refused

      # And a manifest the policy cannot admit for any other reason is refused the same
      # way: an import outside the world's one.
      upload = upload!(context, "\0asm\x01\x00\x00\x00 component")

      assert {:error, {:signing_refused, {:import_not_in_world, "socket"}}} =
               sign(context, upload, imports: ["socket"])
    end

    test "the start id is derived from the name and is not a field a caller may name",
         context do
      upload = upload!(context, "\0asm\x01\x00\x00\x00 component")

      assert {:ok, receipt} = sign(context, upload, name: "vet")
      assert receipt.start_id == "wasm/vet"

      prefix = Base.decode64!(receipt.bundle_prefix)
      {:ok, %{artifact: artifact}} = Bundle.decode(prefix <> "\0asm\x01\x00\x00\x00 component")
      assert artifact.metadata.start == %{id: "wasm/vet", config: "{}"}
    end

    # H2. The epoch was an optional client parameter with no ceiling, and the register
    # admits an epoch only *above* its watermark while refusing one at its plausibility
    # ceiling — so one deploy at the ceiling left no number that was both, on every lane-W
    # capability on that node, durably. There is no parameter now: it is allocated.
    test "the epoch is allocated, not named, and rises with each manifest", context do
      first = upload!(context, "\0asm\x01\x00\x00\x00 component one")
      second = upload!(context, "\0asm\x01\x00\x00\x00 component two")

      assert {:ok, one} = sign(context, first)
      assert {:ok, two} = sign(context, second)

      assert is_integer(one.epoch) and one.epoch > 0
      assert two.epoch > one.epoch

      # And no spelling of it reaches the manifest from the caller.
      assert {:error, {:invalid_sign_request, {:imports, "nil"}}} =
               Deploy.sign(%{upload: first, name: "g", author: "a", epoch: 9}, [])
    end

    # M4. Every other check the signer makes is about numbers computed *from* the bytes, so
    # without this one a signature over a text file is perfectly well formed.
    test "bytes that are not a WebAssembly binary at all are refused before signing",
         context do
      # No magic at all.
      for not_wasm <- ["just some text", "{\"json\": true}", "\x7fELF\x02\x01\x01\x00"] do
        assert {:error, {:not_a_wasm_binary, :magic}} = sign(context, upload!(context, not_wasm))
      end

      # The magic, and then a version word no WebAssembly binary carries. This is the other
      # half of the check and the half a mutation of the preamble list reaches.
      for wrong <- ["\0asmZZZZ rest", "\0asm\x02\x00\x00\x00 rest", "\0asm\x0d\x00\x02\x00 x"] do
        assert {:error, {:not_a_wasm_binary, :preamble, _hex}} =
                 sign(context, upload!(context, wrong))
      end

      # And a file that is only the magic is not one either.
      assert {:error, {:not_a_wasm_binary, :magic}} = sign(context, upload!(context, "\0asm"))

      # A core module's preamble is accepted here and refused by the helper against the
      # world, which is where a linker contract belongs (D5).
      assert {:ok, _receipt} =
               sign(context, upload!(context, "\0asm\x01\x00\x00\x00 core module"))

      assert {:ok, _receipt} =
               sign(context, upload!(context, "\0asm\x0d\x00\x01\x00 component"))
    end

    # H3. The node never parses unsigned bytes. `imports` is the client's to compute, with
    # the *operator's* helper, and a wrong list is refused at stage by the cross-check.
    test "a sign request with no import list is refused rather than resolved", context do
      upload = upload!(context, "\0asm\x01\x00\x00\x00 component")

      assert {:error, {:invalid_sign_request, {:imports, "nil"}}} =
               Deploy.sign(
                 %{upload: upload, name: "greeter", author: "a", eval: @eval},
                 signing_service: context.service,
                 upload_root: context.uploads
               )
    end

    # The reviewer's F5, kept: `Ouroboros.Wasm.Pool` is not on this path at all any more, so
    # a pool handed to `sign/2` is never spoken to. Delete the `imports` requirement and
    # restore a derivation and this goes red on the first inspect.
    test "unsigned uploaded bytes never reach the helper", context do
      parent = self()

      pool =
        spawn(fn ->
          receive do
            {:"$gen_call", from, {:request, "inspect", %{"path" => path}, _d, _o, _l}} ->
              send(parent, {:helper_saw, path})
              GenServer.reply(from, {:error, :not_a_component})
              Process.sleep(:infinity)
          end
        end)

      on_exit(fn -> if Process.alive?(pool), do: Process.exit(pool, :kill) end)

      upload = upload!(context, "\0asm\x01\x00\x00\x00 " <> :crypto.strong_rand_bytes(4096))

      _result = sign(context, upload, pool: pool)

      refute_receive {:helper_saw, _path},
                     1_000,
                     "the helper was handed a path to bytes nobody has signed, at " <>
                       ":operate scope, before the signing policy ran"
    end

    # M20. The id is derived from the name inside this module, so a caller that reaches
    # `Deploy.sign/2` directly — which the gateway does not let anybody do, but a future
    # in-VM caller would — still cannot name a durable id for a component it does not
    # describe. Read the id out of `attrs` instead of deriving it and this goes red.
    test "a caller cannot smuggle a durable id past the name it derives from", context do
      upload = upload!(context, "\0asm\x01\x00\x00\x00 component")

      assert {:ok, receipt} =
               Deploy.sign(
                 %{
                   upload: upload,
                   name: "vet",
                   author: "test-agent",
                   imports: [],
                   start_config: "{}",
                   start_id: "wasm/greeter",
                   start: %{id: "wasm/greeter", config: "{}"},
                   eval: @eval
                 },
                 signing_service: context.service,
                 upload_root: context.uploads
               )

      assert receipt.start_id == "wasm/vet"

      prefix = Base.decode64!(receipt.bundle_prefix)

      {:ok, %{artifact: artifact}} =
        Bundle.decode(prefix <> "\0asm\x01\x00\x00\x00 component")

      assert artifact.metadata.start == %{id: "wasm/vet", config: "{}"}
      refute Map.has_key?(artifact.metadata, :start_id)
    end

    test "an unknown or unfinished upload is refused before anything is built", context do
      {:ok, %{upload: half}} = Upload.append(nil, 0, "half", false, root: context.uploads)

      assert {:error, {:unknown_upload, _}} = sign(context, String.duplicate("0", 32))

      assert {:error, {:upload_incomplete, ^half}} = sign(context, half)
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
      {:ok, receipt} = sign(context, upload!(context, bytes))
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
      {:ok, receipt} = sign(context, upload!(context, bytes))
      bundle = Base.decode64!(receipt.bundle_prefix) <> bytes

      # The same bundle, read by a node whose policy names no signers at all. The policy is
      # the *reading* node's, always: a deployment never carries one.
      before = store_snapshot(context)

      assert {:error, {:untrusted_signer, @signer}} =
               deploy(context, upload!(context, bundle), trust_policy: [allow_unsigned: false])

      assert store_snapshot(context) == before
      assert Registry.list(context.registry) == []
    end

    # M3. The claim that used to sit on this module — "verify, then anything else, and that
    # is the whole of its safety" — was not what made it safe: `Rollout.deploy/4` verifies
    # before its own `:deploying` checkpoint, so deleting the redundant pre-flight left
    # every test green. The pre-flight is gone; this pins the invariant that was always the
    # real one, and it is stated in the terms an operator cares about — a bundle this node
    # refuses spends no epoch and leaves the durable record byte-identical.
    test "a bundle nobody trusts spends no epoch and leaves the register byte-identical",
         context do
      bytes = "\0asm\x01\x00\x00\x00 a component this test never runs"
      {:ok, receipt} = sign(context, upload!(context, bytes))
      bundle = Base.decode64!(receipt.bundle_prefix) <> bytes

      before_checkpoint = checkpoint(context)
      before_watermark = Registry.wasm_epoch(context.registry)

      assert {:error, {:untrusted_signer, @signer}} =
               deploy(context, upload!(context, bundle), trust_policy: [allow_unsigned: false])

      assert Registry.list(context.registry) == []
      assert Registry.wasm_epoch(context.registry) == before_watermark
      assert checkpoint(context) == before_checkpoint
    end

    # M34. `rollout_opts/1` is an allow-list, and this is what it is for: `:epoch_registry`
    # is a seam `Ouroboros.Wasm.Rollout` reads to point a *target's* epoch admission at a
    # different register, and a caller of this module must not be able to reach it. Replace
    # the `Keyword.take/2` with `opts` and the stage below fails on a watermark this
    # deployment never had anything to do with.
    test "a caller's own options do not reach the rollout", context do
      other = start_registry!()

      :ok =
        Registry.admit_wasm_epoch(
          %{
            artifact_id: "someone-else",
            epoch: 90_000_000,
            component_sha256: String.duplicate("f", 64)
          },
          other
        )

      bytes = "\0asm\x01\x00\x00\x00 a component this test never runs"
      {:ok, receipt} = sign(context, upload!(context, bytes))
      bundle = Base.decode64!(receipt.bundle_prefix) <> bytes

      assert {:ok, outcome} =
               deploy(context, upload!(context, bundle), epoch_registry: other)

      # It did not settle live — there is no helper here — but it failed on staging the
      # component, never on an epoch belonging to a register nobody named.
      stage = outcome.deployment[Atom.to_string(node())].stage
      assert stage.outcome == :error

      refute stage.detail =~ "stale_epoch",
             "an option this module holds for its own use was forwarded to the rollout"

      assert {:ok, entry} = Registry.get(receipt.artifact_id, context.registry)
      assert entry.state in [:rolled_back, :quarantined]
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

      # 1. Sign. The imports are the *client's* to declare — this node does not parse
      #    unsigned bytes (D15) — and a wrong list is refused at stage by the cross-check.
      assert {:ok, receipt} =
               sign(context, upload!(context, bytes),
                 name: name,
                 imports: ["log"],
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

  # ---------------------------------------------------------------------------------------
  # W19 — the artifact comes back in the frames the upload used
  # ---------------------------------------------------------------------------------------

  describe "an artifact too large for one reply, end to end over the verbs" do
    @tag @needs_live
    test "sign names a download, the chunks reassemble, and the bundle deploys precompiled",
         context do
      pool = live_pool!()
      name = "download-test-#{System.unique_integer([:positive])}"
      id = "wasm/" <> name
      on_exit(fn -> Mesh.stop_agent(id) end)

      bytes = File.read!(@guest)

      # The whole point of the configuration: the reference guest's artifact is about 258 KiB,
      # and three quarters of a 64 KiB frame is 49 152, so this node cannot put the artifact in
      # the reply it answers `wasm.sign` with. Before W19 that signed the source form alone and
      # said so; now it mints a slot.
      previous_gateway = Application.get_env(:ouroboros, :gateway)

      Application.put_env(
        :ouroboros,
        :gateway,
        Keyword.put(previous_gateway || [], :max_frame, 64 * 1024)
      )

      on_exit(fn -> restore(:gateway, previous_gateway) end)

      # `Gateway.Methods` routes to this node with no options at all, so the upload area, the
      # download area and the signing service all have to be the real, configured ones.
      previous_data_dir = Application.get_env(:ouroboros, :data_dir)
      Application.put_env(:ouroboros, :data_dir, context.tmp)
      on_exit(fn -> restore(:data_dir, previous_data_dir) end)

      previous_signing_node = Application.get_env(:ouroboros, :signing_node)
      Application.delete_env(:ouroboros, :signing_node)
      on_exit(fn -> restore(:signing_node, previous_signing_node) end)

      key_path = Path.join(context.tmp, "gateway-signer.key")
      File.write!(key_path, :crypto.strong_rand_bytes(32))
      File.chmod!(key_path, 0o600)

      start_supervised!(
        {Service,
         [
           name: Service,
           key_path: key_path,
           signer_id: @signer <> "-gateway",
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("w19_journal_#{System.unique_integer([:positive])}")}
         ]}
      )

      {:ok, %{public_key: public}} = Service.public_info(Service)

      trust_policy = [
        allow_unsigned: false,
        trusted_signers: %{(@signer <> "-gateway") => public}
      ]

      Application.put_env(:ouroboros, :upgrade_trust_policy, trust_policy)

      assert Deploy.max_receipt_precompiled_bytes() == 49_152

      # 1. Up in frames, as always.
      upload = gateway_upload!(bytes)

      # 2. Signed. The artifact was compiled and signed — `form` is `precompiled` and nothing
      #    was skipped — and it is named as a download rather than carried.
      assert {:ok, receipt} =
               Methods.invoke("wasm.sign", %{
                 "upload" => upload,
                 "name" => name,
                 "author" => "test-agent",
                 "imports" => ["log"],
                 "start_config" => "{}",
                 "eval" => %{
                   "probes" => [
                     %{
                       "input" => %{"greet" => "world"},
                       "expect" => %{"kind" => "contains", "substring" => "greet"}
                     }
                   ],
                   "budget_ms" => 10_000
                 }
               })

      assert receipt.form == :precompiled
      assert receipt.precompile_skipped == nil
      assert receipt.precompiled != nil

      assert %{download: download, size: size, sha256: sha256, chunk_bytes: chunk_bytes} =
               receipt.artifact

      assert download =~ ~r/\A[0-9a-f]{32}\z/
      assert size > Deploy.max_receipt_precompiled_bytes()
      # The digest a client checks against is the one in the signed manifest, not a second
      # number this node computed for the transfer.
      assert sha256 == receipt.precompiled.sha256
      assert size == receipt.precompiled.size
      assert chunk_bytes == Upload.max_chunk_bytes()

      # 3. Back in frames, walked from the offsets the answers give.
      artifact = gateway_download!(download)

      assert byte_size(artifact) == size
      assert Artifact.digest(artifact) == sha256
      # The container `ouro-wasm precompile` writes, arriving whole through the gateway.
      assert <<"OUROCWASM", 1::8, _rest::binary>> = artifact

      # The slot is gone: the final chunk released it, and a client that lost that answer
      # signs again rather than asking twice (D28).
      assert {:error, code, _message} =
               Methods.invoke("wasm.download", %{"download" => download, "offset" => 0})

      assert code == Methods.code(:not_found)

      # 4. The file: what the node produced, then what this side already held. The prefix is
      #    the header and the envelope alone this time.
      prefix = Base.decode64!(receipt.bundle_prefix)
      bundle = prefix <> artifact <> bytes

      assert byte_size(bundle) == receipt.bundle_bytes
      assert {:ok, decoded} = Bundle.verify(bundle, trust_policy)
      assert decoded.bytes == bytes
      assert decoded.precompiled == artifact
      assert decoded.artifact.precompiled == receipt.precompiled

      # And it is byte for byte the file `Bundle.encode/3` would have written. This is the
      # claim the split prefix has to keep: `prefix_without_artifact/2` plus the two sections
      # is the encoder's own output, so a client that concatenates has composed nothing.
      assert {:ok, ^bundle} = Bundle.encode(decoded.artifact, bytes, artifact)

      # 5. The helper's own word on which form it loaded. `Rollout.stage/3` reports what
      #    `load` answered, so this is the artifact being *mapped* rather than a path being
      #    guessed at — the assertion is on the helper, not on the store.
      assert {:ok, evidence} =
               Rollout.stage(decoded.artifact, bytes,
                 pool: pool,
                 store_root: Path.join(context.tmp, "stage-store"),
                 # A register of this step's own: staging advances a watermark, and the
                 # deploy below has to be able to spend the epoch this signature was minted
                 # with rather than find it already called stale by a check.
                 epoch_registry: start_registry!(),
                 precompiled: artifact
               )

      assert evidence.precompiled == true

      # 6. And the whole verb path: this bundle deploys, live, and the capability answers.
      #    The trust policy is the one that trusts the service this test registered under the
      #    module's own name, because a target reads its own and is never told which to use.
      assert {:ok, outcome} =
               deploy(context, upload!(context, bundle), pool: pool, trust_policy: trust_policy)

      assert outcome.state == :live
      assert outcome.name == name
      assert is_pid(Mesh.whereis(id))
      assert {:ok, _agent} = Mesh.send_message("w19", id, %{"greet" => "world"})
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
      assert Process.alive?(pid)

      # M5. `:unchanged` is proof on the *compensation* path — this rollout started nothing
      # and the process is somebody else's — and it is proof of nothing here. An operator
      # told `rolled_back` while a process still answers under `wasm/<name>` has been told
      # the capability is gone when its name is not. Change `@withdrawn` back to include
      # `:unchanged` and this goes red.
      assert outcome.state == :quarantined
      assert {:ok, entry} = Registry.get(outcome.artifact_id, context.registry)
      assert entry.state == :quarantined
    end

    # M6/M29. The old version of this seeded a lane-B entry whose *module* was an atom, so
    # `Registry.history/2`'s name match already excluded it and `lane_w?/1` was never
    # reached — deleting the filter left the test green. This one seeds an entry the module
    # match *does* find: the module is literally `"wasm/<name>"`, and the only thing that
    # makes it lane B is the absence of a component sha, which is exactly what `lane_w?/1`
    # reads. Delete `lane_w?(&1)` from `live_entry/2` and this goes red.
    test "an entry under a lane-W name with no component is still not a lane-W rollout",
         context do
      name = "impostor-#{System.unique_integer([:positive])}"
      id = "beam-#{System.unique_integer([:positive])}"

      {:ok, _entry} =
        Registry.deploying(
          %{
            artifact_id: id,
            module: "wasm/" <> name,
            epoch: 9_100 + System.unique_integer([:positive]),
            nodes: [node()]
          },
          context.registry
        )

      {:ok, entry} = Registry.mark(id, :live, [], context.registry)

      # The register found it by name, and it is live.
      assert entry.state == :live
      assert entry.component_sha256 == nil

      assert Enum.any?(
               Registry.history("wasm/" <> name, context.registry),
               &(&1.artifact_id == id)
             )

      # And rollback still will not touch it, because a rollout with no component bytes is
      # not a rollout this lane deployed.
      assert {:error, {:no_live_rollout, ^name}} =
               Deploy.rollback(name, registry: context.registry)
    end
  end

  ## Helpers

  defp sign(context, upload, attrs \\ []) do
    attrs = Map.new(attrs)
    {opts, attrs} = Map.split(attrs, [:pool, :epoch_nodes])

    base = %{
      upload: upload,
      name: "greeter",
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

    Deploy.sign(
      attrs,
      [signing_service: context.service, upload_root: context.uploads] ++ Map.to_list(opts)
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

  # W19. An upload through the verb rather than through the module, in the frames a client
  # would use, because the end-to-end case is about what crosses the wire.
  defp gateway_upload!(bytes) do
    chunk = Upload.max_chunk_bytes()

    {id, _offset} =
      bytes
      |> chunks(chunk)
      |> Enum.reduce({nil, 0}, fn slice, {id, offset} ->
        params =
          %{"offset" => offset, "data" => Base.encode64(slice)}
          |> then(&if id, do: Map.put(&1, "upload", id), else: &1)
          |> then(
            &if offset + byte_size(slice) >= byte_size(bytes),
              do: Map.put(&1, "final", true),
              else: &1
          )

        {:ok, receipt} = Methods.invoke("wasm.upload", params)
        {receipt.upload, offset + byte_size(slice)}
      end)

    id
  end

  # And the artifact back out of the slot the signature named, walked exactly as
  # `ouro wasm sign` walks it: sequentially, from the offsets the node's own answers give,
  # until one of them says it was the last.
  defp gateway_download!(download) do
    Enum.reduce_while(Stream.iterate(0, & &1), <<>>, fn _step, acc ->
      {:ok, chunk} =
        Methods.invoke("wasm.download", %{"download" => download, "offset" => byte_size(acc)})

      assert chunk.offset == byte_size(acc)
      assert chunk.download == download

      acc = acc <> Base.decode64!(chunk.data)

      if chunk.final, do: {:halt, acc}, else: {:cont, acc}
    end)
  end

  defp chunks(bytes, size) do
    Stream.unfold(0, fn
      offset when offset >= byte_size(bytes) ->
        nil

      offset ->
        length = min(size, byte_size(bytes) - offset)
        {binary_part(bytes, offset, length), offset + length}
    end)
    |> Enum.to_list()
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
        "bundle" => 2,
        "manifest" => Base.encode64(:erlang.term_to_binary(Artifact.manifest(artifact))),
        "signer" => "nobody",
        "signature" => Base.encode64(:binary.copy("\0", 64))
      })

    "OUROWASM" <>
      <<2::8, byte_size(envelope)::32, 0::32, byte_size(bytes)::32>> <> envelope <> bytes
  end

  # The rollout register's durable record, exactly as it sits in storage. Compared before
  # and after a refusal, because "spent no epoch and wrote nothing" is a claim about the
  # bytes on the other side of the checkpoint rather than about what a listing renders.
  defp checkpoint(context) do
    Jido.Storage.ETS.get_checkpoint(
      Ouroboros.Upgrade.Rollout.Registry.checkpoint_key(),
      table: context.registry_table
    )
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

  defp start_registry!(
         table \\ String.to_atom("wasm_deploy_rollouts_#{System.unique_integer([:positive])}")
       ) do
    name = String.to_atom("wasm_deploy_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} = Registry.start_link(name: name, storage: {Jido.Storage.ETS, table: table})

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
