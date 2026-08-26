defmodule Ouroboros.Upgrade.SigningServiceTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Storage.DurableFile
  alias Ouroboros.Upgrade.Forge
  alias Ouroboros.Upgrade.Forge.{Signer, Source}
  alias Ouroboros.Upgrade.Signing.{Journal, Policy, Service}
  alias Ouroboros.Upgrade.{Artifact, Beam, Verifier}

  @capability Ouroboros.Capability.SignedByService
  @outsider Ouroboros.SigningOutsiderCapability
  @forged Ouroboros.Capability.ForgedByRemoteSigner
  @signer_id "release-key"
  @absent :"ouroboros-absent-signer@127.0.0.1"

  setup do
    on_exit(fn -> Enum.each([@capability, @outsider, @forged], &unload/1) end)
    :ok
  end

  describe "key custody" do
    test "a signer with no key, an unreadable key, or a garbage key refuses to start" do
      # Every one of these is a boot refusal, not a per-request error. A signer that
      # starts anyway and denies looks exactly like a signer that is deliberately
      # denying, and those two need very different operator responses.
      assert_raise ArgumentError, ~r/OUROBOROS_SIGNER_KEY_PATH/, fn ->
        Service.load_key!(signer_id: @signer_id)
      end

      assert_raise ArgumentError, ~r/could not be read/, fn ->
        Service.load_key!(key_path: Path.join(tmp_dir!(), "absent.key"), signer_id: @signer_id)
      end

      garbage = write_key!("this is not a seed, it is a sentence about seeds")

      assert_raise ArgumentError, ~r/does not hold an Ed25519 seed/, fn ->
        Service.load_key!(key_path: garbage, signer_id: @signer_id)
      end

      short = write_key!(:binary.copy(<<7>>, 31))

      assert_raise ArgumentError, ~r/does not hold an Ed25519 seed/, fn ->
        Service.load_key!(key_path: short, signer_id: @signer_id)
      end

      # A key with no identity to sign under is the same class of refusal: the id is
      # what a core node trusts a public key by, so it cannot be defaulted.
      assert_raise ArgumentError, ~r/signer_id/, fn ->
        Service.load_key!(key_path: write_key!(seed()), signer_id: nil)
      end

      # And the GenServer inherits all of it rather than starting into a bad state.
      Process.flag(:trap_exit, true)

      assert {:error, {%ArgumentError{message: message}, _stacktrace}} =
               Service.start_link(name: nil, key_path: garbage, signer_id: @signer_id)

      assert message =~ "Ed25519 seed"
    end

    test "the key is derived correctly, redacts itself, and never leaves the process" do
      # A recognizable seed, so a leak would be unmistakable in any rendering.
      seed = :binary.copy(<<0xAB>>, 32)
      {expected_public, ^seed} = :crypto.generate_key(:eddsa, :ed25519, seed)

      service = start_service!(seed: seed)

      assert {:ok, info} = Service.public_info(service)
      assert info.signer_id == @signer_id
      assert byte_size(info.public_key) == 32
      assert info.public_key == expected_public
      assert info.public_key_base64 == Base.encode64(expected_public)
      assert info.trusted_signers_entry == "#{@signer_id}:#{Base.encode64(expected_public)}"

      # Nothing that answers a question hands back the private half.
      refute info.public_key == seed
      refute Enum.any?(Map.values(info), &(&1 == seed))

      rendered = inspect(:sys.get_state(service), limit: :infinity, printable_limit: :infinity)

      assert rendered =~ "REDACTED"
      refute rendered =~ "171, 171"
      refute rendered =~ Base.encode64(seed)
      refute String.contains?(rendered, inspect(seed, limit: :infinity))

      # The same is true of the surface an operator reads.
      assert {:ok, status} = Service.status(service)
      refute Enum.any?(Map.values(status), &(&1 == seed))
      assert status.signer_id == @signer_id
      assert status.durability == :ephemeral_checkpoint
    end

    test "a seed is accepted raw or base64, and both derive the same identity" do
      seed = seed()
      raw = start_service!(key_path: write_key!(seed))
      encoded = start_service!(key_path: write_key!(Base.encode64(seed) <> "\n"))

      assert {:ok, %{public_key: key}} = Service.public_info(raw)
      assert {:ok, %{public_key: ^key}} = Service.public_info(encoded)
    end
  end

  describe "policy" do
    test "a signature the service issues is one the verifier accepts" do
      service = start_service!()
      artifact = artifact!()

      assert {:ok, signature} = sign(service, artifact)
      assert byte_size(signature) == 64

      assert {:ok, %{public_key: public_key}} = Service.public_info(service)
      signed = %{artifact | signature: %{signer: @signer_id, value: signature}}

      assert :ok = Verifier.verify(signed, trusted_signers: %{@signer_id => public_key})

      # The signature is over the service's own derivation of the payload, which is the
      # same canonical bytes the verifier reconstructs. Nothing about the artifact may
      # move afterwards.
      assert {:error, {:invalid_signature, @signer_id}} =
               Verifier.verify(%{signed | epoch: signed.epoch + 1},
                 trusted_signers: %{@signer_id => public_key}
               )
    end

    test "a module outside the capability namespace is structurally unsignable" do
      service = start_service!()

      assert {:refused, {:module_outside_capability_namespace, @outsider}} =
               sign(service, outsider_artifact!())

      # Not a configuration this deployment happens to have: there is no policy option,
      # signer id, or requester that produces a signature for a control-plane module.
      relaxed = start_service!(require_eval: false, rate_limit_per_minute: 1_000)

      assert {:refused, {:module_outside_capability_namespace, @outsider}} =
               sign(relaxed, outsider_artifact!(), signer_id: @signer_id)
    end

    test "the signer recomputes the manifest and refuses anything it cannot reproduce" do
      service = start_service!()
      artifact = artifact!()
      [beam] = artifact.modules

      # A requester that precomputed a flattering hash is refused on arithmetic.
      rewritten = %{artifact | modules: [%{beam | sha256: Beam.sha256("something else")}]}

      assert {:refused, {:manifest_mismatch, @capability, :sha256, :new}} =
               sign(service, rewritten)

      assert {:refused, {:manifest_mismatch, @capability, :md5, :new}} =
               sign(service, %{artifact | modules: [%{beam | md5: :crypto.hash(:md5, "no")}]})

      assert {:refused, {:manifest_mismatch, @capability, :vsn, :new}} =
               sign(service, %{artifact | modules: [%{beam | vsn: 99}]})

      # And a byte flipped in the bytes themselves, after the artifact was built, cannot
      # survive the recomputation either — whether it breaks the hash or the BEAM.
      tampered = %{artifact | modules: [%{beam | binary: flip_byte(beam.binary)}]}

      assert {:refused, reason} = sign(service, tampered)
      assert elem(reason, 0) in [:manifest_mismatch, :invalid_beam, :module_mismatch]

      # An `:introduce` that smuggles in rollback material is not an introduction.
      assert {:refused, {:invalid_introduction, @capability}} =
               sign(service, %{artifact | modules: [%{beam | old_sha256: beam.sha256}]})

      # An epoch is only checked for sanity here; ordering belongs to the target.
      assert {:refused, {:invalid_epoch, "0"}} = sign(service, %{artifact | epoch: 0})
      assert {:refused, :empty_artifact} = sign(service, %{artifact | modules: []})
    end

    test "provenance is required, and a red build is not provenance" do
      service = start_service!()

      assert {:refused, {:provenance_missing, :forge}} =
               sign(service, artifact!(metadata: %{}))

      assert {:refused, {:provenance_missing, :source_sha256}} =
               sign(service, artifact!(metadata: %{forge: %{test_report: report()}}))

      assert {:refused, {:provenance_missing, :test_report}} =
               sign(service, artifact!(metadata: %{forge: %{source_sha256: source_sha256()}}))

      assert {:refused, {:tests_failed, 1, 2}} =
               sign(service, artifact!(metadata: forge_metadata(report(total: 2, failures: 1))))

      # Nothing ran, so nothing passed. A capability whose tests were never executed has
      # no provenance for a signer to rely on.
      assert {:refused, {:no_tests_passed, 0, 0}} =
               sign(service, artifact!(metadata: forge_metadata(report(total: 0))))

      # Green only because everything was skipped is the same refusal.
      assert {:refused, {:no_tests_passed, 3, 0}} =
               sign(service, artifact!(metadata: forge_metadata(report(total: 3, skipped: 3))))

      assert {:refused, {:invalid_provenance, :source_sha256, _}} =
               sign(service, artifact!(metadata: forge_metadata(report(), "not-a-digest")))
    end

    test "require_eval makes a declared evaluation spec a precondition of a signature" do
      relaxed = start_service!()
      strict = start_service!(require_eval: true)

      without = artifact!()
      with_spec = artifact!(metadata: forge_metadata(report(), source_sha256(), eval_spec()))

      # Off by default: exactly the behaviour that existed before this service.
      assert {:ok, _signature} = sign(relaxed, without)
      assert {:ok, _signature} = sign(relaxed, with_spec)

      assert {:refused, :eval_spec_required} = sign(strict, without)
      assert {:ok, signature} = sign(strict, with_spec)
      assert byte_size(signature) == 64

      # A spec that could never run is refused whether or not one was required, because
      # a signature over unrunnable criteria is worse than one over none.
      broken = artifact!(metadata: forge_metadata(report(), source_sha256(), %{probes: []}))

      assert {:refused, {:invalid_eval_spec, :probes_required}} =
               sign(strict, broken)

      assert {:refused, {:invalid_eval_spec, :probes_required}} =
               sign(relaxed, broken)
    end

    test "the requested identity and the advisory payload are both cross-checked" do
      service = start_service!()
      artifact = artifact!()

      assert {:refused, {:unknown_signer_id, "somebody-else"}} =
               sign(service, artifact, signer_id: "somebody-else")

      # The payload is advisory: the service signs what it derives. A disagreement is
      # version skew between a core node and its signer, and skew stops the deployment.
      assert {:refused, {:payload_mismatch, expected, given}} =
               sign(service, artifact, request: %{requester: node(), payload: "not the payload"})

      assert byte_size(expected) == 64
      assert expected != given

      # And the payload the requester would honestly derive is accepted.
      assert {:ok, _signature} =
               sign(service, artifact,
                 request: %{
                   requester: node(),
                   payload: Artifact.signing_payload(artifact, @signer_id)
                 }
               )

      assert {:refused, {:invalid_signing_request, :requester_required}} =
               sign(service, artifact, request: %{})

      assert {:refused, {:invalid_artifact, _}} = sign(service, :not_an_artifact)
    end

    test "the policy is a pure function of the artifact and refuses rather than raising" do
      context = %{signer_id: @signer_id, requester: node(), require_eval: false}

      assert {:ok, findings} = Policy.Default.evaluate(artifact!(), context)
      assert findings.namespace == :ouroboros_capability
      assert findings.recomputed == 1
      assert [%{module: @capability, disposition: :introduce}] = findings.modules

      assert findings.provenance.tests == %{
               total: 1,
               failures: 0,
               excluded: 0,
               skipped: 0,
               passed: 1
             }

      assert findings.eval == :absent

      assert {:refused, {:invalid_artifact, _}} = Policy.Default.evaluate(%{}, context)
      assert Policy.configured() == Policy.Default
    end
  end

  describe "the decision journal" do
    test "every decision is recorded, issued and refused alike" do
      service = start_service!()
      artifact = artifact!()

      assert {:ok, _signature} = sign(service, artifact)
      assert {:refused, _reason} = sign(service, outsider_artifact!())

      assert {:ok, [issued, refused]} = Service.decisions(service)

      assert issued.decision == :issued
      assert issued.sequence == 1
      assert issued.artifact_id == artifact.id
      assert issued.epoch == artifact.epoch
      assert issued.requester == node()
      assert issued.signer_id == @signer_id
      assert issued.reason == nil
      assert [%{module: @capability, disposition: :introduce}] = issued.modules
      assert issued.findings.provenance.source_sha256 == source_sha256()
      assert is_binary(issued.at)

      assert refused.decision == :refused
      assert refused.sequence == 2
      assert refused.reason == {:module_outside_capability_namespace, @outsider}
      assert [%{module: @outsider}] = refused.modules

      # A refusal is a decision, so it counts.
      assert {:ok, status} = Service.status(service)
      assert status.decisions == %{issued: 1, refused: 1}
    end

    test "a signature is never returned before its entry is durably acknowledged" do
      directory = tmp_dir!()
      caller = self()

      # The rename is the moment the checkpoint becomes the checkpoint. Observing it from
      # the caller's mailbox *after* the reply arrives proves the write preceded the
      # signature rather than racing it.
      observing = fn event ->
        if event == :before_rename, do: send(caller, {:journal_write, event})
        :ok
      end

      service =
        start_service!(storage: {DurableFile, path: directory, durability_hook: observing})

      assert {:ok, signature} = sign(service, artifact!())
      assert byte_size(signature) == 64
      assert_received {:journal_write, :before_rename}

      # And the entry is on disk, readable by anything that can read the adapter.
      assert {:ok, wire} =
               DurableFile.get_checkpoint(Service.checkpoint_key(), path: directory)

      assert [%{decision: :issued}] = Journal.from_wire(wire).decisions
    end

    test "a journal that will not accept the entry is a refusal to sign" do
      directory = tmp_dir!()

      service =
        start_service!(
          storage: {
            DurableFile,
            path: directory, durability_hook: fn _event -> {:error, :induced_disk_failure} end
          }
        )

      assert {:refused, {:journal_unavailable, :induced_disk_failure}} =
               sign(service, artifact!())

      # No signature was produced, no entry was kept in memory, and nothing reached disk.
      # A signer that cannot record what it approved does not approve anything.
      assert {:ok, []} = Service.decisions(service)
      assert :not_found = DurableFile.get_checkpoint(Service.checkpoint_key(), path: directory)

      # The refusal is not sticky: it describes the journal, and it clears with it.
      recovered = start_service!(storage: {DurableFile, path: directory})
      assert {:ok, _signature} = sign(recovered, artifact!())
    end

    test "history is bounded and keeps the most recent decisions" do
      service = start_service!(journal_limit: 3, rate_limit_per_minute: 100)

      for _each <- 1..5, do: assert({:ok, _signature} = sign(service, artifact!()))

      assert {:ok, decisions} = Service.decisions(service)
      assert length(decisions) == 3
      assert Enum.map(decisions, & &1.sequence) == [3, 4, 5]
    end
  end

  describe "admission" do
    test "a requester beyond its rate limit is refused, and refusals count too" do
      service = start_service!(rate_limit_per_minute: 2)

      assert {:ok, _signature} = sign(service, artifact!())

      assert {:refused, {:module_outside_capability_namespace, _}} =
               sign(service, outsider_artifact!())

      assert {:refused, {:rate_limited, requester, 2, 2}} = sign(service, artifact!())
      assert requester == node()

      # A different requester has its own window. The requester is self-reported, which
      # is exactly why this bounds accidents rather than adversaries.
      assert {:ok, _signature} =
               sign(service, artifact!(), request: %{requester: :"other@127.0.0.1"})

      assert {:ok, status} = Service.status(service)
      assert status.tracked_requesters == 2
      assert status.rate_limit_per_minute == 2
    end

    test "an artifact larger than the configured bound is refused before it is read" do
      service = start_service!(max_artifact_bytes: 128)

      assert {:refused, {:artifact_too_large, bytes, 128}} = sign(service, artifact!())
      assert bytes > 128
    end

    test "a service that is not running is a refusal, never a raise" do
      assert {:refused, {:signing_service_unavailable, _reason}} =
               Service.sign_artifact(artifact!(), @signer_id, %{requester: node()}, :no_such_name)

      assert {:error, {:signing_service_unavailable, _reason}} =
               Service.public_info(:no_such_name)

      assert {:refused, {:invalid_signing_request, _}} =
               Service.sign_artifact(artifact!(), "", %{requester: node()})
    end
  end

  describe "the remote signer client" do
    test "a target that is not a :signer node is a typed refusal, not a submission" do
      artifact = artifact!()

      # This node is `:core`. Being connected, running, and reachable is not enough.
      assert {:error, {:remote_signer_refused, target, {:role, :core, :signer}}} =
               Signer.Remote.sign_artifact(artifact, @signer_id, node: node())

      assert target == node()

      assert {:error, {:remote_signer_refused, @absent, :node_not_connected}} =
               Signer.Remote.sign_artifact(artifact, @signer_id, node: @absent)

      assert {:error, {:remote_signer_unconfigured, :node}} =
               Signer.Remote.sign_artifact(artifact, @signer_id, [])

      assert {:error, {:invalid_signer_node, "signer@host"}} =
               Signer.Remote.sign_artifact(artifact, @signer_id, node: "signer@host")

      assert {:error, :invalid_signing_request} =
               Signer.Remote.sign_artifact(artifact, "", node: node())
    end

    test "the forge prefers a whole-artifact signer and leaves the others untouched" do
      assert Signer.artifact_signer?(Signer.Remote)
      refute Signer.artifact_signer?(Signer.Deny)
      refute Signer.artifact_signer?(Signer.Local)
      refute Signer.artifact_signer?(:not_a_module)

      # `Remote` cannot answer the payload-only callback at all: a signer whose whole
      # purpose is inspecting the artifact must not silently sign a hash of one.
      assert Signer.Remote.sign("payload", @signer_id) ==
               {:error, :remote_signer_requires_artifact}

      # And the shipped signers are exactly what they were.
      assert Signer.Deny.sign("payload", @signer_id) == {:error, :signing_denied}
      assert Signer.Local.sign("payload", @signer_id) == {:error, :private_key_not_configured}
    end

    test "a configured remote signer is what the forge asks, and its refusal is the forge's" do
      previous = Application.get_env(:ouroboros, :forge_signer)
      Application.put_env(:ouroboros, :forge_signer, {Signer.Remote, node: @absent})
      on_exit(fn -> restore(:forge_signer, previous) end)

      assert {Signer.Remote, node: @absent} = Signer.configured()

      assert Signer.Remote.sign_artifact(artifact!(), @signer_id) ==
               {:error, {:remote_signer_refused, @absent, :node_not_connected}}
    end
  end

  describe "a signer node" do
    @tag timeout: 180_000
    test "boots the signing service, and nothing a core node owns" do
      signer = start_signer_peer!()

      assert :erpc.call(signer, Ouroboros.Cluster, :role, []) == :signer
      assert is_pid(:erpc.call(signer, Process, :whereis, [Service]))
      assert is_pid(:erpc.call(signer, Process, :whereis, [Ouroboros.Cluster]))

      for name <- [
            Ouroboros.Jido,
            Ouroboros.Agent.EffectLedger,
            Ouroboros.Mesh.Directory,
            Ouroboros.Coding.Store,
            Ouroboros.Team.Store,
            Ouroboros.Orchestration.Scheduler,
            Ouroboros.Control.Store,
            Ouroboros.Release.Runtime,
            Ouroboros.Upgrade.NodeExecutor,
            Ouroboros.Upgrade.Rollout.Registry
          ] do
        assert :erpc.call(signer, Process, :whereis, [name]) == nil,
               "#{inspect(name)} must not run on a :signer node"
      end

      # The public half is reachable, and is what an operator pastes into a core node's
      # trusted signers. The private half has no accessor to reach.
      assert {:ok, info} = :erpc.call(signer, Service, :public_info, [])
      assert info.node == signer
      assert info.signer_id == @signer_id
      assert byte_size(info.public_key) == 32
      assert info.trusted_signers_entry == "#{@signer_id}:#{info.public_key_base64}"
    end

    @tag timeout: 180_000
    test "claims its durable journal directory before a second signer can open it" do
      data_dir = tmp_dir!()
      File.chmod!(data_dir, 0o700)
      key_path = write_key!(seed())
      storage = {DurableFile, path: Path.join(data_dir, "signing-journal")}
      first = start_bare_peer!()
      second = start_bare_peer!()

      for peer <- [first, second] do
        assert {:ok, _applications} =
                 :erpc.call(peer, Application, :ensure_all_started, [:mix])

        :ok = :erpc.call(peer, Mix, :env, [:test])
        put_peer_env!(peer, :node_role, :signer)
        put_peer_env!(peer, :signer_id, @signer_id)
        put_peer_env!(peer, :data_dir, data_dir)
        put_peer_env!(peer, :signing_journal_storage, storage)
        put_signer_key!(peer, key_path)
      end

      assert {:ok, _applications} =
               :erpc.call(first, Application, :ensure_all_started, [:ouroboros])

      assert is_pid(:erpc.call(first, Process, :whereis, [Ouroboros.RuntimeOwner]))
      assert is_pid(:erpc.call(first, Process, :whereis, [Service]))
      assert File.exists?(Ouroboros.RuntimeOwner.marker_path(data_dir))

      assert {:error, reason} =
               :erpc.call(second, Application, :ensure_all_started, [:ouroboros])

      assert inspect(reason) =~ "Ouroboros.RuntimeOwner"
      assert :erpc.call(second, Process, :whereis, [Service]) == nil
    end

    @tag timeout: 180_000
    test "with a missing or malformed key refuses to complete its boot" do
      for contents <- ["not a seed", :binary.copy(<<3>>, 31)] do
        peer = start_bare_peer!()
        put_peer_env!(peer, :node_role, :signer)
        put_peer_env!(peer, :signer_id, @signer_id)
        put_signer_key!(peer, write_key!(contents))

        assert {:error, _reason} =
                 :erpc.call(peer, Application, :ensure_all_started, [:ouroboros])

        assert :erpc.call(peer, Process, :whereis, [Ouroboros.Supervisor]) == nil
      end

      # A key path that names nothing is the same refusal.
      peer = start_bare_peer!()
      put_peer_env!(peer, :node_role, :signer)
      put_peer_env!(peer, :signer_id, @signer_id)
      put_signer_key!(peer, Path.join(tmp_dir!(), "never-written.key"))

      assert {:error, _reason} = :erpc.call(peer, Application, :ensure_all_started, [:ouroboros])
    end

    @tag timeout: 300_000
    test "signs a forged artifact this node then verifies with the signer's own public key" do
      signer = start_signer_peer!()
      assert {:ok, info} = :erpc.call(signer, Service, :public_info, [])

      configure_remote_signer!(signer)
      on_exit(fn -> unload(@forged) end)

      # A real forge: parse-only hygiene, an isolated build peer, an allocated epoch, and
      # then a signature this node cannot produce for itself.
      assert {:ok, signed} =
               Forge.forge(forge_source!(),
                 nodes: [node()],
                 signer_id: @signer_id,
                 storage: ets_storage()
               )

      assert signed.signature.signer == @signer_id
      assert byte_size(signed.signature.value) == 64

      # The key that signed it is the key the signer node published, and nothing about
      # the artifact moved between the two.
      assert :ok = Verifier.verify(signed, trusted_signers: %{@signer_id => info.public_key})

      assert {:error, {:invalid_signature, @signer_id}} =
               Verifier.verify(%{signed | epoch: signed.epoch + 1},
                 trusted_signers: %{@signer_id => info.public_key}
               )

      # And the signer node holds the record of having approved exactly this artifact.
      assert {:ok, decisions} = :erpc.call(signer, Service, :decisions, [])
      assert entry = Enum.find(decisions, &(&1.artifact_id == signed.id))
      assert entry.decision == :issued
      assert entry.requester == node()
      assert entry.signer_id == @signer_id
      assert [%{module: @forged, disposition: :introduce}] = entry.modules
    end

    @tag timeout: 180_000
    test "refuses a control-plane patch over the wire, whoever is asking" do
      signer = start_signer_peer!()

      assert {:error, {:signing_refused, {:module_outside_capability_namespace, @outsider}}} =
               Signer.Remote.sign_artifact(outsider_artifact!(), @signer_id, node: signer)

      assert {:error, {:signing_refused, {:unknown_signer_id, "not-this-signer"}}} =
               Signer.Remote.sign_artifact(artifact!(), "not-this-signer", node: signer)

      # A capability artifact from the same requester is signed, so the refusals above
      # are the policy speaking rather than the transport failing.
      assert {:ok, signature} = Signer.Remote.sign_artifact(artifact!(), @signer_id, node: signer)
      assert byte_size(signature) == 64

      assert {:ok, decisions} = :erpc.call(signer, Service, :decisions, [])
      assert Enum.map(decisions, & &1.decision) == [:refused, :refused, :issued]
      assert Enum.all?(decisions, &(&1.requester == node()))
    end
  end

  describe "production preflight" do
    setup do
      previous = System.get_env()
      data_dir = Path.join(tmp_dir!(), "data")

      managed = [
        "OUROBOROS_DATA_DIR",
        "OUROBOROS_NODE_ROLE",
        "OUROBOROS_CLUSTER_STRATEGY",
        "OUROBOROS_ALLOW_INSECURE_DIST",
        "OUROBOROS_UPGRADE_TRUSTED_SIGNERS",
        "OUROBOROS_SIGNER_KEY_PATH",
        "OUROBOROS_SIGNER_ID",
        "OUROBOROS_SIGNING_NODE",
        "OUROBOROS_SIGNING_REQUIRE_EVAL",
        "OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE",
        "OUROBOROS_SIGNING_CALL_TIMEOUT_MS"
      ]

      Enum.each(managed, &System.delete_env/1)
      System.put_env("OUROBOROS_DATA_DIR", data_dir)

      on_exit(fn ->
        Enum.each(managed, fn name ->
          case Map.fetch(previous, name) do
            {:ok, value} -> System.put_env(name, value)
            :error -> System.delete_env(name)
          end
        end)
      end)

      :ok
    end

    test "a signer role without a usable key or an identity refuses the boot" do
      System.put_env("OUROBOROS_NODE_ROLE", "signer")

      assert_raise RuntimeError, ~r/OUROBOROS_SIGNER_KEY_PATH/, fn -> prod_config() end

      System.put_env("OUROBOROS_SIGNER_KEY_PATH", "relative/signer.key")
      assert_raise RuntimeError, ~r/absolute path/, fn -> prod_config() end

      System.put_env("OUROBOROS_SIGNER_KEY_PATH", Path.join(tmp_dir!(), "absent.key"))
      assert_raise RuntimeError, ~r/not a readable file/, fn -> prod_config() end

      System.put_env("OUROBOROS_SIGNER_KEY_PATH", write_key!(seed()))
      assert_raise RuntimeError, ~r/OUROBOROS_SIGNER_ID/, fn -> prod_config() end

      System.put_env("OUROBOROS_SIGNER_ID", @signer_id)
      config = prod_config()[:ouroboros]
      assert config[:signer_id] == @signer_id
      assert {Ouroboros.Storage.DurableFile, _opts} = config[:signing_journal_storage]

      # A core node with none of this configured is unaffected: the preflight is scoped
      # to the role whose reason to exist is holding a key.
      System.put_env("OUROBOROS_NODE_ROLE", "core")
      System.delete_env("OUROBOROS_SIGNER_KEY_PATH")
      System.delete_env("OUROBOROS_SIGNER_ID")
      assert prod_config()[:ouroboros][:node_role] == :core
    end

    test "naming a signer node is what configures the remote signer, and nothing else does" do
      # Unset, production keeps the shipped refusal rather than acquiring a signer.
      assert prod_config()[:ouroboros][:forge_signer] == Signer.Deny

      System.put_env("OUROBOROS_SIGNING_NODE", "signer-1@10.0.0.30")
      System.put_env("OUROBOROS_SIGNING_CALL_TIMEOUT_MS", "9000")
      System.put_env("OUROBOROS_SIGNING_REQUIRE_EVAL", "true")
      System.put_env("OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE", "5")

      config = prod_config()[:ouroboros]

      assert config[:forge_signer] ==
               {Signer.Remote, node: :"signer-1@10.0.0.30", timeout: 9_000}

      assert config[:signing_node] == :"signer-1@10.0.0.30"
      assert config[:signing_call_timeout] == 9_000
      assert config[:signing_require_eval] == true
      assert config[:signing_rate_limit_per_minute] == 5

      # A bound that cannot be parsed stops the boot rather than silently defaulting.
      System.put_env("OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE", "many")

      assert_raise RuntimeError, ~r/OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE/, fn ->
        prod_config()
      end
    end
  end

  defp prod_config, do: Config.Reader.read!("config/runtime.exs", env: :prod, target: :host)

  # ## Service helpers

  defp start_service!(opts \\ []) do
    {seed, opts} = Keyword.pop_lazy(opts, :seed, &seed/0)

    opts =
      opts
      |> Keyword.put_new_lazy(:key_path, fn -> write_key!(seed) end)
      |> Keyword.put_new(:signer_id, @signer_id)
      |> Keyword.put_new(:storage, ets_storage())
      |> Keyword.put(:name, nil)

    start_supervised!({Service, opts}, id: {Service, System.unique_integer([:positive])})
  end

  defp sign(service, artifact, opts \\ []) do
    Service.sign_artifact(
      artifact,
      Keyword.get(opts, :signer_id, @signer_id),
      Keyword.get(opts, :request, %{requester: node()}),
      service
    )
  end

  # ## Artifact helpers

  defp artifact!(opts \\ []) do
    metadata = Keyword.get_lazy(opts, :metadata, fn -> forge_metadata(report()) end)
    build!(@capability, compile!(@capability), metadata)
  end

  defp outsider_artifact! do
    build!(@outsider, compile!(@outsider), forge_metadata(report()))
  end

  defp build!(module, binary, metadata) do
    {:ok, artifact} =
      Artifact.build([{module, binary, disposition: :introduce}],
        epoch: System.unique_integer([:positive, :monotonic]),
        metadata: metadata
      )

    unload(module)
    artifact
  end

  defp forge_metadata(report, sha256 \\ nil, eval \\ nil) do
    forge = %{
      source_id: "forge-source-1",
      source_sha256: sha256 || source_sha256(),
      author: "test-agent",
      created_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      test_report: report,
      peer_runtime: %{}
    }

    %{forge: if(is_nil(eval), do: forge, else: Map.put(forge, :eval, eval))}
  end

  defp report(opts \\ []) do
    %{
      total: Keyword.get(opts, :total, 1),
      failures: Keyword.get(opts, :failures, 0),
      excluded: Keyword.get(opts, :excluded, 0),
      skipped: Keyword.get(opts, :skipped, 0),
      ran: true
    }
  end

  defp eval_spec do
    %{probes: [%{input: %{op: "ping"}, expect: :any_reply}], budget_ms: 2_000, required: :all}
  end

  defp source_sha256, do: Beam.sha256("capability source")

  defp compile!(module) do
    source = """
    defmodule #{inspect(module)} do
      @vsn 1
      def hello, do: :world
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{^module, binary}] = Code.compile_string(source, "signing_service_capability.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    unload(module)
    binary
  end

  defp forge_source! do
    {:ok, source} =
      Source.new(
        module: @forged,
        author: "test-agent",
        source: """
        defmodule #{inspect(@forged)} do
          @vsn 1

          def double(n) when is_integer(n), do: n * 2
        end
        """,
        test_source: """
        defmodule #{inspect(@forged)}Test do
          use ExUnit.Case, async: false

          test "doubles" do
            assert #{inspect(@forged)}.double(21) == 42
          end
        end
        """
      )

    source
  end

  defp flip_byte(binary) do
    offset = div(byte_size(binary), 2)
    <<prefix::binary-size(^offset), byte, suffix::binary>> = binary
    <<prefix::binary, Bitwise.bxor(byte, 1), suffix::binary>>
  end

  # ## Peer helpers

  defp start_signer_peer! do
    peer = start_bare_peer!()

    put_peer_env!(peer, :node_role, :signer)
    put_peer_env!(peer, :signer_id, @signer_id)
    put_signer_key!(peer, write_key!(seed()))

    {:ok, _applications} = :erpc.call(peer, Application, :ensure_all_started, [:ouroboros])
    peer
  end

  defp start_bare_peer! do
    ensure_distributed!()

    name = String.to_atom("ouroboros_signing_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])
    {:ok, peer, peer_node} = :peer.start(%{name: name, args: args, wait_boot: 30_000})

    on_exit(fn -> stop_peer(peer) end)

    peer_node
  end

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    _kind, _reason -> :ok
  end

  defp put_peer_env!(peer, key, value) do
    :ok = :erpc.call(peer, Application, :put_env, [:ouroboros, key, value])
  end

  defp put_signer_key!(peer, path) do
    :ok = :erpc.call(peer, System, :put_env, [%{"OUROBOROS_SIGNER_KEY_PATH" => path}])
  end

  defp configure_remote_signer!(signer) do
    previous = Application.get_env(:ouroboros, :forge_signer)
    Application.put_env(:ouroboros, :forge_signer, {Signer.Remote, node: signer})
    on_exit(fn -> restore(:forge_signer, previous) end)
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_signing_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end

    :ok
  end

  # ## Plumbing

  defp seed, do: :crypto.strong_rand_bytes(32)

  defp write_key!(contents) do
    path = Path.join(tmp_dir!(), "signer-#{System.unique_integer([:positive])}.key")
    File.write!(path, contents)
    File.chmod!(path, 0o600)
    path
  end

  defp tmp_dir! do
    directory =
      Path.join(System.tmp_dir!(), "ouroboros-signing-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)
    directory
  end

  defp ets_storage do
    {Jido.Storage.ETS,
     table: String.to_atom("signing_journal_#{System.unique_integer([:positive])}")}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end
end
