defmodule Ouroboros.Upgrade.SigningServiceTest.RefusingPolicy do
  @moduledoc false

  # A policy that is nothing but a different answer, so the only thing a refusal from it
  # can be evidence of is that `:signing_policy` was read.

  @behaviour Ouroboros.Upgrade.Signing.Policy

  @impl true
  def evaluate(_artifact, _context), do: {:refused, :this_policy_signs_nothing}
end

defmodule Ouroboros.Upgrade.SigningServiceTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.SigningServiceTest.RefusingPolicy

  alias Ouroboros.Storage.DurableFile
  alias Ouroboros.Upgrade.Signing.{Journal, Policy, Service}
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Verifier

  @bytes "\0asm\x01\x00\x00\x00 pretend this is a component"
  @signer_id "release-key"

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

      assert :ok = Verifier.verify(signed, @bytes, trusted_signers: %{@signer_id => public_key})

      # The signature is over the service's own derivation of the payload, which is the
      # same canonical bytes the verifier reconstructs. Nothing about the manifest may
      # move afterwards.
      assert {:error, {:invalid_signature, @signer_id}} =
               Verifier.verify(%{signed | epoch: signed.epoch + 1}, @bytes,
                 trusted_signers: %{@signer_id => public_key}
               )
    end

    test "the requested identity and the advisory payload are both cross-checked" do
      service = start_service!()
      artifact = artifact!()

      assert {:refused, {:unknown_signer_id, "somebody-else"}} =
               sign(service, artifact, signer_id: "somebody-else")

      # The payload is advisory: the service signs what it derives. A disagreement is
      # version skew between a core node and its signer, and skew stops the deployment.
      assert {:refused, {:payload_mismatch, expected, given}} =
               sign(service, artifact,
                 request: %{
                   requester: node(),
                   component_bytes: @bytes,
                   payload: "not the payload"
                 }
               )

      assert byte_size(expected) == 64
      assert expected != given

      # And the payload the requester would honestly derive is accepted.
      assert {:ok, _signature} =
               sign(service, artifact,
                 request: %{
                   requester: node(),
                   component_bytes: @bytes,
                   payload: Artifact.signing_payload(artifact, @signer_id)
                 }
               )

      assert {:refused, {:invalid_signing_request, :requester_required}} =
               sign(service, artifact, request: %{})

      assert {:refused, {:invalid_artifact, _}} = sign(service, :not_an_artifact)
    end

    test "the shipped policy is the default and `:signing_policy` is what replaces it" do
      # The rules a signature stands on are configuration, so what that configuration
      # resolves to is worth asserting directly rather than inferring from a refusal.
      assert Policy.configured() == Policy.Default

      on_exit(fn -> Application.delete_env(:ouroboros, :signing_policy) end)
      Application.put_env(:ouroboros, :signing_policy, RefusingPolicy)
      assert Policy.configured() == RefusingPolicy

      # And the override is live, not decorative: a service started without an explicit
      # `:policy` takes the configured one and refuses with its reason.
      service = start_service!()
      assert {:refused, :this_policy_signs_nothing} = sign(service, artifact!())

      # Anything that is not a module name is not a policy. A signer that read one would
      # be a signer with no rules at all, so the shipped policy stands instead — the same
      # direction `Service.policy/1` falls back in.
      Application.put_env(:ouroboros, :signing_policy, "Elixir.Not.A.Module")
      assert Policy.configured() == Policy.Default

      Application.put_env(:ouroboros, :signing_policy, nil)
      assert Policy.configured() == Policy.Default

      # An explicit `:policy` still wins over the configured one, which is how a test or a
      # second signer on one node runs its own rules.
      Application.put_env(:ouroboros, :signing_policy, RefusingPolicy)
      assert {:ok, _signature} = sign(start_service!(policy: Policy.Default), artifact!())
    end
  end

  describe "the decision journal" do
    test "every decision is recorded, issued and refused alike" do
      service = start_service!()
      artifact = artifact!()

      assert {:ok, _signature} = sign(service, artifact)
      assert {:refused, _reason} = sign(service, unsignable!())

      assert {:ok, [issued, refused]} = Service.decisions(service)

      assert issued.decision == :issued
      assert issued.sequence == 1
      assert issued.artifact_id == artifact.id
      assert issued.epoch == artifact.epoch
      assert issued.requester == node()
      assert issued.signer_id == @signer_id
      assert issued.reason == nil
      assert [%{module: "wasm/greeter", disposition: :component}] = issued.modules
      assert issued.findings.provenance.author == "test-agent"
      assert is_binary(issued.at)

      assert refused.decision == :refused
      assert refused.sequence == 2
      assert refused.reason == {:world_not_supported, "no-such-world"}
      assert [%{module: "wasm/greeter"}] = refused.modules

      # A refusal is a decision, so it counts.
      assert {:ok, status} = Service.status(service)
      # W8 widened the vocabulary: a lane-W sign is admitted, then issued, and an admission is
      # a real thing the signer did — it committed a rate-limit slot and a policy verdict. The
      # tally seeds all three so a surface reading it never has to ask whether a key is missing
      # because nothing happened or because this build does not know the word.
      assert status.decisions == %{issued: 1, admitted: 0, refused: 1}
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

  describe "the journal bounds a verdict field by field" do
    test "one oversized value does not take the identity fields with it" do
      # Bounding the map as one term let a single requester-chosen value inside it — lane
      # W's `provenance.test_report`, which a manifest carries verbatim — collapse the
      # whole verdict to a rendered string, and with it every field a refusal is read for.
      findings = %{
        lane: :wasm,
        epoch: 7,
        component_sha256: String.duplicate("a", 64),
        world: "ouroboros:capability@0.1.0",
        imports: ["log"],
        start: %{id: "wasm/greeter", config_bytes: 2},
        provenance: %{author: "somebody", test_report: %{failures: 0, notes: fat(6_000)}}
      }

      entry = recorded(findings)

      assert entry.findings.component_sha256 == findings.component_sha256
      assert entry.findings.world == findings.world
      assert entry.findings.start == findings.start
      assert entry.findings.provenance.author == "somebody"
      assert %{too_large: _rendered} = entry.findings.provenance.test_report
    end

    test "a verdict whose shape is hostile still records what it was about" do
      # Bounding each value bounds nothing when there are enough of them. The floor is the
      # identity of the decision plus a marker saying the rest did not fit.
      wide = Map.new(1..4_000, fn n -> {"k#{n}", n} end)

      entry =
        recorded(%{
          lane: :wasm,
          epoch: 7,
          component_sha256: String.duplicate("a", 64),
          world: "ouroboros:capability@0.1.0",
          noise: wide
        })

      assert entry.findings.component_sha256 == String.duplicate("a", 64)
      assert entry.findings.world == "ouroboros:capability@0.1.0"
      assert entry.findings.epoch == 7
      assert entry.findings.findings == :too_large
      refute Map.has_key?(entry.findings, :noise)
    end

    test "an unportable value is a marker rather than a term the next boot cannot read" do
      entry = recorded(%{lane: :wasm, epoch: 7, provenance: %{who: self(), pad: fat(6_000)}})

      assert entry.findings.epoch == 7
      assert %{unportable: _rendered} = entry.findings.provenance.who
    end

    test "and the whole entry stays inside the journal's own ceiling" do
      for findings <- [
            %{lane: :wasm, provenance: %{test_report: %{notes: fat(200_000)}}},
            %{lane: :wasm, noise: Map.new(1..4_000, fn n -> {"k#{n}", fat(64)} end)},
            %{lane: :wasm, epoch: 1, modules: List.duplicate(fat(512), 500)}
          ] do
        entry = recorded(findings)
        assert byte_size(:erlang.term_to_binary(entry.findings)) <= 8_192
      end
    end

    defp fat(bytes), do: String.duplicate("z", bytes)

    defp recorded(findings) do
      [entry] =
        Journal.new()
        |> Journal.record(%{
          artifact_id: "a",
          epoch: 7,
          lane: :wasm,
          modules: [],
          requester: node(),
          signer_id: "signer",
          decision: :issued,
          reason: nil,
          findings: findings
        })
        |> Journal.public()

      entry
    end
  end

  describe "admission" do
    test "a requester beyond its rate limit is refused, and refusals count too" do
      service = start_service!(rate_limit_per_minute: 2)

      assert {:ok, _signature} = sign(service, artifact!())

      assert {:refused, {:world_not_supported, _}} = sign(service, unsignable!())

      assert {:refused, {:rate_limited, requester, 2, 2}} = sign(service, artifact!())
      assert requester == node()

      # A different requester has its own window. The requester is self-reported, which
      # is exactly why this bounds accidents rather than adversaries.
      assert {:ok, _signature} =
               sign(service, artifact!(),
                 request: %{requester: :"other@127.0.0.1", component_bytes: @bytes}
               )

      assert {:ok, status} = Service.status(service)
      assert status.tracked_requesters == 2
      assert status.rate_limit_per_minute == 2
    end

    test "every refusal below the limiter still costs the requester its window" do
      # The limiter used to run *after* the size check, the signer-id check and the
      # component-bytes check, so each of those refusals was free and unlimited — and each
      # one costs this process a `term_to_binary` over a manifest the caller chose the
      # size of, plus a journal write. A refusal an attacker can generate at will is the
      # one outcome that must not be cheaper than an issuance.
      service = start_service!(rate_limit_per_minute: 2, max_artifact_bytes: 128)

      assert {:refused, {:artifact_too_large, _bytes, 128}} = sign(service, artifact!())

      assert {:refused, {:unknown_signer_id, "somebody-else"}} =
               sign(service, artifact!(), signer_id: "somebody-else")

      # Two requests, admitted and refused, is the whole window: the third is rate-limited
      # rather than being told again what was wrong with it.
      assert {:refused, {:rate_limited, requester, 2, 2}} = sign(service, artifact!())
      assert requester == node()

      assert {:ok, status} = Service.status(service)
      assert status.tracked_requesters == 1
    end

    test "an artifact larger than the configured bound is refused before it is read" do
      service = start_service!(max_artifact_bytes: 128)

      assert {:refused, {:artifact_too_large, bytes, 128}} = sign(service, artifact!())
      assert bytes > 128
    end

    test "a service that is not running is a refusal, never a raise" do
      assert {:refused, {:signing_service_unavailable, _reason}} =
               Service.sign_artifact(
                 artifact!(),
                 @signer_id,
                 %{requester: node(), component_bytes: @bytes},
                 :no_such_name
               )

      assert {:error, {:signing_service_unavailable, _reason}} =
               Service.public_info(:no_such_name)

      assert {:refused, {:invalid_signing_request, _}} =
               Service.sign_artifact(artifact!(), "", %{requester: node()})
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

    @tag timeout: 180_000
    test "refuses a manifest it will not sign over the wire, whoever is asking" do
      signer = start_signer_peer!()
      request = %{requester: node(), component_bytes: @bytes}

      assert {:refused, {:world_not_supported, "no-such-world"}} =
               remote_sign(signer, unsignable!(), @signer_id, request)

      assert {:refused, {:unknown_signer_id, "not-this-signer"}} =
               remote_sign(signer, artifact!(), "not-this-signer", request)

      # A well-formed manifest from the same requester is signed, so the refusals above
      # are the policy speaking rather than the transport failing.
      assert {:ok, signature} = remote_sign(signer, artifact!(), @signer_id, request)
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
      # Unset, production names no signer node rather than guessing at a host.
      assert prod_config()[:ouroboros][:signing_node] == nil

      System.put_env("OUROBOROS_SIGNING_NODE", "signer-1@10.0.0.30")
      System.put_env("OUROBOROS_SIGNING_CALL_TIMEOUT_MS", "9000")
      System.put_env("OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE", "5")

      config = prod_config()[:ouroboros]

      assert config[:signing_node] == :"signer-1@10.0.0.30"
      assert config[:signing_call_timeout] == 9_000
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
      Keyword.get(opts, :request, %{requester: node(), component_bytes: @bytes}),
      service
    )
  end

  # ## Manifest helpers

  defp artifact!(attrs \\ []) do
    {:ok, artifact} =
      Artifact.build(
        @bytes,
        Keyword.merge(
          [
            name: "greeter",
            imports: ["log"],
            author: "test-agent",
            source_sha256: String.duplicate("b", 64),
            epoch: System.unique_integer([:positive, :monotonic]),
            eval: %{probes: [%{input: %{"n" => 1}, expect: :any_reply}], budget_ms: 1_000}
          ],
          attrs
        )
      )

    artifact
  end

  # A manifest no configuration can talk this signer into signing: the world is not one
  # this build implements, and there is no option that widens that.
  defp unsignable!, do: %{artifact!() | world: "no-such-world"}

  defp remote_sign(signer, artifact, signer_id, request) do
    :erpc.call(signer, Service, :sign_artifact, [artifact, signer_id, request], 30_000)
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
end
