defmodule Ouroboros.Wasm.PrecompiledTest do
  # Not async: the live half spawns the real helper as an OS child, starts mesh agents, and
  # moves `:upgrade_trust_policy`, which every loading node reads from application environment.
  use ExUnit.Case, async: false

  @moduledoc """
  W8 — a component is compiled once, where the signature is made (docs/WASM.md D22–D24).

  Every claim here is about the *pair* of forms: a bundle carries both, a manifest binds each to
  its own digest, and a node loads the compiled one only when its own helper's readings match the
  ones the signer recorded. The direction that must never break is the fallback: a node that
  cannot use the artifact compiles the source exactly as it did before W8, so a precompiled
  bundle deploys everywhere an ordinary one does.
  """

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Boot
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Deploy
  alias Ouroboros.Wasm.PolicyEngine
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Rollout
  alias Ouroboros.Wasm.Store
  alias Ouroboros.Wasm.Surface
  alias Ouroboros.Wasm.Upload
  alias Ouroboros.Wasm.Verifier

  @moduletag :capture_log

  @guest Path.expand("../support/wasm/echo.wasm", __DIR__)
  @policy_guest Path.expand(
                  "../../tui/wasm/guest/examples/no-network-shell/target/wasm32-wasip2/release/no_network_shell.wasm",
                  __DIR__
                )
  @signer "wasm-precompiled-test-key"

  @needs_live (cond do
                 not Wasm.available?() ->
                   [
                     skip:
                       "no ouro-wasm at #{Wasm.helper_path()}; run `make wasm` — W8 is about " <>
                         "what a real helper compiles and what a real helper maps"
                   ]

                 not File.regular?(@guest) ->
                   [skip: "no acceptance guest at #{@guest}; run `make wasm-guest`"]

                 true ->
                   []
               end)

  @needs_policy (cond do
                   @needs_live != [] ->
                     @needs_live

                   not File.regular?(@policy_guest) ->
                     [skip: "no policy example at #{@policy_guest}; run `make wasm-examples`"]

                   true ->
                     []
                 end)

  @eval %{
    probes: [%{input: %{"greet" => "world"}, expect: {:contains, "greet"}}],
    budget_ms: 10_000,
    required: :all
  }

  setup do
    tmp = Path.join(System.tmp_dir!(), "ouro-wasm-w8-#{System.unique_integer([:positive])}")
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
              table: String.to_atom("wasm_w8_journal_#{System.unique_integer([:positive])}")}
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
      tmp: tmp,
      uploads: Path.join(tmp, "uploads"),
      store_root: Path.join(tmp, "store"),
      registry: start_registry!()
    }
  end

  # ---------------------------------------------------------------------------------------
  # The choice itself: two strings, compared for equality, and no cleverness anywhere
  # ---------------------------------------------------------------------------------------

  describe "Store.form/4 — which of the two forms a node loads" do
    setup context do
      bytes = "\0asm\x0d\x00\x01\x00 a component"
      artifact = "OUROCWASM fake serialized artifact"

      {:ok, put} = Store.put(bytes, nil, root: context.store_root)

      {:ok, _} =
        Store.put_precompiled(artifact, Artifact.digest(artifact), root: context.store_root)

      block = %{
        wasmtime: "48.0.1",
        target: "aarch64-apple-darwin",
        sha256: Artifact.digest(artifact),
        size: byte_size(artifact)
      }

      Map.merge(context, %{sha: put.sha256, source_path: put.path, block: block})
    end

    test "a matching helper takes the artifact, and every mismatch takes the source", context do
      matching = %{"wasmtime" => "48.0.1", "target" => "aarch64-apple-darwin"}
      opts = [root: context.store_root]

      assert {:precompiled, path, sha} =
               Store.form(context.sha, context.block, matching, opts)

      assert sha == context.block.sha256
      assert String.ends_with?(path, "cwasm-#{sha}.cwasm")

      # A different wasmtime, and a different triple. Both are string equality and neither is
      # an ordering: wasmtime's serialized form is checked against an exact build and an exact
      # configuration hash, so "close enough" is a decision nobody here is entitled to make.
      # Delete either comparison in `why/2` and one of these two returns `{:precompiled, …}`
      # for an artifact this node cannot map.
      source = context.source_path

      assert {:source, ^source, {:wasmtime_mismatch, "48.0.1", "47.0.0"}} =
               Store.form(context.sha, context.block, %{matching | "wasmtime" => "47.0.0"}, opts)

      assert {:source, _path,
              {:target_mismatch, "aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}} =
               Store.form(
                 context.sha,
                 context.block,
                 %{matching | "target" => "x86_64-unknown-linux-gnu"},
                 opts
               )
    end

    test "no block, no helper reading, and no file on disk are each the source form", context do
      matching = %{"wasmtime" => "48.0.1", "target" => "aarch64-apple-darwin"}
      opts = [root: context.store_root]

      # A manifest from before W8, or one signed with `--no-precompile`.
      assert {:source, _path, :not_precompiled} = Store.form(context.sha, nil, matching, opts)

      # A node whose pool has not connected. `nil` is "this node does not know", and not
      # knowing is exactly when the form that always works is the right one.
      assert {:source, _path, :helper_build_unknown} =
               Store.form(context.sha, context.block, nil, opts)

      # A manifest that names an artifact this store does not hold — a prune took it, or a
      # stage was interrupted. Still a load, still the component, one line in the log.
      assert {:source, _path, :precompiled_not_stored} =
               Store.form(
                 context.sha,
                 %{context.block | sha256: String.duplicate("f", 64)},
                 matching,
                 opts
               )

      # And a component the store does not hold at all is an error rather than a fallback:
      # the fast form is not a fix for missing bytes, and the caller should hear about the
      # problem it actually has.
      assert {:error, {:unknown_component, _}} =
               Store.form(String.duplicate("e", 64), context.block, matching, opts)
    end
  end

  # ---------------------------------------------------------------------------------------
  # The bundle: two forms, two digests, one signature over both
  # ---------------------------------------------------------------------------------------

  describe "the bundle carries both forms and binds each to its own sha" do
    @tag @needs_live
    test "sign with precompile, and the file holds the component and the artifact", context do
      bytes = File.read!(@guest)
      assert {:ok, receipt} = sign(context, bytes)

      # The signer recorded what its own helper printed, not what this node believes it is.
      assert %{wasmtime: wasmtime, target: target, sha256: sha256, size: size} =
               receipt.precompiled

      doctor = helper_doctor(live_pool!())
      assert receipt.precompile_skipped == nil
      assert wasmtime == doctor["wasmtime"]
      assert target == doctor["target"]
      assert size > byte_size(bytes), "machine code is larger than the wasm it came from"

      bundle = bundle(receipt, bytes)

      assert {:ok, %{artifact: artifact, bytes: ^bytes, precompiled: artifact_bytes}} =
               Bundle.verify(bundle, context.trust_policy)

      assert artifact.precompiled == receipt.precompiled
      assert Artifact.digest(artifact_bytes) == sha256
      assert byte_size(artifact_bytes) == size

      # The artifact is the container `ouro-wasm precompile` writes, and its header names the
      # component it came from. A reader that only trusted the manifest would still be trusting
      # one digest for two files.
      assert <<"OUROCWASM", 1::8, _rest::binary>> = artifact_bytes
    end

    @tag @needs_live
    test "precompile: false signs the source form alone, and it still deploys", context do
      pool = live_pool!()
      name = "w8off-#{System.unique_integer([:positive])}"
      id = "wasm/" <> name
      on_exit(fn -> Mesh.stop_agent(id) end)

      bytes = File.read!(@guest)

      assert {:ok, receipt} =
               sign(context, bytes,
                 name: name,
                 precompile: false,
                 start_config: ~s({"greeting":"hi"})
               )

      # `ouro wasm sign --no-precompile`, and the same shape a node with no helper produces:
      # no block in the manifest, no section in the file, and a receipt that says which of the
      # three reasons it was rather than leaving an absence to be noticed.
      assert receipt.precompiled == nil
      assert receipt.precompile_skipped == ":not_requested"
      bundle = bundle(receipt, bytes)

      assert {:ok, %{artifact: artifact, bytes: ^bytes, precompiled: nil}} =
               Bundle.verify(bundle, context.trust_policy)

      assert artifact.precompiled == nil

      # And it is a whole capability: W8 removes nothing from the path every node had.
      assert {:ok, %{state: :live}} =
               Deploy.deploy(upload!(context, bundle), [node()],
                 upload_root: context.uploads,
                 registry: context.registry,
                 store_root: context.store_root,
                 trust_policy: context.trust_policy,
                 pool: pool
               )

      assert {:ok, _agent} = Mesh.send_message("w8-off", id, %{"greet" => "world"})
      assert %{"echo" => %{"greet" => "world"}} = state(id).last_answer

      # Nothing was staged that nobody signed for: the store holds the component and the
      # manifest, and no artifact.
      assert {:ok, entries} = Store.list(root: context.store_root)
      refute Enum.any?(entries, &(&1.kind == :precompiled))

      list = Surface.list(registry: context.registry, root: context.store_root, pool: pool)
      assert Enum.find(list.rollouts, &(&1.artifact_id == receipt.artifact_id)).form == :source
    end

    @tag @needs_live
    test "one byte of the artifact and the bundle is refused, by that form's own sha", context do
      bytes = File.read!(@guest)
      {:ok, receipt} = sign(context, bytes)
      bundle = bundle(receipt, bytes)

      # Deep in the machine code, past the container's header. Delete
      # `Verifier.verify_precompiled/2`'s digest comparison — or the `verify_precompiled` step
      # in `Bundle.verify/2` — and this file verifies, and a node deserializes machine code
      # nobody signed out of a bundle that was otherwise perfectly signed.
      tampered = flip(bundle, byte_size(bundle) - byte_size(bytes) - 64)

      assert byte_size(tampered) == byte_size(bundle)

      assert {:error, {:precompiled_sha256_mismatch, _}} =
               Bundle.verify(tampered, context.trust_policy)

      # And the two halves have to be one statement: a section nobody declared, and a
      # declaration with no section, are both refused before any digest is compared.
      {:ok, decoded} = Bundle.decode(bundle)
      assert {:error, :missing_precompiled} = Verifier.verify_precompiled(decoded.artifact, nil)

      {:ok, plain} = Artifact.build(bytes, name: "g", epoch: 1, author: "t", imports: ["log"])
      assert {:error, {:unexpected_precompiled, _}} = Verifier.verify_precompiled(plain, "bytes")
    end
  end

  # ---------------------------------------------------------------------------------------
  # Deploying: the fast form where it fits, the slow one everywhere else
  # ---------------------------------------------------------------------------------------

  describe "staging and loading" do
    @tag @needs_live
    test "a matching node deserializes; a node whose build differs compiles", context do
      pool = live_pool!()
      bytes = File.read!(@guest)
      {:ok, receipt} = sign(context, bytes)

      {:ok, %{artifact: artifact, precompiled: artifact_bytes}} =
        Bundle.decode(bundle(receipt, bytes))

      opts = [
        pool: pool,
        store_root: context.store_root,
        epoch_registry: context.registry,
        precompiled: artifact_bytes
      ]

      # The helper's own answer is what says which form ran: `load` reports `precompiled` and
      # `stage/3` passes it through. Delete the `{:precompiled, …}` branch in `loaded/4` and
      # this is `false` while everything else still passes, which is the whole point of the
      # assertion being on the helper's word rather than on a path.
      assert {:ok, evidence} = Rollout.stage(artifact, bytes, opts)
      assert evidence.precompiled == true

      # Both forms are on disk, content-addressed, and the store lists them apart.
      assert {:ok, entries} = Store.list(root: context.store_root)
      kinds = entries |> Enum.map(& &1.kind) |> Enum.sort()
      assert :component in kinds
      assert :precompiled in kinds

      assert {:ok, _path} =
               Store.precompiled_path(artifact.precompiled.sha256, root: context.store_root)

      # The same bytes and the same artifact, under a manifest that records a wasmtime this
      # node is not running. The signer is trusted, the digests are right, and the node still
      # compiles the source — which is the guarantee W8 has to keep: no regression for a node
      # that cannot use the fast form.
      # A second helper as well as a second store, because a component this helper already
      # holds is answered out of its cache whichever form it was admitted in — a cache hit is
      # per world, not per form (see `Host::cache_hit`), and re-reading a component to change
      # a label would be spending a load on bookkeeping. The claim here is about what a *cold*
      # node does with this bundle, so the node has to be cold.
      skewed = skew(artifact, %{artifact.precompiled | wasmtime: "1.0.0"})

      assert {:ok, evidence} =
               Rollout.stage(
                 skewed,
                 bytes,
                 opts
                 |> Keyword.put(:store_root, fresh_store(context))
                 |> Keyword.put(:pool, live_pool!())
               )

      assert evidence.precompiled == false
    end

    @tag @needs_live
    test "an untrusted signature never reaches a deserialize", context do
      pool = live_pool!()
      bytes = File.read!(@guest)
      {:ok, receipt} = sign(context, bytes)

      {:ok, %{artifact: artifact, precompiled: artifact_bytes}} =
        Bundle.decode(bundle(receipt, bytes))

      # Everything about this bundle is well formed — both digests, both sections — and the
      # only thing wrong with it is who signed. `stage/3` verifies before it publishes, so the
      # artifact never reaches the store and therefore never reaches `Component::deserialize`:
      # what makes mapping somebody's machine code sound is the signature, and nothing else in
      # a bundle is a substitute for it (D24).
      Application.put_env(:ouroboros, :upgrade_trust_policy,
        allow_unsigned: false,
        trusted_signers: %{}
      )

      assert {:error, {:component_rejected, {:untrusted_signer, @signer}}} =
               Rollout.stage(artifact, bytes,
                 pool: pool,
                 store_root: context.store_root,
                 epoch_registry: context.registry,
                 precompiled: artifact_bytes
               )

      assert {:ok, []} = Store.list(root: context.store_root)
    end

    @tag @needs_live
    test "deploy end to end, and wasm.list says which form the node loads", context do
      pool = live_pool!()
      name = "w8-#{System.unique_integer([:positive])}"
      id = "wasm/" <> name
      on_exit(fn -> Mesh.stop_agent(id) end)

      bytes = File.read!(@guest)
      {:ok, receipt} = sign(context, bytes, name: name, start_config: ~s({"greeting":"hi"}))
      assert receipt.precompiled != nil

      assert {:ok, outcome} =
               Deploy.deploy(upload!(context, bundle(receipt, bytes)), [node()],
                 upload_root: context.uploads,
                 registry: context.registry,
                 store_root: context.store_root,
                 trust_policy: context.trust_policy,
                 pool: pool
               )

      assert outcome.state == :live

      # It is a real capability, not merely a fast load.
      assert {:ok, _agent} = Mesh.send_message("w8-test", id, %{"greet" => "world"})
      assert %{"echo" => %{"greet" => "world"}} = state(id).last_answer

      # W8's operator surface: which form this node loads that component from. `Surface.list/1`
      # computes it exactly the way a load computes it, out of the manifest in the store and
      # the pool's own doctor reading.
      list = Surface.list(registry: context.registry, root: context.store_root, pool: pool)
      row = Enum.find(list.rollouts, &(&1.artifact_id == receipt.artifact_id))
      assert row.form == :precompiled

      # And a node that cannot read a manifest for a row cannot say, which is `nil` rather
      # than a guess in either direction.
      empty = Surface.list(registry: context.registry, root: fresh_store(context), pool: pool)
      assert Enum.find(empty.rollouts, &(&1.artifact_id == receipt.artifact_id)).form == nil
    end

    @tag @needs_live
    test "a reboot restarts a precompiled live entry, and it answers", context do
      pool = live_pool!()
      name = "w8boot-#{System.unique_integer([:positive])}"
      id = "wasm/" <> name
      on_exit(fn -> Mesh.stop_agent(id) end)

      bytes = File.read!(@guest)
      {:ok, receipt} = sign(context, bytes, name: name, start_config: ~s({"greeting":"hi"}))

      assert {:ok, %{state: :live}} =
               Deploy.deploy(upload!(context, bundle(receipt, bytes)), [node()],
                 upload_root: context.uploads,
                 registry: context.registry,
                 store_root: context.store_root,
                 trust_policy: context.trust_policy,
                 pool: pool
               )

      :ok = Mesh.stop_agent(id)
      assert Mesh.whereis(id) == nil

      # The boot path reads the manifest, verifies it, and derives the start state — which
      # since W8 carries the `precompiled` block, so a restarted wrapper takes the same form
      # the deploy took rather than the slow one. Delete `:precompiled` from
      # `Rollout.start_state/2` and the capability still restarts and still answers, and the
      # assertion below on the wrapper's own state is what turns that red.
      report =
        Boot.restart_live(
          registry: context.registry,
          store_root: context.store_root,
          pool: pool
        )

      assert Enum.any?(report.started, &(&1.id == id)), inspect(report)
      assert is_pid(Mesh.whereis(id))
      assert state(id).precompiled == receipt.precompiled

      assert {:ok, _agent} = Mesh.send_message("w8-boot", id, %{"greet" => "again"})
      assert %{"echo" => %{"greet" => "again"}} = state(id).last_answer
    end

    @tag @needs_policy
    test "the policy engine stands up a precompiled policy", context do
      pool = live_pool!()
      bytes = File.read!(@policy_guest)

      {:ok, receipt} =
        sign(context, bytes,
          name: "w8policy-#{System.unique_integer([:positive])}",
          kind: :policy,
          eval: %{
            cases: [
              %{
                request: %{"tool" => "bash", "input" => %{"command" => "curl https://x.test"}},
                expect: %{decision: :deny}
              }
            ],
            budget_ms: 20_000
          },
          start_config: nil
        )

      assert receipt.kind == :policy
      assert receipt.precompiled != nil

      {:ok, %{artifact: artifact, precompiled: artifact_bytes}} =
        Bundle.decode(bundle(receipt, bytes))

      assert {:ok, evidence} =
               Rollout.stage(artifact, bytes,
                 pool: pool,
                 store_root: context.store_root,
                 epoch_registry: context.registry,
                 precompiled: artifact_bytes
               )

      assert evidence.precompiled == true

      # The engine's own gate: load as a policy, instantiate under the deploy's bounds, and
      # require a readable verdict. It runs against the state `Rollout.start_state/2` builds,
      # so it exercises the artifact this node would actually map.
      state = Rollout.start_state(artifact, pool: pool, store_root: context.store_root)
      assert state.precompiled == artifact.precompiled
      assert :ok = PolicyEngine.probe(state, [])
    end
  end

  ## Helpers

  defp sign(context, bytes, attrs \\ []) do
    attrs = Map.new(attrs)

    base = %{
      upload: upload!(context, bytes),
      name: "greeter",
      author: "test-agent",
      imports: ["log"],
      start_config: "{}",
      eval: @eval
    }

    attrs =
      base
      |> Map.merge(attrs)
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    Deploy.sign(attrs, signing_service: context.service, upload_root: context.uploads)
  end

  # The file an operator would `scp`: the node's prefix — header, envelope and, since W8, the
  # artifact the client has never seen — followed by the bytes the client uploaded.
  defp bundle(receipt, bytes), do: Base.decode64!(receipt.bundle_prefix) <> bytes

  # A manifest re-signed with a different `precompiled` block, which is how a node running
  # another wasmtime looks to a bundle: the digests are honest and the recorded build is not
  # this machine's.
  defp skew(artifact, block) do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, signer_seed())
    signer = "w8-skew-key"

    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)
    trusted = Keyword.get(previous || [], :trusted_signers, %{})

    Application.put_env(:ouroboros, :upgrade_trust_policy,
      allow_unsigned: false,
      trusted_signers: Map.put(trusted, signer, public)
    )

    on_exit(fn -> restore(:upgrade_trust_policy, previous) end)

    skewed = %{artifact | precompiled: block, signature: nil}

    value =
      :crypto.sign(:eddsa, :none, Artifact.signing_payload(skewed, signer), [private, :ed25519])

    {:ok, signed} = Artifact.with_signature(skewed, %{signer: signer, value: value})
    signed
  end

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

  defp flip(binary, at) do
    <<head::binary-size(at), byte, tail::binary>> = binary
    <<head::binary, Bitwise.bxor(byte, 0xFF), tail::binary>>
  end

  defp fresh_store(context) do
    root = Path.join(context.tmp, "store-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    root
  end

  defp helper_doctor(pool) do
    {:ok, report} = Pool.doctor(pool)
    report
  end

  defp upload!(context, bytes) do
    {:ok, %{upload: id}} = Upload.append(nil, 0, bytes, true, root: context.uploads)
    id
  end

  defp live_pool! do
    name = :"wasm_w8_pool_#{System.unique_integer([:positive])}"
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

  defp start_registry! do
    name = String.to_atom("wasm_w8_registry_#{System.unique_integer([:positive])}")
    table = String.to_atom("wasm_w8_rollouts_#{System.unique_integer([:positive])}")

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

  defp state(id) do
    {:ok, server_state} = Mesh.state(id)
    server_state.agent.state
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
