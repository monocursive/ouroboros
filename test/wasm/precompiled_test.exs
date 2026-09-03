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
  alias Ouroboros.Wasm.Download
  alias Ouroboros.Wasm.PolicyEngine
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.SandboxFixture
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
  # The order: admitted first, compiled second (H1)
  # ---------------------------------------------------------------------------------------

  describe "two-phase signing — nothing compiles before the limiter has admitted it" do
    @tag @needs_live
    test "a rate-limited request never reaches the helper", context do
      bytes = File.read!(@guest)
      service = limited_service!(context, 1)
      {wrapper, invocations} = counting_helper!(context)

      opts = [
        signing_service: service,
        upload_root: context.uploads,
        helper_path: wrapper,
        scratch_root: Path.join(context.tmp, "sign"),
        # See `counting_helper!/1`: the shim's journal has nowhere to live under the fence,
        # and what this test measures is the order of admission and compile.
        helper_sandbox: :off
      ]

      # One admission spends the window.
      assert {:ok, first} = Deploy.sign(base(context, bytes), opts)
      assert first.form == :precompiled
      assert invocations.() == 1, "the admitted request compiled, exactly once"

      # The second is refused by the limiter — which runs on the *admission*, before this node
      # spends a core on a requester it is about to turn away. Move `admit/4` back below the
      # compile in `Deploy.sign/2` (or drop the `admit` step entirely) and the count below is 2:
      # a refused sign that cost 1.4 s of a core at the worst shape §7.3 admits.
      assert {:error, {:signing_refused, {:rate_limited, _, _, _}}} =
               Deploy.sign(base(context, bytes), opts)

      assert invocations.() == 1,
             "the helper was invoked for a request the rate limiter refused"
    end

    @tag @needs_live
    test "a policy refusal never reaches the helper either", context do
      bytes = File.read!(@guest)
      {wrapper, invocations} = counting_helper!(context)

      opts = [
        signing_service: context.service,
        upload_root: context.uploads,
        helper_path: wrapper,
        scratch_root: Path.join(context.tmp, "sign")
      ]

      # D12: lane W's signer requires an eval spec. The refusal is the policy's, and it is made
      # on the *source* manifest — the one with no block, because nothing has been compiled.
      assert {:error, {:signing_refused, :eval_spec_required}} =
               Deploy.sign(Map.delete(base(context, bytes), :eval), opts)

      assert invocations.() == 0, "a manifest the policy refuses is never compiled"

      # And an import outside the world's one, which the policy also refuses.
      assert {:error, {:signing_refused, {:import_not_in_world, "socket"}}} =
               Deploy.sign(%{base(context, bytes) | imports: ["socket"]}, opts)

      assert invocations.() == 0
    end

    @tag @needs_live
    test "the admission is journaled, and the signature spends no second slot", context do
      bytes = File.read!(@guest)
      service = limited_service!(context, 1)

      opts = [
        signing_service: service,
        upload_root: context.uploads,
        scratch_root: Path.join(context.tmp, "sign")
      ]

      assert {:ok, receipt} = Deploy.sign(base(context, bytes), opts)

      # Two entries for one signature: the admission this node committed a rate-limit slot and
      # a policy verdict to, and the issuance that followed the compile. An admission is a real
      # thing the signer did — folding it into the issuance would claim a signature before there
      # was one, and folding it into a refusal would claim a refusal that never happened.
      assert {:ok, decisions} = Service.decisions(service)
      mine = Enum.filter(decisions, &(&1.artifact_id == receipt.artifact_id))

      assert [%{decision: :admitted, lane: :wasm}, %{decision: :issued, lane: :wasm}] = mine

      # And one slot, not two: with a limit of one per minute, a second *whole* sign is refused
      # — which it would not be if the signature had spent a slot of its own, because then the
      # first sign would already have spent both.
      assert {:ok, status} = Service.status(service)
      assert status.rate_limit_per_minute == 1
      assert status.decisions.admitted == 1
      assert status.decisions.issued == 1
      assert status.outstanding_admissions == 0, "the ticket was spent by the signature"
    end

    test "a ticket is single use, and is honoured only for its own requester and manifest",
         context do
      bytes = "\0asm\x01\x00\x00\x00 a component this test never runs"
      service = limited_service!(context, 1)

      {:ok, source} =
        Artifact.build(bytes,
          name: "greeter",
          epoch: 4_242,
          author: "test-agent",
          imports: [],
          eval: @eval
        )

      request = %{requester: node(), component_bytes: bytes}

      assert {:ok, %{artifact_id: ticket}} = Service.admit(source, @signer, request, service)
      assert ticket == source.id

      # A ticket for a manifest whose source half moved is not this manifest's ticket, so the
      # limiter is charged again — and the window is spent, so this is refused by it.
      moved = %{source | name: "other"}

      assert {:refused, {:rate_limited, _, _, _}} =
               Service.sign_artifact(
                 moved,
                 @signer,
                 Map.put(request, :admission, ticket),
                 service
               )

      # The *precompiled* block is the one thing that may differ, and it does not spend a slot.
      block = %{
        wasmtime: "48.0.1",
        target: "aarch64-apple-darwin",
        sha256: String.duplicate("a", 64),
        size: 1024
      }

      {:ok, full} = Artifact.with_precompiled(source, block)

      assert {:ok, signature} =
               Service.sign_artifact(
                 full,
                 @signer,
                 Map.put(request, :admission, ticket),
                 service
               )

      assert byte_size(signature) == 64

      # Single use: the same ticket a second time is not a ticket, and the window is gone.
      assert {:refused, {:rate_limited, _, _, _}} =
               Service.sign_artifact(
                 full,
                 @signer,
                 Map.put(request, :admission, ticket),
                 service
               )
    end
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
  # The fallback, and the switch that takes the form away entirely (H2, H3)
  # ---------------------------------------------------------------------------------------

  describe "a node that will not or cannot map an artifact compiles the component" do
    test "an operator can refuse the precompiled form fleet-wide", context do
      block = staged_artifact(context)
      matching = %{"wasmtime" => "48.0.1", "target" => "aarch64-apple-darwin"}
      opts = [root: context.store_root]

      assert {:precompiled, _path, _sha} = Store.form(block.sha, block.block, matching, opts)

      # `config :ouroboros, :wasm, accept_precompiled: false`. What it takes away is the one
      # thing a signature now authorizes that it did not before W8: this node deserializing
      # machine code its signer produced, which wasmtime does not validate and which runs with
      # the helper's own authority rather than inside a guest's fence (D24, §12). Every node can
      # still compile the source, so refusing costs latency and nothing else.
      previous = Application.get_env(:ouroboros, :wasm)

      Application.put_env(
        :ouroboros,
        :wasm,
        Keyword.put(previous || [], :accept_precompiled, false)
      )

      on_exit(fn -> restore(:wasm, previous) end)

      assert {:source, _path, :precompiled_refused_here} =
               Store.form(block.sha, block.block, matching, opts)

      # And a manifest that declares no artifact still reads as what it is, rather than as
      # something this node turned down.
      assert {:source, _path, :not_precompiled} = Store.form(block.sha, nil, matching, opts)
    end

    test "an artifact that rotted on disk is not offered", context do
      block = staged_artifact(context)
      matching = %{"wasmtime" => "48.0.1", "target" => "aarch64-apple-darwin"}
      opts = [root: context.store_root]

      {:ok, path} = Store.precompiled_path(block.block.sha256, opts)
      File.write!(path, :crypto.strong_rand_bytes(block.block.size))

      # A truncated write, a bad block, an rsync. The store's whole story is that the name of a
      # file is its content, and for an artifact that is load-bearing in a way it is not for a
      # component: a rotted component is refused by the helper's own `sha_mismatch` before
      # anything is compiled, and a rotted artifact would be mapped. Delete the digest from
      # `precompiled_path/2` and this reads `{:precompiled, …}` for bytes nobody signed.
      assert {:source, _source, {:precompiled_unusable, {:corrupt_precompiled, _}}} =
               Store.form(block.sha, block.block, matching, opts)

      # A listing does not pay for that digest and says so by answering the other way: fifty
      # rows at 25 ms each is a `:read` verb doing a second's work.
      assert {:precompiled, ^path, _sha} =
               Store.form(block.sha, block.block, matching, Keyword.put(opts, :verify, false))
    end

    @tag @needs_live
    test "a helper that refuses the artifact gets the source form, and the guest answers",
         context do
      pool = live_pool!(context)
      bytes = File.read!(@guest)
      {:ok, receipt} = sign(context, bytes)

      {:ok, %{artifact: artifact, precompiled: artifact_bytes}} =
        Bundle.decode(bundle(receipt, bytes))

      {:ok, _} = Store.put(bytes, artifact.component_sha256, root: context.store_root)

      {:ok, _} =
        Store.put_precompiled(artifact_bytes, receipt.precompiled.sha256,
          root: context.store_root
        )

      # The artifact is intact and its digest is right — so the store offers it — and the helper
      # refuses it, because its header names a wasmtime this node is not running. That is the
      # gap `refusal.rs`, D24 and `doctor`'s own note all promised a fallback for and nothing
      # carried out: before H3 this was a dead capability with the source form sitting on the
      # same disk. Delete the `@fallback_refusals` branch in `Pool.load_component/4` and this
      # goes red at the load.
      # The manifest's block still names *this* node's build, so `Store.form/4` offers the
      # artifact — the fallback under test is the one after the helper has looked at it. Only
      # the container's own header lies, which is the one thing the store cannot see.
      {:ok, path} = Store.precompiled_path(receipt.precompiled.sha256, root: context.store_root)
      rewritten = rewrite_header(File.read!(path), &Map.put(&1, "wasmtime", "1.0.0"))

      {:ok, put} =
        Store.put_precompiled(rewritten, Artifact.digest(rewritten), root: context.store_root)

      offered = %{
        artifact.precompiled
        | sha256: put.sha256,
          size: byte_size(rewritten)
      }

      assert {:precompiled, _path, _sha} =
               Store.form(
                 artifact.component_sha256,
                 offered,
                 Pool.helper_build(pool),
                 root: context.store_root
               )

      assert {:ok, report} =
               Pool.load_component(artifact.component_sha256, offered, pool,
                 store: [root: context.store_root]
               )

      assert report["precompiled"] == false, "the source form was compiled instead"
      assert report["sha256"] == artifact.component_sha256

      # And it is a working component, not merely a load that returned.
      helper_instance = "w8-fallback-#{System.unique_integer([:positive])}"

      assert {:ok, _} =
               Pool.instantiate(
                 helper_instance,
                 artifact.component_sha256,
                 ~s({"greeting":"hi"}),
                 Wasm.capability_limits(),
                 pool
               )

      assert {:ok, %{"payload" => payload}} =
               Pool.call(helper_instance, "handle-message", ~s({"greet":"world"}), pool)

      assert payload =~ "greet"
      Pool.drop(helper_instance, pool)
    end

    @tag @needs_live
    test "a component this node does not hold reaches no helper at all", context do
      pool = live_pool!(context)

      assert {:error, {:store, {:unknown_component, _}}} =
               Pool.load_component(String.duplicate("a", 64), nil, pool,
                 store: [root: context.store_root]
               )

      # `:idle`: nothing spawned a helper to discover a missing file.
      assert %{phase: :idle} = Pool.status(pool)
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

      doctor = helper_doctor(live_pool!(context))
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
      pool = live_pool!(context)
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
      pool = live_pool!(context)
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
                 |> Keyword.put(:pool, live_pool!(context))
               )

      assert evidence.precompiled == false
    end

    @tag @needs_live
    test "both rollout gates hold each form to its own digest", context do
      pool = live_pool!(context)
      bytes = File.read!(@guest)
      {:ok, receipt} = sign(context, bytes)

      {:ok, %{artifact: artifact, precompiled: artifact_bytes}} =
        Bundle.decode(bundle(receipt, bytes))

      opts = [
        pool: pool,
        store_root: context.store_root,
        registry: context.registry,
        epoch_registry: context.registry,
        trust_policy: context.trust_policy
      ]

      # The **driving** node checks before its `:deploying` checkpoint, because it is about to
      # hand a peer machine code the peer will deserialize: a corrupt section refused here is a
      # refusal, and one that got past would be a per-node quarantine on every target. Delete
      # the `verify_precompiled` step from `Rollout.deploy/4` and this deploys.
      rotted = :crypto.strong_rand_bytes(byte_size(artifact_bytes))

      assert {:error, {:precompiled_sha256_mismatch, _}} =
               Rollout.deploy(artifact, bytes, [node()], Keyword.put(opts, :precompiled, rotted))

      # And **every target** checks again, on its own, because a driver is not a trust boundary.
      # Delete `verified_precompiled/2` from `stage/3` and this stages.
      assert {:error, {:precompiled_rejected, {:precompiled_sha256_mismatch, _}}} =
               Rollout.stage(artifact, bytes, Keyword.put(opts, :precompiled, rotted))

      # A manifest that declares a block and a caller that brought no section is the same
      # disagreement from the other side, and is refused at both gates too.
      assert {:error, {:precompiled_rejected, :missing_precompiled}} =
               Rollout.stage(artifact, bytes, opts)

      assert {:ok, []} = Store.list(root: context.store_root)
    end

    @tag @needs_live
    test "an untrusted signature never reaches a deserialize", context do
      pool = live_pool!(context)
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
      pool = live_pool!(context)
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
      pool = live_pool!(context)
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
      pool = live_pool!(context)
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

  # ---------------------------------------------------------------------------------------
  # The signer's own helper runs behind the same fence (W16, D25)
  # ---------------------------------------------------------------------------------------

  describe "sign-time precompile runs under the helper policy" do
    @tag @needs_live
    test "the artifact is produced with the fence on, which is the default", context do
      # The plainest statement of it: every other test in this file already signs with
      # `helper_sandbox: :required`, because that is the default and nothing here sets
      # otherwise — so a policy that broke the compile would have taken the suite with it.
      # This one says the quiet part, and reads the posture back off the pool beside it.
      bytes = File.read!(@guest)

      assert {:ok, receipt} = sign(context, bytes)
      assert receipt.form == :precompiled
      assert receipt.precompile_skipped == nil
      assert %{sha256: _sha, size: size} = receipt.precompiled
      assert size > 0

      assert %{sandbox: %{posture: :sandboxed}} = Pool.status(live_pool!(context))
    end

    @tag @needs_live
    test "the compiling helper cannot read a file outside the roots it was given", context do
      # A shim standing where `ouro-wasm precompile` stands, reporting through its exit status
      # what the operating system let it do: 3 if it read a planted 0600 file outside the sign
      # scratch, 4 if it could not. Under the policy the answer is 4.
      %{secret: secret} = plant(context)
      helper = probing_helper!(context, secret)
      bytes = File.read!(@guest)

      assert {:ok, fenced} = sign(context, bytes, [], helper_path: helper)
      assert fenced.form == :source
      assert fenced.precompile_skipped =~ "precompile_refused, 4"

      # And the mutation: the same shim, the same planted file, `helper_sandbox: :off`. The
      # exit status flips, which is the kernel saying the fence was the only thing stopping it.
      assert {:ok, open} =
               sign(context, bytes, [], helper_path: helper, helper_sandbox: :off)

      assert open.precompile_skipped =~ "precompile_refused, 3"
    end

    @tag @needs_live
    test "one signature, one directory: a concurrent sign is neither readable nor writable",
         context do
      # W16 HIGH-2, proved and then closed. The first cut wrote `sign-<tag>.wasm` and its
      # `.cwasm` straight into `<data_dir>/wasm/sign/` and made that whole root writable, and a
      # review walked through it: a wrapped helper listed the root, read a **concurrent**
      # signature's source — a client's uploaded component — and overwrote a concurrent
      # signature's artifact, which is the file the next signature is issued over.
      scratch = Path.join(context.tmp, "sign")
      File.mkdir_p!(scratch)

      # A signature in flight beside this one, in the shape `compile_in/5` writes.
      victim = Path.join(scratch, "sign-VICTIM")
      File.mkdir_p!(victim)
      File.write!(Path.join(victim, "component.wasm"), "another client's upload")

      # The shim lives in a directory of its **own**, not in `context.tmp`: the readable set
      # names the helper's directory, and a Seatbelt subpath rule is recursive, so a shim
      # sitting above the sign root would have been handed the very thing under test.
      shim = Path.join(context.tmp, "shim")
      File.mkdir_p!(shim)

      helper =
        script!(context, ~s[if ls #{scratch} > /dev/null 2>&1; then exit 3; else exit 4; fi],
          dir: shim
        )

      bytes = File.read!(@guest)

      assert {:ok, listed} = sign(context, bytes, [], helper_path: helper)
      assert listed.precompile_skipped =~ "precompile_refused, 4", "the shared root was listed"

      writer =
        script!(
          context,
          ~s[if echo MALICIOUS > #{victim}/component.wasm 2>/dev/null; then exit 3; else exit 4; fi],
          dir: shim
        )

      assert {:ok, written} = sign(context, bytes, [], helper_path: writer)
      assert written.precompile_skipped =~ "precompile_refused, 4"
      assert File.read!(Path.join(victim, "component.wasm")) == "another client's upload"

      # And the directory this signature *does* own is writable, or the fence would be a
      # broken compiler rather than a fence: the ordinary sign below produces its artifact.
      assert {:ok, receipt} = sign(context, bytes)
      assert receipt.form == :precompiled

      # Nothing of it survives: the whole per-sign directory goes, not just two files.
      assert File.ls!(scratch) == ["sign-VICTIM"]
    end

    @tag @needs_live
    test "a signer that cannot sandbox its helper signs the source form and names why",
         context do
      previous = Application.get_env(:ouroboros, :native_sandbox)
      Application.put_env(:ouroboros, :native_sandbox, :none)
      on_exit(fn -> restore(:native_sandbox, previous) end)

      bytes = File.read!(@guest)

      assert {:ok, receipt} = sign(context, bytes)

      # Not an error: the source form is what every node could always compile, so a signer
      # with no fence costs the fleet a compile per node and says so — the same shape as
      # every other skip reason above.
      assert receipt.form == :source
      assert receipt.precompiled == nil
      assert receipt.precompile_skipped =~ "helper_sandbox_unavailable"
      assert receipt.precompile_skipped =~ "no_backend"

      # And the bundle is whole, verifiable and deployable, which is the whole claim about a
      # skip: it is an answer, not a failure.
      assert {:ok, %{artifact: artifact, precompiled: nil}} =
               Bundle.verify(bundle(receipt, bytes), context.trust_policy)

      assert artifact.precompiled == nil
    end
  end

  # ---------------------------------------------------------------------------------------
  # Every way a signing node ends up with no artifact, and what it says about each
  # ---------------------------------------------------------------------------------------

  describe "a skipped precompile is an answer, and it names itself" do
    @tag @needs_live
    test "every reason this node can have for signing the source form alone", context do
      bytes = File.read!(@guest)
      scratch = Path.join(context.tmp, "sign")

      # A directory this node cannot use. `scratch_root` is normally `<data_dir>/wasm/sign/`,
      # created 0700 and held to `lstat` — a shared `/tmp` root somebody else may have created
      # or symlinked is where every uploaded component and every artifact compiled from one
      # would otherwise be written (M5).
      elsewhere = Path.join(context.tmp, "somebody-elses")
      File.mkdir_p!(elsewhere)
      planted = Path.join(context.tmp, "planted")
      File.ln_s!(elsewhere, planted)

      link = Path.join(context.tmp, "not-a-directory")
      File.write!(Path.join(context.tmp, "plain"), "")
      File.ln_s!(Path.join(context.tmp, "plain"), link)

      cases = [
        {"no helper on disk", ":no_helper", [helper_path: Path.join(context.tmp, "absent")]},
        {"no data directory", ":no_data_dir", [scratch_root: nil]},
        {"a scratch root that is a link to a file", ":enotdir", [scratch_root: link]},
        # The one that matters on a shared filesystem: a link somebody else planted, pointing
        # at a directory they own. `mkdir_p` is happy — the directory exists — and only `lstat`
        # sees that this is not a directory this node made.
        {"a scratch root somebody else planted", "not_a_directory", [scratch_root: planted]},
        {"a helper that will not answer in time", ":precompile_timeout",
         [scratch_root: scratch, precompile_timeout: 0]},
        {"a helper that refuses", "precompile_refused",
         [scratch_root: scratch, helper_path: script!(context, "exit 3")]},
        {"a helper that answers with something else", ":precompile_unreadable",
         [scratch_root: scratch, helper_path: script!(context, ~s(echo 'not json'))]},
        {"a helper whose report does not describe what it wrote", "precompile_digest",
         [
           scratch_root: scratch,
           helper_path:
             script!(
               context,
               ~s[printf 'machine code' > "$3"\n] <>
                 ~s[echo '{"precompiled":{"wasmtime":"48.0.1","target":"t","sha256":"] <>
                 String.duplicate("a", 64) <> ~s["}}']
             )
         ]}
      ]

      for {label, marker, extra} <- cases do
        assert {:ok, receipt} = sign(context, bytes, [], extra), label

        # Every one of them signs, and signs the *source* form: the fast path is an
        # optimisation a signer offers when it can, never a requirement it imposes.
        assert receipt.precompiled == nil, label
        assert receipt.form == :source, label

        assert receipt.precompile_skipped =~ marker,
               "#{label}: expected a reason naming #{marker}, got " <>
                 inspect(receipt.precompile_skipped)

        # And the bundle it produced is a whole, verifiable, deployable one.
        assert {:ok, %{artifact: artifact, precompiled: nil}} =
                 Bundle.verify(bundle(receipt, bytes), context.trust_policy),
               label

        assert artifact.precompiled == nil, label
      end
    end

    # W19 changed this branch and the test says so rather than being deleted. Until W19 an
    # artifact past the reply's ceiling was dropped and the source form was signed; now it is
    # handed over in frames and the manifest keeps its block. What is still true — and is the
    # half worth keeping a test for — is that a node which cannot *stage* one falls back
    # rather than signing a promise it cannot keep.
    @tag @needs_live
    test "an artifact too large for one reply travels in frames instead", context do
      bytes = File.read!(@guest)

      # The ceiling is three quarters of the gateway's own configured frame, because the
      # artifact travels base64 at four bytes to three (M9). An operator who raises the frame
      # raises this, in one place — so a frame small enough makes the reference guest's 258 KiB
      # artifact too large for one reply, which is the branch this exercises. 64 KiB rather
      # than something smaller because W19's review made the *chunk* a function of the frame
      # too: below four kibibytes of chunk a node refuses to stage at all (H1).
      previous = Application.get_env(:ouroboros, :gateway)

      Application.put_env(
        :ouroboros,
        :gateway,
        Keyword.put(previous || [], :max_frame, 64 * 1024)
      )

      on_exit(fn -> restore(:gateway, previous) end)

      assert Deploy.max_receipt_precompiled_bytes() == 49_152

      downloads = Path.join(context.tmp, "downloads")
      assert {:ok, receipt} = sign(context, bytes, [], download_root: downloads)

      # Nothing was skipped: the artifact was compiled, it is in the signed manifest, and the
      # receipt says which form the client is holding.
      assert receipt.form == :precompiled
      assert receipt.precompiled != nil
      assert receipt.precompile_skipped == nil

      # And the prefix is the header and the envelope alone — the artifact is not in it.
      assert %{download: id, size: size, sha256: sha256, chunk_bytes: chunk_bytes} =
               receipt.artifact

      assert sha256 == receipt.precompiled.sha256
      assert byte_size(Base.decode64!(receipt.bundle_prefix)) < size

      assert receipt.bundle_bytes ==
               byte_size(Base.decode64!(receipt.bundle_prefix)) + size + receipt.size

      assert chunk_bytes == Download.max_chunk_bytes()
      assert {:ok, %{download: ^id, size: ^size}} = Download.read(id, 0, root: downloads)
    end

    # The fallback W19 keeps. A slot is claimed before the manifest is signed precisely so
    # that a node which cannot hand an artifact over signs the source form instead — remove
    # the `{:error, reason}` arm of `staged/4` and this node signs a manifest declaring an
    # artifact no client can ever fetch.
    @tag @needs_live
    test "a node that cannot stage the artifact signs the source form and says why", context do
      bytes = File.read!(@guest)

      previous = Application.get_env(:ouroboros, :gateway)
      on_exit(fn -> restore(:gateway, previous) end)

      previous_data_dir = Application.get_env(:ouroboros, :data_dir)
      on_exit(fn -> restore(:data_dir, previous_data_dir) end)

      downloads = Path.join(context.tmp, "unstageable")

      cases = [
        # No data directory to derive a download root from, and no `download_root` either:
        # nowhere at all to put an artifact that will not fit a reply.
        {"no data directory", "no_data_dir", 64 * 1024, fn -> nil end, []},
        # And W19's review added a second way to be unstageable: a frame too small to carry
        # a usable chunk. Shrinking the chunk further would be a transfer nobody could finish,
        # so the node refuses to mint the slot and falls back exactly as above (H1).
        {"a frame too small for a chunk", "frame_too_small", 4_096, fn -> context.tmp end,
         [download_root: downloads]}
      ]

      for {label, marker, frame, data_dir, extra} <- cases do
        Application.put_env(:ouroboros, :gateway, Keyword.put(previous || [], :max_frame, frame))

        case data_dir.() do
          nil -> Application.delete_env(:ouroboros, :data_dir)
          dir -> Application.put_env(:ouroboros, :data_dir, dir)
        end

        assert {:ok, receipt} = sign(context, bytes, [], extra), label

        assert receipt.form == :source, label
        assert receipt.precompiled == nil, label
        assert receipt.artifact == nil, label
        assert receipt.precompile_skipped =~ "artifact_not_staged", label
        assert receipt.precompile_skipped =~ marker, label

        # And the bundle it produced is a whole, verifiable, deployable one.
        assert {:ok, %{artifact: artifact, precompiled: nil}} =
                 Bundle.verify(bundle(receipt, bytes), context.trust_policy),
               label

        assert artifact.precompiled == nil, label
      end
    end

    test "the receipt ceiling follows the gateway's own frame" do
      previous = Application.get_env(:ouroboros, :gateway)
      on_exit(fn -> restore(:gateway, previous) end)

      Application.delete_env(:ouroboros, :gateway)
      assert Deploy.max_receipt_precompiled_bytes() == 786_432

      Application.put_env(:ouroboros, :gateway, max_frame: 8 * 1024 * 1024)
      assert Deploy.max_receipt_precompiled_bytes() == 6_291_456

      # A malformed setting reads as the default rather than as no bound at all, which is the
      # posture every other setting in this lane takes.
      Application.put_env(:ouroboros, :gateway, max_frame: :lots)
      assert Deploy.max_receipt_precompiled_bytes() == 786_432
    end
  end

  ## Helpers

  # A signing service of this test's own with a chosen rate limit, so the ordering claim above
  # is observable in one call rather than in thirty.
  defp limited_service!(context, per_minute) do
    seed = :crypto.strong_rand_bytes(32)
    key_path = Path.join(context.tmp, "limited-#{System.unique_integer([:positive])}.key")
    File.write!(key_path, seed)
    File.chmod!(key_path, 0o600)

    service =
      start_supervised!(
        {Service,
         [
           name: nil,
           key_path: key_path,
           signer_id: @signer,
           rate_limit_per_minute: per_minute,
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("wasm_w8_limited_#{System.unique_integer([:positive])}")}
         ]},
        id: {Service, System.unique_integer([:positive])}
      )

    {:ok, %{public_key: public}} = Service.public_info(service)
    policy = [allow_unsigned: false, trusted_signers: %{@signer => public}]
    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)
    Application.put_env(:ouroboros, :upgrade_trust_policy, policy)
    on_exit(fn -> restore(:upgrade_trust_policy, previous) end)

    service
  end

  # A shim in front of the real helper that records every invocation. The claim it settles is an
  # *ordering*, and an ordering is only observable by watching the expensive half.
  # W16 fix wave. Counting invocations needs a side channel that outlives the invocation, and
  # after HIGH-2 there is none: the only directory a wrapped `precompile` may write is the
  # per-signature one, which `compile_in/5` removes on the way out. So the one test that counts
  # runs its shim with `helper_sandbox: :off` — it is about `sign/2`'s **admission order**, not
  # about containment, and the fence itself is proved by the kernel in
  # `Ouroboros.Wasm.PoolTest` and by the two sign-time tests below.
  defp counting_helper!(context) do
    marker = Path.join(context.tmp, "invocations-#{System.unique_integer([:positive])}")
    wrapper = Path.join(context.tmp, "helper-#{System.unique_integer([:positive])}.sh")

    File.write!(wrapper, """
    #!/bin/sh
    echo "$@" >> #{marker}
    exec #{Wasm.helper_path()} "$@"
    """)

    File.chmod!(wrapper, 0o755)

    count = fn ->
      case File.read(marker) do
        {:ok, text} -> text |> String.split("\n", trim: true) |> length()
        {:error, :enoent} -> 0
      end
    end

    {wrapper, count}
  end

  defp base(context, bytes) do
    %{
      upload: upload!(context, bytes),
      name: "greeter",
      author: "test-agent",
      imports: ["log"],
      start_config: "{}",
      eval: @eval
    }
  end

  # A stand-in for `ouro-wasm precompile`, so every failure a subprocess can have is a failure
  # this suite can produce. `$3` is the output path the real invocation passes.
  # W16. A 0600 file in a directory the sign-time policy never names: the readable set is the
  # platform, the helper's own directory and the sign scratch, and this is none of those.
  #
  # A **sibling** of `context.tmp` and not something inside it, because the helper's directory
  # is `context.tmp` and a Seatbelt subpath rule is recursive: a secret planted below a
  # readable root is a secret the fence was never asked about.
  defp plant(_context) do
    dir =
      Path.join(System.tmp_dir!(), "ouro-wasm-planted-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(dir) end)
    File.mkdir_p!(dir)
    secret = Path.join(dir, "secret")
    File.write!(secret, "the node's own bytes")
    File.chmod!(secret, 0o600)
    %{dir: dir, secret: secret}
  end

  # Stands where `ouro-wasm precompile` stands and answers with its exit status: 3 if it read
  # the planted file, 4 if the kernel refused. Either way it produces no artifact, so the
  # signature falls back to the source form and the reason carries the status.
  #
  # The shim's own directory is `context.tmp`, which the sign-time policy makes readable
  # because `process-exec` has to read the binary — so the planted file sits *outside* that
  # tree, which is where the fence's edge actually is.
  defp probing_helper!(context, secret) do
    script!(context, ~s[if cat "#{secret}" > /dev/null 2>&1; then exit 3; else exit 4; fi])
  end

  defp script!(context, body, opts \\ []) do
    dir = Keyword.get(opts, :dir, context.tmp)
    path = Path.join(dir, "helper-#{System.unique_integer([:positive])}.sh")
    File.write!(path, "#!/bin/sh\n" <> body <> "\n")
    File.chmod!(path, 0o755)
    path
  end

  defp sign(context, bytes, attrs \\ [], extra \\ []) do
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

    Deploy.sign(
      attrs,
      Keyword.merge(
        [
          signing_service: context.service,
          upload_root: context.uploads,
          # W8, M5. The compile's scratch is this node's own, under its data directory and
          # never a shared `/tmp` — a test names its own for the same reason it names its own
          # store.
          scratch_root: Path.join(context.tmp, "sign")
        ],
        extra
      )
    )
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
    head = binary_part(binary, 0, at)
    <<byte>> = binary_part(binary, at, 1)
    tail = binary_part(binary, at + 1, byte_size(binary) - at - 1)
    <<head::binary, Bitwise.bxor(byte, 0xFF), tail::binary>>
  end

  # One component and one artifact in a store of this test's own, with the block a manifest
  # would name for them. The subject of the tests above is the *choice*, not the signature.
  defp staged_artifact(context) do
    bytes = "\0asm\x0d\x00\x01\x00 a component"
    artifact = "OUROCWASM and its machine code"

    {:ok, put} = Store.put(bytes, nil, root: context.store_root)

    {:ok, _} =
      Store.put_precompiled(artifact, Artifact.digest(artifact), root: context.store_root)

    %{
      sha: put.sha256,
      block: %{
        wasmtime: "48.0.1",
        target: "aarch64-apple-darwin",
        sha256: Artifact.digest(artifact),
        size: byte_size(artifact)
      }
    }
  end

  # Rewrites a container's JSON header, keeping the framing exact. The attacker's move, and the
  # only way to put a header in front of a payload it does not describe without a second
  # wasmtime on this machine.
  defp rewrite_header(container, edit) do
    <<magic::binary-size(9), 1::8, header_len::32, payload_len::32, rest::binary>> = container
    header = rest |> binary_part(0, header_len) |> JSON.decode!() |> edit.() |> JSON.encode!()
    payload = binary_part(rest, header_len, payload_len)

    magic <> <<1::8, byte_size(header)::32, payload_len::32>> <> header <> payload
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

  # W16: the helper is spawned under the OS sandbox, so the pool is told where this test's
  # store, its artifacts and its scratch are — `context.tmp` holds all three.
  defp live_pool!(context) do
    name = :"wasm_w8_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start(
        [name: name, handshake_timeout_ms: 15_000] ++ SandboxFixture.pool_opts(context.tmp)
      )

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
