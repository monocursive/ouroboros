defmodule Ouroboros.Wasm.SkewTest do
  # Not async: the real helper is an OS child and `:upgrade_trust_policy` is application
  # environment every loading node reads.
  use ExUnit.Case, async: false

  @moduledoc """
  The precompiled-artifact fallback, against artifacts **another toolchain really produced**
  (docs/WASM.md D22, D24, §12, slice W20).

  W8's skew tests craft the mismatch: a `.cwasm` this build wrote, its header rewritten to name
  another wasmtime or another triple. That is an honest test of the *comparison* — what a node
  reads is the header — and §12 said what it is not: a test that two toolchains disagree, because
  one toolchain wrote both sides. `scripts/wasm-skew-test.sh` builds the other side for real, on
  a Linux kernel and at a pinned-back wasmtime, and this file is what the node does with what it
  brings back.

  Two fallbacks, and a deploy is only honest if both hold:

    * **Before the helper.** A manifest that records the *producing* build — which is what a
      signer on the other machine would really have signed — is compared against this node's own
      `doctor` by `Ouroboros.Wasm.Store.form/4`, and the source form is chosen without the helper
      being asked at all.
    * **After it.** A manifest that records *this* node's build over those same bytes gets the
      artifact offered, and the helper refuses the real container by name; `Wasm.Pool` then
      compiles the source and the capability answers.

  The artifacts are built, not checked in. A `.cwasm` is a built binary and this repository
  keeps none of those in git (see `.gitignore` on `test/support/wasm/echo.wasm`) — the
  triple-skew one is 405 546 bytes and the version-skew one 258 093, which is not the deciding
  reason but is worth saying. So this suite skips with the script's name in the reason when the
  artifacts are not there, including under `OUROBOROS_REQUIRE_WASM`: a machine without Docker
  and a spare wasmtime cannot produce them, and a skip that says how to is better than a failure
  that does not.
  """

  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Rollout
  alias Ouroboros.Wasm.Store

  @moduletag :capture_log
  # Two real compiles of the acceptance guest through the real helper, plus a rollout's four
  # gates, twice over.
  @moduletag timeout: 180_000

  @guest Path.expand("../support/wasm/echo.wasm", __DIR__)
  @signer "wasm-skew-test-key"
  @skew_dir (case System.get_env("OURO_WASM_SKEW_DIR") do
               dir when is_binary(dir) and dir != "" -> dir
               _unset -> Path.expand("../../_build/wasm-skew", __DIR__)
             end)

  @records ["triple-skew.json", "version-skew.json"]

  @needs_skew (cond do
                 not Wasm.available?() ->
                   [
                     skip:
                       "no ouro-wasm at #{Wasm.helper_path()}; run `make wasm` — this suite is " <>
                         "about what a real helper refuses"
                   ]

                 not File.regular?(@guest) ->
                   [skip: "no acceptance guest at #{@guest}; run `make wasm-guest`"]

                 not Enum.all?(@records, &File.regular?(Path.join(@skew_dir, &1))) ->
                   [
                     skip:
                       "no real skewed artifacts in #{@skew_dir}; run `make wasm-skew-test` " <>
                         "(it needs Docker for the other triple and builds one other wasmtime " <>
                         "for the other version). A `.cwasm` is a built binary and is not " <>
                         "checked in, so there is nothing to fall back to here"
                   ]

                 true ->
                   []
               end)

  @eval %{
    probes: [%{input: %{"greet" => "world"}, expect: {:contains, "greet"}}],
    budget_ms: 10_000,
    required: :all
  }

  setup do
    tmp = Path.join(System.tmp_dir!(), "ouro-wasm-skew-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)

    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    trust_policy = [allow_unsigned: false, trusted_signers: %{@signer => public}]

    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)
    Application.put_env(:ouroboros, :upgrade_trust_policy, trust_policy)
    on_exit(fn -> restore(:upgrade_trust_policy, previous) end)

    %{
      tmp: tmp,
      private: private,
      trust_policy: trust_policy,
      store_root: Path.join(tmp, "store"),
      registry: start_registry!()
    }
  end

  for record <- @records do
    @record record

    @tag @needs_skew
    test "#{record}: a real artifact from another toolchain deploys as the source form",
         context do
      skew = read_record!(@record)
      artifact_bytes = File.read!(Path.join(@skew_dir, skew["artifact"]))
      bytes = File.read!(@guest)
      pool = live_pool!()

      # The script compiled the *same* component this node is about to deploy. Without this the
      # rest of the file would be about two unrelated things that happen to disagree.
      assert Artifact.digest(bytes) == skew["component_sha256"]
      assert helper_build(pool) == skew["read_by"]

      produced = skew["produced_by"]

      refute produced == helper_build(pool),
             "the artifact and this helper agree; there is no skew to prove"

      # ---- before the helper: the manifest a signer on that machine would really have signed.
      honest =
        sign!(
          context,
          bytes,
          %{
            wasmtime: produced["wasmtime"],
            target: produced["target"],
            sha256: Artifact.digest(artifact_bytes),
            size: byte_size(artifact_bytes)
          }
        )

      assert {:ok, outcome} = deploy(honest, bytes, artifact_bytes, context)
      assert outcome.state == :live

      # `Store.form/4` compared the manifest's block against this node's own `doctor` and chose
      # the source form without the helper being asked. The reason names which half disagreed —
      # which is the whole of D22's "string equality on both halves and nothing cleverer".
      assert {:source, source, reason} =
               Store.form(honest.component_sha256, honest.precompiled, helper_build(pool),
                 root: context.store_root
               )

      assert String.ends_with?(source, "sha256-#{honest.component_sha256}.wasm")
      assert reason == expected_reason(skew)

      # ---- after it: the same real bytes, under a manifest claiming this node's own build.
      # The store offers them, and the container's own header — written by the other toolchain,
      # not rewritten by a test — is what the helper refuses.
      here = helper_build(pool)

      dishonest =
        sign!(context, bytes, %{
          wasmtime: here["wasmtime"],
          target: here["target"],
          sha256: Artifact.digest(artifact_bytes),
          size: byte_size(artifact_bytes)
        })

      assert {:ok, _} =
               Store.put_precompiled(artifact_bytes, dishonest.precompiled.sha256,
                 root: context.store_root
               )

      assert {:precompiled, _path, _sha} =
               Store.form(dishonest.component_sha256, dishonest.precompiled, here,
                 root: context.store_root
               )

      assert {:ok, report} =
               Pool.load_component(dishonest.component_sha256, dishonest.precompiled, pool,
                 store: [root: context.store_root]
               )

      assert report["precompiled"] == false,
             "the helper mapped an artifact another toolchain produced"

      assert report["sha256"] == dishonest.component_sha256

      # And it is a working component rather than a load that returned: the fallback is the
      # point of the refusal, not a consolation for it.
      instance = "wasm-skew-#{System.unique_integer([:positive])}"

      assert {:ok, _} =
               Pool.instantiate(
                 instance,
                 dishonest.component_sha256,
                 ~s({"greeting":"hi"}),
                 Wasm.capability_limits(),
                 pool
               )

      assert {:ok, %{"payload" => payload}} =
               Pool.call(instance, "handle-message", ~s({"greet":"world"}), pool)

      assert payload =~ "greet"
      Pool.drop(instance, pool)
    end
  end

  ## helpers

  defp expected_reason(%{"produced_by" => produced, "read_by" => read}) do
    cond do
      produced["wasmtime"] != read["wasmtime"] ->
        {:wasmtime_mismatch, produced["wasmtime"], read["wasmtime"]}

      true ->
        {:target_mismatch, produced["target"], read["target"]}
    end
  end

  defp read_record!(name) do
    @skew_dir |> Path.join(name) |> File.read!() |> JSON.decode!()
  end

  defp helper_build(pool), do: Pool.helper_build(pool)

  # This lane's own signing payload, with a `precompiled` block chosen by the test — which is
  # exactly what a signer on the other machine produces, minus the machine.
  defp sign!(context, bytes, block) do
    {:ok, epoch} = Epoch.next([node()])

    {:ok, artifact} =
      Artifact.build(bytes,
        name: "skew-#{System.unique_integer([:positive])}",
        epoch: epoch,
        imports: ["log"],
        author: "skew-test",
        eval: @eval
      )

    unsigned = %{artifact | precompiled: block, signature: nil}

    value =
      :crypto.sign(:eddsa, :none, Artifact.signing_payload(unsigned, @signer), [
        context.private,
        :ed25519
      ])

    {:ok, signed} = Artifact.with_signature(unsigned, %{signer: @signer, value: value})
    signed
  end

  defp deploy(artifact, bytes, artifact_bytes, context) do
    Rollout.deploy(artifact, bytes, [node()],
      registry: context.registry,
      store_root: context.store_root,
      trust_policy: context.trust_policy,
      precompiled: artifact_bytes
    )
  end

  defp live_pool! do
    name = :"wasm_skew_pool_#{System.unique_integer([:positive])}"
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
    name = String.to_atom("wasm_skew_registry_#{System.unique_integer([:positive])}")
    table = String.to_atom("wasm_skew_rollouts_#{System.unique_integer([:positive])}")

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
