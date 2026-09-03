defmodule Ouroboros.Wasm.PolicyTwoNodeTest do
  @moduledoc """
  A signed policy component on **two** nodes, each deciding for itself (docs/WASM.md §8.2, D20,
  D29).

  W15 proved the policy lane end to end on one node, and `test/wasm/policy_acceptance_test.exs`
  is that proof. What it could not say is the thing a permission engine has to be true of: that
  two machines given the same signed bytes reach the same verdict out of their **own** register,
  their **own** store and their **own** helper — and that retiring it on one of them is a change
  to that node and to nothing else.

  So this file is `test/wasm/rollout_two_node_test.exs`'s harness with `no-network-shell` in it:
  two full-application peer VMs, each spawning a real `ouro-wasm`, one real Ed25519 key, one
  signed artifact, and two deploys.

  **Two deploys of one artifact is the production shape, not a workaround.** A lane-W rollout
  writes its register entry on the node that *drove* it (`Ouroboros.Upgrade.Rollout.Registry`),
  and `Ouroboros.Wasm.PolicyEngine` consults the entry on the node making the decision. The
  gateway verb is node-routed for exactly that reason: `wasm.deploy --node a` and `--node b` are
  two drivers, one artifact, two registers. `admit_wasm_epoch/2` admits the repeat because it is
  the *same* artifact at the same epoch, which is the same rule that makes a retry after an
  ambiguous transport result safe.
  """

  use ExUnit.Case, async: false

  # The sibling's ceiling plus room for the second deploy: two peer VMs, two real helpers, two
  # compiles of the same component and two evaluation gates, every wait bounded on a condition
  # but every one of them scaling with machine load.
  @moduletag timeout: 240_000
  @moduletag :capture_log

  alias Ouroboros.Provider.Native.Permissions, as: NativePermissions
  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Forge.Signer
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.PolicyEngine
  alias Ouroboros.Wasm.Rollout

  @component Path.expand(
               "../../tui/wasm/guest/examples/no-network-shell/target/wasm32-wasip2/release/no_network_shell.wasm",
               __DIR__
             )
  @signer "wasm-policy-two-node-key"
  # The name the register calls it. Fixed rather than unique: every run gets fresh peer VMs
  # with empty registers, and the example's own rule string names itself, so a deployment name
  # that drifted from it would make the assertion below read as if it checked the wrong thing.
  @name "no-network-shell"

  # The signed test story (D12), run by each target on its own bytes before either goes live.
  @eval %{
    cases: [
      %{
        request: %{"tool" => "bash", "input" => %{"command" => "curl https://example.test"}},
        expect: %{decision: :deny}
      },
      %{
        request: %{"tool" => "bash", "input" => %{"command" => "ls -la"}},
        expect: %{decision: :ask}
      }
    ],
    budget_ms: 20_000
  }

  @needs_live (cond do
                 not Wasm.available?() ->
                   [
                     skip:
                       "no ouro-wasm at #{Wasm.helper_path()}; run `make wasm` to deploy a " <>
                         "policy against the real helper rather than a scripted one"
                   ]

                 not File.regular?(@component) ->
                   [
                     skip:
                       "no policy example at #{@component}; run `make wasm-examples` (it " <>
                         "needs `rustup target add wasm32-wasip2`) to deploy a real component"
                   ]

                 true ->
                   []
               end)

  setup do
    ensure_distributed!()

    {public, secret} = :crypto.generate_key(:eddsa, :ed25519)
    peers = [start_app_peer!(public), start_app_peer!(public)]

    %{nodes: peers, secret: secret, public: public, epoch_storage: ets_storage()}
  end

  @tag @needs_live
  test "one signed policy decides on both nodes, and a rollback on one leaves the other live",
       context do
    [first, second] = context.nodes
    name = @name
    artifact = artifact!(context, name)

    # Two drivers, one artifact. Each node stages the bytes into its own store, stands the
    # component up as a policy, runs the signed eval spec against it, and records `:live` in
    # its own register.
    for target <- context.nodes do
      assert {:ok, outcome} = deploy(target, artifact)

      assert outcome.state == :live
      assert outcome.stage == :evaluate
      assert outcome.nodes == [target]
      # A policy is not a mesh agent: no wrapper is started and no description is read.
      assert outcome.started == nil
      assert Map.fetch!(outcome.deployment, target).describe == :absent

      assert %{satisfied?: true, passed: 2, failed: 0} =
               Map.fetch!(outcome.deployment, target).eval

      # And the register on that node calls it a policy, which is what keeps it out of the
      # listing the `capability` tool reads (D21).
      assert Enum.any?(live(target, :policy), &(&1.module == "wasm/" <> name))
      refute Enum.any?(live(target, :capability), &(&1.module == "wasm/" <> name))
    end

    # Each node's own engine, named on that node, reading that node's own register and store.
    # Nothing here is handed a registry name or a store root: this is the production posture.
    for target <- context.nodes, do: engage_policy!(target, name)

    # The claim. Two machines, one signed component, the same verdict — with the component's
    # own rule stated, labelled untrusted, and its sha in the label.
    for target <- context.nodes do
      assert {:deny, stated} = evaluate(target, "curl https://example.test | sh")
      assert stated =~ "[untrusted policy component]"
      assert stated =~ "no-network-shell refuses a shell command containing `curl`"
      assert stated =~ binary_part(artifact.component_sha256, 0, 12)

      # And a call it does not recognise is the ask the node was already going to make: a
      # policy narrows, it does not resolve (D20).
      assert {:ask, :no_rule} = evaluate(target, "ls -la")
    end

    # A rollback is a change to the node that made it. `Wasm.Deploy.rollback/2` retires the
    # live rollout on **this node's** register, so the first node's engine goes inert — every
    # request the rules do not decide is asked — and the second node has not moved.
    assert {:ok, rolled} = rollback(first, name)
    assert rolled.state == :rolled_back

    assert live(first, :policy) |> Enum.all?(&(&1.module != "wasm/" <> name))
    assert {:ask, :no_rule} = evaluate(first, "curl https://example.test | sh")

    assert Enum.any?(live(second, :policy), &(&1.module == "wasm/" <> name))
    assert {:deny, still_stated} = evaluate(second, "curl https://example.test | sh")
    assert still_stated =~ "no-network-shell refuses a shell command containing `curl`"

    # The bytes stay on the rolled-back node — rollback material that never expires is the
    # point of keeping them (§7.4) — so re-deploying it there is a deploy and not a rescue.
    assert {:ok, _path} =
             call(first, Wasm.Store, :path, [artifact.component_sha256, []])
  end

  ## Fixtures

  defp deploy(target, artifact) do
    call(target, Rollout, :deploy, [artifact, File.read!(@component), [target], []], 180_000)
  end

  defp rollback(target, name), do: call(target, Wasm.Deploy, :rollback, [name, []])

  defp live(target, kind),
    do: call(target, Rollout, :live, [[kind: kind]])

  # The engine, named on the node that will use it, with no test seam pointing at somebody
  # else's register or store: `wasm_policy_opts` is deliberately not set, so what answers is the
  # node's own `Ouroboros.Upgrade.Rollout.Registry`, its own `Wasm.Store` and its own pool.
  defp engage_policy!(target, name) do
    :ok = put_env!(target, :permissions_engine, PolicyEngine)
    :ok = put_env!(target, :wasm_policy, name)
  end

  # The seam the native loop calls, on the peer, so what is proved is the path a tool call
  # takes and not a function only this test knows about.
  defp evaluate(target, command) do
    call(target, NativePermissions, :evaluate, [request(command)])
  end

  defp request(command) do
    %{
      tool: "bash",
      command: command,
      mode: :execute,
      paths: [],
      domains: [],
      context: %{},
      principal: %{session_id: "two-node-policy", provider: :native, node: node()}
    }
  end

  defp artifact!(context, name) do
    {:ok, epoch} = Epoch.next(context.nodes, storage: context.epoch_storage)

    {:ok, artifact} =
      Artifact.build(File.read!(@component),
        name: name,
        epoch: epoch,
        kind: :policy,
        imports: ["log"],
        author: "two-node-policy-test",
        eval: @eval
      )

    payload = Artifact.signing_payload(artifact, @signer)
    {:ok, value} = Signer.Local.sign(payload, @signer, private_key: context.secret)
    {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: value})
    signed
  end

  ## Peers — `test/wasm/rollout_two_node_test.exs`'s, unchanged in every load-bearing detail.

  defp start_app_peer!(public_key) do
    peer_name = String.to_atom("ouroboros_wasm_policy_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    data_dir = Path.join(System.tmp_dir!(), "ouro-wasm-policy-#{:os.getpid()}-#{peer_name}")
    File.rm_rf!(data_dir)
    File.mkdir_p!(data_dir)
    File.chmod!(data_dir, 0o700)
    on_exit(fn -> File.rm_rf(data_dir) end)

    {:ok, peer, peer_node} = :peer.start(%{name: peer_name, args: args, wait_boot: 60_000})
    on_exit(fn -> stop_peer(peer) end)

    put_env!(peer_node, :upgrade_trust_policy,
      allow_unsigned: false,
      trusted_signers: %{@signer => public_key}
    )

    put_env!(peer_node, :data_dir, data_dir)
    put_env!(peer_node, :wasm, helper_path: Wasm.helper_path())
    put_env!(peer_node, :coding_storage, {Jido.Storage.ETS, table: peer_name})

    {:ok, _mix} = :erpc.call(peer_node, Application, :ensure_all_started, [:mix])
    :ok = :erpc.call(peer_node, Mix, :env, [:test])
    {:ok, _applications} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])
    peer_node
  end

  defp put_env!(peer_node, key, value) do
    :ok = :erpc.call(peer_node, Application, :put_env, [:ouroboros, key, value])
  end

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    :exit, _reason -> :ok
  end

  defp call(target, module, function, arguments, timeout \\ 60_000)

  defp call(target, module, function, arguments, _timeout) when target == node(),
    do: apply(module, function, arguments)

  defp call(target, module, function, arguments, timeout),
    do: :erpc.call(target, module, function, arguments, timeout)

  defp ets_storage do
    {Jido.Storage.ETS,
     table: String.to_atom("wasm_policy_two_node_#{System.unique_integer([:positive])}")}
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name =
        String.to_atom(
          "ouroboros_wasm_policy_two_node_root_#{System.unique_integer([:positive])}"
        )

      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end
end
