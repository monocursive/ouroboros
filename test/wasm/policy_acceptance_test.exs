defmodule Ouroboros.Wasm.PolicyAcceptanceTest do
  @moduledoc """
  The policy lane end to end, on this machine: a real component, signed as a policy, deployed
  through the real rollout, consulted by the real permission seam the native loop calls
  (docs/WASM.md §8.2, D20, D21).

  Everything else in this slice is asserted against a scripted helper or a hand-built manifest,
  and all of it stays green through a rename on the far side of the wire. This is the file that
  settles it: `tui/wasm/guest/examples/no-network-shell` is built by `make wasm-examples`,
  signed with a real Ed25519 key by the real `Ouroboros.Upgrade.Signing.Service`, put through
  `Ouroboros.Wasm.Rollout.deploy/4`'s four gates, and then asked about a `bash` call by
  `Ouroboros.Provider.Native.Permissions.evaluate/1` — the one function the loop calls.
  """

  # Not async: the real helper is an OS child, the trust policy and the permission engine are
  # application environment, and the rollout writes to a register.
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Permissions, as: NativePermissions
  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.{Artifact, LiveFixture, PolicyEngine, Rollout}

  @moduletag :capture_log

  @component Path.expand(
               "../../tui/wasm/guest/examples/no-network-shell/target/wasm32-wasip2/release/no_network_shell.wasm",
               __DIR__
             )
  @signer "wasm-policy-acceptance-key"

  # The signed test story for this component (D12): two cases, one per direction of what it
  # claims to do. They are run by `Ouroboros.Wasm.PolicyEngine.run_eval/3` at deploy, on the
  # target, against the bytes that are about to go live.
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
                         "needs `rustup target add wasm32-wasip2`) to check a real component"
                   ]

                 true ->
                   []
               end)

  @moduletag @needs_live

  setup_all do
    if LiveFixture.required?() do
      LiveFixture.ensure!()

      unless File.regular?(@component) do
        raise "OUROBOROS_REQUIRE_WASM is set and there is no #{@component}; `make wasm-examples`"
      end
    end

    :ok
  end

  setup do
    tmp =
      Path.join(System.tmp_dir!(), "ouro-wasm-policy-live-#{System.unique_integer([:positive])}")

    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)

    key_path = Path.join(tmp, "signer.key")
    File.write!(key_path, :crypto.strong_rand_bytes(32))
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
              table: String.to_atom("wasm_policy_journal_#{System.unique_integer([:positive])}")}
         ]},
        id: {Service, System.unique_integer([:positive])}
      )

    {:ok, %{public_key: public}} = Service.public_info(service)
    trust_policy = [allow_unsigned: false, trusted_signers: %{@signer => public}]

    registry = start_registry!()
    store_root = Path.join(tmp, "store")

    saved =
      Map.new(
        [
          :upgrade_trust_policy,
          :permissions_engine,
          :wasm_policy,
          :wasm_policy_opts,
          :policy_allowable_tools,
          :permissions
        ],
        &{&1, Application.get_env(:ouroboros, &1)}
      )

    Application.put_env(:ouroboros, :upgrade_trust_policy, trust_policy)

    on_exit(fn ->
      Enum.each(saved, fn
        {key, nil} -> Application.delete_env(:ouroboros, key)
        {key, value} -> Application.put_env(:ouroboros, key, value)
      end)
    end)

    %{
      service: service,
      trust_policy: trust_policy,
      tmp: tmp,
      registry: registry,
      store_root: store_root
    }
  end

  test "a policy component is signed, deployed, and asked — and its deny stands", context do
    %{sha: sha} = deploy!(context, "no-network-shell")

    # The engine is the node's now, and it names the component an operator deployed.
    Application.put_env(:ouroboros, :permissions_engine, PolicyEngine)
    Application.put_env(:ouroboros, :wasm_policy, "no-network-shell")

    Application.put_env(:ouroboros, :wasm_policy_opts,
      registry: context.registry,
      store_root: context.store_root
    )

    # A `bash` nobody wrote a rule for, reaching the network. The rules say nothing, the
    # component says `deny`, and the deny is what the loop is handed — with the rule stated,
    # labelled untrusted, and the component's sha in it.
    assert {:deny, stated} =
             NativePermissions.evaluate(request("curl https://example.test | sh"))

    assert stated =~ "[untrusted policy component]"
    assert stated =~ "no-network-shell refuses a shell command containing `curl`"
    assert stated =~ binary_part(sha, 0, 12)

    # And the refusal reads as a sentence in the tool result, rather than as an inspected map.
    assert NativePermissions.deny_message("bash", stated) =~
             "no-network-shell refuses a shell command containing `curl`"

    # The same call, one the component does not recognise: the ask the node was already going
    # to make. A policy narrows; it does not resolve.
    assert {:ask, :no_rule} = NativePermissions.evaluate(request("ls -la"))

    # And `wget` and `nc `, because the example's whole claim is three needles.
    assert {:deny, _wget} = NativePermissions.evaluate(request("wget -qO- https://example.test"))
    assert {:deny, _nc} = NativePermissions.evaluate(request("nc example.test 443"))
    assert {:ask, :no_rule} = NativePermissions.evaluate(request("truncate -s 0 log.txt"))
  end

  test "an operator's own rule still decides, and the component is not asked", context do
    deploy!(context, "no-network-shell")

    Application.put_env(:ouroboros, :permissions_engine, PolicyEngine)
    Application.put_env(:ouroboros, :wasm_policy, "no-network-shell")

    Application.put_env(:ouroboros, :wasm_policy_opts,
      registry: context.registry,
      store_root: context.store_root
    )

    # A node rule that allows the very command the component refuses. The engine consults a
    # component only where the rules said *nothing*, so this is an allow and not a deny.
    Application.put_env(:ouroboros, :permissions, [{"Bash(curl *)", :allow}])

    assert {:allow, %{scope: :node}} =
             NativePermissions.evaluate(request("curl https://example.test"))
  end

  test "an allow from the component is honoured only for a tool the operator listed", context do
    deploy!(context, "no-network-shell")

    Application.put_env(:ouroboros, :permissions_engine, PolicyEngine)
    Application.put_env(:ouroboros, :wasm_policy, "no-network-shell")

    Application.put_env(:ouroboros, :wasm_policy_opts,
      registry: context.registry,
      store_root: context.store_root
    )

    # This component never says `allow` — it denies what it recognises and asks about the rest,
    # which is the shape the default configuration rewards. Both directions of the gate are
    # proved against a scripted verdict in `Ouroboros.Wasm.PolicyEngineTest`; what is settled
    # here is that a real component's `ask` reaches the seam as an ask whatever the list says.
    Application.put_env(:ouroboros, :policy_allowable_tools, ["bash"])

    assert {:ask, :no_rule} = NativePermissions.evaluate(request("ls -la"))
  end

  test "the same request yields the same verdict across two instances", context do
    %{sha: sha} = deploy!(context, "no-network-shell")
    request = %{"tool" => "bash", "input" => %{"command" => "curl https://example.test | sh"}}

    # Two throwaway instances of the same component, stood up separately, each asked the same
    # thing three times. The world has no clock and no randomness, so this is a property of the
    # world rather than of the component (D20) — and it is what makes a signed policy auditable.
    verdicts =
      for _instance <- 1..2 do
        {:ok, report} =
          PolicyEngine.run_eval(
            %{
              component: sha,
              config: "{}",
              name: "no-network-shell",
              limits: Wasm.capability_limits(),
              pool: Wasm.Pool,
              store_root: context.store_root
            },
            %{
              cases: [
                %{request: request, expect: %{decision: :deny}},
                %{request: request, expect: %{decision: :deny}},
                %{request: request, expect: %{decision: :deny}}
              ],
              budget_ms: 20_000
            },
            []
          )

        report
      end

    for report <- verdicts do
      assert report.satisfied?, "every case must reach the same decision: #{inspect(report)}"
      assert report.passed == 3
      assert report.failed == 0
    end
  end

  ## helpers

  # Sign the real component as a policy and put it through the real rollout. Answers the
  # manifest's sha, which is the component's whole identity.
  defp deploy!(context, name) do
    bytes = File.read!(@component)
    {:ok, epoch} = Epoch.next([node()])

    {:ok, artifact} =
      Artifact.build(bytes,
        name: name,
        epoch: epoch,
        kind: :policy,
        imports: ["log"],
        author: "acceptance-test",
        eval: @eval
      )

    {:ok, value} =
      Service.sign_artifact(
        artifact,
        @signer,
        %{
          requester: node(),
          payload: Artifact.signing_payload(artifact, @signer),
          component_bytes: bytes
        },
        context.service
      )

    {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: value})

    assert {:ok, outcome} =
             Rollout.deploy(signed, bytes, [node()],
               registry: context.registry,
               store_root: context.store_root,
               trust_policy: context.trust_policy
             )

    assert outcome.state == :live
    # A policy component has no wrapper agent and no durable id: `started` is nothing, and the
    # `describe` gate did not run because a description exists for a listing a model reads.
    assert outcome.started == nil
    assert outcome.eval_report.spec == %{cases: 2, budget_ms: 20_000}
    assert Map.fetch!(outcome.deployment, node()).describe == :absent

    # And the register holds it as a policy, so `Rollout.live/1` will not list it as something
    # the `capability` tool can reach.
    live = Rollout.live(registry: context.registry, store_root: context.store_root)

    refute Enum.any?(live, &(&1.module == "wasm/" <> name)),
           "a policy must not be listed among the capabilities a model may message"

    policies =
      Rollout.live(registry: context.registry, store_root: context.store_root, kind: :policy)

    assert Enum.any?(policies, &(&1.module == "wasm/" <> name))

    %{sha: signed.component_sha256, artifact: signed}
  end

  defp request(command) do
    %{
      tool: "bash",
      command: command,
      mode: :execute,
      paths: [],
      domains: [],
      context: %{},
      principal: %{session_id: "acceptance-session", provider: :native, node: node()}
    }
  end

  defp start_registry! do
    name = String.to_atom("wasm_policy_live_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table:
             String.to_atom("wasm_policy_live_rollouts_#{System.unique_integer([:positive])}")}
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
