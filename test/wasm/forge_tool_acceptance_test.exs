defmodule Ouroboros.Wasm.ForgeToolAcceptanceTest do
  @moduledoc """
  S1's whole claim, once, against the real thing: a model session writes a Rust project into
  its workspace with the ordinary tools, previews it, forges it, deploys it, and calls the
  capability it just added to the runtime it is running in.

  Nothing here is faked. The model is scripted — that is the only stand-in, and it is the
  one `test/provider/native/*` uses everywhere — and behind it is `Ouroboros.Wasm.Forge`
  with this machine's cargo, the `wasm32-wasip2` target, the OS sandbox the forge refuses to
  build without, a real `Ouroboros.Upgrade.Signing.Service` holding a key, this node's own
  rollout register, and the sealed `ouro-wasm` helper. The evidence at the end is the
  register's and the effect ledger's, not this test's.

  It is tagged `ForgeFixture.tag()`, so a machine without the toolchain skips it with the
  command that fixes it, and `OUROBOROS_REQUIRE_WASM=1` turns that skip into a failure.
  """

  # Not async, and not remotely: it spawns cargo and the helper as OS children, starts a
  # signing service under the node's own name, and moves `:data_dir`,
  # `:upgrade_trust_policy`, `:native_forge_tool` and `:permissions`, all of which every
  # other process on this node reads from application environment.
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Test.NativeModelScript
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm.ForgeFixture

  @moduletag :capture_log
  @needs_build ForgeFixture.tag()

  @signer "forge-tool-acceptance-key"

  setup_all do
    ForgeFixture.ensure!()
    :ok
  end

  setup do
    root = Path.join(System.tmp_dir!(), "forge-tool-acc-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    data_dir = Path.join(root, "data")
    File.mkdir_p!(workspace)
    File.mkdir_p!(Path.join(root, "session"))
    File.mkdir_p!(data_dir)
    on_exit(fn -> File.rm_rf(root) end)

    put(:data_dir, data_dir)
    put(:native_forge_tool, true)
    # An operator naming their own cache, the way `test/wasm/forge_test.exs` does: the
    # node-local default is a download per temporary data directory rather than a build.
    put(:wasm_forge_cargo_home, ForgeFixture.cargo_home())
    put(:permissions, [])

    signer!(root)
    restart_pool!()

    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)
    session_id = "forge-tool-acc-#{System.unique_integer([:positive, :monotonic])}"

    %{
      root: root,
      workspace: scope.root,
      data_dir: data_dir,
      scope: scope,
      session_dir: Path.join(root, "session"),
      session_id: session_id,
      principal: "session:" <> session_id
    }
  end

  @tag @needs_build
  @tag timeout: 900_000
  test "a session writes a capability, forges it, deploys it, and then calls it", context do
    name = "forge-tool-counter-#{System.unique_integer([:positive])}"
    id = "wasm/" <> name
    on_exit(fn -> Ouroboros.Mesh.stop_agent(id) end)

    # The rules an operator would have written. `Forge(<name>)` is the whole permission
    # claim of this slice: an allow keyed on what will be built, honoured because the forge
    # is held to that exact name.
    put(:permissions, [
      {"Write(**)", :allow},
      {"Forge(#{name})", :allow},
      {"Capability(#{name})", :allow}
    ])

    files = ForgeFixture.counter(name)

    # ── turn one: write the project, preview it, forge it ────────────────────────────
    events =
      turn(context, "turn-1", [
        [write("w1", "project/Cargo.toml", files["Cargo.toml"])],
        [write("w2", "project/Cargo.lock", files["Cargo.lock"])],
        [write("w3", "project/src/lib.rs", files["src/lib.rs"])],
        [write("w4", "project/manifest.json", manifest(name))],
        [
          {:tool_call,
           %{
             id: "p1",
             name: "forge",
             input: %{"operation" => "preview", "name" => name, "path" => "project"}
           }}
        ],
        [
          {:tool_call,
           %{
             id: "f1",
             name: "forge",
             input: %{"operation" => "forge", "name" => name, "path" => "project"}
           }}
        ],
        [{:text, "forged"}, {:finish, :stop}]
      ])

    for call <- ~w(w1 w2 w3 w4), do: refute(result(events, call).payload["is_error"])

    preview = result(events, "p1")
    refute preview.payload["is_error"], preview.payload["output"]
    assert preview.payload["output"] =~ name
    assert preview.payload["output"] =~ "dry build: succeeded"
    # A preview signs nothing and writes no bundle, and says so rather than leaving a model
    # to assume a build it can deploy.
    assert preview.payload["output"] =~ "Nothing was signed"
    assert preview.payload["output"] =~ "evaluation spec: 2 probe(s)"

    forged = result(events, "f1")
    refute forged.payload["is_error"], forged.payload["output"]
    output = forged.payload["output"]

    assert output =~ "Forged and signed #{name}"
    assert output =~ "imports: [\"log\"]"
    assert output =~ Ouroboros.Wasm.world()

    artifact_id = capture(output, ~r/artifact id: (\S+)/)
    component_sha = capture(output, ~r/component sha256: ([0-9a-f]{64})/)

    # The forge's own ledger entry: written before the build, settled with the identity of
    # what came out of it, under this session's principal and nobody else's.
    [forge_entry] = entries(context.principal, :forge)
    assert forge_entry.status == :ok
    assert forge_entry.attempt == %{module: id}
    assert forge_entry.result.artifact_id == artifact_id
    assert forge_entry.result.signer == @signer
    assert String.match?(forge_entry.result.source_sha256, ~r/\A[0-9a-f]{64}\z/)

    # And the decision that admitted it was the rule an operator wrote about this name.
    # The engine records a permission decision under the bare session id, which is what
    # `Control.Permissions.principal_id/1` derives from the request's principal — not the
    # `"session:"`-prefixed one the effect entries above carry.
    assert forge_rule_id = rule_id("Forge(#{name})")
    decisions = permissions(context.session_id)

    assert Enum.any?(decisions, &(&1.result.rule_id == forge_rule_id)),
           "no permission entry named the Forge(#{name}) rule: #{inspect(decisions)}"

    assert Enum.any?(decisions, &(&1.attempt.tool == "forge" and &1.result.decision == :approve))

    # ── turn two: deploy the bundle this session forged ──────────────────────────────
    deployed =
      context
      |> turn("turn-2", [
        [
          {:tool_call,
           %{
             id: "d1",
             name: "forge",
             input: %{"operation" => "deploy", "artifact_id" => artifact_id}
           }}
        ],
        [{:text, "deployed"}, {:finish, :stop}]
      ])
      |> result("d1")

    refute deployed.payload["is_error"], deployed.payload["output"]
    assert deployed.payload["output"] =~ ":live"
    assert deployed.payload["output"] =~ component_sha

    [deploy_entry] = entries(context.principal, :deploy)
    assert deploy_entry.status == :ok
    assert deploy_entry.result.artifact_id == artifact_id
    assert deploy_entry.result.module == id
    assert deploy_entry.result.state == :live

    # The register's own record, including the report from the evaluation the signer
    # required and the rollout ran against the real component.
    assert {:ok, entry} = Registry.get(artifact_id)
    assert entry.state == :live
    assert entry.module == id
    assert entry.component_sha256 == component_sha
    assert is_map(entry.eval_report)
    assert deployed.payload["output"] =~ "evaluation:"

    # ── turn three: call the capability this session just added to the runtime ───────
    called =
      context
      |> turn("turn-3", [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "capability",
             input: %{"operation" => "call", "name" => name, "message" => %{"add" => 3}}
           }}
        ],
        [{:text, "called"}, {:finish, :stop}]
      ])
      |> result("c1")

    refute called.payload["is_error"], called.payload["output"]
    assert called.payload["output"] =~ "[untrusted, authored by the component]"
    assert called.payload["output"] =~ "\"count\":3"
    assert called.payload["output"] =~ component_sha
  end

  @tag @needs_build
  @tag timeout: 900_000
  test "a bundle another principal forged is not this session's to deploy", context do
    name = "forge-tool-other-#{System.unique_integer([:positive])}"
    files = ForgeFixture.counter(name)
    project = Path.join(context.workspace, "other")
    File.mkdir_p!(Path.join(project, "src"))
    Enum.each(files, fn {path, body} -> File.write!(Path.join(project, path), body) end)
    File.write!(Path.join(project, "manifest.json"), manifest(name))

    # Forged directly, under somebody else's principal — the shape of "another session on
    # this node did this", with the bundle in the same ring.
    assert {:ok, forged} =
             Ouroboros.Wasm.Forge.forge(%{dir: project},
               author: "session:somebody-else",
               name: name,
               eval: eval(),
               timeout_ms: Ouroboros.Wasm.Forge.build_timeout([])
             )

    put(:permissions, [{"Forge(*)", :allow}])

    result =
      context
      |> turn("turn-1", [
        [
          {:tool_call,
           %{
             id: "d1",
             name: "forge",
             input: %{"operation" => "deploy", "artifact_id" => forged.artifact_id}
           }}
        ],
        [{:text, "refused"}, {:finish, :stop}]
      ])
      |> result("d1")

    assert result.payload["is_error"]
    assert result.payload["output"] =~ "forged by another principal"

    # Nothing was deployed and nothing was recorded as a deploy: the refusal is before the
    # ledger entry, because a deploy that was never admitted has no attempt to account for.
    assert Registry.get(forged.artifact_id) == :not_found
    assert entries(context.principal, :deploy) == []
  end

  ## Fixtures

  defp write(id, path, content),
    do: {:tool_call, %{id: id, name: "write", input: %{"path" => path, "content" => content}}}

  # The one proposal format: what an operator's `capabilities.admit` reads beside a project,
  # and what this tool reads for the same fields.
  defp manifest(name) do
    JSON.encode!(%{
      "name" => name,
      "description" => "a counter forged by a model session",
      "eval" => %{
        "probes" => [
          %{"input" => %{"add" => 1}, "expect" => "any_reply"},
          %{
            "input" => %{"add" => 1},
            "expect" => ["state_matches", "messages_received", 2]
          }
        ],
        "budget_ms" => 10_000,
        "required" => "all"
      },
      # Without a `start` block the signed manifest declares no durable id, so a deploy
      # registers the rollout and starts nothing — and the capability tool would answer
      # "a live rollout but no agent is running for it". The config is the JSON string
      # `init` receives; the id is derived from the name by the signing policy and is not
      # a manifest's to claim.
      "start" => %{"config" => "{}"}
    })
  end

  defp eval do
    %{
      probes: [
        %{input: %{"add" => 1}, expect: :any_reply},
        %{input: %{"add" => 1}, expect: {:state_matches, :messages_received, 2}}
      ],
      budget_ms: 10_000,
      required: :all
    }
  end

  # A signing service under the name `Ouroboros.Wasm.Deploy` looks for when nothing was
  # passed to it, which is the shape of a single-node operator setup: one machine that is
  # both `:core` and `:signer`. The forge tool passes nothing, deliberately — it is a tool,
  # not a test seam — so this is the only way it can be signed at all.
  defp signer!(root) do
    key_path = Path.join(root, "signer.key")
    File.write!(key_path, :crypto.strong_rand_bytes(32))
    File.chmod!(key_path, 0o600)

    service =
      start_supervised!(
        {Service,
         [
           key_path: key_path,
           signer_id: @signer,
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("forge_tool_acc_#{System.unique_integer([:positive])}")}
         ]}
      )

    {:ok, %{public_key: public}} = Service.public_info(service)

    put(:upgrade_trust_policy, allow_unsigned: false, trusted_signers: %{@signer => public})
    delete(:signing_node)

    service
  end

  # The node's own helper pool computes its sandbox policy — which directories the sealed
  # child may read — when it spawns the helper, from `:data_dir` as it is at that moment.
  # This suite moves `:data_dir`, and the tool reaches the pool the way production does (by
  # its registered name, with no option to point it elsewhere), so the child is restarted
  # here to be spawned under this suite's directory and again on the way out to leave the
  # node as it was found.
  defp restart_pool! do
    cycle = fn ->
      _ = Supervisor.terminate_child(Ouroboros.Wasm.Supervisor, Ouroboros.Wasm.Pool)
      _ = Supervisor.restart_child(Ouroboros.Wasm.Supervisor, Ouroboros.Wasm.Pool)
    end

    cycle.()
    on_exit(cycle)
    :ok
  end

  defp turn(context, turn_id, script) do
    {model_spec, _agent} = NativeModelScript.start(script)
    test = self()

    loop = %Loop{
      emit: fn event -> send(test, {:event, event}) end,
      model_module: NativeModelScript,
      model_spec: model_spec,
      system: "system",
      scope: context.scope,
      session_dir: context.session_dir,
      session_id: context.session_id,
      provider_session_id: "forge-tool-acceptance",
      turn_id: turn_id,
      # The corpus posture: every question is answered rather than blocking, so a call the
      # rules did not decide still runs and is counted. The rules above are what actually
      # admit the forge, and the ledger records which.
      approval_mode: :auto_approve,
      approval_timeout_ms: 2_000
    }

    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "forge a capability")}) end)

    collect()
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:event, event} ->
        collect([event | acc])
    after
      880_000 -> flunk("no terminal turn event")
    end
  end

  defp result(events, call_id) do
    Enum.find(events, &(&1.type == :tool_result and &1.payload["call_id"] == call_id)) ||
      flunk("no tool_result for #{call_id} in #{inspect(Enum.map(events, & &1.type))}")
  end

  defp capture(output, regex) do
    [_whole, captured] = Regex.run(regex, output)
    captured
  end

  defp entries(principal, effect) do
    {:ok, entries} = EffectLedger.list(principal: principal, effect: effect)
    entries
  end

  defp permissions(principal) do
    {:ok, entries} = EffectLedger.list(principal: principal, effect: :permission)
    entries
  end

  defp rule_id(pattern) do
    {:ok, rules} = Permissions.list(scope: :node)

    case Enum.find(rules, &(&1.pattern == pattern)) do
      %{id: id} -> id
      nil -> flunk("no node rule for #{pattern}")
    end
  end

  defp put(key, value) do
    previous = Application.fetch_env(:ouroboros, key)
    Application.put_env(:ouroboros, key, value)
    on_exit(fn -> restore(key, previous) end)
    :ok
  end

  defp delete(key) do
    previous = Application.fetch_env(:ouroboros, key)
    Application.delete_env(:ouroboros, key)
    on_exit(fn -> restore(key, previous) end)
    :ok
  end

  defp restore(key, {:ok, value}), do: Application.put_env(:ouroboros, key, value)
  defp restore(key, :error), do: Application.delete_env(:ouroboros, key)
end
