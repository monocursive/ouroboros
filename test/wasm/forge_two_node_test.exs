defmodule Ouroboros.Wasm.ForgeTwoNodeTest do
  @moduledoc """
  A `:builder`-placed forge across a **real** node boundary (docs/WASM.md D29, C14, §14 W22).

  W20 proved the forward on a loopback: `forge_here/2` ran for real behind a fake `:erpc`, so
  everything about the exchange was watched except the one thing distribution does — copy
  terms between machines. This file is that half. The origin is this test VM in the `:core`
  role; the builder is a full-application peer VM booted with `config :ouroboros, :node_role,
  :builder`; the signer is a third peer booted `:signer`, running the application's own named
  `Ouroboros.Upgrade.Signing.Service` from a key file and configuration, exactly as a signer
  host does. The forward goes through the real `Ouroboros.Cluster.nodes_by_role/1` and the
  real `:erpc`: no `:peers` and no `:rpc` seam appears anywhere in the positive path, and no
  option the origin passes names a peer at all — the fleet is read off the cluster, as an
  operator's is.

  The harness is `test/wasm/rollout_two_node_test.exs`'s, unchanged in every load-bearing
  detail, plus the three things a builder needs that a deploy target does not: a warm cargo
  home, a signing node to ask, and a role.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Cluster
  alias Ouroboros.Mesh
  alias Ouroboros.Runtime.Capabilities
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Deploy
  alias Ouroboros.Wasm.Forge
  alias Ouroboros.Wasm.ForgeFixture
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.SandboxFixture

  @signer "wasm-forge-two-node-key"
  # The server-owned principal a forward carries and the origin holds the returned bundle to.
  @author "forge-two-node-principal"

  @needs_build ForgeFixture.tag()

  # What a forwarded forge waits beyond cargo's own ceiling, twice: `Forge`'s `@remote_slack`.
  # Restated here so the arithmetic the deadline test relies on is written where it is used.
  @remote_slack 10_000

  setup_all do
    ForgeFixture.ensure!()
    :ok
  end

  setup do
    ensure_distributed!()

    tmp =
      Path.join(
        System.tmp_dir!(),
        "ouro-wasm-forge-origin-#{:os.getpid()}-#{System.unique_integer([:positive])}"
      )

    File.rm_rf!(tmp)
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)

    # One Ed25519 seed, generated here so the public half is known before any peer boots:
    # every node in this fleet — the origin included — trusts exactly this signer, and the
    # signer peer reads the secret half from a file the way a signer host does.
    {public, seed} = :crypto.generate_key(:eddsa, :ed25519)
    key_path = Path.join(tmp, "signer.key")
    File.write!(key_path, seed)
    File.chmod!(key_path, 0o600)

    trust_policy = [allow_unsigned: false, trusted_signers: %{@signer => public}]

    %{
      tmp: tmp,
      builds: Path.join(tmp, "builds"),
      forged: Path.join(tmp, "forged"),
      uploads: Path.join(tmp, "uploads"),
      store_root: Path.join(tmp, "store"),
      key_path: key_path,
      public: public,
      trust_policy: trust_policy
    }
  end

  ## --------------------------------------------------------------- the round trip

  # Proofs 1, 2 and 7 (the forward half). Red without a real `:builder` peer: with no builder
  # connected the origin refuses `:no_builder_node` before it reads a byte, and that refusal
  # has its own test below. Red without the builder running a helper pool: `forge_here/2` on
  # the builder reads the imports off the bytes it built (D18), and a `:builder` tree that
  # omitted the pool answered `{:imports_unreadable, {:pool_unavailable, …}}` — the defect
  # this file found on its first run (§13 W-F31), with its own regression test below.
  @tag @needs_build
  @tag timeout: 900_000
  test "a forge forwarded over real distribution builds there, signs there, and deploys here",
       context do
    live = origin!(context)
    signer = start_app_peer!(context, :signer)
    builder = start_app_peer!(context, :builder, signing_node: signer.node)

    name = "counter-peer-#{System.unique_integer([:positive])}"
    id = "wasm/" <> name
    on_exit(fn -> Mesh.stop_agent(id) end)
    files = ForgeFixture.counter(name)

    # The fleet as `Ouroboros.Cluster` reports it, through the same multicall `forge/2` uses.
    assert Cluster.nodes_by_role(:builder) == [builder.node]
    assert Cluster.nodes_by_role(:signer) == [signer.node]
    assert Cluster.role() == :core

    # The signer peer is the application's own named service, holding the key this fleet
    # trusts — asked over `:erpc` exactly as the builder is about to ask it.
    assert {:ok, %{signer_id: @signer, public_key: public}} =
             call(signer.node, Service, :public_info, [])

    assert public == context.public

    # The builder's toolchain is its own (D29): its SDK resolves from the code path it runs
    # from, its cache is the one its configuration names, and it runs a helper pool of its own
    # to read the product with.
    assert {:ok, sdk} = call(builder.node, Forge, :sdk_root, [[]])
    assert File.regular?(Path.join(sdk, "Cargo.toml"))
    assert %{cache: :warm, cargo: cargo} = call(builder.node, Forge, :toolchain, [[]])
    assert is_binary(cargo)
    assert is_pid(call(builder.node, Process, :whereis, [Pool]))

    # Proof 7. The operator surface reports the decision before anybody spends a build.
    workspace = proposal!(context, name)

    assert {:ok, preview} = Capabilities.preview(workspace, ".ouroboros/capabilities/Counter")
    assert preview.placement == %{decision: :forward, node: builder.node}
    assert preview.build == :not_placed_here
    assert Forge.placement_report(Forge.placement_here()) == preview.placement

    # Proof 1. Nothing here names a peer: placement comes from this node's configuration, the
    # builder from the cluster, and the signer from the builder's own configuration.
    origin = origin_opts(context, live, name: name, start_config: "{}")
    refute Keyword.has_key?(origin, :peers)
    refute Keyword.has_key?(origin, :rpc)
    refute Keyword.has_key?(origin, :signing_node)
    refute Keyword.has_key?(origin, :signing_service)

    assert {:ok, forged} = Forge.forge(%{files: files}, origin)

    # The receipt is a local forge's in every respect an operator or an effect reads.
    assert forged.name == name
    assert forged.module == id
    assert forged.imports == ["log"]
    assert forged.world == Wasm.world()
    assert forged.signer == @signer
    assert forged.artifact.metadata.author == @author
    assert forged.artifact.metadata.source_sha256 == forged.source_sha256

    # The bytes came back over the wire and were retained **here**, in the origin's own forged
    # root, and the receipt does not carry them.
    refute Map.has_key?(forged, :bundle)
    assert String.starts_with?(forged.bundle_path, context.forged)
    assert File.regular?(forged.bundle_path)

    # What was retained verifies against this node's trust policy and is the artifact the
    # receipt describes — the check the origin makes because it never saw what was signed. And
    # the receipt **is** that artifact's (W-F32): what the builder answered beside the bytes is
    # not what the origin answers with.
    assert {:ok, decoded} = Bundle.verify(File.read!(forged.bundle_path), context.trust_policy)
    assert forged.artifact == decoded.artifact
    assert decoded.artifact.id == forged.artifact_id
    assert decoded.artifact.component_sha256 == forged.component_sha256
    assert decoded.artifact.epoch == forged.epoch
    assert decoded.artifact.signature.signer == forged.signer
    assert decoded.artifact.imports == forged.imports
    refute Map.has_key?(forged, :build_bytes)

    # And the signer journaled the decision under the **builder's** name: it was the builder
    # that asked, from its own configuration, and not this node.
    assert {:ok, decisions} = call(signer.node, Service, :decisions, [])

    assert Enum.any?(decisions, &(&1.decision == :issued and &1.requester == builder.node)),
           "the signer's journal holds no signature issued to #{builder.node}: " <>
             inspect(Enum.map(decisions, &{&1.decision, &1.requester}))

    refute Enum.any?(decisions, &(&1.requester == node()))

    # Proof 2. The builder kept nothing: no bundle anywhere under its data directory, no
    # forged root at all, and an empty build scratch once its own `after` has run.
    assert Path.wildcard(Path.join(builder.data_dir, "**/*" <> Bundle.extension())) == []
    refute File.exists?(Path.join(builder.data_dir, "wasm/forged"))
    assert await_no_builds!(builder) == []

    # H2's claim, across the wire: the receipt is deployable from the origin.
    assert {:ok, outcome} = Forge.deploy(forged.artifact, [node()], origin_opts(context, live))
    assert outcome.state == :live
    assert outcome.name == name
    assert outcome.component_sha256 == forged.component_sha256

    assert is_pid(Mesh.whereis(id))
    assert {:ok, _agent} = Mesh.send_message("forge-two-node", id, %{"add" => 2})
    assert %{"count" => 2} = state(id).last_answer

    assert {:ok, rolled} = Deploy.rollback(name, registry: live.registry)
    assert rolled.state == :rolled_back
    assert Mesh.whereis(id) == nil
  end

  # W-F31's regression, on a peer and without a toolchain: a `:builder` runs a helper pool
  # of its own, under its own supervisor, beside cluster formation — and nothing else. The
  # first cut of D29's `:builder` tree was cluster formation alone, which a lane-B build
  # peer could live with and a lane-W builder could not.
  @tag timeout: 120_000
  test "a :builder peer runs a helper pool of its own and nothing of a core node's", context do
    builder = start_app_peer!(context, :builder)

    assert is_pid(call(builder.node, Process, :whereis, [Pool]))
    assert is_pid(call(builder.node, Process, :whereis, [Wasm.Supervisor]))

    ids =
      builder.node
      |> call(Supervisor, :which_children, [Ouroboros.Supervisor])
      |> Enum.map(&elem(&1, 0))
      |> Enum.sort()

    assert ids == [Cluster, Wasm.Supervisor]
    assert call(builder.node, Process, :whereis, [Ouroboros.Upgrade.NodeExecutor]) == nil
    assert call(builder.node, Process, :whereis, [Registry]) == nil
  end

  ## ------------------------------------------------------------- the refusals

  # Proofs 3, 4 and 7 (the refusal half). A fleet of the origin and a `:signer` peer: no
  # builder anywhere, and a node that must never build reachable by `:erpc`.
  @tag @needs_build
  @tag timeout: 180_000
  test "a :signer peer refuses over the wire, and a fleet with no builder is refused before any RPC",
       context do
    live = origin!(context)
    signer = start_app_peer!(context, :signer)

    name = "counter-refused-#{System.unique_integer([:positive])}"
    files = ForgeFixture.counter(name)

    assert Cluster.nodes_by_role(:builder) == []
    assert Cluster.nodes_by_role(:signer) == [signer.node]

    # A signer never builds, so it runs no helper pool to build with.
    assert call(signer.node, Process, :whereis, [Pool]) == nil

    # Proof 4. Refused by name, before the input is read: this node's scratch root never
    # appears, and neither does the signer's.
    assert {:error, {:forge_refused, :no_builder_node, why}} =
             Forge.forge(%{files: files}, origin_opts(context, live, name: name))

    assert why =~ ":builder"
    refute File.exists?(context.builds)
    refute File.exists?(context.forged)
    refute File.exists?(Path.join(signer.data_dir, "wasm/builds"))

    # Proof 7. The operator surface says so too, with the reason, and does not dry-build.
    workspace = proposal!(context, name)

    assert {:ok, preview} = Capabilities.preview(workspace, ".ouroboros/capabilities/Counter")
    assert %{decision: :refuse, reason: :no_builder_node, detail: detail} = preview.placement
    assert detail =~ ":builder"
    assert preview.build == :not_placed_here
    assert preview.lock == :sdk_lock
    assert Forge.placement_report(Forge.placement_here()) == preview.placement

    # Proof 3. The signer, asked directly over `:erpc` with a valid inline project — which is
    # what a compromised or misconfigured origin would send — refuses as a signer through
    # both entry points, and creates no build directory: the check is in front of the input.
    remote = remote_opts(live, name)

    assert {:error, {:forge_refused, :signer_node, refusal}} =
             call(signer.node, Forge, :forge_here, [%{files: files}, remote])

    assert refusal =~ "signing key"

    assert {:error, {:forge_refused, :signer_node, _}} =
             call(signer.node, Forge, :forge, [%{files: files}, remote])

    refute File.exists?(Path.join(signer.data_dir, "wasm/builds"))
    assert Path.wildcard(Path.join(signer.data_dir, "**/forge-*")) == []
  end

  ## ------------------------------------------------------------- the deadline

  # Proof 5, and the `%{dir: …}` shape. The origin collects the directory and only files
  # cross: the builder materialises them, starts a real cargo under a ceiling too small to
  # finish, and its own named refusal comes back inside the origin's budget. A directory name
  # that had crossed would have been refused `:path_over_the_wire` instead, and that refusal
  # is proved cross-node here too, on the same builder, without a build.
  @tag @needs_build
  @tag timeout: 180_000
  test "the deadline crosses the wire: a real build the builder cannot finish comes back named",
       context do
    live = origin!(context)
    builder = start_app_peer!(context, :builder)

    name = "counter-deadline-#{System.unique_integer([:positive])}"
    files = ForgeFixture.counter(name)
    dir = write_project!(context, name, files)

    # A 22 s budget hands cargo 2 s and the builder's whole forge 12 s (`forwarded_opts/2`):
    # the counter example does not compile from a cold target directory in two seconds.
    budget = 22_000
    started = System.monotonic_time(:millisecond)

    task =
      Task.async(fn ->
        Forge.forge(%{dir: dir}, origin_opts(context, live, name: name, timeout_ms: budget))
      end)

    # The project is on the builder, as files, while cargo runs: the entry file is byte for
    # byte what the origin collected, in a build directory the builder made under its own
    # data directory.
    build = await_build!(builder)
    assert File.read!(Path.join(build, "src/lib.rs")) == Map.fetch!(files, "src/lib.rs")
    assert File.regular?(Path.join(build, "Cargo.lock"))

    assert {:error, {:forge_refused_by, target, reason}} = Task.await(task, budget + 30_000)
    elapsed = System.monotonic_time(:millisecond) - started

    assert target == builder.node

    # Cargo's ceiling is the innermost of the three deadlines and the one that fires, so the
    # refusal is the build's own — not the builder's backstop and not an `:erpc` timeout.
    assert reason == {:build_failed, {:timeout, :deadline}}

    assert elapsed < budget,
           "the builder's refusal took #{elapsed} ms against a #{budget} ms budget"

    assert elapsed >= budget - 2 * @remote_slack,
           "cargo was stopped after #{elapsed} ms, before its #{budget - 2 * @remote_slack} ms ceiling"

    # Nothing outlives the refusal on either side: the builder's build tree is swept and the
    # origin retained nothing it did not receive.
    assert await_no_builds!(builder) == []
    refute File.exists?(context.forged)

    # And the far end refuses a directory by name rather than walking its own filesystem at
    # it — on a real peer, where "its own filesystem" is a different VM's view of this host.
    assert {:error, {:forge_refused, :path_over_the_wire, why}} =
             call(builder.node, Forge, :forge_here, [%{dir: dir}, remote_opts(live, name)])

    assert why =~ "origin's filesystem"
    assert builds_in(builder) == []
  end

  ## ----------------------------------------------------------- a dead builder

  # Proof 6. The origin is waiting on a builder that is compiling, and the builder's VM goes
  # away. Distribution notices a closed connection at once — this is not the net tick, it is
  # the socket — so `:erpc` raises `:noconnection` into `request/4`'s catch and the forge
  # returns a named forward failure promptly, not after the budget.
  @tag @needs_build
  @tag timeout: 180_000
  test "a builder that dies mid-build comes back as a named forward failure, promptly",
       context do
    live = origin!(context)
    builder = start_app_peer!(context, :builder)

    name = "counter-orphaned-#{System.unique_integer([:positive])}"
    files = ForgeFixture.counter(name)
    budget = 120_000

    task =
      Task.async(fn ->
        Forge.forge(%{files: files}, origin_opts(context, live, name: name, timeout_ms: budget))
      end)

    # Cargo is running on the builder: its build directory exists.
    build = await_build!(builder)
    assert File.regular?(Path.join(build, "src/lib.rs"))

    stopped = System.monotonic_time(:millisecond)
    :ok = :peer.stop(builder.peer)

    assert {:error, {:forge_forward_failed, target, {:error, detail}}} =
             Task.await(task, 60_000)

    elapsed = System.monotonic_time(:millisecond) - stopped

    assert target == builder.node
    assert detail =~ "noconnection"

    assert elapsed < 15_000,
           "the origin learned of the dead builder after #{elapsed} ms against a #{budget} ms budget"

    await_disconnected!(builder.node)
    refute File.exists?(context.forged)

    # And the compiler the dead builder was running did not outlive it on this host — the
    # rustc processes, which carry the build directory on their command line; a bare `cargo`
    # that had not yet spawned one would not be matched.
    await_settled!(builder)
  end

  ## --------------------------------------------------------------------- origin

  # The signer, the trust policy, the register and the helper pool the **origin** needs to
  # verify and deploy what comes back — `test/wasm/forge_test.exs`'s `live!/1` without the
  # signing service, which lives on its own peer here.
  defp origin!(context) do
    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)
    Application.put_env(:ouroboros, :upgrade_trust_policy, context.trust_policy)
    on_exit(fn -> restore(:upgrade_trust_policy, previous) end)

    # The operator's setting, on the origin, which is where `forge/2` reads it from.
    placement = Application.get_env(:ouroboros, :wasm_forge_placement)
    Application.put_env(:ouroboros, :wasm_forge_placement, :builder)
    on_exit(fn -> restore(:wasm_forge_placement, placement) end)

    registry_name = :"wasm_forge_two_node_registry_#{System.unique_integer([:positive])}"

    {:ok, registry} =
      Registry.start_link(
        name: registry_name,
        storage:
          {Jido.Storage.ETS,
           table: :"wasm_forge_two_node_rollouts_#{System.unique_integer([:positive])}"}
      )

    on_exit(fn ->
      try do
        GenServer.stop(registry)
      catch
        :exit, _reason -> :ok
      end
    end)

    {:ok, pool} =
      Pool.start(
        [
          name: :"wasm_forge_two_node_pool_#{System.unique_integer([:positive])}",
          handshake_timeout_ms: 15_000
        ]
        |> Keyword.merge(SandboxFixture.pool_opts(context.tmp))
      )

    on_exit(fn ->
      if Process.alive?(pool) do
        try do
          GenServer.stop(pool, :normal, 5_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    %{
      registry: registry_name,
      pool: pool,
      eval: %{
        probes: [
          %{input: %{"add" => 1}, expect: :any_reply},
          %{input: %{"add" => 1}, expect: {:state_matches, :messages_received, 2}}
        ],
        budget_ms: 10_000,
        required: :all
      }
    }
  end

  # Origin-local seams and the attrs, and nothing that names a peer. `:placement` is not here
  # either: the origin reads it from its own configuration, as a node does.
  defp origin_opts(context, live, extra \\ []) do
    [
      author: @author,
      scratch_root: context.builds,
      forged_root: context.forged,
      upload_root: context.uploads,
      store_root: context.store_root,
      # Deliberately **cold and absent**. The origin never builds under `:builder` placement,
      # so this is a fact about this machine that must not travel: a builder that received it
      # would refuse the build for a cold cache, and the review's M5 mutation — forwarding
      # `:cargo_home` — stayed green while this was the same warm directory the builder names
      # in its own configuration. What the positive path proves is that the builder built from
      # its OWN configuration; the allow-list itself is W20's seam pin.
      cargo_home: Path.join(context.tmp, "cold-cargo-home"),
      registry: live.registry,
      pool: live.pool,
      trust_policy: context.trust_policy,
      eval: live.eval
    ] ++ extra
  end

  # What a forward puts on the wire, for the direct `:erpc` calls that bypass `forge/2`.
  defp remote_opts(live, name) do
    [
      author: @author,
      name: name,
      eval: live.eval,
      start_config: "{}",
      timeout_ms: 60_000,
      forge_deadline_ms: 70_000
    ]
  end

  defp write_project!(context, name, files) do
    dir = Path.join(context.tmp, "proposal-" <> name)

    Enum.each(files, fn {path, contents} ->
      target = Path.join(dir, path)
      File.mkdir_p!(Path.dirname(target))
      File.write!(target, contents)
    end)

    dir
  end

  # A workspace holding one lane-W proposal, the way `test/wasm/forge_test.exs` builds one:
  # the counter beside the operator's `manifest.json`. The operator path takes its data
  # directory and its cache from configuration, so both are set here and restored.
  defp proposal!(context, name) do
    previous = Application.get_env(:ouroboros, :data_dir)
    Application.put_env(:ouroboros, :data_dir, context.tmp)
    on_exit(fn -> restore(:data_dir, previous) end)

    previous_home = Application.get_env(:ouroboros, :wasm_forge_cargo_home)
    Application.put_env(:ouroboros, :wasm_forge_cargo_home, ForgeFixture.cargo_home())
    on_exit(fn -> restore(:wasm_forge_cargo_home, previous_home) end)

    workspace = Path.join(context.tmp, "workspace-#{System.unique_integer([:positive])}")
    directory = Path.join(workspace, ".ouroboros/capabilities/Counter")
    File.mkdir_p!(Path.join(directory, "src"))

    Enum.each(ForgeFixture.counter(name), fn {path, contents} ->
      File.write!(Path.join(directory, path), contents)
    end)

    manifest = %{
      "name" => name,
      "description" => "Counts, and says so.",
      "eval" => %{
        "probes" => [
          %{"input" => %{"add" => 1}, "expect" => "any_reply"},
          %{"input" => %{"add" => 1}, "expect" => ["state_matches", "messages_received", 2]}
        ],
        "budget_ms" => 10_000,
        "required" => "all"
      }
    }

    File.write!(Path.join(directory, "manifest.json"), JSON.encode!(manifest))
    workspace
  end

  ## ---------------------------------------------------------------------- peers

  # `test/wasm/rollout_two_node_test.exs`'s peer, unchanged in every load-bearing detail —
  # the `-pa` code path, the 0700 data directory named with the OS pid, `put_env` before the
  # application starts, `Mix.env` told to the peer, the ETS coding storage — plus what a
  # role needs. A `:signer` reads its seed from the file `OUROBOROS_SIGNER_KEY_PATH` names in
  # its environment and signs as `config :ouroboros, :signer_id`, which is how a signer host
  # is configured. A `:builder` names the warm cache it builds against and the signer it asks;
  # its SDK checkout resolves from the code path it runs from and is not configured.
  defp start_app_peer!(context, role, opts \\ []) do
    peer_name = :"ouroboros_wasm_forge_#{role}_#{System.unique_integer([:positive])}"
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    data_dir = Path.join(System.tmp_dir!(), "ouro-wasm-forge-peer-#{:os.getpid()}-#{peer_name}")
    File.rm_rf!(data_dir)
    File.mkdir_p!(data_dir)
    File.chmod!(data_dir, 0o700)
    on_exit(fn -> File.rm_rf(data_dir) end)

    env =
      case role do
        :signer -> [{~c"OUROBOROS_SIGNER_KEY_PATH", String.to_charlist(context.key_path)}]
        _other -> []
      end

    {:ok, peer, peer_node} =
      :peer.start(%{name: peer_name, args: args, env: env, wait_boot: 60_000})

    on_exit(fn -> stop_peer(peer) end)

    put_env!(peer_node, :node_role, role)
    put_env!(peer_node, :upgrade_trust_policy, context.trust_policy)
    put_env!(peer_node, :data_dir, data_dir)
    put_env!(peer_node, :wasm, helper_path: Wasm.helper_path())
    put_env!(peer_node, :coding_storage, {Jido.Storage.ETS, table: peer_name})

    case role do
      :signer ->
        put_env!(peer_node, :signer_id, @signer)

      :builder ->
        put_env!(peer_node, :wasm_forge_cargo_home, ForgeFixture.cargo_home())

        case Keyword.get(opts, :signing_node) do
          nil -> :ok
          signing_node -> put_env!(peer_node, :signing_node, signing_node)
        end
    end

    {:ok, _mix} = :erpc.call(peer_node, Application, :ensure_all_started, [:mix])
    :ok = :erpc.call(peer_node, Mix, :env, [:test])
    {:ok, _applications} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    assert :erpc.call(peer_node, Cluster, :role, []) == role

    %{node: peer_node, peer: peer, data_dir: data_dir}
  end

  defp put_env!(peer_node, key, value) do
    :ok = :erpc.call(peer_node, Application, :put_env, [:ouroboros, key, value])
  end

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    :exit, _reason -> :ok
  end

  defp call(target, module, function, arguments, timeout \\ 60_000),
    do: :erpc.call(target, module, function, arguments, timeout)

  # The peer's build scratch, read from this side of the boundary: the peer's data directory
  # is on this host, so what the origin watches is the same directory the builder writes.
  defp builds_root(peer), do: Path.join(peer.data_dir, "wasm/builds")

  defp builds_in(peer) do
    case File.ls(builds_root(peer)) do
      {:ok, entries} -> entries |> Enum.filter(&String.starts_with?(&1, "forge-")) |> Enum.sort()
      {:error, _absent} -> []
    end
  end

  # 1200 x 25 ms: a build directory appears once the builder has collected, validated and
  # materialised the project, which is quick, and the ceiling is for a builder that never
  # starts rather than a race with one that does.
  defp await_build!(peer, attempts \\ 1_200)

  defp await_build!(peer, 0),
    do: flunk("no build directory appeared under #{builds_root(peer)}")

  defp await_build!(peer, attempts) do
    case builds_in(peer) do
      [entry | _rest] ->
        build = Path.join(builds_root(peer), entry)

        if File.regular?(Path.join(build, "src/lib.rs")),
          do: build,
          else: retry_build(peer, attempts)

      [] ->
        retry_build(peer, attempts)
    end
  end

  defp retry_build(peer, attempts) do
    Process.sleep(25)
    await_build!(peer, attempts - 1)
  end

  # The sweep runs in the builder's own `after`, a moment after its reply is on the wire.
  defp await_no_builds!(peer, attempts \\ 400)
  defp await_no_builds!(peer, 0), do: builds_in(peer)

  defp await_no_builds!(peer, attempts) do
    case builds_in(peer) do
      [] ->
        []

      _some ->
        Process.sleep(25)
        await_no_builds!(peer, attempts - 1)
    end
  end

  # Nothing of the dead builder's build may outlive it: `pgrep -f` over its data directory
  # catches a rustc still compiling in the tree, because every rustc this build spawned carries
  # an `--out-dir` beneath it (`test/wasm/forge_test.exs`'s own check); cargo itself is not
  # matched, so what is watched is the compiler and not its driver. The
  # builder's sandboxed process group is signalled when its VM's port closes, and this is where
  # that is watched rather than supposed.
  defp await_settled!(peer, attempts \\ 400)

  defp await_settled!(peer, 0),
    do: flunk("a build process outlived #{peer.node}: #{survivors(peer)}")

  defp await_settled!(peer, attempts) do
    case survivors(peer) do
      "" ->
        :ok

      _some ->
        Process.sleep(25)
        await_settled!(peer, attempts - 1)
    end
  end

  defp survivors(peer) do
    {output, _status} =
      System.cmd("/usr/bin/pgrep", ["-f", peer.data_dir], stderr_to_stdout: true)

    String.trim(output)
  end

  defp await_disconnected!(target, attempts \\ 400)

  defp await_disconnected!(target, 0),
    do: flunk("#{target} is still connected: #{inspect(Node.list())}")

  defp await_disconnected!(target, attempts) do
    if target in Node.list() do
      Process.sleep(25)
      await_disconnected!(target, attempts - 1)
    else
      :ok
    end
  end

  defp state(agent_id) do
    {:ok, server_state} = Mesh.state(agent_id)
    server_state.agent.state
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp ensure_distributed! do
    unless Node.alive?() do
      name = :"ouroboros_wasm_forge_two_node_root_#{System.unique_integer([:positive])}"
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end
end
