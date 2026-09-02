defmodule Ouroboros.Wasm.BootTest do
  # Not async: it starts real mesh agents, which live in a cluster-wide `:pg` scope.
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Boot
  alias Ouroboros.Wasm.Store

  # No helper and no component compilation anywhere in this file: the wrapper agent is
  # lazy, so "did the boot restart start it" is answerable without one. What a started
  # wrapper would do with its bytes is the acceptance test's question.
  @bytes "\0asm\x01\x00\x00\x00 pretend this is a component"
  @signer "wasm-boot-test-key"

  setup do
    {public, secret} = :crypto.generate_key(:eddsa, :ed25519)

    root = Path.join(System.tmp_dir!(), "ouro-wasm-boot-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    %{
      root: root,
      secret: secret,
      registry: start_registry!(),
      opts: [store_root: root, trust_policy: [trusted_signers: %{@signer => public}]]
    }
  end

  test "starts the wrapper for a live entry whose manifest declares one", context do
    name = unique_name()
    id = start_id(name)
    artifact = seed!(context, name: name, start: %{id: id, config: ~s({"greeting":"hello"})})

    assert %{started: [started], skipped: [], failed: []} = restart(context)

    assert started.id == id
    assert started.artifact_id == artifact.id
    assert started.node == node()
    assert started.component_sha256 == artifact.component_sha256

    pid = Mesh.whereis(id)
    assert is_pid(pid)

    # All six deciding keys are seeded, and the config is the manifest's rather than the
    # wrapper's default. See `Ouroboros.Wasm.Rollout.start_state/2`.
    {:ok, server_state} = Mesh.state(id)
    state = server_state.agent.state

    assert state.component == artifact.component_sha256
    assert state.config == ~s({"greeting":"hello"})
    assert state.name == artifact.name
    assert state.store_root == context.root
    assert state.pool == Ouroboros.Wasm.Pool
    assert %{fuel: _, memory_bytes: _, deadline_ms: _} = state.limits
  end

  test "running twice is running once: an id already claimed is a success", context do
    name = unique_name()
    id = start_id(name)
    seed!(context, name: name, start: %{id: id, config: "{}"})

    assert %{started: [first]} = restart(context)
    refute Map.get(first, :already_started)

    assert %{started: [second], failed: []} = restart(context)
    assert second.already_started == true
    assert second.id == id

    assert Mesh.whereis(id) == Mesh.whereis(id)
  end

  test "an entry with no start block starts nothing", context do
    artifact = seed!(context, start: nil)

    assert %{started: [], failed: [], skipped: [skipped]} = restart(context)
    assert skipped.reason == :no_start_block
    assert skipped.artifact_id == artifact.id
  end

  test "a manifest this node does not hold is named, not guessed at", context do
    # The shape a node that drove a rollout it was not a target of ends up in: it has the
    # record and not the bytes.
    name = unique_name()

    artifact =
      seed!(context, name: name, start: %{id: start_id(name), config: "{}"}, manifest?: false)

    assert %{started: [], failed: [], skipped: [skipped]} = restart(context)
    assert skipped.reason == :manifest_missing
    assert skipped.artifact_id == artifact.id
  end

  test "a manifest that no longer verifies does not start anything", context do
    name = unique_name()
    id = start_id(name)
    seed!(context, name: name, start: %{id: id, config: "{}"})

    # A different trust policy is the same fact as a tampered manifest, from here.
    assert %{started: [], failed: [], skipped: [skipped]} =
             Boot.restart_live(
               registry: context.registry,
               store_root: context.root,
               trust_policy: [trusted_signers: %{}]
             )

    assert {:manifest_rejected, {:untrusted_signer, @signer}} = skipped.reason
    assert Mesh.whereis(id) == nil
  end

  test "a manifest describing a different component than the entry is refused", context do
    name = unique_name()
    id = start_id(name)

    artifact =
      seed!(context,
        name: name,
        start: %{id: id, config: "{}"},
        register_sha: String.duplicate("b", 64)
      )

    assert %{started: [], failed: [], skipped: [skipped]} = restart(context)

    assert {:component_mismatch, register, manifest} = skipped.reason
    assert register == String.duplicate("b", 64)
    assert manifest == artifact.component_sha256
    assert Mesh.whereis(id) == nil
  end

  test "entries that are not live, and lane-B entries, are not looked at", context do
    # A quarantined lane-W rollout keeps its bytes as evidence (§7.4) and starts nothing.
    name = unique_name()

    quarantined =
      seed!(context, name: name, start: %{id: start_id(name), config: "{}"}, state: :quarantined)

    # And a BEAM rollout carries no component sha, so it is not this restart's business.
    {:ok, beam} =
      Registry.deploying(
        %{
          artifact_id: "beam-#{System.unique_integer([:positive])}",
          module: Ouroboros.Capability.NotWasm,
          epoch: System.unique_integer([:positive, :monotonic]),
          nodes: [node()]
        },
        context.registry
      )

    {:ok, _live} = Registry.mark(beam.artifact_id, :live, [], context.registry)

    assert %{started: [], failed: [], skipped: []} = restart(context)
    assert {:ok, %{state: :quarantined}} = Registry.get(quarantined.id, context.registry)
  end

  test "an id already held by a different component is a failure, never a start", context do
    # Two `:live` entries can name one start id. Whichever boots first takes the name, and
    # counting the loser as started would report *its* sha as running while the winner's
    # component answered for the id — and a reboot would re-elect the same winner, so the
    # report would keep saying it.
    # A start id is `"wasm/" <> name`, so two entries naming one id are two rollouts of the
    # same capability — the ordinary shape of a redeploy that has not finished everywhere.
    # They target different nodes, which is what keeps the register's supersede rule from
    # retiring one of them: overlapping targets is exactly when a later `:live` displaces
    # an earlier one.
    name = unique_name()
    id = start_id(name)

    winner = seed!(context, name: name, start: %{id: id, config: ~s({"who":"winner"})})

    loser =
      seed!(context,
        name: name,
        nodes: [:"boot-test-elsewhere@nowhere"],
        bytes: "\0asm\x01\x00\x00\x00 a different component",
        start: %{id: id, config: ~s({"who":"loser"})}
      )

    refute loser.component_sha256 == winner.component_sha256

    assert %{started: started, failed: failed, skipped: []} = restart(context)

    assert [%{artifact_id: started_id, component_sha256: started_sha}] = started
    assert [%{artifact_id: failed_id, reason: reason}] = failed

    # Whichever the register listed first won the name; the other is a failure naming who
    # actually holds it, and the two agree about which sha that is.
    assert started_id != failed_id
    assert {:start_id_claimed_by, ^started_sha} = reason
    assert Ouroboros.Wasm.Rollout.holder_component(id) == started_sha

    # And the process behind the id is the winner's, not a mix of the two.
    {:ok, server_state} = Mesh.state(id)
    assert server_state.agent.state.component == started_sha
  end

  test "a registry that is not running restarts nothing rather than raising", context do
    assert %{started: [], failed: []} =
             Boot.restart_live(registry: :"wasm-boot-absent-registry", store_root: context.root)
  end

  test "run/0 survives a register that answers with something it cannot read", context do
    # `restart_live/1`'s rescue is the whole safety of this boot task, and `run/0` used to
    # raise a `KeyError` rendering exactly the report that rescue produces — so the one path
    # designed not to take the supervision chain down was the one that did.
    _ = context
    registry = start_supervised!({__MODULE__.NonsenseRegistry, :not_a_list})

    assert %{started: [], failed: [], skipped: [skipped]} =
             Boot.restart_live(registry: registry, store_root: "/nonexistent")

    assert Map.has_key?(skipped, :artifact_id)
    assert Map.has_key?(skipped, :reason)

    # And the shape the supervision tree actually starts returns rather than raising.
    assert :ok = Boot.run()
  end

  defmodule NonsenseRegistry do
    @moduledoc false
    use GenServer

    def start_link(reply), do: GenServer.start_link(__MODULE__, reply)

    @impl true
    def init(reply), do: {:ok, reply}

    @impl true
    def handle_call(:list, _from, reply), do: {:reply, reply, reply}
  end

  test "enabled?/0 is the data directory, because that is where a manifest would be" do
    previous = Application.get_env(:ouroboros, :data_dir)
    on_exit(fn -> restore(:data_dir, previous) end)

    Application.delete_env(:ouroboros, :data_dir)
    refute Boot.enabled?()

    Application.put_env(:ouroboros, :data_dir, "")
    refute Boot.enabled?()

    Application.put_env(:ouroboros, :data_dir, "/tmp/ouro-wasm-boot-enabled")
    assert Boot.enabled?()
  end

  ## Fixtures

  defp restart(context), do: Boot.restart_live([registry: context.registry] ++ context.opts)

  # A signed manifest in the store and a `:live` entry in the register: the two node-local
  # facts a boot restart reads, and nothing else.
  defp seed!(context, opts) do
    start = Keyword.get(opts, :start)
    metadata = if start, do: [start: start], else: []

    {:ok, artifact} =
      Artifact.build(
        Keyword.get(opts, :bytes, @bytes),
        [
          name: Keyword.get(opts, :name, "greeter"),
          author: "test-agent",
          imports: ["log"],
          epoch: Keyword.get(opts, :epoch, System.unique_integer([:positive, :monotonic]))
        ] ++ metadata
      )

    artifact = sign(artifact, context.secret)

    if Keyword.get(opts, :manifest?, true) do
      {:ok, _written} = Store.put_manifest(artifact, root: context.root)
    end

    {:ok, entry} =
      Registry.deploying(
        %{
          artifact_id: artifact.id,
          module: "wasm/" <> artifact.name,
          epoch: artifact.epoch,
          nodes: Keyword.get(opts, :nodes, [node()]),
          component_sha256: Keyword.get(opts, :register_sha, artifact.component_sha256)
        },
        context.registry
      )

    {:ok, _marked} =
      Registry.mark(entry.artifact_id, Keyword.get(opts, :state, :live), [], context.registry)

    if start, do: on_exit(fn -> Mesh.stop_agent(start.id) end)

    artifact
  end

  defp sign(artifact, secret) do
    payload = Artifact.signing_payload(artifact, @signer)
    value = :crypto.sign(:eddsa, :none, payload, [secret, :ed25519])
    {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: value})
    signed
  end

  # A start id is derived from the component's own name and is never free-standing: the
  # signer refuses any other id, and `Ouroboros.Wasm.Rollout.start_block/1` re-derives it
  # rather than reading whatever the manifest said.
  defp unique_name, do: "boot-test-#{System.unique_integer([:positive])}"
  defp start_id(name), do: "wasm/" <> name

  defp start_registry! do
    name = String.to_atom("wasm_boot_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("wasm_boot_rollouts_#{System.unique_integer([:positive])}")}
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

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
