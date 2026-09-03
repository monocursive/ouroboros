defmodule Ouroboros.Wasm.StoreTest do
  # Async: every test writes into a directory of its own and hands `prune/1` a registry of
  # its own. Nothing here touches application environment or a globally named process.
  use ExUnit.Case, async: true

  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Store

  # `Store.protected_shas/1` reads whatever `Ouroboros.Upgrade.Rollout.Registry` exposes,
  # which today is `list/1` over entries that carry no component sha at all. This stands in
  # for it so a test can hand it entries that do — which is exactly the shape checkpoint v3
  # will write in W3 — without inventing a checkpoint version this build cannot read.
  defmodule FakeRegistry do
    @moduledoc false
    use GenServer

    def start_link(entries), do: GenServer.start_link(__MODULE__, entries)

    @impl true
    def init(entries), do: {:ok, entries}

    @impl true
    def handle_call(:list, _from, entries), do: {:reply, entries, entries}
  end

  setup do
    root =
      Path.join(System.tmp_dir!(), "ouro-wasm-store-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(root) end)
    %{root: root, opts: [root: root]}
  end

  describe "content addressing" do
    test "publishes bytes under their own digest and reads them back", %{
      root: root,
      opts: opts
    } do
      bytes = "\0asm\x01\x00\x00\x00 not really a component"
      sha = sha256(bytes)

      assert {:ok, %{sha256: ^sha, path: path, size: size, published: true}} =
               Store.put(bytes, nil, opts)

      assert path == Path.join(root, "sha256-#{sha}.wasm")
      assert size == byte_size(bytes)
      assert {:ok, ^bytes} = Store.fetch(sha, opts)
      assert {:ok, ^path} = Store.path(sha, opts)
      assert {:ok, [%{sha256: ^sha, size: ^size}]} = Store.list(opts)
    end

    test "a sha this store does not hold is not a path", %{opts: opts} do
      sha = sha256("absent")
      assert {:error, {:unknown_component, ^sha}} = Store.path(sha, opts)
      assert {:error, {:unknown_component, ^sha}} = Store.fetch(sha, opts)
    end

    test "a malformed sha is refused before any file is touched", %{opts: opts} do
      assert {:error, {:invalid_sha256, "nope"}} = Store.fetch("nope", opts)
      assert {:error, {:invalid_sha256, _}} = Store.put("bytes", "nope", opts)
      assert {:ok, []} = Store.list(opts)
    end

    test "deleting is idempotent", %{opts: opts} do
      {:ok, %{sha256: sha}} = Store.put("bytes", nil, opts)
      assert :ok = Store.delete(sha, opts)
      assert :ok = Store.delete(sha, opts)
      assert {:ok, []} = Store.list(opts)
    end
  end

  describe "publish once" do
    test "a second put of the same bytes succeeds without rewriting the file", %{opts: opts} do
      bytes = "the same component twice"
      assert {:ok, %{sha256: sha, published: true, path: path}} = Store.put(bytes, nil, opts)

      # The published file is never rewritten, so the inode it was linked under survives.
      {:ok, %{inode: inode}} = File.stat(path)
      assert {:ok, %{sha256: ^sha, published: false, path: ^path}} = Store.put(bytes, nil, opts)
      assert {:ok, %{inode: ^inode}} = File.stat(path)

      assert {:ok, ^bytes} = Store.fetch(sha, opts)
      assert {:ok, [_only_one]} = Store.list(opts)
    end

    test "no temporary file is left behind", %{root: root, opts: opts} do
      {:ok, _} = Store.put("bytes", nil, opts)
      {:ok, _} = Store.put("bytes", nil, opts)

      assert {:ok, names} = File.ls(root)
      assert Enum.reject(names, &String.ends_with?(&1, ".wasm")) == []
    end
  end

  describe "the digest is validated against the bytes" do
    test "put refuses an expected sha the bytes do not hash to", %{opts: opts} do
      bytes = "these bytes"
      wrong = sha256("other bytes")

      assert {:error, {:sha_mismatch, ^wrong, actual}} = Store.put(bytes, wrong, opts)
      assert actual == sha256(bytes)
      assert {:ok, []} = Store.list(opts)
    end

    test "put accepts an expected sha the bytes do hash to, in either case", %{opts: opts} do
      bytes = "these bytes"
      sha = sha256(bytes)

      assert {:ok, %{sha256: ^sha}} = Store.put(bytes, String.upcase(sha), opts)
    end

    test "fetch refuses a file whose bytes no longer hash to its name", %{opts: opts} do
      {:ok, %{sha256: sha, path: path}} = Store.put("honest bytes", nil, opts)
      File.write!(path, "tampered bytes")

      assert {:error, {:corrupt_component, ^sha}} = Store.fetch(sha, opts)
    end
  end

  describe "budget pruning" do
    test "evicts oldest first until the store is under budget", %{opts: opts} do
      {old, middle, new} = three_components(opts)
      registry = start_supervised!({FakeRegistry, []})

      # Two of the three fit; the oldest has to go.
      assert {:ok, report} = Store.prune([budget_bytes: 2_000, registry: registry] ++ opts)
      assert report.evicted == [old]
      assert report.reclaimed == 1_000
      assert report.bytes == 2_000

      assert Enum.map(elem(Store.list(opts), 1), & &1.sha256) == [middle, new]
    end

    test "evicts nothing when the store is already under budget", %{opts: opts} do
      {old, middle, new} = three_components(opts)
      registry = start_supervised!({FakeRegistry, []})

      assert {:ok, %{evicted: [], reclaimed: 0, bytes: 3_000}} =
               Store.prune([budget_bytes: 10_000, registry: registry] ++ opts)

      assert Enum.map(elem(Store.list(opts), 1), & &1.sha256) == [old, middle, new]
    end

    test "never evicts a sha a live, deploying, or quarantined entry references", %{opts: opts} do
      {old, middle, new} = three_components(opts)

      registry =
        start_supervised!(
          {FakeRegistry,
           [
             %{state: :live, component_sha256: old},
             %{state: :deploying, component_sha256: middle},
             %{state: :rolled_back, component_sha256: new}
           ]}
        )

      # Room for one, and the only evictable one is the newest.
      assert {:ok, report} = Store.prune([budget_bytes: 1_000, registry: registry] ++ opts)
      assert report.evicted == [new]
      assert Enum.map(elem(Store.list(opts), 1), & &1.sha256) == [old, middle]
    end

    test "quarantined bytes are kept as evidence", %{opts: opts} do
      {old, _middle, _new} = three_components(opts)

      registry =
        start_supervised!({FakeRegistry, [%{state: :quarantined, component_sha256: old}]})

      assert {:ok, report} = Store.prune([budget_bytes: 0, registry: registry] ++ opts)
      refute old in report.evicted
      assert Enum.map(elem(Store.list(opts), 1), & &1.sha256) == [old]
    end

    test "an entry that names no component protects nothing, which is today's registry", %{
      opts: opts
    } do
      {old, _middle, _new} = three_components(opts)

      # A lane-B rollout: a module name and a *source* sha, neither of which is a component
      # sha. It deployed modules, so it protects no component bytes — which is correct.
      registry =
        start_supervised!(
          {FakeRegistry, [%{state: :live, module: "wasm/echo", source_sha256: old}]}
        )

      assert {:ok, %{evicted: [^old | _rest]}} =
               Store.prune([budget_bytes: 0, registry: registry] ++ opts)
    end

    test "fails closed when the registry answers with a shape this build cannot read", %{
      opts: opts
    } do
      {old, middle, new} = three_components(opts)
      registry = start_supervised!({FakeRegistry, [:not_an_entry]})

      assert {:error, :registry_unavailable} =
               Store.prune([budget_bytes: 0, registry: registry] ++ opts)

      assert Enum.map(elem(Store.list(opts), 1), & &1.sha256) == [old, middle, new]
    end

    test "fails closed when the registry cannot be read", %{opts: opts} do
      {old, middle, new} = three_components(opts)
      absent = :"absent_registry_#{System.unique_integer([:positive])}"

      assert {:error, :registry_unavailable} =
               Store.prune([budget_bytes: 0, registry: absent] ++ opts)

      assert Enum.map(elem(Store.list(opts), 1), & &1.sha256) == [old, middle, new]
    end
  end

  # Everything above hands `protected_shas/1` a stand-in. This hands it the real thing:
  # `Ouroboros.Upgrade.Rollout.Registry` at checkpoint v3, whose entries carry
  # `component_sha256` (docs/WASM.md §7.6). W1 wrote the extraction against a field that
  # did not exist yet; this is it switched on.
  describe "the real rollout registry at checkpoint v3" do
    test "a live, deploying, or quarantined entry protects its component bytes", %{opts: opts} do
      {live, deploying, quarantined} = three_components(opts)
      retired = publish(opts, "retired component bytes")
      registry = start_registry!()

      record!(registry, "wasm/live", live, :live, registry)
      record!(registry, "wasm/deploying", deploying, :deploying, registry)
      record!(registry, "wasm/quarantined", quarantined, :quarantined, registry)
      record!(registry, "wasm/retired", retired, :rolled_back, registry)

      assert {:ok, protected} = Store.protected_shas(registry: registry)

      assert MapSet.member?(protected, live)
      assert MapSet.member?(protected, deploying)
      assert MapSet.member?(protected, quarantined)
      refute MapSet.member?(protected, retired)

      # And a prune with no budget at all evicts only the one nothing references.
      assert {:ok, report} = Store.prune([budget_bytes: 0, registry: registry] ++ opts)
      assert report.evicted == [retired]

      assert Enum.sort(Enum.map(elem(Store.list(opts), 1), & &1.sha256)) ==
               Enum.sort([live, deploying, quarantined])
    end

    test "a lane-B entry names no component and protects nothing", %{opts: opts} do
      sha = publish(opts, "lane B deployed modules, not this")
      registry = start_registry!()

      {:ok, entry} =
        Registry.deploying(
          %{
            artifact_id: "beam-#{System.unique_integer([:positive])}",
            module: Ouroboros.Capability.NotAComponent,
            epoch: System.unique_integer([:positive, :monotonic]),
            nodes: [node()],
            source_sha256: sha
          },
          registry
        )

      {:ok, _live} = Registry.mark(entry.artifact_id, :live, [], registry)

      assert {:ok, protected} = Store.protected_shas(registry: registry)
      assert MapSet.size(protected) == 0

      assert {:ok, %{evicted: [^sha]}} =
               Store.prune([budget_bytes: 0, registry: registry] ++ opts)
    end
  end

  describe "manifests beside the bytes" do
    test "publishes a manifest and reads it back as the artifact that was signed", %{opts: opts} do
      artifact = manifest_artifact!()

      assert {:ok, %{artifact_id: id, path: path, published: true}} =
               Store.put_manifest(artifact, opts)

      assert id == artifact.id
      assert Path.basename(path) =~ ~r/\Amanifest-[0-9a-f]{64}\.manifest\z/
      assert {:ok, read} = Store.fetch_manifest(artifact.id, opts)
      assert read == artifact

      # Exactly, down to the key types. A signed eval spec's `input` is a JSON body with
      # **string** keys, and a boundary that resolved `"n"` to `:n` would change the thing
      # the signature covers — which is why this is not written through
      # `Ouroboros.Upgrade.Wire`.
      assert [%{input: %{"n" => 1}}] = read.metadata.eval.probes

      assert Artifact.signing_payload(read, "store-test-key") ==
               Artifact.signing_payload(artifact, "store-test-key")

      # Publishing is once, and an identical manifest is not a conflict.
      assert {:ok, %{published: false}} = Store.put_manifest(artifact, opts)
    end

    test "a different manifest under one artifact id is a conflict, never an overwrite", %{
      opts: opts
    } do
      artifact = manifest_artifact!()
      moved = %{artifact | epoch: artifact.epoch + 1}

      assert {:ok, %{published: true}} = Store.put_manifest(artifact, opts)
      assert {:error, {:manifest_conflict, id}} = Store.put_manifest(moved, opts)
      assert id == artifact.id

      # The record on disk is still the first one.
      assert {:ok, ^artifact} = Store.fetch_manifest(artifact.id, opts)
    end

    test "an absent or unreadable manifest is named rather than guessed at", %{
      root: root,
      opts: opts
    } do
      assert {:error, {:unknown_manifest, "nobody"}} = Store.fetch_manifest("nobody", opts)

      artifact = manifest_artifact!()
      {:ok, %{path: path}} = Store.put_manifest(artifact, opts)
      File.write!(path, "not a term at all")

      assert {:error, {:unreadable_manifest, id}} = Store.fetch_manifest(artifact.id, opts)
      assert id == artifact.id

      # A manifest is about a kilobyte. Anything this large is not one, and is refused on
      # its size rather than read into memory to find out.
      File.write!(path, :binary.copy("x", 2 * 1024 * 1024))

      assert {:error, {:manifest_too_large, ^id, size}} = Store.fetch_manifest(artifact.id, opts)
      assert size == 2 * 1024 * 1024

      # A manifest is not a component — `components/1` still says nothing is held — but it
      # is a file on this disk, so `list/1` reports it under its own kind and its bytes
      # count against the budget a prune enforces.
      assert {:ok, []} = Store.components(opts)
      assert {:ok, [%{kind: :manifest, size: size}]} = Store.list(opts)
      assert size == 2 * 1024 * 1024
      assert File.exists?(Path.join(root, Path.basename(path)))
    end

    test "a manifest is bounded on the way in at the size it is read back under", %{opts: opts} do
      # A manifest published above the read ceiling is a durable, unprunable file that no
      # reboot can ever use: `fetch_manifest/2` refuses it on its size, and nothing rewrites
      # it. One bound, both directions.
      fat = manifest_artifact!(language: String.duplicate("L", 1_200_000))

      assert {:error, {:manifest_too_large, id, bytes}} = Store.put_manifest(fat, opts)
      assert id == fat.id
      assert bytes > 1024 * 1024

      assert {:error, {:unknown_manifest, ^id}} = Store.fetch_manifest(fat.id, opts)
      assert {:ok, []} = Store.list(opts)
    end

    test "manifest bytes count against the prune budget", %{opts: opts} do
      registry = start_registry!()
      artifact = manifest_artifact!()

      assert {:ok, _put} = Store.put_manifest(artifact, opts)
      assert {:ok, %{size: manifest_bytes}} = one_manifest(opts)

      # A budget that ignored a whole class of files in the directory it governs was a
      # budget the store exceeded quietly.
      assert {:ok, report} = Store.prune([budget_bytes: 10_000_000, registry: registry] ++ opts)
      assert report.bytes == manifest_bytes
      assert report.evicted == []

      # And a manifest is never the thing evicted to get back under it.
      assert {:ok, _report} = Store.prune([budget_bytes: 0, registry: registry] ++ opts)
      assert {:ok, %{size: ^manifest_bytes}} = one_manifest(opts)
    end

    test "a stale manifest temporary is swept like any other", %{root: root, opts: opts} do
      File.mkdir_p!(root)
      leftover = Path.join(root, "manifest-#{String.duplicate("a", 64)}.manifest.tmp-xyz")
      File.write!(leftover, "half a manifest")

      registry = start_registry!()

      assert {:ok, report} =
               Store.prune([temp_grace_seconds: 0, registry: registry] ++ opts)

      assert Path.basename(leftover) in report.swept
      refute File.exists?(leftover)
    end
  end

  describe "pruning sweeps stale temporaries (F5)" do
    test "a stale .tmp- leftover is swept while a fresh one is left alone", %{
      root: root,
      opts: opts
    } do
      {:ok, _real} = Store.put("a real component", nil, opts)
      sha = String.duplicate("a", 64)

      # A crash mid-put leaves this behind: content addressing never sees it (it does not end
      # in `.wasm`) and nothing else removes it, so it would defeat the byte budget silently.
      stale = Path.join(root, "sha256-#{sha}.wasm.tmp-oldcrash")
      File.write!(stale, "leftover")
      File.touch!(stale, System.os_time(:second) - 7_200)

      # A concurrent put's own in-flight temp, moments old: must never be swept.
      fresh = Path.join(root, "sha256-#{sha}.wasm.tmp-inflight")
      File.write!(fresh, "still being written")

      registry = start_supervised!({FakeRegistry, []})

      assert {:ok, %{swept: swept}} =
               Store.prune([budget_bytes: 1_000_000_000, registry: registry] ++ opts)

      assert "sha256-#{sha}.wasm.tmp-oldcrash" in swept
      refute File.exists?(stale)
      assert File.exists?(fresh)

      # The real component was never at risk.
      assert {:ok, [_one]} = Store.list(opts)
    end

    test "a stale temp is swept even when the registry is unavailable", %{root: root, opts: opts} do
      {:ok, _real} = Store.put("a real component", nil, opts)
      sha = String.duplicate("b", 64)
      stale = Path.join(root, "sha256-#{sha}.wasm.tmp-oldcrash")
      File.write!(stale, "leftover")
      File.touch!(stale, System.os_time(:second) - 7_200)

      absent = :"absent_registry_#{System.unique_integer([:positive])}"

      # Pruning fails closed on the eviction decision, but a leaked temp references nothing,
      # so the sweep still runs.
      assert {:error, :registry_unavailable} =
               Store.prune([budget_bytes: 0, registry: absent] ++ opts)

      refute File.exists?(stale)
    end
  end

  describe "the second form (W8)" do
    test "an artifact is published under its own digest, and a wrong one is refused", %{
      opts: opts
    } do
      artifact = "OUROCWASM and its machine code"
      sha = sha256(artifact)

      # The caller says which artifact it believes it is holding, and a mismatch means one of
      # the two is wrong. Delete `check_expected/2` from `put_precompiled/3` and this file is
      # published under a name that is not its content — which is the whole of what makes it
      # safe for a helper to map without validating it (D24).
      assert {:error, {:sha_mismatch, _, ^sha}} =
               Store.put_precompiled(artifact, String.duplicate("a", 64), opts)

      assert {:ok, %{sha256: ^sha, published: true}} = Store.put_precompiled(artifact, sha, opts)
      assert {:ok, %{published: false}} = Store.put_precompiled(artifact, sha, opts)

      assert {:ok, path} = Store.precompiled_path(sha, opts)
      assert Path.basename(path) == "cwasm-#{sha}.cwasm"

      # A listing sees it as its own kind, beside the components and the manifests.
      assert {:ok, entries} = Store.list(opts)
      assert [%{kind: :precompiled, sha256: ^sha}] = entries
    end

    test "a rotted artifact is not offered, and `verify: false` says so", %{opts: opts} do
      artifact = "OUROCWASM and its machine code"
      sha = sha256(artifact)
      {:ok, %{path: path}} = Store.put_precompiled(artifact, sha, opts)

      File.write!(path, "OUROCWASM and somebody else's")

      assert {:error, {:corrupt_precompiled, ^sha}} = Store.precompiled_path(sha, opts)
      assert {:ok, ^path} = Store.precompiled_path(sha, [verify: false] ++ opts)
      assert {:error, {:unknown_precompiled, _}} = Store.precompiled_path(sha256("absent"), opts)
    end

    test "an artifact is a prune candidate, and a live entry's artifact is protected", %{
      opts: opts
    } do
      component = publish(opts, "\0asm\x0d\x00\x01\x00 a live component")
      artifact = "OUROCWASM for the live one"
      {:ok, %{sha256: held}} = Store.put_precompiled(artifact, sha256(artifact), opts)

      orphan = "OUROCWASM for nothing at all"
      {:ok, %{sha256: unreferenced}} = Store.put_precompiled(orphan, sha256(orphan), opts)

      registry = start_registry!()
      artifact_id = record_live!(registry, "wasm/live", component)

      {:ok, manifest} =
        Artifact.build("\0asm\x0d\x00\x01\x00 a live component",
          id: artifact_id,
          name: "live",
          epoch: 7,
          author: "test",
          imports: [],
          precompiled: %{
            wasmtime: "48.0.1",
            target: "aarch64-apple-darwin",
            sha256: held,
            size: byte_size(artifact)
          }
        )

      {:ok, _} = Store.put_manifest(manifest, opts)

      # The register names the component and nothing else — identity is the component (D2) — so
      # the artifact a live entry depends on is read out of the *manifest* that entry points at.
      # Delete `precompiled_shas/2` from `protected_shas/1` and a prune evicts the fast form of
      # a running capability, which then silently recompiles on every helper restart.
      assert {:ok, protected} = Store.protected_shas([registry: registry] ++ opts)
      assert MapSet.member?(protected, component)
      assert MapSet.member?(protected, held)
      refute MapSet.member?(protected, unreferenced)

      # And an artifact nothing references *is* evictable, which it has to be: it is several
      # times the component it came from, and a budget that could not reach it would be one the
      # fast path walked straight through. Delete `:precompiled` from the prune's candidate
      # filter and `evicted` is empty here.
      assert {:ok, report} = Store.prune([budget_bytes: 0, registry: registry] ++ opts)
      assert report.evicted == [unreferenced]
      assert {:ok, _still_there} = Store.precompiled_path(held, opts)
    end
  end

  describe "a component file is what it claims (F10)" do
    @describetag :symlink

    test "a symlink planted at a component name is not treated as a component", %{
      root: root,
      opts: opts
    } do
      {:ok, %{sha256: real_sha, path: real_path}} = Store.put("real component bytes", nil, opts)

      fake_sha = String.duplicate("c", 64)
      link = Path.join(root, "sha256-#{fake_sha}.wasm")
      File.ln_s!(real_path, link)

      # `list` (and therefore `prune`) does not report the symlink's target as a component.
      assert {:ok, [%{sha256: ^real_sha}]} = Store.list(opts)

      # `path` refuses the planted name rather than resolving it.
      assert {:error, {:unknown_component, ^fake_sha}} = Store.path(fake_sha, opts)

      # `fetch` reads through the link but the digest does not match the name, so it is an
      # error rather than wrong bytes returned.
      assert {:error, {:corrupt_component, ^fake_sha}} = Store.fetch(fake_sha, opts)
    end

    test "publish-once refuses a symlink squatting on a real component's name", %{
      root: root,
      opts: opts
    } do
      bytes = "the honest bytes"
      sha = sha256(bytes)
      File.mkdir_p!(root)
      link = Path.join(root, "sha256-#{sha}.wasm")
      # Point it anywhere real; publish-once must reject it on being a symlink, not on its
      # target's bytes.
      File.ln_s!(Path.join(root, "decoy"), link)
      File.write!(Path.join(root, "decoy"), bytes)

      assert {:error, {:invalid_component_file, ^sha, :symlink}} = Store.put(bytes, nil, opts)
    end
  end

  ## Helpers

  # Three components of a thousand bytes each, with distinct mtimes so "oldest" is a fact
  # rather than a filesystem timestamp resolution. Returned oldest first.
  defp three_components(opts) do
    now = System.os_time(:second)

    [old, middle, new] =
      Enum.map([{"a", -300}, {"b", -200}, {"c", -100}], fn {seed, age} ->
        {:ok, %{sha256: sha, path: path}} =
          Store.put(String.duplicate(seed, 1_000), nil, opts)

        File.touch!(path, now + age)
        sha
      end)

    {old, middle, new}
  end

  # One `:live` lane-W entry, and the artifact id it was recorded under.
  defp record_live!(registry, module, component_sha256) do
    artifact_id = "rollout-#{System.unique_integer([:positive])}"

    {:ok, _entry} =
      Registry.deploying(
        %{
          artifact_id: artifact_id,
          module: module,
          epoch: System.unique_integer([:positive, :monotonic]),
          nodes: [node()],
          component_sha256: component_sha256
        },
        registry
      )

    {:ok, _live} = Registry.mark(artifact_id, :live, [], registry)
    artifact_id
  end

  defp publish(opts, bytes) do
    {:ok, %{sha256: sha}} = Store.put(bytes, nil, opts)
    sha
  end

  # One lane-W rollout in the register, at `state`, naming `component_sha256`.
  defp record!(_registry, module, component_sha256, state, server) do
    artifact_id = "rollout-#{System.unique_integer([:positive])}"

    {:ok, entry} =
      Registry.deploying(
        %{
          artifact_id: artifact_id,
          module: module,
          epoch: System.unique_integer([:positive, :monotonic]),
          nodes: [node()],
          component_sha256: component_sha256
        },
        server
      )

    if state == :deploying do
      entry
    else
      {:ok, marked} = Registry.mark(artifact_id, state, [], server)
      marked
    end
  end

  defp start_registry! do
    name = String.to_atom("wasm_store_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("wasm_store_rollouts_#{System.unique_integer([:positive])}")}
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

  defp one_manifest(opts) do
    with {:ok, entries} <- Store.list(opts) do
      case Enum.filter(entries, &(&1.kind == :manifest)) do
        [manifest] -> {:ok, manifest}
        other -> {:error, other}
      end
    end
  end

  defp manifest_artifact!(extra \\ []) do
    {:ok, artifact} =
      Artifact.build(
        "\0asm\x01\x00\x00\x00 manifest fixture #{System.unique_integer([:positive])}",
        Keyword.merge(
          [
            name: "greeter",
            author: "test-agent",
            imports: ["log"],
            epoch: System.unique_integer([:positive, :monotonic]),
            eval: %{probes: [%{input: %{"n" => 1}, expect: :any_reply}], budget_ms: 1_000},
            start: %{id: "wasm/greeter", config: "{}"}
          ],
          extra
        )
      )

    {:ok, signed} =
      Artifact.with_signature(artifact, %{
        signer: "store-test-key",
        value: :binary.copy(<<9>>, 64)
      })

    signed
  end

  defp sha256(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
end

defmodule Ouroboros.Wasm.StoreNoDataDirTest do
  # Not async: this reads the global `:ouroboros, :data_dir` application key. Every other
  # store test passes an explicit `:root` and touches nothing global, so those stay async;
  # this one is separated out rather than making the whole file serial (F8).
  use ExUnit.Case, async: false

  alias Ouroboros.Wasm.Store

  test "a node with no data directory says so rather than inventing a store" do
    # The suite configures no `:data_dir`, and no `:root` is passed.
    assert Application.get_env(:ouroboros, :data_dir) in [nil, ""]

    assert {:error, :no_data_dir} = Store.root()
    assert {:error, :no_data_dir} = Store.put("bytes")
    assert {:error, :no_data_dir} = Store.list()
    assert {:error, :no_data_dir} = Store.prune()
  end
end
