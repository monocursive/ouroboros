defmodule Ouroboros.Wasm.StoreTest do
  # Async: every test writes into a directory of its own and hands `prune/1` a registry of
  # its own. Nothing here touches application environment or a globally named process.
  use ExUnit.Case, async: true

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

      # The shape `Rollout.Registry.Entry` actually has today: a module name and a *source*
      # sha, neither of which is a component sha.
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
