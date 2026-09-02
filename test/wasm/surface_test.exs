defmodule Ouroboros.Wasm.SurfaceTest do
  # Async: every test is handed a store directory, a register and a pool of its own. The
  # only global this reads is `:store_budget_bytes`, which nothing here writes.
  use ExUnit.Case, async: true

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Store
  alias Ouroboros.Wasm.Surface

  @moduletag :capture_log

  # A pool that answers `:status` from a fixed report and **counts every message it gets**.
  #
  # The real-pool test below cannot prove "this starts nothing": it points a pool at a binary
  # that does not exist, so the phase stays `:idle` whatever this module does — adding a
  # `Pool.doctor/1` call to `pool_status/1` passes it. This one bites, because a surface that
  # asked the pool to *do* anything would send `{:request, …}` and the counter would say so.
  defmodule CountingPool do
    @moduledoc false
    use GenServer

    def start_link(status), do: GenServer.start_link(__MODULE__, status)

    @impl true
    def init(status), do: {:ok, %{status: status, calls: 0, requests: 0}}

    @impl true
    def handle_call(:status, _from, state),
      do: {:reply, state.status, %{state | calls: state.calls + 1}}

    def handle_call(:calls, _from, state), do: {:reply, state.calls, state}
    def handle_call(:requests, _from, state), do: {:reply, state.requests, state}

    # `doctor`, `load`, `instantiate`, `call`, `drop` — every one of them arrives as
    # `{:request, …}`. A read-only surface sends none of them, so any that arrives is
    # recorded and refused rather than served.
    def handle_call(_anything_that_would_do_work, _from, state),
      do:
        {:reply, {:error, :a_read_only_surface_asks_a_pool_for_nothing},
         %{state | requests: state.requests + 1}}
  end

  # A register that answers `:list` with exactly the entries a test hands it. The real one
  # retains 200 by configuration, which is below the row ceiling this has to exercise, and
  # it will not hold a malformed row at all.
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
    root = Path.join(System.tmp_dir!(), "ouro-wasm-surface-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(root) end)

    %{root: root, registry: start_registry!()}
  end

  describe "status/1 starts nothing" do
    test "a node with no pool process reports `:absent`, which is not `:broken`", context do
      status = Surface.status([pool: :a_pool_this_node_never_started] ++ opts(context))

      assert status.node == node()
      assert status.helper.phase == :absent
      assert status.helper.os_pid == nil
      assert status.helper.instances == 0
      assert status.helper.hook_components == 0
      assert status.helper.broken_reason == nil
    end

    test "an idle pool stays idle: reading the status spawns no helper", context do
      pool = start_pool!()
      assert %{phase: :idle, os_pid: nil} = Pool.status(pool)

      status = Surface.status([pool: pool] ++ opts(context))

      assert status.helper.phase == :idle
      assert status.helper.os_pid == nil
      assert status.helper.usable == nil
      assert status.helper.worlds == []
      assert status.helper.limits == nil

      # The whole claim of this verb, asserted rather than described: after answering, the
      # pool holds no child and the helper was never spawned.
      assert %{phase: :idle, os_pid: nil, doctor: nil} = Pool.status(pool)
    end

    test "the helper's disk presence and the node's world are always reported", context do
      status = Surface.status([pool: :a_pool_this_node_never_started] ++ opts(context))

      assert status.helper.present == Wasm.available?()

      # A basename, never the absolute path: both verbs are `:read`, the lowest scope the
      # gateway has, and an install prefix (often with an account name in it) is a fact
      # about this operator's disk rather than about lane W.
      assert status.helper.path == Path.basename(Wasm.helper_path())
      refute String.contains?(status.helper.path, "/")
      assert status.helper.world == Wasm.world()
      assert status.helper.hook_component_budget == Pool.hook_component_budget()
    end

    test "a running pool's own helper path is what is reported, and what `present` stats",
         context do
      pool = start_pool!()

      status = Surface.status([pool: pool] ++ opts(context))

      # The pool in this test was started against a path that names nothing, which is what
      # `present: false` has to mean here — not the module's answer for this checkout.
      assert status.helper.path == Path.basename(Pool.status(pool).helper_path)
      assert status.helper.present == false
    end
  end

  describe "status/1 — the store" do
    test "counts what is held, the bytes it occupies, and what a rollout protects", context do
      {:ok, %{sha256: kept}} = Store.put("\0asm keeper", nil, opts(context))
      {:ok, %{sha256: loose}} = Store.put("\0asm loose bytes here", nil, opts(context))

      live!(context, "vet", kept)

      status = Surface.status(opts(context))

      assert status.store.root == Path.basename(context.root)
      refute String.contains?(status.store.root, "/")
      assert status.store.held == 2
      assert status.store.bytes == byte_size("\0asm keeper") + byte_size("\0asm loose bytes here")
      assert status.store.budget_bytes == Wasm.config(:store_budget_bytes)
      assert status.store.protected == 1

      refute loose == kept
    end

    test "no data directory is no store, and that is `nil` rather than zero" do
      status = Surface.status(root: nil, registry: :a_register_that_is_not_running)

      # `root: nil` falls through to `:data_dir`, which the suite does not set.
      assert status.store.root == nil
      assert status.store.held == nil
      assert status.store.bytes == nil
    end

    test "a register that is not running leaves protection unknown, never zero", context do
      {:ok, _entry} = Store.put("\0asm orphan", nil, opts(context))

      status = Surface.status(root: context.root, registry: :a_register_that_is_not_running)

      assert status.store.held == 1
      assert status.store.protected == nil
      assert status.rollouts.total == nil
      assert status.rollouts.by_state == %{}
    end
  end

  describe "status/1 — rollouts" do
    test "counts lane-W entries by state and zero-fills the ones with none", context do
      live!(context, "vet", String.duplicate("a", 64))
      quarantined!(context, "lint", String.duplicate("b", 64))

      status = Surface.status(opts(context))

      assert status.rollouts.total == 2

      assert status.rollouts.by_state == %{
               deploying: 0,
               live: 1,
               superseded: 0,
               rolled_back: 0,
               quarantined: 1
             }
    end

    test "a lane-B rollout is not lane W and is not counted here", context do
      {:ok, _entry} =
        Registry.deploying(
          %{
            artifact_id: "lane-b-1",
            module: Ouroboros.Wasm.SurfaceTest,
            epoch: 1,
            nodes: [node()]
          },
          context.registry
        )

      assert Surface.status(opts(context)).rollouts.total == 0
    end
  end

  describe "list/1" do
    test "lists lane-W rollouts and held components, both sorted by their own identity",
         context do
      big = String.duplicate("b", 64)
      small = String.duplicate("a", 64)

      # Published in the order that makes an mtime sort disagree with a digest sort.
      {:ok, %{sha256: ^big}} = put_named(context, big)
      {:ok, %{sha256: ^small}} = put_named(context, small)

      live!(context, "vet", small, "wasm-2")
      quarantined!(context, "lint", big, "wasm-1")

      list = Surface.list(opts(context))

      assert list.node == node()
      assert Enum.map(list.rollouts, & &1.artifact_id) == ["wasm-1", "wasm-2"]
      assert Enum.map(list.components, & &1.sha256) == [small, big]
      assert list.rollout_count == 2
      assert list.component_count == 2

      [quarantined, live] = list.rollouts

      assert quarantined.name == "lint"
      assert quarantined.state == :quarantined
      assert quarantined.component_sha256 == big
      assert live.name == "vet"
      assert live.state == :live
      assert live.nodes == [Atom.to_string(node())]
      assert is_binary(live.created_at) and is_binary(live.updated_at)
    end

    test "a rollout row is a listing, not a record: no detail, no eval report", context do
      live!(context, "vet", String.duplicate("a", 64))

      [row] = Surface.list(opts(context)).rollouts

      assert Map.keys(row) |> Enum.sort() == [
               :artifact_id,
               :component_sha256,
               :created_at,
               :epoch,
               :name,
               :nodes,
               :state,
               :updated_at
             ]
    end

    test "a component row carries the digest, the size and the mtime, and nothing else",
         context do
      {:ok, %{sha256: sha}} = Store.put("\0asm one", nil, opts(context))

      [row] = Surface.list(opts(context)).components

      assert Map.keys(row) |> Enum.sort() == [:mtime, :sha256, :size]
      assert row.sha256 == sha
      assert row.size == byte_size("\0asm one")
      assert is_integer(row.mtime)
    end

    test "an unreadable store and an unavailable register are empty lists with nil counts" do
      # A directory this process may not read, rather than `root: nil`: `nil` falls through
      # to the global `:data_dir`, which other test files set, and an `async: true` module
      # that asserts on global application environment is a flake waiting for a neighbour.
      unreadable =
        Path.join(
          System.tmp_dir!(),
          "ouroboros-surface-unreadable-#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(unreadable)
      File.chmod!(unreadable, 0o000)
      on_exit(fn -> File.chmod(unreadable, 0o700) && File.rm_rf(unreadable) end)

      list = Surface.list(root: unreadable, registry: :a_register_that_is_not_running)

      assert list.rollouts == []
      assert list.components == []
      assert list.rollout_count == nil
      assert list.component_count == nil
    end
  end

  describe "wire hygiene" do
    test "every leaf either encodes as JSON or is an atom the runtime chose", context do
      live!(context, "vet", String.duplicate("a", 64))
      {:ok, _entry} = Store.put("\0asm one", nil, opts(context))

      for answer <- [Surface.status(opts(context)), Surface.list(opts(context))] do
        assert portable?(answer), "an unportable leaf reached the wire: #{inspect(answer)}"
      end
    end
  end

  describe "nothing helper-written reaches the wire unbounded" do
    test "a string ending on a multi-byte character at the ceiling stays a valid string",
         context do
      # 511 ASCII bytes and one two-byte character: 513 bytes, so the cut lands *inside* the
      # `é`. A raw `binary_part/3` keeps the lead byte alone, `Wire` then renders the result
      # as a `%{"_b64" => …}` object rather than a string, and the Rust client's string
      # decode drops it — a helper that picked this boundary would hide its own version.
      edge = String.duplicate("a", 511) <> "é"
      assert byte_size(edge) == 513

      status = with_report(context, %{"wasmtime" => edge, "worlds" => [edge, Wasm.world()]})

      assert String.valid?(status.helper.wasmtime)
      assert byte_size(status.helper.wasmtime) <= 512
      assert status.helper.wasmtime == String.duplicate("a", 511)

      assert Enum.all?(status.helper.worlds, &String.valid?/1)
      assert Enum.all?(status.helper.worlds, &(byte_size(&1) <= 512))

      # The claim that matters is what the encoder does with it: strings, not base64 blobs.
      encoded = Wire.to_json(status)
      assert is_binary(encoded["helper"]["wasmtime"])
      assert Enum.all?(encoded["helper"]["worlds"], &is_binary/1)
    end

    test "a string that is not UTF-8 at all is nothing, rather than a blob", context do
      status = with_report(context, %{"wasmtime" => <<0xFF, 0xFE>>, "worlds" => [<<0xFF>>]})

      assert status.helper.wasmtime == nil
      assert status.helper.worlds == []
      assert is_binary(Wire.to_json(status)["helper"]["world"])
    end

    test "the limits table is bounded in bytes, not only in key count", context do
      # A count alone bounds nothing: this is 100 keys of ~200 KB, which a count-only bound
      # would forward as megabytes crossing `:erpc` on every poll.
      hostile = Map.new(1..100, fn n -> {String.duplicate("k#{n}", 50_000), n} end)
      status = with_report(context, %{"limits" => hostile})

      assert map_size(status.helper.limits) <= 32
      assert Enum.all?(Map.keys(status.helper.limits), &(byte_size(&1) <= 512))

      encoded = status |> Wire.to_json() |> JSON.encode!() |> byte_size()
      assert encoded < 64 * 1024, "a status answer of #{encoded} bytes is not a status answer"
    end

    test "a legitimate table larger than the ceiling keeps 32 keys and sorts them", context do
      wide = Map.new(0..99, fn n -> {"bound_#{String.pad_leading("#{n}", 3, "0")}", n} end)
      status = with_report(context, %{"limits" => wide})

      assert map_size(status.helper.limits) == 32
      assert Enum.all?(Map.keys(status.helper.limits), &(byte_size(&1) <= 512))
      # Deterministic for one report: the same report always projects the same table.
      assert Surface.status(pool_opts(context, %{"limits" => wide})).helper.limits ==
               status.helper.limits
    end

    test "a hostile world list is cut to the ceiling", context do
      status = with_report(context, %{"worlds" => Enum.map(1..20, &"world:#{&1}")})

      assert length(status.helper.worlds) == 8
    end
  end

  describe "the read-only claim, against a pool that would notice" do
    test "status/1 reads the pool exactly once and asks it to do nothing", context do
      pool = counting_pool(doctor_report())

      status = Surface.status([pool: pool] ++ opts(context))

      assert status.helper.phase == :ready
      assert status.helper.usable == true

      assert GenServer.call(pool, :calls) == 1

      assert GenServer.call(pool, :requests) == 0,
             "a read-only surface must never send the pool a request"
    end

    test "list/1 never touches the pool at all", context do
      pool = counting_pool(doctor_report())

      _list = Surface.list([pool: pool] ++ opts(context))

      assert GenServer.call(pool, :calls) == 0
      assert GenServer.call(pool, :requests) == 0
    end

    test "a server this side cannot verify is absent, never broken with an empty path",
         context do
      status = Surface.status([pool: {:no_such_pool, node()}] ++ opts(context))

      assert status.helper.phase == :absent
      assert status.helper.path == Path.basename(Wasm.helper_path())
      assert status.helper.broken_reason == nil
      refute status.helper.path == ""
    end
  end

  describe "the bounds are bounds" do
    test "a register holding more rows than the ceiling is cut, and says how many it holds",
         context do
      entries = Enum.map(0..599, &entry("wasm-#{String.pad_leading("#{&1}", 3, "0")}"))
      registry = fake_registry(entries)

      list = Surface.list(root: context.root, registry: registry)

      assert list.rollout_count == 600
      assert length(list.rollouts) == 512
      # Cut after sorting, so which 512 survive is the answer's own order and not a
      # directory's or a map traversal's.
      assert List.first(list.rollouts).artifact_id == "wasm-000"
      assert List.last(list.rollouts).artifact_id == "wasm-511"
    end

    test "a node name a checkpoint should never have held is drawn, not raised on", context do
      registry = fake_registry([entry("wasm-odd", nodes: [%{not: "a node"}, :ouroboros@real])])

      list = Surface.list(root: context.root, registry: registry)

      assert [row] = list.rollouts
      assert [rendered, "ouroboros@real"] = row.nodes
      assert is_binary(rendered)
      assert byte_size(rendered) <= 512
    end

    test "a module a checkpoint should never have held is drawn, not raised on", context do
      # `name_of/1` ended in `to_string/1`, which raises on a map, a tuple, or a pid — and
      # inside the gateway's `safe/1` that turned one malformed row from a checkpoint this
      # build did not write into `-32006` for the whole listing. The same guard
      # `node_name/1` already had, for the same reason.
      registry =
        fake_registry([
          %{entry("wasm-map") | module: %{not: "a module"}},
          %{entry("wasm-atom") | module: Ouroboros.Capability.NotWasm},
          %{entry("wasm-long") | module: "wasm/" <> String.duplicate("n", 5_000)}
        ])

      list = Surface.list(root: context.root, registry: registry)

      assert [atom_named, long, rendered] = Enum.sort_by(list.rollouts, & &1.artifact_id)

      assert atom_named.artifact_id == "wasm-atom"
      assert atom_named.name == "Elixir.Ouroboros.Capability.NotWasm"

      assert long.artifact_id == "wasm-long"
      assert byte_size(long.name) <= 512

      assert rendered.artifact_id == "wasm-map"
      assert is_binary(rendered.name)
      assert byte_size(rendered.name) <= 512
    end
  end

  describe "the fixtures and the live verbs describe the same shape" do
    test "wasm.status: every key path the pinned frame has, and no other", context do
      seed_store!(context)
      live!(context, "vet", String.duplicate("a", 64))

      live = Surface.status([pool: counting_pool(doctor_report())] ++ opts(context))

      assert_same_shape(live, "wasm_status_result")
    end

    test "wasm.list: every key path the pinned frame has, and no other", context do
      seed_store!(context)
      live!(context, "vet", String.duplicate("a", 64))
      superseded!(context, "vet", String.duplicate("b", 64))
      quarantined!(context, "lint", String.duplicate("c", 64))

      live = Surface.list([pool: counting_pool(doctor_report())] ++ opts(context))

      assert_same_shape(live, "wasm_list_result")
    end
  end

  ## Helpers

  defp opts(context), do: [root: context.root, registry: context.registry]

  defp put_named(context, sha) do
    # Bytes chosen so the digest is not the one asked for would fail the store's own check,
    # so publish real bytes and rename: this test is about ordering, not about hashing.
    {:ok, published} = Store.put("\0asm #{sha}", nil, opts(context))
    File.rename!(published.path, Path.join(context.root, "sha256-#{sha}.wasm"))
    {:ok, %{published | sha256: sha}}
  end

  defp live!(context, name, sha, id \\ nil) do
    id = id || "wasm-#{System.unique_integer([:positive])}"
    deploying!(context, name, sha, id)
    {:ok, entry} = Registry.mark(id, :live, [], context.registry)
    entry
  end

  defp superseded!(context, name, sha, id \\ nil) do
    id = id || "wasm-#{System.unique_integer([:positive])}"
    deploying!(context, name, sha, id)
    {:ok, _live} = Registry.mark(id, :live, [], context.registry)
    {:ok, entry} = Registry.mark(id, :superseded, [], context.registry)
    entry
  end

  defp quarantined!(context, name, sha, id \\ nil) do
    id = id || "wasm-#{System.unique_integer([:positive])}"
    deploying!(context, name, sha, id)
    {:ok, entry} = Registry.mark(id, :quarantined, [], context.registry)
    entry
  end

  defp deploying!(context, name, sha, id) do
    {:ok, entry} =
      Registry.deploying(
        %{
          artifact_id: id,
          module: "wasm/#{name}",
          epoch: System.unique_integer([:positive, :monotonic]) + 1_000,
          nodes: [node()],
          component_sha256: sha
        },
        context.registry
      )

    entry
  end

  defp start_pool! do
    name = :"wasm_surface_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start(
        name: name,
        helper_path: Path.join(System.tmp_dir!(), "ouro-wasm-that-was-never-built")
      )

    on_exit(fn ->
      if Process.alive?(pid) do
        try do
          GenServer.stop(pid, :normal, 1_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    pid
  end

  # ---- the counting pool, and the reports it answers with -------------------

  defp doctor_report(overrides \\ %{}) do
    Map.merge(
      %{
        "usable" => true,
        "worlds" => [Wasm.world()],
        "wasmtime" => "43.0.1",
        "limits" => %{"max_deadline_ms" => 60_000, "max_components" => 64},
        # Forwarded by nothing: the projection names what it carries.
        "notes" => ["the helper's prose, which no status answer repeats"]
      },
      overrides
    )
  end

  defp counting_pool(report) do
    {:ok, pid} =
      CountingPool.start_link(%{
        phase: :ready,
        helper_path: "/fake/ouro-wasm",
        os_pid: 4242,
        doctor: report,
        instances: 2,
        owned: 1,
        pending_drops: 0,
        hook_components: 3,
        broken_reason: nil
      })

    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  defp pool_opts(context, overrides),
    do: [pool: counting_pool(doctor_report(overrides))] ++ opts(context)

  defp with_report(context, overrides), do: Surface.status(pool_opts(context, overrides))

  defp fake_registry(entries) do
    {:ok, pid} = FakeRegistry.start_link(entries)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  defp entry(id, opts \\ []) do
    struct!(Registry.Entry,
      artifact_id: id,
      module: "wasm/#{Keyword.get(opts, :name, "vet")}",
      epoch: 1,
      nodes: Keyword.get(opts, :nodes, [node()]),
      state: Keyword.get(opts, :state, :live),
      component_sha256: Keyword.get(opts, :sha, String.duplicate("a", 64)),
      created_at: "2026-01-01T00:00:00.000000Z",
      updated_at: "2026-01-01T00:00:00.000000Z"
    )
  end

  defp seed_store!(context) do
    {:ok, _one} = Store.put("\0asm first component", nil, opts(context))
    {:ok, _two} = Store.put("\0asm second component", nil, opts(context))
    :ok
  end

  # ---- key-path parity ------------------------------------------------------

  # The fixtures are hand-written terms, so nothing but a test keeps them in the shape the
  # verbs actually answer: a field added to `Surface` and not to the fixture is a field the
  # Rust decode never learns about, and a field removed is one a client still branches on.
  defp assert_same_shape(live, fixture) do
    pinned = fixture |> Golden.path() |> File.read!() |> JSON.decode!() |> Map.fetch!("result")

    missing = MapSet.difference(key_paths(pinned), key_paths(live))
    extra = MapSet.difference(key_paths(live), key_paths(pinned))

    assert MapSet.to_list(missing) == [],
           "#{fixture}.json pins key paths the live verb no longer answers"

    assert MapSet.to_list(extra) == [],
           "the live verb answers key paths #{fixture}.json does not pin; " <>
             "run `mix ouroboros.gateway.golden` and review the diff"
  end

  # Every key path in a term. A list contributes `[]` to its elements' path, so
  # `rollouts[].nodes` is one path however many rows there are; a `nil` leaf still
  # contributes its own key, because a field this node cannot answer is part of the shape.
  defp key_paths(value), do: value |> paths("") |> Enum.map(&family/1) |> MapSet.new()

  defp paths(map, prefix) when is_map(map) and not is_struct(map) do
    Enum.flat_map(map, fn {key, leaf} ->
      path = if prefix == "", do: to_string(key), else: prefix <> "." <> to_string(key)
      [path | paths(leaf, path)]
    end)
  end

  defp paths(list, prefix) when is_list(list),
    do: Enum.flat_map(list, &paths(&1, prefix <> "[]"))

  defp paths(_leaf, _prefix), do: []

  # The helper's own bounds table is a family, not a field list: the whole point of the
  # projection is that this side does not enumerate what the helper may report.
  defp family("helper.limits." <> _bound), do: "helper.limits.*"
  defp family(path), do: path

  defp start_registry! do
    name = :"wasm_surface_registry_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS, table: :"wasm_surface_store_#{System.unique_integer([:positive])}"}
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

  # Portable means what the gateway's encoder can render without inventing anything: no
  # pids, refs, ports, functions or tuples anywhere in the tree. Atoms are allowed, because
  # every atom here is one this runtime chose (a state name, a phase, a node) and the wire
  # renders it as its own text.
  defp portable?(value) when is_map(value) and not is_struct(value) do
    Enum.all?(value, fn {key, leaf} -> portable?(key) and portable?(leaf) end)
  end

  defp portable?(value) when is_list(value), do: Enum.all?(value, &portable?/1)

  defp portable?(value)
       when is_binary(value) or is_number(value) or is_boolean(value) or is_nil(value) or
              is_atom(value),
       do: true

  defp portable?(_unportable), do: false
end
