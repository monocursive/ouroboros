defmodule Ouroboros.Wasm.PoolAcceptanceTest do
  # Not async: each test spawns the real helper as an OS child of this node.
  use ExUnit.Case, async: false

  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Store

  # These run against the real `ouro-wasm`. Where it has not been built they are skipped
  # with the reason printed rather than silently passing, the same honesty
  # `Ouroboros.Provider.Native.SandboxTest` applies to a missing sandbox binary: a green run
  # on a machine that never ran `make wasm` should say what it did not check.
  # `Ouroboros.Wasm.LiveFixture` decides, so that CI — which builds the helper and sets
  # `OUROBOROS_REQUIRE_WASM=1` — fails on a missing build instead of skipping green. No guest
  # here: everything in this file is reachable without one.
  @needs_helper Ouroboros.Wasm.LiveFixture.tag()

  setup_all do
    Ouroboros.Wasm.LiveFixture.ensure!()
  end

  # W2 owns the first real guest. Everything here is reachable without one: the handshake,
  # the refusals that fire before a component is ever compiled, and the ones that fire when
  # the bytes turn out not to be a component at all.
  describe "the real helper's handshake" do
    @tag @needs_helper
    test "reports a usable engine implementing this node's world" do
      pool = start_pool()

      assert {:ok, report} = Pool.doctor(pool)
      assert report["usable"] == true
      assert Wasm.world() in report["worlds"]
      assert is_binary(report["wasmtime"])
      assert is_integer(report["limits"]["max_deadline_ms"])

      # The accepted report is kept, because it carries the bounds `instantiate` accepts and
      # there is no other way to learn them.
      status = Pool.status(pool)
      assert status.phase == :ready
      assert status.doctor["worlds"] == report["worlds"]
    end

    @tag @needs_helper
    test "the pair a precompiled artifact is bound to, and the ceiling both sides hold (W8)" do
      pool = start_pool()

      assert {:ok, report} = Pool.doctor(pool)

      # The two strings `Ouroboros.Wasm.Store.form/4` compares before this node will map an
      # artifact its signer compiled. `helper_build/2` reads them off the accepted report rather
      # than asking again, so what it answers has to be what the helper actually said.
      assert is_binary(report["target"]) and report["target"] != ""

      assert Pool.helper_build(pool) == %{
               "wasmtime" => report["wasmtime"],
               "target" => report["target"]
             }

      # M6. One number, two implementations. `Ouroboros.Wasm.Bundle` mirrors the helper's own
      # artifact ceiling because a bundle this build admits and the helper refuses is a file an
      # operator moves around and a node will not load, for a reason neither of them named.
      assert report["limits"]["max_precompiled_bytes"] == Bundle.helper_precompiled_bytes()
      assert Bundle.max_precompiled_bytes() <= report["limits"]["max_precompiled_bytes"]
    end
  end

  describe "refusals travel as codes and names, not prose" do
    @tag @needs_helper
    test "bytes that are not a component are refused by inspect" do
      pool = start_pool()
      path = write_bytes("not a component at all")

      assert {:error, %{code: code, refusal: refusal, message: message}} =
               Pool.inspect(path, pool)

      assert refusal == "compile_failed"
      assert code in -32_099..-32_001
      assert is_binary(message)
    end

    @tag @needs_helper
    test "a path that cannot be read is refused by inspect" do
      pool = start_pool()

      assert {:error, %{refusal: "unreadable_component"}} =
               Pool.inspect(Path.join(tmp_dir(), "never-written.wasm"), pool)
    end

    @tag @needs_helper
    test "load refuses bytes that do not hash to the sha it was given" do
      pool = start_pool()
      path = write_bytes("some bytes")

      assert {:error, %{refusal: "sha_mismatch"}} =
               Pool.load(String.duplicate("a", 64), path, pool)
    end

    @tag @needs_helper
    test "instantiate refuses a limit outside the helper's range before the wire (F2)" do
      # This used to reach the real helper and come back `limits_out_of_range`. It no longer
      # travels at all: the pool carries the same bounds `tui/wasm/src/host.rs` enforces and
      # refuses ahead of the frame, which is what keeps a caller-chosen `deadline_ms` from
      # ever reaching `Process.send_after/3`. The acceptance value of the test is that the
      # two agree — a build whose helper had *narrower* bounds than these constants would be
      # caught by `doctor.limits` below, and one with wider bounds by the `{:ok, _}` here.
      pool = start_pool()

      assert {:error, {:invalid_limits, {:memory_bytes, 1}}} =
               Pool.instantiate(
                 "acceptance",
                 String.duplicate("a", 64),
                 "{}",
                 %{fuel: 1_000_000, memory_bytes: 1, deadline_ms: 1_000},
                 pool
               )

      # The real helper's own report of the same four numbers, so a drift between this
      # build's constants and the binary on disk is a failing test rather than a surprise.
      assert {:ok, report} = Pool.doctor(pool)

      assert %{
               "max_fuel" => 1_000_000_000_000,
               "min_memory_bytes" => 65_536,
               "max_memory_bytes" => 1_073_741_824,
               "max_deadline_ms" => 60_000
             } = report["limits"]

      # And a request at the very edge of those bounds is one this side still sends: it comes
      # back `unknown_component`, which is the helper answering rather than the pool refusing.
      assert {:error, %{refusal: "unknown_component"}} =
               Pool.instantiate(
                 "acceptance",
                 String.duplicate("a", 64),
                 "{}",
                 %{fuel: 1_000_000_000_000, memory_bytes: 65_536, deadline_ms: 60_000},
                 pool
               )
    end

    @tag @needs_helper
    test "instantiate refuses a component nobody loaded" do
      pool = start_pool()

      assert {:error, %{refusal: "unknown_component"}} =
               Pool.instantiate(
                 "acceptance",
                 String.duplicate("a", 64),
                 "{}",
                 %{fuel: 1_000_000, memory_bytes: 65_536, deadline_ms: 1_000},
                 pool
               )
    end

    @tag @needs_helper
    test "call refuses an instance that is not live, and drop says so idempotently" do
      pool = start_pool()

      assert {:error, %{refusal: "unknown_instance"}} =
               Pool.call("never-instantiated", "handle-message", "{}", pool)

      assert {:ok, %{"dropped" => false}} = Pool.drop("never-instantiated", pool)
      assert {:ok, %{"dropped" => false}} = Pool.drop("never-instantiated", pool)
      assert %{phase: :ready} = Pool.status(pool)
    end
  end

  describe "the store hands the helper a path" do
    @tag @needs_helper
    test "a stored sha loads under its own name and is refused on its content" do
      pool = start_pool()
      opts = [root: tmp_dir()]

      # Not a component, so the helper gets past the digest check — which is the half this
      # slice owns — and refuses on the bytes. W2 replaces these bytes with a real guest.
      assert {:ok, %{sha256: sha, path: path}} = Store.put("\0asm\x01\x00\x00\x00", nil, opts)
      assert {:ok, ^path} = Store.path(sha, opts)

      assert {:error, %{refusal: refusal}} = Pool.load(sha, path, pool)
      refute refusal == "sha_mismatch", "the store and the helper disagreed about the digest"
      assert refusal == "compile_failed"
    end
  end

  ## Helpers

  # W16. The helper is spawned under the OS sandbox by default now, so a pool has to be told
  # the two node-local roots a real node reads from its own configuration: where its scratch
  # goes, and what its components may be read from. Here both are this test's own directory —
  # which is also what the pool refuses a `load` outside of, so the fence and the kernel are
  # measuring the same list. Nothing in this file turns the sandbox off.
  defp start_pool do
    name = :"wasm_acceptance_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start(
        name: name,
        readable: [tmp_dir()],
        scratch_root: Path.join(tmp_dir(), "scratch")
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

  defp write_bytes(bytes) do
    path = Path.join(tmp_dir(), "component.wasm")
    File.write!(path, bytes)
    path
  end

  # One directory per *test*, not per call: the pool is told to read it and the components are
  # written into it, and two directories would mean a component the fence has never heard of.
  defp tmp_dir do
    case Process.get(:wasm_acceptance_tmp) do
      dir when is_binary(dir) ->
        dir

      nil ->
        dir =
          Path.join(
            System.tmp_dir!(),
            "ouro-wasm-acceptance-#{System.unique_integer([:positive])}"
          )

        File.mkdir_p!(dir)
        Process.put(:wasm_acceptance_tmp, dir)
        on_exit(fn -> File.rm_rf(dir) end)
        dir
    end
  end
end
