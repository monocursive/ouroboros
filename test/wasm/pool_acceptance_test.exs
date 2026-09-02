defmodule Ouroboros.Wasm.PoolAcceptanceTest do
  # Not async: each test spawns the real helper as an OS child of this node.
  use ExUnit.Case, async: false

  alias Ouroboros.Wasm
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
    test "instantiate refuses a limit outside the helper's range" do
      pool = start_pool()

      assert {:error, %{refusal: "limits_out_of_range"}} =
               Pool.instantiate(
                 "acceptance",
                 String.duplicate("a", 64),
                 "{}",
                 %{fuel: 1_000_000, memory_bytes: 1, deadline_ms: 1_000},
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

  defp start_pool do
    name = :"wasm_acceptance_#{System.unique_integer([:positive])}"
    {:ok, pid} = Pool.start(name: name)

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

  defp tmp_dir do
    dir =
      Path.join(System.tmp_dir!(), "ouro-wasm-acceptance-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end
end
