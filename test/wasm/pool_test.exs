defmodule Ouroboros.Wasm.PoolTest do
  # Not async: each test spawns a real OS child, and the env-filtering test writes to this
  # node's environment, which every other spawn on it reads.
  use ExUnit.Case, async: false

  alias Ouroboros.Wasm.Codec
  alias Ouroboros.Wasm.Pool

  @world "ouroboros:capability@0.1.0"

  describe "Codec — newline-delimited JSON-RPC, bounded" do
    test "encodes one newline-terminated request line that decodes back" do
      frame = Codec.request(1, "doctor", %{}) |> IO.iodata_to_binary()
      assert String.ends_with?(frame, "\n")

      assert {:ok, [%{"id" => 1, "method" => "doctor", "params" => %{}}], 0, ""} =
               Codec.decode(frame, 1_000_000)
    end

    test "splits several frames and carries the unterminated remainder" do
      assert {:ok, frames, 0, rest} = Codec.decode(~s({"a":1}\n{"b":2}\n{"c), 1_000_000)
      assert frames == [%{"a" => 1}, %{"b" => 2}]
      assert rest == ~s({"c)
    end

    test "counts a non-JSON line as noise and skips it" do
      assert {:ok, [%{"ok" => 1}], 1, ""} = Codec.decode("a banner line\n{\"ok\":1}\n", 1_000_000)
    end

    test "refuses a frame past max_frame_bytes rather than allocating it" do
      assert {:error, {:frame_too_large, _size, 4}} = Codec.decode("abcdef\n", 4)
    end
  end

  describe "lazy: nothing is spawned until a request needs it" do
    test "an idle pool holds no child, and the first request is what starts one" do
      pool = start_pool(responding_helper())

      assert %{phase: :idle, os_pid: nil, doctor: nil} = Pool.status(pool)

      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)
      status = Pool.status(pool)
      assert status.phase == :ready
      assert is_integer(status.os_pid)
      assert status.doctor["worlds"] == [@world]
    end

    test "no helper on disk is :unavailable, not broken — absence is the operator opt-in" do
      pool = start_pool(Path.join(System.tmp_dir!(), "ouro-wasm-that-was-never-built"))

      assert {:error, :unavailable} = Pool.doctor(pool)
      assert {:error, :unavailable} = Pool.inspect("/tmp/whatever", pool)

      # Idle, not broken: installing a helper has to take effect at once, with no cooldown.
      assert %{phase: :idle, os_pid: nil} = Pool.status(pool)
    end
  end

  describe "the handshake is an admission decision" do
    test "a helper that reports itself unusable is refused" do
      pool =
        start_pool(
          doctor_helper(~S(\"usable\":false,\"worlds\":[\"ouroboros:capability@0.1.0\"]))
        )

      assert {:error, :broken} = Pool.doctor(pool)
      assert %{phase: :broken, broken_reason: {:handshake_refused, summary}} = Pool.status(pool)
      assert summary.usable == false
    end

    test "a helper that does not implement this node's world is refused" do
      pool =
        start_pool(doctor_helper(~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.2.0\"])))

      assert {:error, :broken} = Pool.doctor(pool)
      assert %{phase: :broken, broken_reason: {:handshake_refused, summary}} = Pool.status(pool)
      assert summary.worlds == ["ouroboros:capability@0.2.0"]
    end

    test "a helper that never answers its handshake is broken, not waited on" do
      pool = start_pool(silent_helper(), handshake_timeout_ms: 150)

      assert {:error, :broken} = Pool.doctor(pool)
      assert %{phase: :broken, broken_reason: :handshake_timeout} = Pool.status(pool)
    end
  end

  describe "broken is a state with a cooldown" do
    test "the window is honored, and a request after it reconnects" do
      spawns = spawn_log()
      pool = start_pool(flaky_helper(), broken_ms: 400, handshake_timeout_ms: 2_000)

      # The first spawn exits before answering: broken.
      assert {:error, :broken} = Pool.doctor(pool)
      assert spawn_count(spawns) == 1

      # Inside the window nothing is respawned; the answer is immediate.
      assert {:error, :broken} = Pool.doctor(pool)
      assert spawn_count(spawns) == 1

      Process.sleep(500)
      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)
      assert spawn_count(spawns) == 2
      assert %{phase: :ready} = Pool.status(pool)
    end

    test "a helper that dies mid-conversation breaks the pool without crashing it" do
      pool = start_pool(dying_helper())
      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)

      assert {:error, :broken} = Pool.inspect("/tmp/anything", pool)

      assert Process.alive?(pool)
      assert %{phase: :broken, broken_reason: {:helper_exited, _status}} = Pool.status(pool)
    end

    test "a frame that is neither a result nor an error breaks the pool" do
      pool = start_pool(malformed_helper())
      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)

      assert {:error, :broken} = Pool.inspect("/tmp/anything", pool)
      assert Process.alive?(pool)
      assert %{phase: :broken, broken_reason: {:malformed_frame, "inspect"}} = Pool.status(pool)
    end

    test "a request that outlives its deadline breaks the pool and kills the child" do
      # `sleeping_helper` execs `sleep` after the handshake, so it ignores EOF: closing the
      # port cannot reap it, and only kill-by-os-pid can. That is what makes this a real test
      # of the kill (F4) — every `awk` fake exits on EOF, so `close_port` alone would reap it
      # and deleting the kill block would leave the suite green.
      #
      # `request_timeout_ms` is deliberately 2s and not the 300ms this test used to set. The
      # setting bounds *every* `:fixed` request, and the first one here is the `doctor` below
      # — whose deadline is armed on arrival, before a `/bin/sh` and an `awk` have been
      # spawned. Under a loaded full-suite run that spawn can outlast 300ms, and the test
      # then failed on its own setup rather than on the kill it exists to prove. Two seconds
      # is still far below any real wait and gives the spawn most of an order of magnitude.
      pool = start_pool(sleeping_helper(), request_timeout_ms: 2_000)
      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)

      os_pid = Pool.status(pool).os_pid
      assert is_integer(os_pid)

      assert {:error, :timeout} = Pool.inspect("/tmp/anything", pool)
      assert %{phase: :broken, broken_reason: {:request_timeout, "inspect"}} = Pool.status(pool)
      assert Process.alive?(pool)
      assert wait_until_gone(os_pid), "the wedged helper is still running as pid #{os_pid}"
    end

    test "a helper that forges a reply and stops draining is a broken transport, not a hang (F1)" do
      # The exploit the fix answers: a helper reads a request's first bytes (the id is early
      # on the wire), forges a reply, then stops draining stdin. The forged reply lets the
      # pool issue the *next* request, whose bytes now pile up unread — and with the default
      # `Port.command/2` that next write would *suspend* this pool inside the port until the
      # pipe drained. A suspended pool cannot fire the deadline that would kill the wedged
      # child, so every caller would hang. `:nosuspend` turns the busy port into a broken
      # transport, and the same `go_broken`/`hard_close` path F4 proves then kills the child.
      pool = start_pool(forging_helper())

      # One undrained ~300 KiB request already sits past the child's stdin pipe and the port's
      # busy watermark, so the pool's next write finds the port busy. Two concurrent callers:
      # one rides the forged reply, the other meets the busy port.
      payload = String.duplicate("x", 300_000)
      a = Task.async(fn -> Pool.call("a", "handle-message", payload, pool) end)
      b = Task.async(fn -> Pool.call("b", "handle-message", payload, pool) end)

      results = [Task.await(a, 10_000), Task.await(b, 10_000)]

      # Neither hung: one was answered by the forged reply, the other refused as broken.
      assert {:error, :broken} in results
      assert Enum.any?(results, &match?({:ok, _result}, &1))

      assert %{phase: :broken, broken_reason: {:transport_closed, :port_busy}} = Pool.status(pool)
      assert Process.alive?(pool)
    end
  end

  describe "requests are correlated by id" do
    test "each caller gets the answer to its own request" do
      pool = start_pool(responding_helper())

      assert {:ok, %{"method" => "inspect", "echo_id" => first}} =
               Pool.inspect("/tmp/one", pool)

      assert {:ok, %{"method" => "drop", "echo_id" => second}} = Pool.drop("instance-a", pool)
      assert second > first
    end

    test "a frame whose id matches nothing in flight is dropped, not answered with" do
      pool = start_pool(unsolicited_helper())

      assert {:ok, %{"method" => "inspect", "echo_id" => id}} = Pool.inspect("/tmp/one", pool)
      refute id == 9999
      assert %{phase: :ready} = Pool.status(pool)
    end

    test "two overlapping callers both get answered, in order" do
      pool = start_pool(slow_helper())
      assert {:ok, _report} = Pool.doctor(pool)

      first = Task.async(fn -> Pool.inspect("/tmp/first", pool) end)
      Process.sleep(60)
      second = Task.async(fn -> Pool.drop("instance-b", pool) end)

      assert {:ok, %{"method" => "inspect"}} = Task.await(first, 5_000)
      assert {:ok, %{"method" => "drop"}} = Task.await(second, 5_000)
    end
  end

  describe "refusals are surfaced as the helper's own vocabulary" do
    test "an error frame becomes code, refusal, and message" do
      pool = start_pool(refusing_helper())

      assert {:error, %{code: -32001, refusal: "sha_mismatch", message: message}} =
               Pool.load(String.duplicate("0", 64), "/tmp/whatever.wasm", pool)

      assert message =~ "hashes to"

      # A refusal is the helper working, not failing: the pool stays ready for the next one.
      assert %{phase: :ready} = Pool.status(pool)
    end

    test "limits are required and are never invented on this side" do
      pool = start_pool(responding_helper())

      assert {:error, {:invalid_limits, _}} =
               Pool.instantiate("i", String.duplicate("0", 64), "{}", %{fuel: 1}, pool)

      assert {:error, {:invalid_limits, _}} =
               Pool.instantiate(
                 "i",
                 String.duplicate("0", 64),
                 "{}",
                 %{fuel: 1, memory_bytes: 65_536, deadline_ms: 0},
                 pool
               )

      # Nothing was sent, so nothing was spawned.
      assert %{phase: :idle} = Pool.status(pool)
    end
  end

  describe "env is filtered" do
    test "the helper is spawned without the gateway token but keeps a benign variable" do
      System.put_env("OUROBOROS_GATEWAY_TOKEN", "supersecret")
      System.put_env("OURO_WASM_MARKER", "keepme")

      on_exit(fn ->
        System.delete_env("OUROBOROS_GATEWAY_TOKEN")
        System.delete_env("OURO_WASM_MARKER")
      end)

      pool = start_pool(env_echo_helper())

      assert {:ok, %{"token" => "", "marker" => "keepme"}} = Pool.inspect("/tmp/one", pool)
    end
  end

  describe "outbound frames are bounded (F2)" do
    test "an oversize request is refused to its caller without breaking the helper" do
      # A small cap so a buggy caller's request is oversize without needing megabytes.
      pool = start_pool(responding_helper(), max_frame_bytes: 4_096)
      assert {:ok, _report} = Pool.doctor(pool)

      oversize = String.duplicate("x", 20_000)

      assert {:error, {:frame_too_large, size, 4_096}} =
               Pool.call("i", "handle-message", oversize, pool)

      assert size > 4_096

      # The oversize request never touched the port, so the helper is untouched and the very
      # next caller — a legitimate small one — is answered.
      assert %{phase: :ready} = Pool.status(pool)
      assert {:ok, %{"method" => "inspect"}} = Pool.inspect("/tmp/small", pool)
    end

    test "an oversize request queued behind a slow one is refused without breaking it" do
      pool = start_pool(slow_helper(), max_frame_bytes: 4_096)
      assert {:ok, _report} = Pool.doctor(pool)

      slow = Task.async(fn -> Pool.inspect("/tmp/slow", pool) end)
      Process.sleep(60)
      oversize = String.duplicate("x", 20_000)
      big = Task.async(fn -> Pool.call("i", "handle-message", oversize, pool) end)

      assert {:error, {:frame_too_large, _size, 4_096}} = Task.await(big, 5_000)
      assert {:ok, %{"method" => "inspect"}} = Task.await(slow, 5_000)
      assert %{phase: :ready} = Pool.status(pool)
    end
  end

  describe "the pool guards its own heap (F3)" do
    test "a soft max_heap_size ceiling is armed, logging rather than killing" do
      pool = start_pool(responding_helper())
      expected = div(128 * 1024 * 1024, :erlang.system_info(:wordsize))

      assert {:max_heap_size, %{size: ^expected, kill: false, error_logger: true}} =
               Process.info(pool, :max_heap_size)
    end
  end

  describe "helper prose is bounded before it is kept (F6)" do
    test "an error frame's message is capped no matter how long the helper made it" do
      pool = start_pool(huge_message_helper())
      assert {:ok, _report} = Pool.doctor(pool)

      assert {:error, %{message: message}} =
               Pool.load(String.duplicate("0", 64), "/tmp/x.wasm", pool)

      # 1 MB on the wire, at most the cap plus a multibyte ellipsis on this side.
      assert byte_size(message) <= 2_048 + 8
      assert byte_size(message) > 1_000
    end

    test "a refused handshake's world strings are capped in broken_reason" do
      pool = start_pool(huge_world_helper())
      assert {:error, :broken} = Pool.doctor(pool)

      assert %{broken_reason: {:handshake_refused, %{worlds: worlds}}} = Pool.status(pool)
      assert worlds != []
      assert Enum.all?(worlds, &(byte_size(&1) <= 2_048 + 8))
    end
  end

  describe "instance bookkeeping is bounded (F9)" do
    test "the deadline map is bounded oldest-first, not grown by caller-chosen names" do
      # A tiny cap so the bound is provable without hundreds of round trips.
      pool = start_pool(responding_helper(), max_instances: 4)
      sha = String.duplicate("0", 64)
      limits = %{fuel: 1_000, memory_bytes: 65_536, deadline_ms: 1_000}

      for n <- 1..10 do
        assert {:ok, _result} = Pool.instantiate("inst-#{n}", sha, "{}", limits, pool)
      end

      # Ten instantiated, four tracked: the map did not grow with the caller-chosen names.
      assert Pool.status(pool).instances == 4
    end

    test "an over-long instance name is refused at the API boundary before any frame" do
      pool = start_pool(responding_helper())
      long = String.duplicate("i", 257)
      sha = String.duplicate("0", 64)
      limits = %{fuel: 1_000, memory_bytes: 65_536, deadline_ms: 1_000}

      assert {:error, {:invalid_instance, 257}} = Pool.call(long, "handle-message", "{}", pool)
      assert {:error, {:invalid_instance, 257}} = Pool.drop(long, pool)
      assert {:error, {:invalid_instance, 257}} = Pool.instantiate(long, sha, "{}", limits, pool)

      # Refused on this side, so the helper was never even spawned.
      assert %{phase: :idle} = Pool.status(pool)
    end
  end

  describe "instances have owners, because nothing else would ever drop them" do
    test "an owner's death drops its instance on the pool's own wire" do
      # Without this, every throwaway agent leaks an instance: a rollout probe and an
      # evaluation each stand one up under an id carrying a unique integer, stop, and never
      # come back. The helper evicts nothing, so a node walks into `too_many_instances` —
      # and a *full* helper is not a *broken* one, so nothing here would ever respawn it.
      journal = journal_file()
      pool = start_pool(journaling_helper(journal))

      owner = spawn(fn -> Process.sleep(:infinity) end)

      assert {:ok, _result} = instantiate(pool, "owned", owner: owner)
      assert %{instances: 1, owned: 1, pending_drops: 0} = Pool.status(pool)

      Process.exit(owner, :kill)

      assert wait_until(fn -> Pool.status(pool).instances == 0 end),
             "the dead owner's instance was never reclaimed"

      # Not merely forgotten on this side: a `drop` frame for that exact name went out.
      assert %{"method" => "drop", "params" => %{"instance" => "owned"}} =
               journal |> requests() |> List.last()

      # And the reclaim settled: no monitor, no scheduled drop, and a pool still answering.
      assert %{phase: :ready, owned: 0, pending_drops: 0} = Pool.status(pool)
      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)
    end

    test "an instance nobody claimed is nobody's to reclaim" do
      # `owner:` is optional, and an unowned instance is a legitimate one — it is simply one
      # whose lifetime its caller manages. Nothing here may drop it behind that caller's back.
      journal = journal_file()
      pool = start_pool(journaling_helper(journal))

      unrelated = spawn(fn -> Process.sleep(:infinity) end)

      assert {:ok, _result} = instantiate(pool, "unowned")
      assert %{instances: 1, owned: 0} = Pool.status(pool)

      Process.exit(unrelated, :kill)
      Process.sleep(100)

      assert %{instances: 1, owned: 0, pending_drops: 0} = Pool.status(pool)
      refute Enum.any?(requests(journal), &(&1["method"] == "drop"))
    end

    test "a broken pool forgets its ownership instead of reclaiming a table that is gone" do
      # Going broken hard-closes and kills the child, and the whole instance table goes with
      # it. Issuing drops against the next helper would be asking it about names it has never
      # heard of, so the monitors are released and the schedule is dropped.
      pool = start_pool(malformed_helper())
      owner = spawn(fn -> Process.sleep(:infinity) end)

      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)
      assert {:ok, _result} = instantiate(pool, "doomed", owner: owner)
      assert %{owned: 1} = Pool.status(pool)

      assert {:error, :broken} = Pool.inspect("/tmp/anything", pool)
      assert %{phase: :broken, owned: 0, pending_drops: 0, instances: 0} = Pool.status(pool)

      # And the owner dying afterwards is a `:DOWN` for a monitor that no longer exists.
      Process.exit(owner, :kill)
      Process.sleep(100)

      assert Process.alive?(pool)
      assert %{owned: 0, pending_drops: 0} = Pool.status(pool)
    end

    test "a non-pid owner is no owner, and does not refuse an otherwise valid instantiate" do
      pool = start_pool(responding_helper())

      assert {:ok, _result} = instantiate(pool, "bad-owner", owner: "not a pid")
      assert %{instances: 1, owned: 0} = Pool.status(pool)
    end
  end

  describe "the hook lane is budgeted against the shared component cache" do
    test "sixteen distinct hook components load and the seventeenth never touches the wire" do
      # The helper's cache is 64 slots with no eviction and it is shared by every lane, so
      # an untrusted workspace shipping components could fill it in one turn — and from then
      # on every `load` on this node fails `too_many_components`, including the *operator's
      # own* component hook's. That is an untrusted workspace deleting somebody else's deny.
      journal = journal_file()
      pool = start_pool(journaling_helper(journal))

      for n <- 1..16 do
        assert {:ok, _result} = Pool.load(sha(n), "/tmp/hook-#{n}.wasm", pool, lane: :hook)
      end

      assert Pool.status(pool).hook_components == 16

      assert {:error, :hook_component_budget} =
               Pool.load(sha(17), "/tmp/hook-17.wasm", pool, lane: :hook)

      # Refused before a frame was built: the helper never heard of the seventeenth.
      loads = journal |> requests() |> Enum.filter(&(&1["method"] == "load"))
      assert length(loads) == 16
      refute Enum.any?(loads, &(&1["params"]["sha256"] == sha(17)))

      # A sha already counted is free, so a hook that runs forever costs one slot.
      assert {:ok, _result} = Pool.load(sha(3), "/tmp/hook-3.wasm", pool, lane: :hook)
      assert Pool.status(pool).hook_components == 16
    end

    test "the capability lane is untouched by an exhausted hook budget" do
      # The whole point of the bound: what a repository spends is its own, and the lane that
      # carries signed artifacts keeps the other 48 slots.
      pool = start_pool(responding_helper())

      for n <- 1..16 do
        assert {:ok, _result} = Pool.load(sha(n), "/tmp/hook-#{n}.wasm", pool, lane: :hook)
      end

      assert {:error, :hook_component_budget} =
               Pool.load(sha(99), "/tmp/x.wasm", pool, lane: :hook)

      # The default lane, and an explicit one, both still load.
      assert {:ok, _result} = Pool.load(sha(99), "/tmp/capability.wasm", pool)

      assert {:ok, _result} =
               Pool.load(sha(98), "/tmp/capability.wasm", pool, lane: :capability)

      assert Pool.status(pool).hook_components == 16
    end

    test "a broken transition forgets the budget, because the cache it bounded is gone" do
      pool = start_pool(malformed_helper())
      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)

      for n <- 1..16 do
        assert {:ok, _result} = Pool.load(sha(n), "/tmp/hook-#{n}.wasm", pool, lane: :hook)
      end

      assert {:error, :hook_component_budget} =
               Pool.load(sha(17), "/tmp/x.wasm", pool, lane: :hook)

      # `inspect` is the method this fake answers with a frame the pool refuses.
      assert {:error, :broken} = Pool.inspect("/tmp/anything", pool)
      assert %{phase: :broken, hook_components: 0} = Pool.status(pool)
    end

    test "an unrecognized lane is the budgeted one, so a typo cannot buy an exemption" do
      pool = start_pool(responding_helper())

      assert {:ok, _result} = Pool.load(sha(1), "/tmp/one.wasm", pool, lane: :hooks)
      assert Pool.status(pool).hook_components == 1
    end
  end

  ## Helpers

  # Sixty-four hex characters, distinct per `n`, in the shape the helper's `sha256` is.
  defp sha(n), do: String.pad_leading(Integer.to_string(n), 64, "0")

  defp instantiate(pool, instance, opts \\ []) do
    Pool.instantiate(
      instance,
      String.duplicate("a", 64),
      "{}",
      %{fuel: 1_000, memory_bytes: 65_536, deadline_ms: 1_000},
      pool,
      opts
    )
  end

  defp wait_until(fun, attempts \\ 150)
  defp wait_until(_fun, 0), do: false

  defp wait_until(fun, attempts) do
    if fun.() do
      true
    else
      Process.sleep(20)
      wait_until(fun, attempts - 1)
    end
  end

  defp journal_file do
    path = Path.join(tmp_dir(), "journal")
    File.write!(path, "")
    path
  end

  defp requests(journal) do
    journal
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(&JSON.decode!/1)
  end

  defp start_pool(helper_path, opts \\ []) do
    name = :"wasm_pool_#{System.unique_integer([:positive])}"

    # Started detached (not `start_link`) so the pool is independent of the test process:
    # its child's exit does not travel through us, and we stop it explicitly at teardown,
    # which reaps the helper via `terminate/2`.
    {:ok, pid} =
      Pool.start(
        Keyword.merge([name: name, helper_path: helper_path, handshake_timeout_ms: 15_000], opts)
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

  defp wait_until_gone(os_pid, attempts \\ 150) do
    case System.cmd("kill", ["-0", Integer.to_string(os_pid)], stderr_to_stdout: true) do
      {_output, 0} when attempts > 0 ->
        Process.sleep(20)
        wait_until_gone(os_pid, attempts - 1)

      {_output, 0} ->
        false

      _gone ->
        true
    end
  end

  ## Fake helpers
  #
  # Shell scripts standing in for `ouro-wasm`, the same technique
  # `Ouroboros.Provider.Native.Desktop.PoolTest` uses: `awk` reads a line at a time and
  # `fflush()` puts each answer on the pipe immediately, which is the one portable way to
  # keep a shell's stdout buffering out of the handshake.

  # Written with the quotes already escaped, because these strings are interpolated into an
  # `awk` printf *format*, not into JSON.
  @doctor_ok ~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.1.0\"],) <>
               ~S(\"wasmtime\":\"48.0.1\",\"limits\":{\"max_deadline_ms\":60000})

  defp responding_helper, do: write_helper(awk_body(@doctor_ok, "", ""))

  # The same, with every request it read appended to `journal` before it is answered. That
  # is how a test sees a frame the pool issued for itself, which no caller ever receives.
  defp journaling_helper(journal),
    do:
      write_helper(awk_body(@doctor_ok, "", ~s|print $0 >> "#{journal}"; close("#{journal}"); |))

  defp slow_helper, do: write_helper(awk_body(@doctor_ok, "", ~s|system("sleep 0.3"); |))

  defp doctor_helper(report), do: write_helper(awk_body(report, "", ""))

  defp refusing_helper do
    write_helper(
      awk_body(
        @doctor_ok,
        """
        } else if ($0 ~ /"method":"load"/) {
          printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"error\\":{\\"code\\":-32001,\\"message\\":\\"/tmp/whatever.wasm hashes to abc, not the requested 000\\",\\"data\\":{\\"refusal\\":\\"sha_mismatch\\"}}}\\n", id)
        """,
        ""
      )
    )
  end

  # Emits a frame for an id nobody asked about before the real answer.
  defp unsolicited_helper do
    write_helper(
      awk_body(
        @doctor_ok,
        """
        } else if ($0 ~ /"method":"inspect"/) {
          printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":9999,\\"result\\":{\\"method\\":\\"inspect\\",\\"echo_id\\":9999}}\\n")
          printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"method\\":\\"inspect\\",\\"echo_id\\":%s}}\\n", id, id)
        """,
        ""
      )
    )
  end

  # `awk` answers the first two doctor requests — the pool's internal handshake and the
  # public `Pool.doctor` that drives it — then exits, and the shell `exec sleep`s. From then
  # on this pid is a `sleep`: it stops draining stdin and does *not* exit on EOF. Two things
  # need exactly this. F4: closing the port cannot reap a `sleep`, so only kill-by-os-pid
  # can, and because the shell `exec`s it there is no orphan to leak. F1: a frame past its
  # stdin pipe then overflows into a busy port rather than being read. `awk`'s `fflush` is
  # what makes the two handshake replies reach the pipe promptly on every platform.
  defp sleeping_helper do
    write_helper("""
    #!/bin/sh
    awk '
    {
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{#{@doctor_ok}}}\\n", id)
      fflush()
      if (NR == 2) { exit }
    }
    '
    exec sleep 30
    """)
  end

  # Forges a reply to the first real request without ever reading it: on the one handshake
  # line it emits the handshake's answer (id 1) *and* a forged answer for the first caller
  # request (id 2, which the pool's monotonic ids make certain), then exits, and the shell
  # `exec sleep`s so the pid stops draining stdin. Both frames reach the pool in one read, so
  # by the time the forged id-2 answer is routed the pool has already issued that request and
  # written its (undrained) body — which is what makes the *next* write find a busy port,
  # deterministically and with no timing race.
  defp forging_helper do
    write_helper("""
    #!/bin/sh
    awk '
    NR == 1 {
      printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"result\\":{#{@doctor_ok}}}\\n")
      printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":2,\\"result\\":{#{@doctor_ok}}}\\n")
      fflush()
      exit
    }
    '
    exec sleep 30
    """)
  end

  # Answers the handshake, then answers `load` with an error frame whose `message` is ~1 MB —
  # the helper prose the pool must bound before it surfaces or stores it (F6).
  defp huge_message_helper do
    write_helper(
      awk_body(
        @doctor_ok,
        """
        } else if ($0 ~ /"method":"load"/) {
          big = sprintf("%1000000s", "x")
          printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"error\\":{\\"code\\":-32001,\\"message\\":\\"%s\\",\\"data\\":{\\"refusal\\":\\"sha_mismatch\\"}}}\\n", id, big)
        """,
        ""
      )
    )
  end

  # Answers the doctor with `usable:true` but a single ~1 MB world string that is not this
  # node's world: a refused handshake whose world list the pool must bound in broken_reason.
  defp huge_world_helper do
    write_helper("""
    #!/bin/sh
    exec awk '
    {
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      big = sprintf("%1000000s", "x")
      printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"usable\\":true,\\"worlds\\":[\\"%s\\"]}}\\n", id, big)
      fflush()
    }
    '
    """)
  end

  # Answers the handshake and then sends a well-framed reply carrying neither a result nor
  # an error: the helper breaking its own contract rather than the pipe breaking.
  defp malformed_helper do
    write_helper(
      awk_body(
        @doctor_ok,
        """
        } else if ($0 ~ /"method":"inspect"/) {
          printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"outcome\\":\\"who knows\\"}\\n", id)
        """,
        ""
      )
    )
  end

  # Answers the handshake and then exits, which arrives as a port exit rather than a frame.
  defp dying_helper do
    write_helper(
      awk_body(
        @doctor_ok,
        """
        } else if ($0 ~ /"method":"inspect"/) {
          exit 0
        """,
        ""
      )
    )
  end

  defp env_echo_helper do
    write_helper("""
    #!/bin/sh
    exec awk '
    {
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      if ($0 ~ /"method":"doctor"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{#{@doctor_ok}}}\\n", id)
      } else {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"token\\":\\"%s\\",\\"marker\\":\\"%s\\"}}\\n", id, ENVIRON["OUROBOROS_GATEWAY_TOKEN"], ENVIRON["OURO_WASM_MARKER"])
      }
      fflush()
    }
    '
    """)
  end

  defp silent_helper, do: write_helper("#!/bin/sh\nexec cat >/dev/null\n")

  # Exits without answering the first time it is spawned and behaves the second time, so a
  # test can prove the cooldown window is honored and then cleared.
  defp flaky_helper do
    write_helper("""
    #!/bin/sh
    echo spawn >> "$OURO_WASM_SPAWNS"
    if [ "$(wc -l < "$OURO_WASM_SPAWNS")" -le 1 ]; then
      exit 3
    fi
    #{awk_program(@doctor_ok, "", "")}
    """)
  end

  defp awk_body(report, extra_rules, prelude) do
    "#!/bin/sh\n" <> awk_program(report, extra_rules, prelude) <> "\n"
  end

  defp awk_program(report, extra_rules, prelude) do
    """
    exec awk '
    {
      #{prelude}id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      if ($0 ~ /"method":"doctor"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{#{report}}}\\n", id)
    #{extra_rules}  } else {
        method = $0
        sub(/.*"method":"/, "", method)
        sub(/".*/, "", method)
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"method\\":\\"%s\\",\\"echo_id\\":%s}}\\n", id, method, id)
      }
      fflush()
    }
    '
    """
    |> String.trim_trailing()
  end

  defp spawn_log do
    path = Path.join(tmp_dir(), "spawns")
    File.write!(path, "")
    previous = System.get_env("OURO_WASM_SPAWNS")
    System.put_env("OURO_WASM_SPAWNS", path)

    on_exit(fn ->
      if previous,
        do: System.put_env("OURO_WASM_SPAWNS", previous),
        else: System.delete_env("OURO_WASM_SPAWNS")
    end)

    path
  end

  defp spawn_count(path), do: path |> File.read!() |> String.split("\n", trim: true) |> length()

  defp write_helper(body) do
    path = Path.join(tmp_dir(), "ouro-wasm-helper.sh")
    File.write!(path, body)
    File.chmod!(path, 0o755)
    path
  end

  # One directory per test, removed at teardown: a shared tmp name is the flake this suite
  # has been bitten by before.
  defp tmp_dir do
    dir = Path.join(System.tmp_dir!(), "ouro-wasm-pool-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end
end
