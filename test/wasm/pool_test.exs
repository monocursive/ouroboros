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

    test "an unterminated remainder past the cap is an error, not a growing buffer" do
      # The other half of the same bound, and the one a complete-line check does not cover: a
      # helper that writes 8 MiB and no newline would otherwise be buffered forever, one
      # chunk at a time, by a side that is waiting for a delimiter that never comes.
      assert {:ok, [], 0, "abcd"} = Codec.decode("abcd", 4)
      assert {:error, {:frame_too_large, 5, 4}} = Codec.decode("abcde", 4)
    end
  end

  describe "a helper that stops speaking the protocol is broken, not read forever" do
    test "noise past the budget breaks the transport" do
      # The helper writes its diagnostics to stderr and its answers to stdout. Lines on
      # stdout that are not JSON objects are counted rather than acted on, and past
      # `@max_noise` the transport is one that has stopped speaking this protocol.
      pool = start_pool(noisy_helper(25))

      assert {:error, :broken} = Pool.doctor(pool)
      assert %{phase: :broken, broken_reason: {:noise_limit, noise}} = Pool.status(pool)
      assert noise > 20
      assert Process.alive?(pool)
    end

    test "noise inside the budget is skipped, and the answer after it is still read" do
      pool = start_pool(noisy_helper(5))

      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)
      assert %{phase: :ready} = Pool.status(pool)
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

    # W8. The two strings a precompiled artifact is bound to, read off the report the handshake
    # already accepted rather than asked for again. `Ouroboros.Wasm.Store.form/4` calls this on
    # the way to every load, so what it says decides whether this node will
    # `Component::deserialize` machine code somebody else produced (D22, D24).
    test "helper_build reports the wasmtime and the target a doctor named" do
      pool =
        start_pool(
          doctor_helper(
            ~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.1.0\"],) <>
              ~S(\"wasmtime\":\"47.0.0\",\"target\":\"x86_64-unknown-linux-gnu\")
          )
        )

      assert {:ok, _report} = Pool.doctor(pool)

      assert Pool.helper_build(pool) == %{
               "wasmtime" => "47.0.0",
               "target" => "x86_64-unknown-linux-gnu"
             }
    end

    # A helper too old to report a triple cannot be matched against one, and guessing this
    # node's own would be exactly the guess D22 forbids: the answer is "I do not know", and
    # `form/4` reads that as the source form, which every node can always compile.
    test "a helper that names no target is a build this node cannot claim to know" do
      pool =
        start_pool(
          doctor_helper(
            ~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.1.0\"],\"wasmtime\":\"48.0.1\")
          )
        )

      assert {:ok, _report} = Pool.doctor(pool)
      assert Pool.helper_build(pool) == nil
    end

    # `wasm.list` is `:read` and W5's rule is that it never starts a helper to answer. A pool
    # that has not connected has no report, and asking with `connect: false` says so rather
    # than spawning one to find out.
    test "a reader asks without connecting, and an idle pool answers that it does not know" do
      pool = start_pool(responding_helper())

      assert %{phase: :idle} = Pool.status(pool)
      assert Pool.helper_build(pool, connect: false) == nil
      assert %{phase: :idle} = Pool.status(pool)
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
      pool = start_pool(flaky_helper(spawns), broken_ms: 400, handshake_timeout_ms: 2_000)

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

  describe "env is deny-by-default (F4)" do
    # The deny-list this replaces was a regex over names, and the names that matter are not
    # the ones it knew: `rel/env.sh.eex` puts the fleet's real distribution cookie in
    # `RELEASE_COOKIE`, which `(API_?KEY|_TOKEN|SECRET|OAUTH|PASSWORD|CREDENTIAL|
    # GATEWAY_TOKEN)` does not match, and neither do any of the rest of these. Every one is a
    # variable a real node running this daemon plausibly holds.
    @secret_env %{
      "RELEASE_COOKIE" => "the-fleet-cookie",
      "OUROBOROS_COOKIE" => "the-fleet-cookie",
      "OUROBOROS_COOKIE_FILE" => "/etc/ouroboros/cookie",
      "AWS_ACCESS_KEY_ID" => "AKIAIOSFODNN7EXAMPLE",
      "SSH_AUTH_SOCK" => "/private/tmp/ssh-agent.sock",
      "DATABASE_URL" => "postgres://user:pw@db.internal/ouroboros",
      "OUROBOROS_SIGNING_PRIVATE_KEY" => "-----BEGIN PRIVATE KEY-----",
      "AUTHORIZATION" => "Bearer abc123",
      "SIGNING_KEY" => "deadbeef",
      "NPM_CONFIG_AUTH" => "hunter2",
      "OUROBOROS_GATEWAY_TOKEN" => "supersecret",
      # Not secret-shaped at all, and still not the helper's business: the old posture kept
      # everything it could not name, which is the half of the failure a longer deny-list
      # would not have fixed either.
      "OURO_WASM_MARKER" => "keepme"
    }

    test "the helper is spawned with PATH, HOME and TMPDIR and nothing else this node holds" do
      Enum.each(@secret_env, fn {name, value} -> System.put_env(name, value) end)
      on_exit(fn -> Enum.each(@secret_env, fn {name, _} -> System.delete_env(name) end) end)

      pool = start_pool(env_dump_helper())

      assert {:ok, %{"env" => dumped}} = Pool.inspect("/tmp/one", pool)
      names = dumped |> String.split(" ", trim: true) |> MapSet.new()

      for {name, _value} <- @secret_env do
        refute MapSet.member?(names, name), "#{name} reached the helper"
      end

      # The child still has what it needs to run at all: this fake helper is `/bin/sh`
      # running `awk`, and it found both through PATH.
      assert MapSet.member?(names, "PATH")

      # And nothing else *this node holds*, which is the half a longer deny-list would never
      # have reached. The claim is about inheritance, so it is checked against this node's
      # own environment: a name the child shows that this node never had is the wrapper's
      # doing, not a leak — `/bin/sh` exports `PWD`/`SHLVL` into every child it runs, and
      # gawk on Linux plants `AWKPATH`/`AWKLIBPATH` into its own `ENVIRON` whether or not
      # they were ever set. Both are excluded by construction rather than by name.
      node_env = System.get_env() |> Map.keys() |> MapSet.new()

      leaked =
        names
        |> MapSet.intersection(node_env)
        |> MapSet.difference(MapSet.new(~w(PATH HOME TMPDIR)))
        |> MapSet.difference(MapSet.new(~w(PWD SHLVL OLDPWD _)))

      assert MapSet.size(leaked) == 0,
             "the helper's environment is not an allow-list: #{Enum.join(leaked, ", ")}"
    end

    test "an allowed name carrying a credential-shaped value is dropped too" do
      previous = System.get_env("TMPDIR")
      System.put_env("TMPDIR", "postgres://user:pw@db.internal/scratch")

      on_exit(fn ->
        if previous, do: System.put_env("TMPDIR", previous), else: System.delete_env("TMPDIR")
      end)

      pool = start_pool(env_dump_helper())

      assert {:ok, %{"env" => dumped}} = Pool.inspect("/tmp/one", pool)
      names = dumped |> String.split(" ", trim: true) |> MapSet.new()

      refute MapSet.member?(names, "TMPDIR")
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

  describe "limits are bounded before they reach a timer (F2)" do
    test "a caller-chosen deadline past what a timer accepts is refused, and the pool lives" do
      # The finding. `resolve_timeout/4` handed `limits.deadline_ms + call_margin_ms` to
      # `Process.send_after/3` before anything validated it, so one `instantiate` with a
      # deadline near the 61-bit maximum raised `badarg` inside `handle_call/3` and killed
      # this GenServer. Forty-four of them exhausted `Ouroboros.Wasm.Supervisor`'s 10-in-60s
      # and the `:rest_for_one` parent shut down with it.
      pool = start_pool(responding_helper())
      assert {:ok, _report} = Pool.doctor(pool)

      huge = %{fuel: 1_000, memory_bytes: 65_536, deadline_ms: 4_611_686_018_427_387_000}

      for _attempt <- 1..44 do
        assert {:error, {:invalid_limits, {:deadline_ms, 4_611_686_018_427_387_000}}} =
                 Pool.instantiate("boom", sha(1), "{}", huge, pool)
      end

      assert Process.alive?(pool)
      assert %{phase: :ready} = Pool.status(pool)
      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)
    end

    test "each of the three bounds is refused at both ends, before any frame" do
      journal = journal_file()
      pool = start_pool(journaling_helper(journal))
      assert {:ok, _report} = Pool.doctor(pool)

      # The helper's own maxima, mirrored from `tui/wasm/src/host.rs`.
      ok = %{fuel: 1_000, memory_bytes: 65_536, deadline_ms: 1_000}

      refusals = [
        {%{ok | fuel: 0}, {:fuel, 0}},
        {%{ok | fuel: 1_000_000_000_001}, {:fuel, 1_000_000_000_001}},
        {%{ok | memory_bytes: 65_535}, {:memory_bytes, 65_535}},
        {%{ok | memory_bytes: 1_073_741_825}, {:memory_bytes, 1_073_741_825}},
        {%{ok | deadline_ms: 0}, {:deadline_ms, 0}},
        {%{ok | deadline_ms: 60_001}, {:deadline_ms, 60_001}}
      ]

      for {limits, expected} <- refusals do
        assert {:error, {:invalid_limits, ^expected}} =
                 Pool.instantiate("i", sha(1), "{}", limits, pool)
      end

      # In range, and it goes out.
      assert {:ok, _result} = Pool.instantiate("i", sha(1), "{}", ok, pool)

      instantiates =
        journal |> requests() |> Enum.filter(&(&1["method"] == "instantiate"))

      assert length(instantiates) == 1
    end

    test "a helper whose own doctor limits are narrower has the last word" do
      # The constants above are this build's reading of `host.rs`; a binary with tighter
      # bounds is honoured rather than overridden, and the check is server-side because only
      # the pool holds the report.
      pool = start_pool(limited_helper(1_000))
      assert {:ok, _report} = Pool.doctor(pool)

      within_constants = %{fuel: 1_000, memory_bytes: 65_536, deadline_ms: 5_000}

      assert {:error, {:invalid_limits, {:deadline_ms, 5_000}}} =
               Pool.instantiate("i", sha(1), "{}", within_constants, pool)

      assert {:ok, _result} =
               Pool.instantiate("i", sha(1), "{}", %{within_constants | deadline_ms: 100}, pool)
    end

    test "a call waits the deadline its own instance was created with, plus the margin" do
      # `resolve_timeout/4`'s `call` branch and the per-instance deadline map, which had no
      # test of their own. The helper answers `instantiate` and then never answers `call`, so
      # what the pool waits is exactly what it derived.
      pool = start_pool(limited_helper(30_000, deaf_call_rules()), call_margin_ms: 50)
      assert {:ok, _report} = Pool.doctor(pool)

      assert {:ok, _result} =
               Pool.instantiate(
                 "known",
                 sha(1),
                 "{}",
                 %{fuel: 1_000, memory_bytes: 65_536, deadline_ms: 150},
                 pool
               )

      {elapsed, reply} =
        :timer.tc(fn -> Pool.call("known", "handle-message", "{}", pool) end, :millisecond)

      assert reply == {:error, :timeout}

      # 150 + 50, not the helper's 30 s ceiling and not `request_timeout_ms`.
      assert elapsed >= 150 and elapsed < 3_000, "waited #{elapsed} ms, not the instance's own"
    end

    test "a helper that reports an absurd ceiling cannot make the pool arm an absurd timer" do
      # The second way a number reaches `Process.send_after/3` here, and the one no
      # caller-side validation covers: `helper_max_deadline/1` reads `max_deadline_ms` off
      # the helper's own `doctor`, which is somebody else's JSON. A helper reporting a value
      # past what a timer accepts would raise `badarg` inside `handle_call/3` and kill this
      # pool — which is why every derived interval is clamped at the one place it leaves
      # `resolve_timeout/4`, and not only where a caller's number is checked.
      pool = start_pool(limited_helper(4_611_686_018_427_387_000, deaf_call_rules()))
      assert {:ok, report} = Pool.doctor(pool)
      assert report["limits"]["max_deadline_ms"] == 4_611_686_018_427_387_000

      # The request is armed and then abandoned: what this asserts is that arming it did not
      # kill the pool. Waiting for it would mean waiting out `@max_timeout_ms`, which is the
      # point — the clamp is what makes the wait finite at all.
      waiting = Task.async(fn -> Pool.call("never-created", "handle-message", "{}", pool) end)
      Process.sleep(200)

      assert Process.alive?(pool)
      assert %{phase: :ready} = Pool.status(pool)
      Task.shutdown(waiting, :brutal_kill)
    end

    test "a call on an instance this pool never created waits the helper's own ceiling" do
      # The other branch: `helper_max_deadline/1`, read off the accepted doctor report. A
      # helper reporting a 400 ms ceiling is waited for 400 ms plus the margin, which is how
      # a leftover instance from before a reconnect is bounded at all.
      pool = start_pool(limited_helper(400, deaf_call_rules()), call_margin_ms: 50)
      assert {:ok, _report} = Pool.doctor(pool)

      {elapsed, reply} =
        :timer.tc(
          fn -> Pool.call("never-created", "handle-message", "{}", pool) end,
          :millisecond
        )

      assert reply == {:error, :timeout}
      assert elapsed >= 400 and elapsed < 3_000, "waited #{elapsed} ms, not the helper's ceiling"
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

    test "the owner map is bounded oldest-first, exactly as the deadline map is" do
      # `bound_owners/2`. A peer that instantiates under caller-chosen names and never drops
      # would otherwise grow a map — and a monitor per entry — in this process without limit.
      pool = start_pool(responding_helper(), max_instances: 4)
      owner = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> Process.exit(owner, :kill) end)

      before = length(Process.info(pool, :monitors) |> elem(1))

      for n <- 1..10 do
        assert {:ok, _result} = instantiate(pool, "owned-#{n}", owner: owner)
      end

      assert %{owned: 4, instances: 4} = Pool.status(pool)

      # Evicting an entry releases its monitor rather than leaking one per instance.
      assert length(Process.info(pool, :monitors) |> elem(1)) - before == 4
    end

    test "re-instantiating a name releases the monitor the previous one took" do
      # `remember_owner/4`'s `forget_owner/2` first step. Without it a guest that traps on
      # every message — so its wrapper re-instantiates under the same derived name every
      # time — leaves one monitor behind per message, forever.
      pool = start_pool(responding_helper())
      owner = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> Process.exit(owner, :kill) end)

      before = length(Process.info(pool, :monitors) |> elem(1))

      for _again <- 1..20 do
        assert {:ok, _result} = instantiate(pool, "same-name", owner: owner)
      end

      assert %{owned: 1, instances: 1} = Pool.status(pool)
      assert length(Process.info(pool, :monitors) |> elem(1)) - before == 1
    end

    test "reclaims a helper never answers pile up on a bounded list, not an unbounded one" do
      # `schedule_drop/2` and the `pending_drops` surface. This helper reads a `drop` and
      # never answers it, so the first reclaim occupies the wire forever and the rest wait —
      # which is the only state in which anything can queue here at all. The list is bounded
      # by the same cap as the maps it reclaims from, so a peer cannot grow it.
      pool = start_pool(limited_helper(60_000, deaf_drop_rules()), max_instances: 2)
      assert {:ok, _report} = Pool.doctor(pool)

      owners =
        for n <- 1..2 do
          owner = spawn(fn -> Process.sleep(:infinity) end)
          assert {:ok, _result} = instantiate(pool, "owned-#{n}", owner: owner)
          owner
        end

      assert %{owned: 2, pending_drops: 0} = Pool.status(pool)

      Enum.each(owners, &Process.exit(&1, :kill))
      assert wait_until(fn -> Pool.status(pool).owned == 0 end)

      # One reclaim is in flight and unanswered; whatever is behind it is bounded.
      status = Pool.status(pool)
      assert status.pending_drops >= 1
      assert status.pending_drops <= 2
      assert Process.alive?(pool)
    end
  end

  describe "the queue is bounded, and a full one is :busy rather than a wait" do
    test "callers past the queue are refused at once, and the pool keeps working" do
      # `@max_queue` and `queueable?/1`. One request is in flight and eight may wait; the
      # tenth is answered `:busy` immediately rather than being buffered behind a helper that
      # is sequential by design.
      pool = start_pool(slow_helper())
      assert {:ok, _report} = Pool.doctor(pool)

      waiting =
        for n <- 1..9 do
          Task.async(fn -> Pool.inspect("/tmp/#{n}", pool) end)
        end

      # Give the nine time to arrive: one takes the in-flight slot, eight fill the queue.
      Process.sleep(120)

      assert {:error, :busy} = Pool.inspect("/tmp/too-many", pool)

      # Every queued caller is still answered — `:busy` refused the arrival, not the queue.
      for task <- waiting do
        assert {:ok, %{"method" => "inspect"}} = Task.await(task, 10_000)
      end

      assert %{phase: :ready} = Pool.status(pool)
    end
  end

  describe "the untrusted hook lane is budgeted against the shared component cache" do
    test "sixteen distinct untrusted components load and the seventeenth never touches the wire" do
      # The helper's cache is 64 slots shared by every lane. Before it evicted, an untrusted
      # workspace shipping components could fill it in one turn — and from then on every
      # `load` on this node failed `too_many_components`, including the *operator's own*
      # component hook's: an untrusted workspace deleting somebody else's deny. The helper
      # now evicts (never a component with a live instance), and this budget bounds the
      # churn a repository can cause instead: compiles, and evictions somebody else repays.
      journal = journal_file()
      pool = start_pool(journaling_helper(journal))

      for n <- 1..16 do
        assert {:ok, _result} =
                 Pool.load(sha(n), "/tmp/hook-#{n}.wasm", pool, lane: :untrusted_hook)
      end

      assert Pool.status(pool).hook_components == 16

      assert {:error, :hook_component_budget} =
               Pool.load(sha(17), "/tmp/hook-17.wasm", pool, lane: :untrusted_hook)

      # Refused before a frame was built: the helper never heard of the seventeenth.
      loads = journal |> requests() |> Enum.filter(&(&1["method"] == "load"))
      assert length(loads) == 16
      refute Enum.any?(loads, &(&1["params"]["sha256"] == sha(17)))

      # A sha already counted is free, so a hook that runs forever costs one slot.
      assert {:ok, _result} =
               Pool.load(sha(3), "/tmp/hook-3.wasm", pool, lane: :untrusted_hook)

      assert Pool.status(pool).hook_components == 16
    end

    test "the operator's own trusted hook lane is never budgeted (F7)" do
      # The finding, exactly. One counter for both lanes meant an untrusted clone could spend
      # the whole budget on shas of its own and the operator's trusted `deny` hook then
      # failed to load — a bound written to protect the trusted lane disarming it instead.
      pool = start_pool(responding_helper())

      for n <- 1..16 do
        assert {:ok, _result} =
                 Pool.load(sha(n), "/tmp/clone-#{n}.wasm", pool, lane: :untrusted_hook)
      end

      assert {:error, :hook_component_budget} =
               Pool.load(sha(99), "/tmp/clone-17.wasm", pool, lane: :untrusted_hook)

      # The operator's own hooks load past the exhausted budget, seventeen distinct shas in,
      # and spend none of it. Trusted churn is bounded by the helper's own eviction.
      for n <- 100..116 do
        assert {:ok, _result} = Pool.load(sha(n), "/tmp/operator-#{n}.wasm", pool, lane: :hook)
      end

      assert Pool.status(pool).hook_components == 16
    end

    test "a load the helper refuses spends no budget (F7)" do
      # The count is taken on the helper's `{:ok, _}` and not at admission. Counting at
      # admission let sixteen *refused* loads — a sha mismatch, bytes that are not a
      # component — exhaust a budget on a cache they never touched.
      pool = start_pool(refusing_helper())

      for n <- 1..16 do
        assert {:error, %{refusal: "sha_mismatch"}} =
                 Pool.load(sha(n), "/tmp/clone-#{n}.wasm", pool, lane: :untrusted_hook)
      end

      assert Pool.status(pool).hook_components == 0
    end

    test "the capability lane is untouched by an exhausted hook budget" do
      # The whole point of the bound: what a repository spends is its own, and the lane that
      # carries signed artifacts keeps the other 48 slots.
      pool = start_pool(responding_helper())

      for n <- 1..16 do
        assert {:ok, _result} =
                 Pool.load(sha(n), "/tmp/hook-#{n}.wasm", pool, lane: :untrusted_hook)
      end

      assert {:error, :hook_component_budget} =
               Pool.load(sha(99), "/tmp/x.wasm", pool, lane: :untrusted_hook)

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
        assert {:ok, _result} =
                 Pool.load(sha(n), "/tmp/hook-#{n}.wasm", pool, lane: :untrusted_hook)
      end

      assert {:error, :hook_component_budget} =
               Pool.load(sha(17), "/tmp/x.wasm", pool, lane: :untrusted_hook)

      # `inspect` is the method this fake answers with a frame the pool refuses.
      assert {:error, :broken} = Pool.inspect("/tmp/anything", pool)
      assert %{phase: :broken, hook_components: 0} = Pool.status(pool)
    end

    test "an unrecognized lane is refused, so a typo cannot buy an exemption" do
      pool = start_pool(responding_helper())

      assert {:error, {:invalid_lane, :hooks}} =
               Pool.load(sha(1), "/tmp/one.wasm", pool, lane: :hooks)

      assert {:error, {:invalid_lane, "hook"}} =
               Pool.load(sha(1), "/tmp/one.wasm", pool, lane: "hook")

      # Refused at the API boundary: nothing was spawned and nothing was counted.
      assert %{phase: :idle, hook_components: 0} = Pool.status(pool)
    end
  end

  describe "the lane-W boot task reruns when the chain restarts it (F6)" do
    test "the supervised child spec is transient, not temporary" do
      # A supervisor drops every *temporary* child from the list it restarts after a
      # sibling's crash — `supervisor:terminate_children/2` terminates them and does not
      # return them — so the boot task was started exactly once per VM and the `rest_for_one`
      # comment beside it was wrong. Transient is the shape it needs: not restarted on its
      # own normal exit, restarted when the chain takes it down.
      previous = Application.get_env(:ouroboros, :data_dir)
      Application.put_env(:ouroboros, :data_dir, Path.join(tmp_dir(), "data"))

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ouroboros, :data_dir, previous),
          else: Application.delete_env(:ouroboros, :data_dir)
      end)

      assert [%{id: Ouroboros.Wasm.Boot, restart: :transient}] =
               Ouroboros.Application.wasm_restart_children()
    end

    test "a transient one-shot task under rest_for_one reruns; a temporary one does not" do
      # And what that restart type buys, proved against a real supervisor rather than
      # asserted. The leader is what a pool restart stands in for here.
      for {restart, expected} <- [{:transient, 2}, {:temporary, 1}] do
        test_pid = self()
        {:ok, sup} = start_rest_for_one(restart, test_pid)

        assert_receive {:ran, ^restart}, 2_000
        Process.exit(Process.whereis(leader_name()), :kill)

        runs = drain_runs(restart, 1)
        Supervisor.stop(sup)

        assert runs == expected,
               "a #{restart} one-shot task ran #{runs} time(s) across a sibling restart"
      end
    end
  end

  describe "an eviction the helper reports is legible on this side" do
    test "a load answer naming what was evicted is handed back whole and logged, bounded" do
      # The helper evicts at its ceiling and names the sha it let go in the `load` that took
      # it. That answer reaches the caller untouched — the caller may want to know — and the
      # node's log once, at debug, cut to the pool's own bound on helper prose.
      pool = start_pool(evicting_helper([sha(7), String.duplicate("x", 5_000)]))

      log =
        ExUnit.CaptureLog.capture_log([level: :debug], fn ->
          assert {:ok, %{"cached" => false, "evicted" => [evicted, long]}} =
                   Pool.load(sha(1), "/tmp/one.wasm", pool)

          assert evicted == sha(7)
          assert byte_size(long) == 5_000
        end)

      assert log =~ "wasm helper evicted 2 component(s)"
      assert log =~ sha(7)
      refute log =~ String.duplicate("x", 3_000), "helper prose reached the log unbounded"
    end

    test "a load that evicted nothing is not an event" do
      pool = start_pool(evicting_helper([]))

      log =
        ExUnit.CaptureLog.capture_log([level: :debug], fn ->
          assert {:ok, %{"evicted" => []}} = Pool.load(sha(1), "/tmp/one.wasm", pool)
        end)

      refute log =~ "evicted"
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

  # A helper whose `doctor` reports a chosen `max_deadline_ms`, so a test can prove both what
  # the pool derives from a report and what it refuses against one.
  defp limited_helper(max_deadline_ms, extra_rules \\ "") do
    report =
      ~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.1.0\"],) <>
        ~S(\"wasmtime\":\"48.0.1\",\"limits\":{\"max_deadline_ms\":) <>
        Integer.to_string(max_deadline_ms) <> "}"

    write_helper(awk_body(report, extra_rules, ""))
  end

  # Reads a `call` and never answers it, so the pool's own derived deadline is the whole of
  # the wait.
  defp deaf_call_rules do
    """
    } else if ($0 ~ /"method":"call"/) {
      next
    """
  end

  # The same for `drop`, which is how a reclaim can be observed *waiting* rather than
  # settling on the next idle turn of the wire.
  defp deaf_drop_rules do
    """
    } else if ($0 ~ /"method":"drop"/) {
      next
    """
  end

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

  # Answers every `load` as a fresh compile that evicted `shas` to make room.
  defp evicting_helper(shas) do
    evicted = Enum.map_join(shas, ",", &~s(\\"#{&1}\\"))

    write_helper(
      awk_body(
        @doctor_ok,
        """
        } else if ($0 ~ /"method":"load"/) {
          printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"cached\\":false,\\"evicted\\":[#{evicted}]}}\\n", id)
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

  # Answers every non-`doctor` request with the *names* of every variable in its own
  # environment, space-separated. Names only: the point is which variables crossed the spawn
  # boundary at all, and a value that did cross has no business in a test log either.
  defp env_dump_helper do
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
        names = ""
        for (k in ENVIRON) { names = names k " " }
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"env\\":\\"%s\\"}}\\n", id, names)
      }
      fflush()
    }
    '
    """)
  end

  defp silent_helper, do: write_helper("#!/bin/sh\nexec cat >/dev/null\n")

  # Writes `lines` complete non-JSON lines to stdout before every answer, which is the shape
  # of a helper that has started printing to the wrong descriptor.
  defp noisy_helper(lines) do
    write_helper(
      awk_body(
        @doctor_ok,
        "",
        ~s|for (i = 0; i < #{lines}; i++) { print "a banner line" } |
      )
    )
  end

  # Exits without answering the first time it is spawned and behaves the second time, so a
  # test can prove the cooldown window is honored and then cleared.
  #
  # The spawn log's path is baked into the script rather than passed through the environment:
  # the pool spawns its child with an allow-list environment (F4), so a variable this test
  # exported would not reach it — and a fake helper that needs the node's environment to work
  # is one that stops testing the real spawn.
  defp flaky_helper(spawns) do
    write_helper("""
    #!/bin/sh
    echo spawn >> "#{spawns}"
    if [ "$(wc -l < "#{spawns}")" -le 1 ]; then
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
    path
  end

  ## The F6 supervision fixture
  #
  # A `rest_for_one` tree shaped like the `:core` tail: a restartable leader (the pool's
  # stand-in) and a one-shot task behind it (the boot task's stand-in) that reports each run.

  defp leader_name, do: :ouro_wasm_boot_leader

  defp start_rest_for_one(restart, test_pid) do
    leader = %{
      id: :leader,
      start: {Agent, :start_link, [fn -> :up end, [name: leader_name()]]}
    }

    follower = %{
      id: :follower,
      start: {Task, :start_link, [fn -> send(test_pid, {:ran, restart}) end]},
      restart: restart
    }

    Supervisor.start_link([leader, follower], strategy: :rest_for_one)
  end

  defp drain_runs(restart, seen) do
    receive do
      {:ran, ^restart} -> drain_runs(restart, seen + 1)
    after
      500 -> seen
    end
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
