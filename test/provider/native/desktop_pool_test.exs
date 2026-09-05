defmodule Ouroboros.Provider.Native.Desktop.PoolTest do
  # Not async: each test spawns a real OS child and one of them lowers a timeout.
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Desktop.Codec
  alias Ouroboros.Provider.Native.Desktop.Pool

  describe "Codec — newline-delimited JSON-RPC, bounded" do
    test "encodes one newline-terminated request line that decodes back" do
      frame = Codec.request(1, "doctor", %{}) |> IO.iodata_to_binary()
      assert String.ends_with?(frame, "\n")
      assert {:ok, [%{"id" => 1, "method" => "doctor"}], 0, ""} = Codec.decode(frame, 1_000_000)
    end

    test "splits several frames and carries the unterminated remainder" do
      assert {:ok, frames, 0, rest} =
               Codec.decode(~s({"a":1}\n{"b":2}\n{"c), 1_000_000)

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

  describe "one helper per node — handshake and requests" do
    test "handshakes to ready and answers doctor, windows, and state" do
      pid = start_pool(responding_helper())
      assert %{phase: :ready} = wait_status(pid, &(&1.phase == :ready), 15_000)

      assert {:ok, %{"readiness" => %{"screenshot" => "ok"}}} = Pool.doctor(pid, 2_000)
      assert {:ok, %{"windows" => []}} = Pool.windows(pid, 2_000)
      assert {:ok, %{"app" => %{"id" => "com.apple.calculator"}}} = Pool.state(pid, %{}, 2_000)
    end

    test "a second in-flight request waits in the queue and both complete" do
      pid = start_pool(slow_helper())
      wait_status(pid, &(&1.phase == :ready), 15_000)

      first = Task.async(fn -> Pool.state(pid, %{}, 3_000) end)
      Process.sleep(80)
      second = Task.async(fn -> Pool.state(pid, %{}, 3_000) end)

      assert {:ok, %{"app" => _}} = Task.await(first, 5_000)
      assert {:ok, %{"app" => _}} = Task.await(second, 5_000)
    end

    test "a queued request expires on its original deadline and is never sent later" do
      log = request_log()
      pid = start_pool(recording_slow_helper())
      wait_status(pid, &(&1.phase == :ready), 15_000)

      first = Task.async(fn -> Pool.state(pid, %{"tag" => "first"}, 3_000) end)
      wait_internal(pid, &(get_in(&1, [:inflight, :method]) == "state"))
      stale = Task.async(fn -> Pool.state(pid, %{"tag" => "stale"}, 100) end)

      assert {:error, :timeout} = Task.await(stale, 1_000)
      assert {:ok, %{"app" => _}} = Task.await(first, 5_000)
      Process.sleep(100)

      requests = File.read!(log)
      assert requests =~ "first"
      refute requests =~ "stale"
    end

    test "a queued request is removed when its caller dies" do
      log = request_log()
      pid = start_pool(recording_slow_helper())
      wait_status(pid, &(&1.phase == :ready), 15_000)

      first = Task.async(fn -> Pool.state(pid, %{"tag" => "first"}, 3_000) end)
      wait_internal(pid, &(get_in(&1, [:inflight, :method]) == "state"))

      caller =
        spawn(fn ->
          _ = Pool.state(pid, %{"tag" => "abandoned"}, 3_000)
        end)

      wait_internal(pid, &(:queue.len(&1.queue) == 1))
      Process.exit(caller, :kill)
      wait_internal(pid, &(:queue.len(&1.queue) == 0))

      assert {:ok, %{"app" => _}} = Task.await(first, 5_000)
      Process.sleep(100)
      refute File.read!(log) =~ "abandoned"
    end

    test "cancel of a queued caller does not abort a different caller's inflight act" do
      log = request_log()
      pid = start_pool(recording_act_helper())
      wait_status(pid, &(&1.phase == :ready), 15_000)

      first = Task.async(fn -> Pool.request(pid, "act", %{"tag" => "first"}, 3_000) end)
      wait_internal(pid, &(get_in(&1, [:inflight, :method]) == "act"))

      second = Task.async(fn -> Pool.request(pid, "act", %{"tag" => "second"}, 3_000) end)
      wait_internal(pid, &(:queue.len(&1.queue) == 1))

      Pool.cancel(pid, second.pid)
      Process.sleep(80)
      refute File.read!(log) =~ "cancel"

      assert {:ok, %{"ok" => true}} = Task.await(first, 5_000)
      assert {:ok, %{"ok" => true}} = Task.await(second, 5_000)
    end

    test "an in-flight timeout stays occupied until the helper acknowledges, then drains" do
      _log = request_log()
      pid = start_pool(recording_slow_helper())
      wait_status(pid, &(&1.phase == :ready), 15_000)

      assert {:error, :timeout} = Pool.state(pid, %{"tag" => "timed-out"}, 100)

      queued = Task.async(fn -> Pool.state(pid, %{"tag" => "after-timeout"}, 2_000) end)
      wait_internal(pid, &(:queue.len(&1.queue) == 1))

      assert {:ok, %{"app" => _}} = Task.await(queued, 3_000)
      assert %{phase: :ready} = Pool.status(pid)
    end
  end

  describe "broken is a state, not a crash (like MCP)" do
    test "a helper that exits at once leaves the pool broken and answering errors" do
      pid = start_pool(exiting_helper(), handshake_timeout_ms: 1_000)
      assert %{phase: :broken} = wait_status(pid, &(&1.phase == :broken))

      # The pool process is still alive and still answers — it holds the snapshot map.
      assert Process.alive?(pid)
      assert {:error, _reason} = Pool.state(pid, %{}, 500)
    end

    test "a helper that never answers its handshake is broken, not waited on" do
      pid = start_pool(silent_helper(), handshake_timeout_ms: 150)
      status = wait_status(pid, &(&1.phase == :broken), 2_000)

      assert status.phase == :broken
      assert status.broken_reason == :handshake_timeout
    end
  end

  describe "env is filtered (§7)" do
    test "the helper inherits only its capture environment" do
      secrets =
        ~w(OUROBOROS_GATEWAY_TOKEN DATABASE_URL AWS_ACCESS_KEY_ID DEPLOY_PRIVATE_KEY SSH_AUTH_SOCK OURO_CU_MARKER)

      variables = ["LANG" | secrets]
      before = Map.new(variables, &{&1, System.get_env(&1)})
      Enum.each(secrets, &System.put_env(&1, "synthetic-sentinel"))
      System.put_env("LANG", "C")

      on_exit(fn ->
        Enum.each(before, fn
          {name, nil} -> System.delete_env(name)
          {name, value} -> System.put_env(name, value)
        end)
      end)

      pid = start_pool(env_echo_helper())
      wait_status(pid, &(&1.phase == :ready), 15_000)

      assert {:ok, %{"token" => token, "marker" => marker}} = Pool.doctor(pid, 2_000)
      assert token == "", "no synthetic secret or arbitrary setting reaches the helper"
      assert marker == "C", "an explicitly allowed execution variable survives"
    end
  end

  describe "the last state lives here, in the BEAM (D11)" do
    test "remember, read back, and forget a session's last state" do
      pid = start_pool(responding_helper())

      assert Pool.last_state(pid, "/session/a") == nil
      Pool.remember_state(pid, "/session/a", %{"app" => %{"id" => "com.apple.calculator"}})
      # A cast then a call from this process are ordered, so no polling is needed.
      assert Pool.last_state(pid, "/session/a") == %{"app" => %{"id" => "com.apple.calculator"}}

      Pool.forget_state(pid, "/session/a")
      assert Pool.last_state(pid, "/session/a") == nil
    end
  end

  ## Helpers

  defp start_pool(helper_path, opts \\ []) do
    name = :"desktop_pool_#{System.unique_integer([:positive])}"

    # Started detached (not `start_link`) so the pool is independent of the test process:
    # its child's exit does not travel through us, and we stop it explicitly at teardown,
    # which reaps the helper via `terminate/2`.
    #
    # The default handshake ceiling is sized to a loaded machine: the handshake spawns an
    # OS child and round-trips a doctor request, and a loaded full-suite run was seen
    # blowing 3s on that (helper broken: :handshake_timeout). Tests that *assert* the
    # broken path pass their own deliberately small ceiling.
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

  defp wait_status(pid, pred, timeout \\ 2_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait(pid, pred, deadline)
  end

  defp wait_internal(pid, pred, timeout \\ 2_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait_internal(pid, pred, deadline)
  end

  defp do_wait_internal(pid, pred, deadline) do
    state = :sys.get_state(pid)

    cond do
      pred.(state) -> state
      System.monotonic_time(:millisecond) >= deadline -> flunk("pool state did not converge")
      true -> Process.sleep(10) && do_wait_internal(pid, pred, deadline)
    end
  end

  defp do_wait(pid, pred, deadline) do
    status = Pool.status(pid)

    cond do
      pred.(status) -> status
      System.monotonic_time(:millisecond) >= deadline -> status
      true -> Process.sleep(20) && do_wait(pid, pred, deadline)
    end
  end

  # A helper that answers each request line, echoing back the id. `awk` reads a line at a
  # time and `fflush()` guarantees each response reaches the port immediately — the one
  # portable way to avoid a shell's stdout buffering stalling the handshake.
  defp responding_helper, do: write_helper(awk_body(""))
  defp slow_helper, do: write_helper(awk_body(~s|system("sleep 0.3"); |))

  defp recording_act_helper do
    write_helper("""
    #!/bin/sh
    exec awk '
    {
      line = $0
      print line >> "#{System.fetch_env!("OURO_CU_REQUEST_LOG")}"
      close("#{System.fetch_env!("OURO_CU_REQUEST_LOG")}")
      if ($0 ~ /"method":"cancel"/) {
        fflush()
        next
      }
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      if ($0 ~ /"method":"doctor"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"readiness\\":{\\"screenshot\\":\\"ok\\",\\"ax\\":\\"ok\\",\\"input\\":\\"ok\\"}}}\\n", id)
      } else if ($0 ~ /"method":"act"/) {
        system("sleep 0.4")
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"ok\\":true}}\\n", id)
      } else {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"error\\":{\\"code\\":-32601,\\"message\\":\\"nope\\"}}\\n", id)
      }
      fflush()
    }
    '
    """)
  end

  defp recording_slow_helper do
    write_helper("""
    #!/bin/sh
    exec awk '
    {
      line = $0
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      if ($0 ~ /"method":"doctor"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"readiness\\":{\\"screenshot\\":\\"ok\\",\\"ax\\":\\"ok\\",\\"input\\":\\"ok\\"}}}\\n", id)
      } else if ($0 ~ /"method":"state"/) {
        print line >> "#{System.fetch_env!("OURO_CU_REQUEST_LOG")}"
        close("#{System.fetch_env!("OURO_CU_REQUEST_LOG")}")
        system("sleep 0.6")
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"app\\":{\\"id\\":\\"com.apple.calculator\\"}}}\\n", id)
      }
      fflush()
    }
    '
    """)
  end

  defp request_log do
    path = Path.join(System.tmp_dir!(), "ouro-cu-requests-#{System.unique_integer([:positive])}")
    File.write!(path, "")
    previous = System.get_env("OURO_CU_REQUEST_LOG")
    System.put_env("OURO_CU_REQUEST_LOG", path)

    on_exit(fn ->
      File.rm(path)

      if previous,
        do: System.put_env("OURO_CU_REQUEST_LOG", previous),
        else: System.delete_env("OURO_CU_REQUEST_LOG")
    end)

    path
  end

  defp awk_body(prelude) do
    """
    #!/bin/sh
    exec awk '
    {
      #{prelude}id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      if ($0 ~ /"method":"doctor"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"readiness\\":{\\"screenshot\\":\\"ok\\",\\"ax\\":\\"ok\\",\\"input\\":\\"ok\\"}}}\\n", id)
      } else if ($0 ~ /"method":"windows"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"windows\\":[]}}\\n", id)
      } else if ($0 ~ /"method":"state"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"app\\":{\\"id\\":\\"com.apple.calculator\\",\\"name\\":\\"Calculator\\"}}}\\n", id)
      } else {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"error\\":{\\"code\\":-32601,\\"message\\":\\"nope\\"}}\\n", id)
      }
      fflush()
    }
    '
    """
  end

  # Only synthetic values are echoed; no host credentials are exposed by this test.
  defp env_echo_helper do
    write_helper("""
    #!/bin/sh
    exec awk '
    {
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"token\\":\\"%s\\",\\"marker\\":\\"%s\\"}}\\n", id, ENVIRON["OUROBOROS_GATEWAY_TOKEN"] ENVIRON["DATABASE_URL"] ENVIRON["AWS_ACCESS_KEY_ID"] ENVIRON["DEPLOY_PRIVATE_KEY"] ENVIRON["SSH_AUTH_SOCK"] ENVIRON["OURO_CU_MARKER"], ENVIRON["LANG"])
      fflush()
    }
    '
    """)
  end

  defp exiting_helper, do: write_helper("#!/bin/sh\nexit 0\n")
  defp silent_helper, do: write_helper("#!/bin/sh\nexec cat >/dev/null\n")

  defp write_helper(body) do
    path = Path.join(System.tmp_dir!(), "ouro-cu-helper-#{System.unique_integer([:positive])}.sh")
    File.write!(path, body)
    File.chmod!(path, 0o755)
    on_exit(fn -> File.rm_rf(path) end)
    path
  end
end
