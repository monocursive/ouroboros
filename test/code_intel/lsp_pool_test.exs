defmodule Ouroboros.CodeIntel.LspPoolTest do
  use ExUnit.Case, async: false

  alias Ouroboros.CodeIntel.Handle
  alias Ouroboros.CodeIntel.Lsp.Server
  alias Ouroboros.CodeIntel.LspPool

  # Servers are killed on purpose here; the client logs that and stops.
  @moduletag :capture_log

  @script Path.expand("../support/fake_language_server.exs", __DIR__)

  setup context do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-lsp-pool-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    pool_name = :"code_intel_pool_#{System.unique_integer([:positive])}"

    opts =
      Keyword.merge(
        [
          name: :"code_intel_sup_#{System.unique_integer([:positive])}",
          pool_name: pool_name,
          idle_ms: 60_000,
          sweep_ms: 60_000,
          memory_poll_ms: 60_000,
          max_restarts: 1,
          restart_backoff_ms: 20,
          broken_ms: 60_000,
          initialize_timeout_ms: 20_000,
          shutdown_grace_ms: 500
        ],
        Map.get(context, :pool_opts, [])
      )

    start_supervised!({Ouroboros.CodeIntel.Supervisor, opts})
    {:ok, root: root, pool: pool_name}
  end

  defp spec(root, extra_args \\ []) do
    %{
      root: root,
      server_id: "fake",
      executable: System.find_executable("elixir"),
      args: [@script] ++ extra_args
    }
  end

  # Deliberately returns the server map or nil, never an `{:ok, _}` tuple: `await/2`
  # treats `{:ok, _}` as success, and a helper that leaked one would make every poll
  # succeed on its first look.
  defp server_in(pool, root), do: Enum.find(LspPool.status(pool).servers, &(&1.root == root))

  defp await(fun, timeout \\ 20_000) do
    do_await(fun, System.monotonic_time(:millisecond) + timeout)
  end

  defp do_await(fun, deadline) do
    case fun.() do
      {:ok, value} ->
        value

      other ->
        if System.monotonic_time(:millisecond) >= deadline do
          flunk("condition never held; last saw #{inspect(other)}")
        else
          Process.sleep(20)
          do_await(fun, deadline)
        end
    end
  end

  defp await_state(pool, root, states) do
    await(fn ->
      case server_in(pool, root) do
        %{state: state} = server when is_map(server) ->
          if state in states, do: {:ok, server}, else: server

        other ->
          other
      end
    end)
  end

  test "the first acquire spawns lazily and a second one shares the same server", context do
    assert LspPool.status(context.pool).servers == []

    assert {:ok, %Handle{root: root, server_id: "fake"} = first} =
             LspPool.acquire(context.pool, spec(context.root))

    assert root == context.root
    assert first.node == node()
    assert first.id == "#{node()}:fake:#{context.root}"

    assert {:ok, second} = LspPool.acquire(context.pool, spec(context.root))
    assert second.ref != first.ref

    server = await_state(context.pool, context.root, [:ready])
    assert server.owners == 2
    assert server.server_info == %{"name" => "fake-language-server", "version" => "1"}
    assert is_integer(server.os_pid)
    assert is_binary(server.pid)
    assert server.documents == []
    assert [_only_one] = LspPool.status(context.pool).servers
  end

  test "a dead owner releases its claim without anyone calling release", context do
    owner = spawn(fn -> Process.sleep(60_000) end)
    assert {:ok, _handle} = LspPool.acquire(context.pool, spec(context.root), owner: owner)
    assert %{owners: 1} = server_in(context.pool, context.root)

    Process.exit(owner, :kill)

    await(fn ->
      case server_in(context.pool, context.root) do
        %{owners: 0} -> {:ok, :released}
        other -> other
      end
    end)
  end

  test "release drops the claim and leaves the server up for the next caller", context do
    assert {:ok, handle} = LspPool.acquire(context.pool, spec(context.root))
    assert :ok = LspPool.release(context.pool, handle)
    assert %{owners: 0} = server_in(context.pool, context.root)

    # Releasing twice is not an error; a session that crashes after releasing must not
    # take the pool with it.
    assert :ok = LspPool.release(context.pool, handle)
    assert %{owners: 0} = server_in(context.pool, context.root)
  end

  @tag pool_opts: [idle_ms: 300, sweep_ms: 300]
  test "an unclaimed server is stopped once its idle window passes", context do
    assert {:ok, handle} = LspPool.acquire(context.pool, spec(context.root))
    await_state(context.pool, context.root, [:ready])
    assert :ok = LspPool.release(context.pool, handle)

    await(fn ->
      case LspPool.status(context.pool).servers do
        [] -> {:ok, :idle_stopped}
        other -> other
      end
    end)
  end

  @tag pool_opts: [idle_ms: 300, sweep_ms: 300]
  test "a claimed server is never idle-stopped, however long it sits", context do
    assert {:ok, _handle} = LspPool.acquire(context.pool, spec(context.root))
    await_state(context.pool, context.root, [:ready])

    Process.sleep(900)
    assert :ok = LspPool.sweep(context.pool)
    assert %{owners: 1, state: :ready} = server_in(context.pool, context.root)
  end

  test "a crashing server restarts up to the cap and is then broken for broken_ms", context do
    spec = spec(context.root, ["--crash-on", "textDocument/hover"])
    assert {:ok, _handle} = LspPool.acquire(context.pool, spec)

    # max_restarts is 1 here, so the second death is the one that breaks the key.
    for _attempt <- 1..2 do
      pid =
        await(fn ->
          case LspPool.checkout(context.pool, spec, wait_ready_ms: 20_000) do
            {:ok, pid} -> {:ok, pid}
            other -> other
          end
        end)

      Server.notify(pid, "textDocument/hover", %{})
      await_state(context.pool, context.root, [:restarting, :broken])
    end

    assert %{state: :broken, broken_until_ms: remaining, restarts: 2} =
             await_state(context.pool, context.root, [:broken])

    assert remaining > 0

    # Broken is an answer, never an exception, and it is the same answer for every entry
    # point until the window expires.
    assert {:error, :broken} = LspPool.acquire(context.pool, spec)
    assert {:error, :broken} = LspPool.checkout(context.pool, spec)
  end

  @tag pool_opts: [broken_ms: 1, max_restarts: 0]
  test "a broken key is retried once its window expires", context do
    spec = spec(context.root, ["--crash-on", "textDocument/hover"])
    assert {:ok, pid} = LspPool.checkout(context.pool, spec, wait_ready_ms: 20_000)
    Server.notify(pid, "textDocument/hover", %{})
    await_state(context.pool, context.root, [:broken])

    Process.sleep(10)
    assert {:ok, _handle} = LspPool.acquire(context.pool, spec(context.root))
    assert %{restarts: 0} = server_in(context.pool, context.root)
  end

  @tag pool_opts: [
         memory_budget_bytes: 8_000,
         server_memory_limit_bytes: 4_000,
         rss_reader: {Ouroboros.CodeIntel.LspPoolTest, :fixed_rss, [10_000]}
       ]
  test "a server over its own soft limit is restarted once, then marked broken", context do
    assert {:ok, _handle} = LspPool.acquire(context.pool, spec(context.root))
    await_measurable(context)

    assert :ok = LspPool.measure(context.pool)

    # First breach: the server is stopped and comes back up with its memory budget spent.
    # The wait is for the *replacement* to be live, not merely for the old one to be on
    # its way out — those are different entries wearing the same key.
    assert %{memory_restarts: 1} =
             await(fn ->
               case server_in(context.pool, context.root) do
                 %{memory_restarts: 1, state: state, os_pid: os_pid} = server
                 when state in [:starting, :ready] and is_integer(os_pid) ->
                   {:ok, server}

                 other ->
                   other
               end
             end)

    assert :ok = LspPool.measure(context.pool)
    assert %{state: :broken} = await_state(context.pool, context.root, [:broken])
  end

  @tag pool_opts: [
         memory_budget_bytes: 8_000,
         server_memory_limit_bytes: 1_000_000_000,
         rss_reader: {Ouroboros.CodeIntel.LspPoolTest, :fixed_rss, [9_000]}
       ]
  test "spawning is refused while the host budget is exhausted", context do
    assert {:ok, _handle} = LspPool.acquire(context.pool, spec(context.root))
    await_measurable(context)

    assert :ok = LspPool.measure(context.pool)
    assert LspPool.status(context.pool).used_bytes == 9_000

    other_root = Path.join(context.root, "nested")
    File.mkdir_p!(other_root)

    assert {:error, {:memory_budget_exhausted, 9_000, 8_000}} =
             LspPool.acquire(context.pool, spec(other_root))

    # The server already running is never killed to make room for a new one.
    assert [%{root: root}] = LspPool.status(context.pool).servers
    assert root == context.root
  end

  test "an unreachable pool answers an error tuple rather than exiting the caller", _context do
    absent = :code_intel_pool_that_does_not_exist

    assert {:error, {:pool_unavailable, _reason}} =
             LspPool.acquire(absent, %{root: "/tmp", server_id: "fake", executable: "/bin/true"})

    assert %{servers: [], error: {:pool_unavailable, _reason}} = LspPool.status(absent)
  end

  test "a spec without a root or a server id is refused before anything is spawned", context do
    assert {:error, {:invalid_server_spec, _spec}} =
             LspPool.acquire(context.pool, %{root: "", server_id: "fake", executable: "/bin/true"})

    assert LspPool.status(context.pool).servers == []
  end

  defp await_measurable(context) do
    await(fn ->
      case server_in(context.pool, context.root) do
        %{os_pid: os_pid} = server when is_integer(os_pid) -> {:ok, server}
        other -> other
      end
    end)
  end

  @doc false
  def fixed_rss(_os_pid, bytes), do: {:ok, bytes}
end
