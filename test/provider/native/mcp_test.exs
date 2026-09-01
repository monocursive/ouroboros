defmodule Ouroboros.Provider.Native.McpTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Desktop
  alias Ouroboros.Provider.Native.Mcp
  alias Ouroboros.Provider.Native.Mcp.Pool
  alias Ouroboros.Provider.Native.Mcp.Result
  alias Ouroboros.Provider.Native.Tools

  @moduletag :capture_log

  @script Path.expand("../../support/fake_mcp_server.exs", __DIR__)

  setup do
    root = Path.join(System.tmp_dir!(), "mcp-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)
    user_path = Path.join(root, "user-mcp.json")

    previous_servers = Application.get_env(:ouroboros, :mcp_servers)
    previous_user = Application.get_env(:ouroboros, :mcp_user_path)
    previous_mcp = Application.get_env(:ouroboros, :mcp)

    # Never the operator's own `~/.config/ouroboros/mcp.json`: a test that read it would
    # spawn whatever the machine happens to have configured.
    Application.put_env(:ouroboros, :mcp_user_path, user_path)
    Application.put_env(:ouroboros, :mcp_servers, %{})

    on_exit(fn ->
      restore(:mcp_servers, previous_servers)
      restore(:mcp_user_path, previous_user)
      restore(:mcp, previous_mcp)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, user_path: user_path}
  end

  describe "supervision" do
    # `rest_for_one` makes child order a blast radius. This subtree owns ports to
    # programs a stranger wrote, and nothing downstream rebuilds from what it knows, so
    # it belongs in the operator-surface tail beside the gateway rather than above the
    # planes: a crash-looping MCP server must not restart a single live session.
    test "the MCP subtree is supervised in the tail, after every plane and the gateway" do
      start_order =
        Ouroboros.Supervisor
        |> Supervisor.which_children()
        # A non-dynamic supervisor keeps its children in reverse start order.
        |> Enum.reverse()
        |> Enum.map(fn {id, _pid, _type, _modules} -> id end)

      mcp = index!(start_order, Ouroboros.Provider.Native.Mcp.Supervisor)

      for upstream <- [
            Ouroboros.Cluster,
            Ouroboros.Release.Runtime,
            Ouroboros.Coding.Recovery,
            Ouroboros.Interactive.Recovery,
            Ouroboros.Team.Recovery,
            Ouroboros.CodeIntel.Supervisor
          ] do
        assert mcp > index!(start_order, upstream),
               "the MCP subtree starts before #{inspect(upstream)}, so its crash restarts it"
      end

      # Nothing may start after it: it is the last child, so its crash restarts nothing.
      assert Enum.drop(start_order, mcp + 1) == []
    end

    test "the pool and its dynamic supervisor are both running under it" do
      children =
        Ouroboros.Provider.Native.Mcp.Supervisor
        |> Supervisor.which_children()
        |> Map.new(fn {id, pid, _type, _modules} -> {id, pid} end)

      assert is_pid(children[Ouroboros.Provider.Native.Mcp.Pool])
      assert is_pid(children[Module.concat(Ouroboros.Provider.Native.Mcp.Pool, ServerSupervisor)])
    end
  end

  describe "the handshake" do
    test "a server that answers initialize is ready, and its tools are named mcp__server__tool",
         context do
      pool = start_pool(context, [])
      configure(context, args: [])

      specs = Mcp.specs(context.workspace, pool: pool)

      assert Enum.map(specs, & &1.name) == [
               "mcp__fake__echo",
               "mcp__fake__add",
               "mcp__fake__blob"
             ]

      assert %{servers: [server]} = Pool.status(pool)
      assert server.state == :ready
      assert server.name == "fake"
      assert server.tools == 3
      assert server.transport == :stdio
    end

    test "a server that never answers initialize is broken, not waited on", context do
      pool = start_pool(context, handshake_timeout_ms: 300, list_wait_ms: 400, max_restarts: 0)
      configure(context, args: ["--slow", "initialize"])

      started = System.monotonic_time(:millisecond)
      assert Mcp.specs(context.workspace, pool: pool) == []
      elapsed = System.monotonic_time(:millisecond) - started

      assert elapsed < 3_000, "the turn waited #{elapsed} ms on a server that never answers"
      assert eventually(fn -> state_of(pool, "fake") == :broken end)
    end

    test "the client sends the pinned protocol revision and its own identity", context do
      record = Path.join(context.root, "frames.jsonl")
      pool = start_pool(context, [])
      configure(context, args: ["--record", record])

      Mcp.specs(context.workspace, pool: pool)

      frames = recorded(record)
      initialize = Enum.find(frames, &(&1["method"] == "initialize"))

      assert initialize["params"]["protocolVersion"] == "2026-07-28"
      assert initialize["params"]["clientInfo"]["name"] == "ouroboros"
      # Declaring a capability this client does not serve invites a server to ask for
      # something it will never be answered.
      assert initialize["params"]["capabilities"] == %{}
      assert Enum.any?(frames, &(&1["method"] == "notifications/initialized"))
    end

    test "a server that writes a banner to stdout is tolerated up to the noise bound",
         context do
      pool = start_pool(context, [])
      configure(context, args: ["--noise", "3"])

      assert length(Mcp.specs(context.workspace, pool: pool)) == 3
    end

    test "a server that answers initialize and then refuses tools/list is ready with no tools",
         context do
      pool = start_pool(context, [])
      configure(context, args: ["--fail-list"])

      assert Mcp.specs(context.workspace, pool: pool) == []
      assert eventually(fn -> state_of(pool, "fake") == :ready end)
      assert %{servers: [%{tools: 0}]} = Pool.status(pool)
    end
  end

  describe "tools/list" do
    test "a paginated list is followed through nextCursor until the server stops", context do
      pool = start_pool(context, [])
      configure(context, args: ["--tools", "a,b,c,d,e", "--page-size", "2"])

      assert Enum.map(Mcp.specs(context.workspace, pool: pool), & &1.name) == [
               "mcp__fake__a",
               "mcp__fake__b",
               "mcp__fake__c",
               "mcp__fake__d",
               "mcp__fake__e"
             ]
    end

    test "a server that paginates forever is stopped at the page cap", context do
      pool = start_pool(context, max_tool_pages: 3)
      configure(context, args: ["--tools", "a,b,c,d,e,f", "--page-size", "1", "--endless-pages"])

      assert length(Mcp.specs(context.workspace, pool: pool)) == 3
    end

    test "a server advertising more tools than the cap contributes only the cap", context do
      pool = start_pool(context, max_tools_per_server: 2)
      configure(context, args: ["--tools", "a,b,c,d"])

      assert length(Mcp.specs(context.workspace, pool: pool)) == 2
    end

    test "a schema that fits is sent to the model; one past the bound is withheld visibly",
         context do
      pool = start_pool(context, [])
      configure(context, args: ["--tools", "echo"])

      assert [%{parameters: parameters, description: description}] =
               Mcp.specs(context.workspace, pool: pool)

      assert parameters["properties"]["text"]["type"] == "string"
      assert description =~ "MCP server `fake`"
      refute description =~ "withheld"

      Pool.stop_workspace(pool, context.workspace)
      configure(context, args: ["--tools", "echo", "--schema-bytes", "5000"])

      assert [%{parameters: open, description: noted}] =
               Mcp.specs(context.workspace, pool: pool, max_tool_schema_bytes: 512)

      assert open == %{"type" => "object", "additionalProperties" => true}
      assert noted =~ "withheld"
    end

    test "the whole-session schema budget stops adding schemas but never hides a tool",
         context do
      pool = start_pool(context, [])
      configure(context, args: ["--tools", "a,b,c"])

      specs = Mcp.specs(context.workspace, pool: pool, max_schema_budget_bytes: 120)

      assert length(specs) == 3

      assert Enum.any?(
               specs,
               &(&1.parameters == %{"type" => "object", "additionalProperties" => true})
             )
    end
  end

  describe "tools/call" do
    setup context do
      pool = start_pool(context, [])
      configure(context, args: ["--tools", "echo,add,blob,picture"])
      Mcp.specs(context.workspace, pool: pool)
      %{pool: pool}
    end

    test "a call round-trips and its text content is the tool result", context do
      assert %{output: "echo: hello", is_error: false} =
               Mcp.call("mcp__fake__echo", %{"text" => "hello"}, opts(context))
    end

    test "structuredContent is appended rather than dropped", context do
      assert %{output: output, is_error: false} =
               Mcp.call("mcp__fake__add", %{"a" => 2, "b" => 3}, opts(context))

      assert output =~ "sum"
      assert output =~ ~s(structuredContent: {"sum":5})
    end

    test "an image block is described, never inlined as base64", context do
      assert %{output: output, is_error: false} =
               Mcp.call("mcp__fake__picture", %{}, opts(context))

      assert output == "[image, image/png, 128 base64 bytes]"
    end

    test "a tool this server does not advertise is refused with the list that exists",
         context do
      assert %{output: output, is_error: true} =
               Mcp.call("mcp__fake__nope", %{}, opts(context))

      assert output =~ "advertises no tool named `nope`"
      assert output =~ "echo"
    end

    test "a server that is not configured is named, with the servers that are", context do
      assert %{output: output, is_error: true} =
               Mcp.call("mcp__ghost__echo", %{}, opts(context))

      assert output =~ "no MCP server named `ghost`"
      assert output =~ "Available: fake"
    end

    test "a name that is not mcp__server__tool is refused before anything is spawned",
         context do
      assert %{output: output, is_error: true} = Mcp.call("mcp__fake", %{}, opts(context))
      assert output =~ "is not a `mcp__<server>__<tool>` name"
    end
  end

  describe "failure" do
    test "a call that outlives its timeout is a typed error, not a hung turn", context do
      pool = start_pool(context, call_timeout_ms: 300)
      configure(context, args: ["--slow", "tools/call"])
      Mcp.specs(context.workspace, pool: pool)

      assert %{output: output, is_error: true} =
               Mcp.call("mcp__fake__echo", %{}, pool: pool, workspace: context.workspace)

      assert output =~ "did not answer before the call timeout"
    end

    test "a JSON-RPC error is reported with its code, not swallowed", context do
      pool = start_pool(context, [])
      configure(context, args: ["--rpc-error"])
      Mcp.specs(context.workspace, pool: pool)

      assert %{output: output, is_error: true} =
               Mcp.call("mcp__fake__echo", %{}, pool: pool, workspace: context.workspace)

      assert output =~ "refused the call (JSON-RPC -32602)"
      assert output =~ "the server refuses this call"
    end

    test "isError from the server is an error result the model reads, not a crash", context do
      pool = start_pool(context, [])
      configure(context, args: ["--tool-error"])
      Mcp.specs(context.workspace, pool: pool)

      assert %{output: "the tool failed on purpose", is_error: true} =
               Mcp.call("mcp__fake__echo", %{}, pool: pool, workspace: context.workspace)
    end

    test "a server that dies mid-call answers the caller instead of stranding it", context do
      pool = start_pool(context, [])
      configure(context, args: ["--crash-after-ready"])
      Mcp.specs(context.workspace, pool: pool)

      assert %{output: output, is_error: true} =
               Mcp.call("mcp__fake__echo", %{}, pool: pool, workspace: context.workspace)

      assert output =~ "the server exited (status 1) while the call was in flight"
    end

    test "a server that fails on every spawn is marked broken and stops being respawned",
         context do
      pool =
        start_pool(context,
          max_restarts: 1,
          restart_backoff_ms: 20,
          handshake_timeout_ms: 500,
          list_wait_ms: 200
        )

      configure(context, args: ["--crash-on", "initialize"])
      Mcp.specs(context.workspace, pool: pool)

      assert eventually(fn -> state_of(pool, "fake") == :broken end)
      assert %{servers: [server]} = Pool.status(pool)
      assert server.restarts == 2
      assert server.broken_reason =~ "restart_limit"

      # And every call against a broken key answers immediately rather than respawning.
      assert %{output: output, is_error: true} =
               Mcp.call("mcp__fake__echo", %{}, pool: pool, workspace: context.workspace)

      assert output =~ "failed to start repeatedly"
    end

    test "output past the result cap is truncated with a visible byte count", context do
      pool = start_pool(context, max_result_bytes: 200)
      configure(context, args: ["--tools", "blob", "--blob-bytes", "5000"])
      Mcp.specs(context.workspace, pool: pool)

      assert %{output: output, is_error: false} =
               Mcp.call("mcp__fake__blob", %{}, pool: pool, workspace: context.workspace)

      assert byte_size(output) < 400
      assert output =~ ~r/… \+\d+ bytes \(MCP result truncated at 200 bytes\)/
    end

    test "a `url` server is refused at call time with the reason the loader gave", context do
      pool = start_pool(context, [])

      File.write!(
        context.user_path,
        JSON.encode!(%{"mcpServers" => %{"remote" => %{"url" => "https://x"}}})
      )

      assert %{output: output, is_error: true} =
               Mcp.call("mcp__remote__anything", %{}, pool: pool, workspace: context.workspace)

      assert output =~ "stdio only"
    end
  end

  describe "the pool" do
    test "two sessions in one workspace share one child", context do
      pool = start_pool(context, [])
      configure(context, args: [])

      Mcp.specs(context.workspace, pool: pool)
      before = server_status(pool, "fake")
      Mcp.specs(context.workspace, pool: pool)
      after_second_session = server_status(pool, "fake")

      assert after_second_session.restarts == before.restarts
      assert after_second_session.uptime_ms >= before.uptime_ms
      assert %{servers: [_one]} = Pool.status(pool)
    end

    test "the last claim released stops the child, which is the kill on session end",
         context do
      pool = start_pool(context, idle_ms: 600_000)
      configure(context, args: [])
      Mcp.specs(context.workspace, pool: pool)

      owner = spawn(fn -> Process.sleep(:infinity) end)

      assert %{is_error: false} =
               Mcp.call("mcp__fake__echo", %{"text" => "x"},
                 pool: pool,
                 workspace: context.workspace,
                 owner: owner
               )

      assert %{servers: [%{claims: 1}]} = Pool.status(pool)

      Process.exit(owner, :kill)

      assert eventually(fn -> Pool.status(pool).servers == [] end)
    end

    # `Map.update/4` evaluates its initial value whether or not the key is there, so every
    # claim after the first created a monitor the pool then threw away — one leaked
    # reference per tool call, for the life of the node.
    test "one monitor per owner, however many tool calls it makes", context do
      pool = start_pool(context, idle_ms: 600_000)
      configure(context, args: [])
      Mcp.specs(context.workspace, pool: pool)

      owner = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> Process.exit(owner, :kill) end)

      pool_pid = Process.whereis(pool)
      before = length(monitors(pool_pid))

      for _call <- 1..3 do
        assert %{is_error: false} =
                 Mcp.call("mcp__fake__echo", %{"text" => "x"},
                   pool: pool,
                   workspace: context.workspace,
                   owner: owner
                 )
      end

      assert length(monitors(pool_pid)) == before + 1
      assert Enum.count(monitors(pool_pid), &(&1 == {:process, owner})) == 1
    end

    test "an idle server with no claim is stopped by the sweep", context do
      pool = start_pool(context, idle_ms: 300, sweep_ms: 100)
      configure(context, args: [])
      Mcp.specs(context.workspace, pool: pool)

      assert eventually(fn -> Pool.status(pool).servers == [] end, 5_000)
    end

    test "past the server cap a further definition is refused rather than spawned",
         context do
      pool = start_pool(context, max_servers: 1)

      Application.put_env(:ouroboros, :mcp_servers, %{
        "one" => %{command: elixir(), args: [@script, "--tools", "echo"]},
        "two" => %{command: elixir(), args: [@script, "--tools", "echo"]}
      })

      specs = Mcp.specs(context.workspace, pool: pool)

      assert Enum.map(specs, & &1.name) == ["mcp__one__echo"]
    end
  end

  describe "the environment" do
    test "a declared variable reaches the child and never reaches a status projection",
         context do
      pool = start_pool(context, [])

      Application.put_env(:ouroboros, :mcp_servers, %{
        "fake" => %{
          command: elixir(),
          args: [@script, "--tools", "env", "--echo-env", "OUROBOROS_MCP_TEST_TOKEN"],
          env: %{"OUROBOROS_MCP_TEST_TOKEN" => "s3cret"}
        }
      })

      Mcp.specs(context.workspace, pool: pool)

      assert %{output: "present=true", is_error: false} =
               Mcp.call("mcp__fake__env", %{}, pool: pool, workspace: context.workspace)

      status = Pool.status(pool)
      refute inspect(status) =~ "s3cret"
      assert [%{env_count: 1}] = status.servers
    end
  end

  describe "the tool registry seam" do
    setup context do
      configure(context, args: ["--tools", "echo,add"])
      on_exit(fn -> Pool.stop_workspace(Pool, context.workspace) end)
      specs = Tools.specs(nil, nil, workspace: context.workspace)
      %{specs: specs}
    end

    test "MCP tools follow the static and any node-local desktop tools in the spec list",
         context do
      names = Enum.map(context.specs, & &1.name)

      desktop =
        if Desktop.enabled?() do
          ["desktop_state"] ++ if(Desktop.act_enabled?(), do: ["desktop_act"], else: [])
        else
          []
        end

      assert names ==
               Enum.map(Tools.modules(), & &1.name()) ++
                 desktop ++ ["mcp__fake__echo", "mcp__fake__add"]
    end

    test "no MCP tool appears when the caller named no workspace" do
      assert Enum.map(Tools.specs(nil, nil), & &1.name) == Enum.map(Tools.modules(), & &1.name())
    end

    test "lookup resolves an advertised name to the one dynamic module, carrying the name",
         _context do
      assert {:ok, {Ouroboros.Provider.Native.Tools.Mcp, "mcp__fake__echo"}} =
               Tools.lookup("mcp__fake__echo", nil, nil)

      assert {:error, :unknown_tool} = Tools.lookup("mcp__ghost__echo", nil, nil)
      assert {:error, :unknown_tool} = Tools.lookup("mcp__fake", nil, nil)
    end

    test "the tool filters apply to an MCP name exactly as they do to a static one",
         context do
      assert {:error, :unknown_tool} = Tools.lookup("mcp__fake__echo", nil, ["mcp__fake__echo"])
      assert {:error, :unknown_tool} = Tools.lookup("mcp__fake__echo", ["read"], nil)

      filtered = Tools.specs(nil, ["mcp__fake__echo"], workspace: context.workspace)
      names = Enum.map(filtered, & &1.name)

      refute "mcp__fake__echo" in names
      assert "mcp__fake__add" in names
    end

    test "an MCP call classifies as execute, under its full name, claiming no paths" do
      scope = %{root: "/tmp", roots: ["/tmp"], sandbox_mode: :workspace_write}

      assert %{tool: "mcp__fake__echo", mode: :execute, paths: [], write_paths: [], domains: []} =
               Tools.classify("mcp__fake__echo", %{"text" => "x"}, scope)
    end

    test "no MCP tool is answered on the approval path" do
      refute Tools.interactive?({Ouroboros.Provider.Native.Tools.Mcp, "mcp__fake__echo"})
    end

    test "execute/4 carries the resolved name to the server", context do
      {:ok, resolved} = Tools.lookup("mcp__fake__echo", nil, nil)

      tool_context = %{
        scope: %{
          root: context.workspace,
          roots: [context.workspace],
          sandbox_mode: :workspace_write
        },
        session_dir: Path.join(context.root, "no-such-session"),
        reads: %{}
      }

      assert %{output: "echo: seam", is_error: false} =
               Tools.execute(resolved, %{"text" => "seam"}, tool_context, 30_000)
    end
  end

  describe "Result rendering" do
    test "a result with no content says so rather than returning an empty string" do
      assert %{output: "(the server returned no content)", is_error: false} =
               Result.render(%{"content" => []})
    end

    test "an unknown content block is named rather than dropped" do
      assert %{output: "[video content]"} =
               Result.render(%{"content" => [%{"type" => "video", "blob" => "…"}]})
    end

    test "a resource block carries its text, and a binary one says it is not text" do
      assert %{output: "[resource file:///a]\nhello"} =
               Result.render(%{
                 "content" => [
                   %{
                     "type" => "resource",
                     "resource" => %{"uri" => "file:///a", "text" => "hello"}
                   }
                 ]
               })

      assert %{output: "[resource file:///a, not text]"} =
               Result.render(%{
                 "content" => [
                   %{"type" => "resource", "resource" => %{"uri" => "file:///a", "blob" => "AA"}}
                 ]
               })
    end
  end

  ## Helpers

  defp opts(context), do: [pool: context.pool, workspace: context.workspace]

  # Two knobs, deliberately set together: the pool passes the bounds a *server process*
  # reads down to its children, and `Ouroboros.Provider.Native.Mcp.Config` is what the
  # bounds a *caller* reads come from. A test that set only one would be testing a
  # default it did not choose.
  defp start_pool(context, settings) do
    name = Module.concat(__MODULE__, "Pool#{System.unique_integer([:positive])}")
    Application.put_env(:ouroboros, :mcp, [shutdown_grace_ms: 200] ++ settings)

    start_supervised!(
      {Ouroboros.Provider.Native.Mcp.Supervisor,
       [name: Module.concat(name, Supervisor), pool_name: name] ++ settings}
    )

    on_exit(fn -> File.rm_rf(context.root) end)
    name
  end

  defp configure(_context, opts) do
    args = [@script] ++ Keyword.get(opts, :args, [])
    Application.put_env(:ouroboros, :mcp_servers, %{"fake" => %{command: elixir(), args: args}})
  end

  defp elixir, do: System.find_executable("elixir") || raise("elixir executable not found")

  defp state_of(pool, name) do
    case Enum.find(Pool.status(pool).servers, &(&1.name == name)) do
      nil -> nil
      server -> server.state
    end
  end

  defp server_status(pool, name) do
    Enum.find(Pool.status(pool).servers, &(&1.name == name))
  end

  defp monitors(pool_pid) do
    {:monitors, monitors} = Process.info(pool_pid, :monitors)
    monitors
  end

  defp recorded(path) do
    path
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(&JSON.decode!/1)
  end

  defp eventually(fun, timeout \\ 3_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    poll(fun, deadline)
  end

  defp poll(fun, deadline) do
    cond do
      fun.() -> true
      System.monotonic_time(:millisecond) >= deadline -> false
      true -> Process.sleep(25) && poll(fun, deadline)
    end
  end

  defp index!(order, id) do
    case Enum.find_index(order, &(&1 == id)) do
      nil -> flunk("#{inspect(id)} is not supervised by Ouroboros.Supervisor on this node")
      index -> index
    end
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
