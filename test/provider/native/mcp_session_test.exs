defmodule Ouroboros.Provider.Native.McpSessionTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Mcp.Pool
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Test.NativeModelScript

  @moduletag :capture_log

  @script Path.expand("../../support/fake_mcp_server.exs", __DIR__)

  # The whole point of this file: an MCP tool has to reach the model, come back as a real
  # `tool_call`/`tool_result` pair, and be gated by the permission engine like anything
  # else — through the same session API a client drives, not through a helper written for
  # the test.

  setup do
    root = Path.join(System.tmp_dir!(), "mcp-session-#{System.unique_integer([:positive])}")
    data_dir = Path.join(root, "data")
    File.mkdir_p!(Path.join(root, "workspace"))
    File.mkdir_p!(data_dir)

    # The session canonicalizes its `cwd` through every symlink before it becomes the
    # scope root, and the pool is keyed on that root. On a machine where the temporary
    # directory is itself a link — macOS, where `/var` is `/private/var` — a test that
    # kept the unresolved path would be talking about a different key than the runtime.
    {:ok, %{root: workspace}} =
      Ouroboros.Provider.Native.Paths.scope(Path.join(root, "workspace"), [], :workspace_write)

    user_path = Path.join(root, "user-mcp.json")
    record = Path.join(root, "frames.jsonl")

    previous = %{
      data_dir: Application.get_env(:ouroboros, :native_data_dir),
      model: Application.get_env(:ouroboros, :native_model_module),
      servers: Application.get_env(:ouroboros, :mcp_servers),
      user_path: Application.get_env(:ouroboros, :mcp_user_path),
      engine: Application.get_env(:ouroboros, :permissions_engine)
    }

    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)
    Application.put_env(:ouroboros, :mcp_user_path, user_path)

    Application.put_env(:ouroboros, :mcp_servers, %{
      "fake" => %{
        command: System.find_executable("elixir"),
        args: [@script, "--tools", "echo,add", "--record", record]
      }
    })

    on_exit(fn ->
      Pool.stop_workspace(Pool, workspace)
      Enum.each(previous, fn {key, value} -> restore(env_key(key), value) end)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, record: record}
  end

  test "an mcp__fake__echo call round-trips through a real session's events", context do
    %{handle: handle} =
      open(context, [
        [
          {:tool_call, %{id: "c1", name: "mcp__fake__echo", input: %{"text" => "round trip"}}}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ])

    assert :ok = Session.send(handle, TurnRequest.new!("use the mcp tool"), "turn-1")
    events = collect_until(:turn_completed)

    call = find_event(events, :tool_call)
    result = find_event(events, :tool_result)

    assert call.payload["name"] == "mcp__fake__echo"
    assert call.payload["input"] == %{"text" => "round trip"}
    assert result.payload["output"] == "echo: round trip"
    assert result.payload["is_error"] == false

    # The name the model saw is the name the server was told, minus the routing prefix.
    frames = recorded(context.record)
    called = Enum.find(frames, &(&1["method"] == "tools/call"))
    assert called["params"]["name"] == "echo"
    assert called["params"]["arguments"] == %{"text" => "round trip"}
  end

  test "the model is shown the MCP tools alongside this runtime's own", context do
    %{agent: agent, handle: handle} =
      open(context, [[{:text, "hello"}, {:finish, :stop}]])

    assert :ok = Session.send(handle, TurnRequest.new!("hi"), "turn-1")
    collect_until(:turn_completed)

    [request | _rest] = NativeModelScript.requests(agent)
    names = Enum.map(request.tools, & &1.name)

    assert "mcp__fake__echo" in names
    assert "mcp__fake__add" in names
    assert "read" in names
    # MCP tools are last, so the cacheable part of the prefix stays first.
    assert List.last(names) == "mcp__fake__add"
  end

  test "a deny rule refuses the call before the server ever sees it", context do
    Application.put_env(:ouroboros, :permissions_engine, __MODULE__.DenyMcp)

    %{handle: handle} =
      open(
        context,
        [
          [{:tool_call, %{id: "c1", name: "mcp__fake__echo", input: %{"text" => "nope"}}}],
          [{:text, "understood"}, {:finish, :stop}]
        ],
        %{approval_mode: :prompt}
      )

    assert :ok = Session.send(handle, TurnRequest.new!("use the mcp tool"), "turn-1")
    events = collect_until(:turn_completed)

    result = find_event(events, :tool_result)
    assert result.payload["is_error"] == true
    assert result.payload["output"] =~ "denies mcp__fake__echo"

    # The proof that "before the server sees it" is not a figure of speech: the server
    # was started to advertise its tools, and never received a `tools/call`.
    frames = recorded(context.record)
    assert Enum.any?(frames, &(&1["method"] == "tools/list"))
    refute Enum.any?(frames, &(&1["method"] == "tools/call"))
  end

  test "the server this session claimed is stopped when the session ends", context do
    %{handle: handle} =
      open(context, [
        [{:tool_call, %{id: "c1", name: "mcp__fake__echo", input: %{"text" => "x"}}}],
        [{:text, "done"}, {:finish, :stop}]
      ])

    assert :ok = Session.send(handle, TurnRequest.new!("go"), "turn-1")
    collect_until(:turn_completed)

    assert [%{name: "fake", claims: 1}] =
             Enum.filter(Pool.status(Pool).servers, &(&1.workspace == context.workspace))

    :ok = Session.close(handle)

    assert eventually(fn ->
             Enum.filter(Pool.status(Pool).servers, &(&1.workspace == context.workspace)) == []
           end)
  end

  # A permission engine that denies exactly one tool, so the assertion is about the seam
  # and not about whatever rules this node happens to carry.
  defmodule DenyMcp do
    @moduledoc false

    def evaluate(%{tool: "mcp__fake__echo", mode: :execute}), do: {:deny, "test:no-mcp"}
    def evaluate(_request), do: {:allow, "test:allow"}
    def record(_id, _attrs), do: :ok
  end

  ## Helpers

  defp open(context, script, overrides \\ %{}) do
    {model_spec, agent} = NativeModelScript.start(script)

    request =
      SessionRequest.new!(
        Map.merge(
          %{
            provider: :native,
            cwd: context.workspace,
            model: model_spec,
            approval_mode: :auto_approve,
            approval_timeout_ms: 2_000
          },
          overrides
        )
      )

    session_context = %{
      session_id: "sess-#{System.unique_integer([:positive])}",
      provider: :native,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: %{},
      process_manager: Jido.Harness.ProcessDriver.Erlexec,
      telemetry_context: %{}
    }

    {:ok, handle} = Session.open(request, session_context)
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)
    await_event(:provider_event)
    %{handle: handle, agent: agent}
  end

  defp collect_until(type, acc \\ []) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> Enum.reverse([event | acc])
      {:session_adapter_event, event} -> collect_until(type, [event | acc])
    after
      30_000 -> flunk("no #{type} within 30s; got #{inspect(Enum.map(acc, & &1.type))}")
    end
  end

  defp await_event(type) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> event
      {:session_adapter_event, _other} -> await_event(type)
    after
      30_000 -> flunk("no #{type} within 30s")
    end
  end

  defp find_event(events, type) do
    case Enum.find(events, &(&1.type == type)) do
      nil -> flunk("no #{type} in #{inspect(Enum.map(events, & &1.type))}")
      event -> event
    end
  end

  defp recorded(path) do
    path
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(&JSON.decode!/1)
  end

  defp eventually(fun, timeout \\ 5_000) do
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

  defp env_key(:data_dir), do: :native_data_dir
  defp env_key(:model), do: :native_model_module
  defp env_key(:servers), do: :mcp_servers
  defp env_key(:user_path), do: :mcp_user_path
  defp env_key(:engine), do: :permissions_engine

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
