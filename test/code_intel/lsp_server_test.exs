defmodule Ouroboros.CodeIntel.Lsp.ServerTest do
  use ExUnit.Case, async: false

  alias Ouroboros.CodeIntel.Lsp.Server

  # Two of these tests kill a language server on purpose; the client is expected to log
  # that and stop.
  @moduletag :capture_log

  @script Path.expand("../support/fake_language_server.exs", __DIR__)

  setup do
    Process.flag(:trap_exit, true)

    root =
      Path.join(System.tmp_dir!(), "ouroboros-lsp-server-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    record = Path.join(root, "frames.jsonl")
    on_exit(fn -> File.rm_rf(root) end)
    {:ok, root: root, record: record}
  end

  defp start(context, extra_args \\ [], opts \\ []) do
    Server.start_link(
      [
        owner: self(),
        key: {context.root, "fake"},
        root: context.root,
        server_id: "fake",
        executable: System.find_executable("elixir"),
        args: [@script, "--record", context.record] ++ extra_args,
        initialize_timeout_ms: 20_000,
        shutdown_grace_ms: 2_000
      ] ++ opts
    )
  end

  defp recorded(record) do
    case File.read(record) do
      {:ok, contents} ->
        contents
        |> String.split("\n", trim: true)
        |> Enum.flat_map(fn line ->
          case JSON.decode(line) do
            {:ok, frame} -> [frame]
            _other -> []
          end
        end)

      _other ->
        []
    end
  end

  defp await(fun, timeout \\ 20_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await(fun, deadline, nil)
  end

  defp await(fun, deadline, _last) do
    case fun.() do
      {:ok, value} ->
        value

      other ->
        if System.monotonic_time(:millisecond) >= deadline do
          flunk("condition never held; last saw #{inspect(other)}")
        else
          Process.sleep(25)
          await(fun, deadline, other)
        end
    end
  end

  test "initialize announces ouroboros as the client and the server reaches :ready", context do
    {:ok, server} = start(context)

    initialize =
      await(fn ->
        case Enum.find(recorded(context.record), &(&1["method"] == "initialize")) do
          nil -> :pending
          frame -> {:ok, frame}
        end
      end)

    assert %{"name" => "ouroboros", "version" => version} = initialize["params"]["clientInfo"]
    assert is_binary(version)
    assert initialize["params"]["rootUri"] == "file://" <> context.root

    assert initialize["params"]["capabilities"]["textDocument"]["publishDiagnostics"][
             "versionSupport"
           ]

    assert initialize["params"]["capabilities"]["textDocument"]["callHierarchy"]
    assert initialize["params"]["capabilities"]["workspace"]["configuration"]

    assert %{state: :ready, server_info: %{"name" => "fake-language-server"}} =
             await(fn ->
               case Server.info(server) do
                 {:ok, %{state: :ready} = info} -> {:ok, info}
                 _other -> :pending
               end
             end)
  end

  test "a server-initiated workspace/configuration is answered rather than stalled", context do
    {:ok, _server} = start(context)

    answer =
      await(fn ->
        case Enum.find(
               recorded(context.record),
               &(&1["id"] == "cfg-1" and is_map_key(&1, "result"))
             ) do
          nil -> :pending
          frame -> {:ok, frame}
        end
      end)

    assert answer["result"] == [%{}]
  end

  test "a request answers with a normalised LSP result", context do
    {:ok, server} = start(context)

    params = %{
      "textDocument" => %{"uri" => "file://" <> context.root <> "/a.ex"},
      "position" => %{"line" => 1, "character" => 2}
    }

    assert {:ok, [%{"uri" => _uri, "range" => _range}]} =
             Server.request(server, "textDocument/definition", params, 15_000)
  end

  test "a request the server never answers times out without killing the server", context do
    {:ok, server} = start(context, ["--slow", "textDocument/hover"])

    # Prove the transport is live before asking for the answer that will never come.
    assert {:ok, _result} =
             Server.request(
               server,
               "textDocument/definition",
               %{"textDocument" => %{"uri" => "file:///x"}},
               15_000
             )

    assert {:error, :timeout} = Server.request(server, "textDocument/hover", %{}, 300)
    assert Process.alive?(server)
    assert {:ok, %{state: :ready}} = Server.info(server)
  end

  test "a language server that exits takes the client process down with a named reason",
       context do
    {:ok, server} = start(context, ["--crash-on", "textDocument/hover"])
    ref = Process.monitor(server)

    Server.notify(server, "textDocument/hover", %{})

    assert_receive {:DOWN, ^ref, :process, ^server, {:server_exited, 1}}, 20_000
  end

  test "shutdown is graceful when the server cooperates", context do
    {:ok, server} = start(context)
    ref = Process.monitor(server)

    # Wait for :ready so the shutdown request is not merely buffered.
    await(fn ->
      case Server.info(server) do
        {:ok, %{state: :ready}} -> {:ok, :ready}
        _other -> :pending
      end
    end)

    Server.stop(server)
    assert_receive {:DOWN, ^ref, :process, ^server, :normal}, 20_000
  end

  test "a server that ignores shutdown is killed once the grace expires", context do
    {:ok, server} = start(context, ["--ignore-shutdown"], shutdown_grace_ms: 300)
    ref = Process.monitor(server)

    os_pid =
      await(fn ->
        case Server.info(server) do
          {:ok, %{state: :ready, os_pid: pid}} when is_integer(pid) -> {:ok, pid}
          _other -> :pending
        end
      end)

    Server.stop(server)
    assert_receive {:DOWN, ^ref, :process, ^server, :normal}, 20_000

    await(fn ->
      case System.cmd("ps", ["-o", "pid=", "-p", Integer.to_string(os_pid)],
             stderr_to_stdout: true
           ) do
        {_output, 0} -> :still_running
        {_output, _status} -> {:ok, :reaped}
      end
    end)
  end
end
