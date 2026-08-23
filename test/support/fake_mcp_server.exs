# An MCP server that speaks just enough of the protocol to exercise
# `Ouroboros.Provider.Native.Mcp` without installing anything. It is run as
# `elixir test/support/fake_mcp_server.exs <flags>` — the pool spawns it through the same
# `priv/provider-exec` wrapper every real server crosses, so the umask and cwd posture
# under test is the production one.
#
# Behaviour is chosen entirely by flags so one script covers every scenario:
#
#   --tools NAME,NAME        which tools to advertise (default echo,add,blob)
#   --page-size N            paginate tools/list N at a time, with a nextCursor
#   --endless-pages          always return a nextCursor (the runaway-pagination case)
#   --slow METHOD            never answer this method (the timeout case)
#   --crash-on METHOD        exit(1) when this method arrives (the restart case)
#   --crash-after-ready      exit(1) on the first tools/call, after a clean handshake
#   --fail-list              answer tools/list with a JSON-RPC error
#   --rpc-error              answer tools/call with a JSON-RPC error
#   --tool-error             answer tools/call with isError: true
#   --blob-bytes N           how many bytes the `blob` tool returns (default 64)
#   --schema-bytes N         pad every inputSchema's description to about N bytes
#   --noise N                write N non-JSON lines to stdout before the handshake
#   --echo-env NAME          `env` tool reports whether this variable is set (never its value)
#   --record PATH            append every received frame as a JSON line
#   --no-server-info         omit serverInfo from the initialize result
#   --ignore-eof             never exit on stdin EOF (the SIGKILL case)
defmodule Ouroboros.Test.FakeMcpServer do
  @moduledoc false

  @protocol_version "2026-07-28"

  def main(argv) do
    :io.setopts(:standard_io, encoding: :latin1)
    opts = parse(argv, defaults())
    Enum.each(1..opts.noise//1, fn n -> IO.binwrite(:stdio, "starting up (#{n})\n") end)
    loop(%{opts: opts, calls: 0})
  end

  defp defaults do
    %{
      tools: ~w(echo add blob),
      page_size: nil,
      endless_pages: false,
      slow: nil,
      crash_on: nil,
      crash_after_ready: false,
      fail_list: false,
      rpc_error: false,
      tool_error: false,
      blob_bytes: 64,
      schema_bytes: 0,
      noise: 0,
      echo_env: nil,
      record: nil,
      server_info: true,
      ignore_eof: false
    }
  end

  defp parse([], opts), do: opts
  defp parse(["--tools", list | rest], opts), do: parse(rest, %{opts | tools: split(list)})

  defp parse(["--page-size", n | rest], opts),
    do: parse(rest, %{opts | page_size: String.to_integer(n)})

  defp parse(["--endless-pages" | rest], opts), do: parse(rest, %{opts | endless_pages: true})
  defp parse(["--slow", method | rest], opts), do: parse(rest, %{opts | slow: method})
  defp parse(["--crash-on", method | rest], opts), do: parse(rest, %{opts | crash_on: method})

  defp parse(["--crash-after-ready" | rest], opts),
    do: parse(rest, %{opts | crash_after_ready: true})

  defp parse(["--fail-list" | rest], opts), do: parse(rest, %{opts | fail_list: true})
  defp parse(["--rpc-error" | rest], opts), do: parse(rest, %{opts | rpc_error: true})
  defp parse(["--tool-error" | rest], opts), do: parse(rest, %{opts | tool_error: true})

  defp parse(["--blob-bytes", n | rest], opts),
    do: parse(rest, %{opts | blob_bytes: String.to_integer(n)})

  defp parse(["--schema-bytes", n | rest], opts),
    do: parse(rest, %{opts | schema_bytes: String.to_integer(n)})

  defp parse(["--noise", n | rest], opts), do: parse(rest, %{opts | noise: String.to_integer(n)})
  defp parse(["--echo-env", name | rest], opts), do: parse(rest, %{opts | echo_env: name})
  defp parse(["--record", path | rest], opts), do: parse(rest, %{opts | record: path})
  defp parse(["--no-server-info" | rest], opts), do: parse(rest, %{opts | server_info: false})
  defp parse(["--ignore-eof" | rest], opts), do: parse(rest, %{opts | ignore_eof: true})
  defp parse([_unknown | rest], opts), do: parse(rest, opts)

  defp split(list), do: list |> String.split(",", trim: true) |> Enum.map(&String.trim/1)

  ## Loop

  defp loop(state) do
    case read_frame(state) do
      :eof -> System.halt(0)
      {:ok, frame} -> state |> record(frame) |> handle(frame) |> loop()
    end
  end

  defp record(state, frame) do
    if state.opts.record do
      File.write!(state.opts.record, JSON.encode!(frame) <> "\n", [:append])
    end

    state
  end

  defp handle(state, %{"method" => method} = frame) do
    if method == state.opts.crash_on, do: System.halt(1)

    if method == state.opts.slow,
      do: state,
      else: dispatch(state, method, frame["id"], frame["params"] || %{})
  end

  defp handle(state, _frame), do: state

  defp dispatch(state, "initialize", id, _params) do
    result =
      %{
        "protocolVersion" => @protocol_version,
        "capabilities" => %{"tools" => %{"listChanged" => false}}
      }
      |> then(fn result ->
        if state.opts.server_info,
          do: Map.put(result, "serverInfo", %{"name" => "fake", "version" => "1.0.0"}),
          else: result
      end)

    reply(id, result)
    state
  end

  defp dispatch(state, "tools/list", id, params) do
    cond do
      state.opts.fail_list ->
        error(id, -32_603, "no tools today")

      true ->
        {page, cursor} = page(state, Map.get(params, "cursor"))
        result = %{"tools" => Enum.map(page, &descriptor(state, &1))}
        reply(id, if(cursor, do: Map.put(result, "nextCursor", cursor), else: result))
    end

    state
  end

  defp dispatch(state, "tools/call", id, params) do
    if state.opts.crash_after_ready, do: System.halt(1)

    cond do
      state.opts.rpc_error ->
        error(id, -32_602, "the server refuses this call")

      state.opts.tool_error ->
        reply(id, %{
          "content" => [%{"type" => "text", "text" => "the tool failed on purpose"}],
          "isError" => true
        })

      true ->
        reply(id, invoke(state, Map.get(params, "name"), Map.get(params, "arguments") || %{}))
    end

    %{state | calls: state.calls + 1}
  end

  defp dispatch(state, "notifications/initialized", _id, _params), do: state

  defp dispatch(state, _method, nil, _params), do: state

  defp dispatch(state, method, id, _params) do
    error(id, -32_601, "no such method: #{method}")
    state
  end

  ## Tools

  defp page(state, cursor) do
    index = if is_binary(cursor), do: String.to_integer(cursor), else: 0
    size = state.opts.page_size || length(state.opts.tools)
    page = state.opts.tools |> Enum.drop(index) |> Enum.take(size)
    next = index + length(page)

    cond do
      state.opts.endless_pages -> {page, Integer.to_string(next)}
      next < length(state.opts.tools) -> {page, Integer.to_string(next)}
      true -> {page, nil}
    end
  end

  defp descriptor(state, name) do
    %{
      "name" => name,
      "description" => "The fake #{name} tool." <> padding(state.opts.schema_bytes),
      "inputSchema" => %{
        "type" => "object",
        "properties" => %{
          "text" => %{
            "type" => "string",
            "description" => "Anything" <> padding(state.opts.schema_bytes)
          }
        }
      }
    }
  end

  defp padding(0), do: ""
  defp padding(bytes), do: " " <> String.duplicate("x", bytes)

  defp invoke(_state, "echo", arguments) do
    text = Map.get(arguments, "text") || ""
    %{"content" => [%{"type" => "text", "text" => "echo: #{text}"}], "isError" => false}
  end

  defp invoke(_state, "add", arguments) do
    sum = number(Map.get(arguments, "a")) + number(Map.get(arguments, "b"))

    %{
      "content" => [%{"type" => "text", "text" => "sum"}],
      "structuredContent" => %{"sum" => sum},
      "isError" => false
    }
  end

  defp invoke(state, "blob", _arguments) do
    %{
      "content" => [%{"type" => "text", "text" => String.duplicate("b", state.opts.blob_bytes)}],
      "isError" => false
    }
  end

  defp invoke(_state, "picture", _arguments) do
    %{
      "content" => [
        %{"type" => "image", "data" => String.duplicate("A", 128), "mimeType" => "image/png"}
      ],
      "isError" => false
    }
  end

  defp invoke(state, "env", _arguments) do
    present? = state.opts.echo_env && System.get_env(state.opts.echo_env) != nil

    %{
      "content" => [%{"type" => "text", "text" => "present=#{present? == true}"}],
      "isError" => false
    }
  end

  defp invoke(_state, name, _arguments) do
    %{"content" => [%{"type" => "text", "text" => "no such tool: #{name}"}], "isError" => true}
  end

  defp number(value) when is_number(value), do: value
  defp number(_value), do: 0

  ## Framing

  defp reply(nil, _result), do: :ok
  defp reply(id, result), do: write(%{"jsonrpc" => "2.0", "id" => id, "result" => result})

  defp error(nil, _code, _message), do: :ok

  defp error(id, code, message),
    do:
      write(%{"jsonrpc" => "2.0", "id" => id, "error" => %{"code" => code, "message" => message}})

  defp write(message), do: IO.binwrite(:stdio, [JSON.encode_to_iodata!(message), "\n"])

  defp read_frame(state) do
    case IO.binread(:stdio, :line) do
      :eof ->
        if state.opts.ignore_eof, do: sleep_forever(), else: :eof

      line when is_binary(line) ->
        case JSON.decode(String.trim(line)) do
          {:ok, frame} when is_map(frame) -> {:ok, frame}
          _other -> read_frame(state)
        end

      _error ->
        :eof
    end
  end

  defp sleep_forever do
    Process.sleep(60_000)
    sleep_forever()
  end
end

Ouroboros.Test.FakeMcpServer.main(System.argv())
