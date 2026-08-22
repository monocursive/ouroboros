# A language server that speaks just enough LSP to exercise
# `Ouroboros.CodeIntel.Lsp.Server` and `Ouroboros.CodeIntel.LspPool` without installing
# anything. It is run as `elixir test/support/fake_language_server.exs <flags>` — the
# pool spawns it through the same `priv/provider-exec` wrapper every real server crosses,
# so the umask and cwd posture under test is the production one.
#
# Behaviour is chosen entirely by flags so one script covers every scenario:
#
#   --record PATH            append every received frame as a JSON line
#   --publish-on-change      publish diagnostics on didOpen and didChange
#   --publish-version N      publish with this fixed version (the stale-push case)
#   --publish-unversioned    publish with no version field at all
#   --publish-duplicates     publish the same diagnostic twice (the dedupe case)
#   --slow METHOD            never answer this method (the timeout case)
#   --crash-on METHOD        exit(1) when this method arrives (the restart case)
#   --ignore-shutdown        never answer shutdown and never exit (the SIGKILL case)
#   --definitions N          return N locations for textDocument/definition
#   --no-server-info         omit serverInfo from the initialize result
defmodule Ouroboros.Test.FakeLanguageServer do
  @moduledoc false

  def main(argv) do
    :io.setopts(:standard_io, encoding: :latin1)
    loop(%{opts: parse(argv, defaults()), documents: %{}})
  end

  defp defaults do
    %{
      record: nil,
      publish_on_change: false,
      publish_version: nil,
      publish_unversioned: false,
      publish_duplicates: false,
      slow: nil,
      crash_on: nil,
      ignore_shutdown: false,
      definitions: 1,
      server_info: true
    }
  end

  defp parse([], opts), do: opts
  defp parse(["--record", path | rest], opts), do: parse(rest, %{opts | record: path})

  defp parse(["--publish-on-change" | rest], opts),
    do: parse(rest, %{opts | publish_on_change: true})

  defp parse(["--publish-version", value | rest], opts),
    do: parse(rest, %{opts | publish_version: String.to_integer(value)})

  defp parse(["--publish-unversioned" | rest], opts),
    do: parse(rest, %{opts | publish_unversioned: true})

  defp parse(["--publish-duplicates" | rest], opts),
    do: parse(rest, %{opts | publish_duplicates: true})

  defp parse(["--slow", method | rest], opts), do: parse(rest, %{opts | slow: method})
  defp parse(["--crash-on", method | rest], opts), do: parse(rest, %{opts | crash_on: method})
  defp parse(["--ignore-shutdown" | rest], opts), do: parse(rest, %{opts | ignore_shutdown: true})

  defp parse(["--definitions", value | rest], opts),
    do: parse(rest, %{opts | definitions: String.to_integer(value)})

  defp parse(["--no-server-info" | rest], opts), do: parse(rest, %{opts | server_info: false})
  defp parse([_unknown | rest], opts), do: parse(rest, opts)

  ## Loop

  defp loop(state) do
    case read_frame() do
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

    if method == state.opts.slow do
      state
    else
      dispatch(state, method, frame["id"], frame["params"] || %{})
    end
  end

  defp handle(state, _frame), do: state

  defp dispatch(state, "initialize", id, _params) do
    result = %{
      "capabilities" => %{
        "textDocumentSync" => 1,
        "definitionProvider" => true,
        "referencesProvider" => true,
        "hoverProvider" => true,
        "documentSymbolProvider" => true,
        "workspaceSymbolProvider" => true,
        "implementationProvider" => true,
        "callHierarchyProvider" => true
      }
    }

    result =
      if state.opts.server_info,
        do: Map.put(result, "serverInfo", %{"name" => "fake-language-server", "version" => "1"}),
        else: result

    respond(id, result)
    state
  end

  defp dispatch(state, "initialized", _id, _params) do
    # A real server commonly asks for configuration right here; doing the same proves the
    # client answers server-initiated requests instead of stalling.
    write(%{
      "jsonrpc" => "2.0",
      "id" => "cfg-1",
      "method" => "workspace/configuration",
      "params" => %{"items" => [%{"section" => "fake"}]}
    })

    state
  end

  defp dispatch(state, "textDocument/didOpen", _id, params) do
    document = params["textDocument"] || %{}
    uri = document["uri"]
    version = document["version"]
    state = %{state | documents: Map.put(state.documents, uri, version)}
    maybe_publish(state, uri, version)
    state
  end

  defp dispatch(state, "textDocument/didChange", _id, params) do
    document = params["textDocument"] || %{}
    uri = document["uri"]
    version = document["version"]
    state = %{state | documents: Map.put(state.documents, uri, version)}
    maybe_publish(state, uri, version)
    state
  end

  defp dispatch(state, "textDocument/didClose", _id, params) do
    uri = get_in(params, ["textDocument", "uri"])
    %{state | documents: Map.delete(state.documents, uri)}
  end

  defp dispatch(state, "textDocument/definition", id, params) do
    uri = get_in(params, ["textDocument", "uri"])

    respond(
      id,
      Enum.map(1..state.opts.definitions//1, fn index ->
        %{"uri" => uri, "range" => range(index, 0, index, 4)}
      end)
    )

    state
  end

  defp dispatch(state, "textDocument/references", id, params) do
    uri = get_in(params, ["textDocument", "uri"])
    respond(id, [%{"uri" => uri, "range" => range(7, 2, 7, 9)}])
    state
  end

  defp dispatch(state, "textDocument/hover", id, _params) do
    respond(id, %{"contents" => %{"kind" => "markdown", "value" => "fake hover"}})
    state
  end

  defp dispatch(state, "textDocument/documentSymbol", id, _params) do
    respond(id, [
      %{
        "name" => "Widget",
        "kind" => 5,
        "range" => range(0, 0, 12, 0),
        "selectionRange" => range(0, 6, 0, 12)
      }
    ])

    state
  end

  defp dispatch(state, "workspace/symbol", id, _params) do
    respond(id, [
      %{
        "name" => "Widget",
        "kind" => 5,
        "location" => %{
          "uri" => state.documents |> Map.keys() |> List.first() || "file:///dev/null",
          "range" => range(0, 0, 0, 6)
        }
      }
    ])

    state
  end

  defp dispatch(state, "textDocument/implementation", id, params) do
    uri = get_in(params, ["textDocument", "uri"])
    respond(id, %{"uri" => uri, "range" => range(3, 0, 3, 8)})
    state
  end

  defp dispatch(state, "textDocument/prepareCallHierarchy", id, params) do
    uri = get_in(params, ["textDocument", "uri"])

    respond(id, [
      %{
        "name" => "call_me",
        "kind" => 12,
        "uri" => uri,
        "range" => range(4, 0, 6, 3),
        "selectionRange" => range(4, 4, 4, 11)
      }
    ])

    state
  end

  defp dispatch(state, "callHierarchy/incomingCalls", id, _params) do
    respond(id, [
      %{
        "from" => %{
          "name" => "caller",
          "kind" => 12,
          "uri" => "file:///dev/null",
          "range" => range(1, 0, 2, 3),
          "selectionRange" => range(1, 4, 1, 10)
        },
        "fromRanges" => [range(1, 4, 1, 10)]
      }
    ])

    state
  end

  defp dispatch(state, "callHierarchy/outgoingCalls", id, _params) do
    respond(id, [
      %{
        "to" => %{
          "name" => "callee",
          "kind" => 12,
          "uri" => "file:///dev/null",
          "range" => range(9, 0, 9, 3),
          "selectionRange" => range(9, 4, 9, 10)
        },
        "fromRanges" => [range(9, 4, 9, 10)]
      }
    ])

    state
  end

  defp dispatch(state, "shutdown", id, _params) do
    if not state.opts.ignore_shutdown, do: respond(id, nil)
    state
  end

  defp dispatch(state, "exit", _id, _params) do
    if not state.opts.ignore_shutdown, do: System.halt(0)
    state
  end

  defp dispatch(state, _method, nil, _params), do: state

  defp dispatch(state, method, id, _params) do
    write(%{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => -32_601, "message" => "fake server does not implement #{method}"}
    })

    state
  end

  ## Diagnostics

  defp maybe_publish(%{opts: %{publish_on_change: false}}, _uri, _version), do: :ok

  defp maybe_publish(state, uri, version) do
    item = %{
      "range" => range(1, 0, 1, 5),
      "severity" => 1,
      "code" => "E001",
      "source" => "fake",
      "message" => "undefined variable"
    }

    items =
      if state.opts.publish_duplicates,
        do: [item, item, %{item | "severity" => 2, "code" => "W002", "message" => "unused"}],
        else: [item]

    params = %{"uri" => uri, "diagnostics" => items}

    params =
      cond do
        state.opts.publish_unversioned -> params
        state.opts.publish_version -> Map.put(params, "version", state.opts.publish_version)
        true -> Map.put(params, "version", version)
      end

    write(%{
      "jsonrpc" => "2.0",
      "method" => "textDocument/publishDiagnostics",
      "params" => params
    })
  end

  defp range(start_line, start_character, end_line, end_character) do
    %{
      "start" => %{"line" => start_line, "character" => start_character},
      "end" => %{"line" => end_line, "character" => end_character}
    }
  end

  ## Transport

  defp respond(nil, _result), do: :ok
  defp respond(id, result), do: write(%{"jsonrpc" => "2.0", "id" => id, "result" => result})

  defp write(message) do
    body = JSON.encode_to_iodata!(message)

    IO.binwrite(:stdio, [
      "Content-Length: ",
      Integer.to_string(:erlang.iolist_size(body)),
      "\r\n\r\n",
      body
    ])
  end

  defp read_frame do
    case read_headers(%{}) do
      :eof ->
        :eof

      {:ok, headers} ->
        case Map.fetch(headers, "content-length") do
          {:ok, length} ->
            case IO.binread(:stdio, length) do
              body when is_binary(body) -> JSON.decode(body) |> normalize()
              _other -> :eof
            end

          :error ->
            :eof
        end
    end
  end

  defp normalize({:ok, frame}) when is_map(frame), do: {:ok, frame}
  defp normalize(_other), do: :eof

  defp read_headers(acc) do
    case IO.binread(:stdio, :line) do
      line when is_binary(line) ->
        case String.trim(line) do
          "" -> {:ok, acc}
          header -> read_headers(put_header(acc, header))
        end

      _eof_or_error ->
        :eof
    end
  end

  defp put_header(acc, header) do
    case String.split(header, ":", parts: 2) do
      ["Content-Length", value] -> Map.put(acc, "content-length", parse_length(value))
      _other -> acc
    end
  end

  defp parse_length(value) do
    case value |> String.trim() |> Integer.parse() do
      {length, ""} -> length
      _other -> 0
    end
  end
end

Ouroboros.Test.FakeLanguageServer.main(System.argv())
