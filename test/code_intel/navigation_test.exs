defmodule Ouroboros.CodeIntel.NavigationTest do
  use ExUnit.Case, async: false

  alias Ouroboros.CodeIntel
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @moduletag :capture_log

  @script Path.expand("../support/fake_language_server.exs", __DIR__)

  setup context do
    base =
      Path.join(System.tmp_dir!(), "ouroboros-lsp-nav-#{System.unique_integer([:positive])}")

    File.mkdir_p!(base)
    {:ok, root} = WorkspacePath.canonicalize(base)
    File.write!(Path.join(root, "widget.toml"), "")
    source = Path.join(root, "thing.widget")
    File.write!(source, "widget code\n")

    pool_name = :"code_intel_nav_#{System.unique_integer([:positive])}"

    previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots, [])
    previous_code_intel = Application.get_env(:ouroboros, :code_intel, [])

    Application.put_env(:ouroboros, :workspace_allowed_roots, [root])

    Application.put_env(
      :ouroboros,
      :code_intel,
      Keyword.put(previous_code_intel, :servers, [
        %{
          language: :widget,
          extensions: [".widget"],
          root_markers: ["widget.toml"],
          candidates: [
            %{
              server_id: "fake",
              command: "elixir",
              args: [@script] ++ Map.get(context, :server_args, [])
            }
          ]
        }
      ])
    )

    on_exit(fn ->
      Application.put_env(:ouroboros, :workspace_allowed_roots, previous_roots)
      Application.put_env(:ouroboros, :code_intel, previous_code_intel)
      File.rm_rf(base)
    end)

    start_supervised!(
      {Ouroboros.CodeIntel.Supervisor,
       [
         name: :"code_intel_nav_sup_#{System.unique_integer([:positive])}",
         pool_name: pool_name,
         idle_ms: 60_000,
         sweep_ms: 60_000,
         memory_poll_ms: 60_000,
         initialize_timeout_ms: 20_000,
         shutdown_grace_ms: 500
       ]}
    )

    {:ok, root: root, source: source, pool: pool_name}
  end

  defp at(context, line \\ 1, character \\ 2),
    do: %{path: context.source, line: line, character: character}

  defp opts(context, extra \\ []), do: [pool: context.pool] ++ extra

  test "definition answers locations relative to the project root", context do
    assert {:ok, %{items: items, truncated: 0}} =
             CodeIntel.request(:definition, at(context), opts(context))

    assert [%{path: "thing.widget", external: false, range: range}] = items
    assert range.start.line == 1
    assert range.start.character == 0
  end

  test "references carry includeDeclaration and answer 0-based positions", context do
    assert {:ok, %{items: [%{path: "thing.widget", range: range}]}} =
             CodeIntel.request(:references, at(context), opts(context))

    assert range == %{start: %{line: 7, character: 2}, end: %{line: 7, character: 9}}
  end

  test "hover flattens markup contents to one string", context do
    assert {:ok, %{items: [%{value: "fake hover"}]}} =
             CodeIntel.request(:hover, at(context), opts(context))
  end

  test "document symbols keep their hierarchy and their file", context do
    assert {:ok, %{items: [symbol]}} =
             CodeIntel.request(:document_symbols, at(context), opts(context))

    assert symbol.name == "Widget"
    assert symbol.kind == :class
    assert symbol.path == "thing.widget"
    assert symbol.children == []

    assert symbol.selection_range == %{
             start: %{line: 0, character: 6},
             end: %{line: 0, character: 12}
           }
  end

  test "workspace symbols take a query and answer with locations", context do
    assert {:ok, %{items: [%{name: "Widget", kind: :class, path: "thing.widget"}]}} =
             CodeIntel.request(:workspace_symbols, at(context), opts(context, query: "Widget"))
  end

  test "implementation accepts a single Location as well as a list", context do
    assert {:ok, %{items: [%{path: "thing.widget", range: range}]}} =
             CodeIntel.request(:implementation, at(context), opts(context))

    assert range.start.line == 3
  end

  test "prepare_call_hierarchy answers items", context do
    assert {:ok, %{items: [item]}} =
             CodeIntel.request(:prepare_call_hierarchy, at(context), opts(context))

    assert item.name == "call_me"
    assert item.kind == :function
    assert item.path == "thing.widget"
  end

  test "incoming and outgoing calls prepare the item themselves", context do
    assert {:ok, %{items: [%{item: %{name: "caller"}, ranges: [range]}]}} =
             CodeIntel.request(:incoming_calls, at(context), opts(context))

    assert range == %{start: %{line: 1, character: 4}, end: %{line: 1, character: 10}}

    assert {:ok, %{items: [%{item: %{name: "callee"}}]}} =
             CodeIntel.request(:outgoing_calls, at(context), opts(context))
  end

  test "a result outside the project root keeps its absolute path and says so", context do
    # The fake server answers incoming calls from file:///dev/null, which no project root
    # contains. A definition in a dependency or a standard library looks exactly like this.
    assert {:ok, %{items: [%{item: %{path: "/dev/null", external: true}}]}} =
             CodeIntel.request(:incoming_calls, at(context), opts(context))
  end

  @tag server_args: ["--definitions", "50"]
  test "results are capped and the surplus is counted", context do
    assert {:ok, %{items: items, truncated: 45}} =
             CodeIntel.request(:definition, at(context), opts(context, max_results: 5))

    assert length(items) == 5
  end

  test "the document is opened before the first question is asked", context do
    assert {:ok, _result} = CodeIntel.request(:definition, at(context), opts(context))

    assert [%{documents: [%{path: path, version: 1}]}] =
             Ouroboros.CodeIntel.LspPool.status(context.pool).servers

    assert path == context.source

    # A second request does not re-open the document, because a version that moves under
    # a caller is the exact thing the freshness gate is built to catch.
    assert {:ok, _again} = CodeIntel.request(:hover, at(context), opts(context))

    assert [%{documents: [%{version: 1}]}] =
             Ouroboros.CodeIntel.LspPool.status(context.pool).servers
  end

  @tag server_args: ["--slow", "textDocument/hover"]
  test "a request the server never answers times out as a tuple", context do
    assert {:error, :timeout} =
             CodeIntel.request(:hover, at(context), opts(context, request_timeout_ms: 300))

    # And the server is still usable afterwards.
    assert {:ok, %{items: [_definition]}} =
             CodeIntel.request(:definition, at(context), opts(context))
  end

  test "an unknown operation is refused before anything is spawned", context do
    assert {:error, {:unknown_operation, :rename, operations}} =
             CodeIntel.request(:rename, at(context), opts(context))

    assert length(operations) == 9
    assert Ouroboros.CodeIntel.LspPool.status(context.pool).servers == []
  end

  test "a location without a path is refused", context do
    assert {:error, {:invalid_location, _location}} =
             CodeIntel.request(:definition, %{line: 1, character: 2}, opts(context))
  end

  test "a file with no language server resolves to an error, not an exception", context do
    other = Path.join(context.root, "thing.unknownext")
    File.write!(other, "")

    assert {:error, {:unsupported_language, ".unknownext"}} =
             CodeIntel.request(:definition, %{path: other, line: 0, character: 0}, opts(context))
  end

  test "the nine operations are exactly the documented set" do
    assert CodeIntel.operations() == [
             :definition,
             :references,
             :hover,
             :document_symbols,
             :workspace_symbols,
             :implementation,
             :prepare_call_hierarchy,
             :incoming_calls,
             :outgoing_calls
           ]
  end

  test "status is shaped for a client and names the node it describes", context do
    assert {:ok, _result} = CodeIntel.request(:definition, at(context), opts(context))

    status = CodeIntel.status(opts(context))
    assert status.enabled
    assert status.node == node()
    assert status.budget_bytes > 0

    assert [server] = status.servers
    assert server.node == node()
    assert server.id == "#{node()}:fake:#{context.root}"
    assert server.server_id == "fake"
    assert server.root == context.root
    assert is_binary(server.pid)
    assert is_integer(server.os_pid)
    assert is_integer(server.uptime_ms)
    assert server.restarts == 0
    assert [%{path: _path, version: 1}] = server.documents
  end

  test "code intelligence turned off answers :disabled everywhere", context do
    existing = Application.get_env(:ouroboros, :code_intel, [])
    Application.put_env(:ouroboros, :code_intel, Keyword.put(existing, :enabled, false))
    on_exit(fn -> Application.put_env(:ouroboros, :code_intel, existing) end)

    assert {:error, :disabled} = CodeIntel.request(:definition, at(context), opts(context))
    assert {:error, :disabled} = CodeIntel.touch(context.source, :open, opts(context))
    assert {:error, :disabled} = CodeIntel.diagnostics(context.source, opts(context))
    assert %{enabled: false, servers: []} = CodeIntel.status(opts(context))
  end
end
