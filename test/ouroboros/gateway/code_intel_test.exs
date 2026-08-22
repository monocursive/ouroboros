defmodule Ouroboros.Gateway.CodeIntelTest do
  use ExUnit.Case, async: false

  @moduledoc """
  The four code-intelligence verbs, driven through `Methods.invoke/2` against the node's
  own pool and the fake language server.

  Nothing here stubs `Ouroboros.CodeIntel`. The point of the slice is that a vendor agent
  reaches a real language server through the gateway, so the test spawns one — the same
  `test/support/fake_language_server.exs` the pool's own suite uses — and asserts the
  shapes a client and `ouro hook post-tool-use` branch on: the `status` discriminator, the
  `signature` that makes the new-only rule possible, and the typed refusals.
  """

  alias Ouroboros.CodeIntel
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @moduletag :capture_log

  @script Path.expand("../../support/fake_language_server.exs", __DIR__)

  setup context do
    base =
      Path.join(System.tmp_dir!(), "ouroboros-gateway-lsp-#{System.unique_integer([:positive])}")

    File.mkdir_p!(base)
    {:ok, root} = WorkspacePath.canonicalize(base)
    File.write!(Path.join(root, "widget.toml"), "")
    source = Path.join(root, "thing.widget")
    File.write!(source, "widget code\n")

    previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots, [])
    previous_code_intel = Application.get_env(:ouroboros, :code_intel, [])

    pool_name = :"gateway_code_intel_#{System.unique_integer([:positive])}"

    Application.put_env(:ouroboros, :workspace_allowed_roots, [root])

    Application.put_env(
      :ouroboros,
      :code_intel,
      previous_code_intel
      # The gateway names no pool, so it uses the node's. Pointing that at a pool this test
      # owns is what makes the teardown safe: `start_supervised!` stops every language
      # server before `on_exit` runs, so nothing is left to respawn into a directory that
      # has been removed.
      |> Keyword.put(:pool, pool_name)
      |> Keyword.put(:servers, [
        %{
          language: :widget,
          extensions: [".widget"],
          root_markers: ["widget.toml"],
          candidates: [
            %{
              server_id: "fake",
              command: "elixir",
              args: [@script] ++ Map.get(context, :server_args, ["--publish-on-change"])
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
         name: :"gateway_code_intel_sup_#{System.unique_integer([:positive])}",
         pool_name: pool_name,
         idle_ms: 60_000,
         sweep_ms: 60_000,
         initialize_timeout_ms: 20_000,
         shutdown_grace_ms: 500
       ]}
    )

    {:ok, root: root, source: source}
  end

  defp touch(context, action \\ "changed") do
    Methods.invoke("code_intel.touch", %{
      "workspace" => context.root,
      "path" => context.source,
      "action" => action
    })
  end

  test "the four verbs are in the table, and only the one that spends memory is operate" do
    for name <- [
          "runtime.lsp.status",
          "code_intel.request",
          "code_intel.diagnostics",
          "code_intel.touch"
        ] do
      assert name in Methods.names()
    end

    assert {:ok, %{scope: :read}} = Methods.fetch("runtime.lsp.status")
    assert {:ok, %{scope: :read}} = Methods.fetch("code_intel.request")
    assert {:ok, %{scope: :read}} = Methods.fetch("code_intel.diagnostics")
    assert {:ok, %{scope: :operate}} = Methods.fetch("code_intel.touch")
  end

  test "runtime.lsp.status describes this node's pool without starting anything" do
    assert {:ok, status} = Methods.invoke("runtime.lsp.status", %{})

    assert status.enabled == true
    assert status.node == node()
    assert is_list(status.servers)
  end

  test "touch announces an edit and answers with the picture that preceded it", context do
    # Nothing has been opened, so the honest baseline is "there is no baseline" rather
    # than "the baseline was empty".
    assert {:ok, first} = touch(context, "open")
    assert first.version == 1
    assert first.baseline.version == nil
    assert first.baseline.fresh? == false
    assert first.baseline.signatures == []

    # The server published for version 1, so the next touch sees it as the pre-edit state.
    assert {:ok, %{status: :ok, items: [item]}} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => context.source
             })

    assert {:ok, second} = touch(context)
    assert second.version == 2
    assert second.baseline.fresh? == true
    assert second.baseline.signatures == [item.signature]
    assert second.baseline.counts.error == 1
  end

  test "ensure_open asks about a file without claiming it changed", context do
    # `open` re-reads and assigns a new version every time, which invalidates the
    # diagnostics cache; a caller asking "what is wrong with this file" twice would wait out
    # the freshness gate on the second ask for a push a server with nothing new to say never
    # sends. A live run against clangd is where this was found.
    assert {:ok, %{version: 1}} = touch(context, "ensure_open")
    assert {:ok, %{version: 1}} = touch(context, "ensure_open")

    assert {:ok, %{status: :ok, version: 1}} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => context.source
             })

    # `open` is still the verb that says "re-read this from disk".
    assert {:ok, %{version: 2}} = touch(context, "open")
  end

  test "a path that cannot be read is a path error, not an upstream failure", context do
    # A relative path is expanded against the *runtime's* working directory, which is why
    # the MCP client resolves one against the session workspace before it calls. Reaching
    # here with one has to read as a bad path rather than as a fault in the runtime.
    assert {:error, -32_602, message, data} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => "csrc/nowhere.widget"
             })

    assert message =~ "params.path could not be read as a file"
    assert data["reason"] == "unreadable_path"
  end

  test "diagnostics carry a signature and the counts a client renders", context do
    assert {:ok, _touched} = touch(context, "open")

    assert {:ok, answer} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => context.source
             })

    assert answer.status == :ok
    assert answer.version == 1
    assert answer.counts.error == 1

    assert [%{severity: :error, message: "undefined variable", signature: signature}] =
             answer.items

    assert byte_size(signature) == 16
    # The identity is the one the runtime computes, not a second definition at the edge.
    assert signature ==
             CodeIntel.Diagnostics.signature(%{
               code: "E001",
               severity: :error,
               message: "undefined variable",
               range: %{start: %{line: 1, character: 0}, end: %{line: 1, character: 5}}
             })
  end

  @tag server_args: []
  test "a server that never publishes answers pending rather than an empty list", context do
    assert {:ok, _touched} = touch(context, "open")

    # A document the server has said nothing about has no diagnostics *and no evidence of
    # none*. The reply carries no `items` key at all, so the two cannot be confused by a
    # client that reads the list and skips the discriminator.
    assert {:ok, answer} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => context.source,
               "wait_ms" => 0
             })

    assert answer.status == :pending
    refute Map.has_key?(answer, :items)
  end

  test "diagnostics against a document nobody announced says so", context do
    assert {:error, -32_004, message, data} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => context.source,
               "wait_ms" => 0
             })

    assert message =~ "announce the edit with code_intel.touch first"
    assert data["reason"] == "document_not_open"
  end

  test "request answers the nine operations with paths relative to the root", context do
    assert {:ok, answer} =
             Methods.invoke("code_intel.request", %{
               "workspace" => context.root,
               "operation" => "definition",
               "path" => context.source,
               "line" => 1,
               "character" => 2
             })

    assert answer.status == :ok
    assert [%{path: "thing.widget", external: false}] = answer.items
    assert answer.truncated == 0
  end

  test "workspace_symbols carries its query", context do
    assert {:ok, answer} =
             Methods.invoke("code_intel.request", %{
               "workspace" => context.root,
               "operation" => "workspace_symbols",
               "path" => context.source,
               "query" => "widget"
             })

    assert answer.status == :ok
    assert is_list(answer.items)
  end

  test "an unknown operation is a parameter error naming the nine", context do
    assert {:error, -32_602, message} =
             Methods.invoke("code_intel.request", %{
               "workspace" => context.root,
               "operation" => "rename",
               "path" => context.source
             })

    assert message =~ "params.operation must be one of"
    assert message =~ "references"
  end

  test "an unknown parameter is named rather than dropped", context do
    assert {:error, -32_602, message} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => context.source,
               "waitMs" => 10
             })

    assert message =~ "waitMs"
  end

  test "a path outside the workspace is a typed refusal", context do
    outside = Path.join(System.tmp_dir!(), "ouroboros-outside-#{System.unique_integer()}.widget")
    File.write!(outside, "")
    on_exit(fn -> File.rm(outside) end)

    assert {:error, -32_602, message, data} =
             Methods.invoke("code_intel.request", %{
               "workspace" => context.root,
               "operation" => "definition",
               "path" => outside
             })

    assert message =~ "not inside a workspace root this node admits"
    assert data["reason"] == "outside_workspace"
  end

  test "a caller cannot widen the boundary by naming a workspace of its own", context do
    # The whole hazard of putting a workspace on the wire: `/` would turn the containment
    # check into "is this path absolute". The registry admits an explicit root only where
    # it admits an implicit one.
    assert {:error, -32_602, _message, %{"reason" => "outside_workspace"}} =
             Methods.invoke("code_intel.request", %{
               "workspace" => "/",
               "operation" => "definition",
               "path" => context.source
             })
  end

  test "a file with no registered server is a typed refusal naming the extension",
       context do
    unknown = Path.join(context.root, "notes.unknownext")
    File.write!(unknown, "")

    assert {:error, -32_602, message, data} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => unknown
             })

    assert message =~ "no language server is registered"
    assert data["reason"] == "unsupported_language"
    assert data["extension"] == ".unknownext"
  end

  test "a language whose server is not installed answers the install hint", context do
    Application.put_env(
      :ouroboros,
      :code_intel,
      Keyword.put(Application.get_env(:ouroboros, :code_intel, []), :servers, [
        %{
          language: :widget,
          extensions: [".widget"],
          root_markers: ["widget.toml"],
          candidates: [
            %{
              server_id: "absent-widget-server",
              command: "ouroboros-no-such-language-server",
              args: [],
              hint: "install it with `brew install widget-lsp`"
            }
          ]
        }
      ])
    )

    assert {:error, -32_004, message, data} =
             Methods.invoke("code_intel.request", %{
               "workspace" => context.root,
               "operation" => "definition",
               "path" => context.source
             })

    assert message =~ "brew install widget-lsp"
    assert data["reason"] == "server_unavailable"
    assert data["server"] == "absent-widget-server"
  end

  test "wait_ms is bounded so a caller cannot outlive the method ceiling", context do
    assert {:error, -32_602, message} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => context.source,
               "wait_ms" => 60_000
             })

    assert message =~ "params.wait_ms must be an integer between 0 and"
  end

  test "an unknown node is refused by name, not converted into one", context do
    assert {:error, -32_602, message} =
             Methods.invoke("code_intel.diagnostics", %{
               "workspace" => context.root,
               "path" => context.source,
               "node" => "nowhere@nohost"
             })

    assert message =~ "params.node must name a connected machine or BEAM node"
  end
end
