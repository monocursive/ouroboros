defmodule Ouroboros.Provider.Native.CodeIntelTest do
  @moduledoc """
  The diagnostics feedback policy and the `code_intel` tool, against the fake language
  server.

  The node's own pool is used — the one a session would use — with an operator-shaped
  `:servers` entry pointing a made-up extension at `test/support/fake_language_server.exs`.
  So the path under test is the real one: registry, pool, document sync, version gate.

  Baselines are supplied by hand where the direction of the assertion needs it. That is
  not a shortcut: `feedback/3` takes the baseline as an argument precisely so the policy
  is testable without a language server that changes its mind, and the two directions —
  a pre-existing error stays quiet, a new one is reported — are the whole of Hermes'
  contribution to this design.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.CodeIntel
  alias Ouroboros.CodeIntel.LspPool
  alias Ouroboros.Provider.Native.CodeIntel, as: Native
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.CodeIntel, as: Tool

  @script Path.expand("../../support/fake_language_server.exs", __DIR__)

  setup context do
    root = Path.join(System.tmp_dir!(), "native-ci-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    {:ok, workspace} = Ouroboros.Workspace.Path.canonicalize(root)
    File.write!(Path.join(workspace, "fake.root"), "")

    previous = Application.get_env(:ouroboros, :code_intel, [])
    previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots, [])

    # The registry fails closed: a file under no admitted workspace root gets no server.
    # A session's workspace is admitted by the runtime; a test admits its own.
    Application.put_env(:ouroboros, :workspace_allowed_roots, [workspace | previous_roots])

    Application.put_env(
      :ouroboros,
      :code_intel,
      Keyword.merge(previous,
        # A short shutdown grace so a test's server is gone before the directory it was
        # started in is: an `elixir` child booting with a deleted cwd writes a crash dump.
        shutdown_grace_ms: 300,
        servers: [
          %{
            language: :faketest,
            extensions: [".fake"],
            root_markers: ["fake.root"],
            candidates: [
              %{
                server_id: "fake",
                command: System.find_executable("elixir"),
                args: [@script] ++ Map.get(context, :server_args, ["--publish-on-change"]),
                hint: "not installable; this is a test fixture"
              }
            ]
          }
        ]
      )
    )

    on_exit(fn ->
      _ = LspPool.stop_server(LspPool, {workspace, "fake"})
      # Wait for the OS process to actually go before the directory it was started in
      # disappears: an `elixir` child booting with a deleted cwd writes a crash dump.
      wait_for_stop(workspace)
      Application.put_env(:ouroboros, :code_intel, previous)
      Application.put_env(:ouroboros, :workspace_allowed_roots, previous_roots)

      # The contents go; the directory itself stays. The pool may still restart a
      # language server it has not finished reaping, and a child process whose cwd has
      # been removed writes an Erlang crash dump into the repository. An empty directory
      # under the system temp root is the cheaper of the two kinds of litter.
      for entry <- File.ls!(root), do: File.rm_rf(Path.join(root, entry))
    end)

    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)

    %{
      workspace: workspace,
      scope: scope,
      context: %{scope: scope, session_dir: workspace, reads: %{}}
    }
  end

  defp wait_for_stop(workspace, attempts \\ 100) do
    gone? =
      LspPool
      |> LspPool.status()
      |> Map.get(:servers, [])
      |> Enum.all?(&(&1[:root] != workspace))

    cond do
      gone? -> :ok
      attempts <= 0 -> :ok
      true -> Process.sleep(50) && wait_for_stop(workspace, attempts - 1)
    end
  end

  defp fake_file(workspace, name \\ "thing.fake", content \\ "one\ntwo\nthree\n") do
    path = Path.join(workspace, name)
    File.write!(path, content)
    path
  end

  defp await(fun, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 20_000

    case fun.() do
      nil ->
        if System.monotonic_time(:millisecond) > deadline do
          flunk("condition never held")
        else
          Process.sleep(50)
          await(fun, deadline)
        end

      value ->
        value
    end
  end

  # ================================================================ feedback

  describe "the post-edit report" do
    test "puts `Edit applied.` on its own line before anything a server said", %{
      workspace: workspace
    } do
      path = fake_file(workspace)
      {:ok, _version} = CodeIntel.touch(path, :open)

      # An empty baseline makes every diagnostic the server has new.
      feedback = await(fn -> present(Native.feedback([path], %{path => {:ok, %{items: []}}})) end)

      [first | rest] = feedback |> String.trim_leading() |> String.split("\n")

      assert first == "Edit applied."
      assert Native.applied_line() == "Edit applied."
      assert Enum.join(rest, "\n") =~ "undefined variable"
      assert Enum.join(rest, "\n") =~ "1 new error"
    end

    test "reports only what the baseline did not already have", %{workspace: workspace} do
      path = fake_file(workspace)
      {:ok, _version} = CodeIntel.touch(path, :open)

      # Wait for the server's own diagnostics to land, then use them as the baseline.
      baseline = await(fn -> settled(path) end)

      feedback = Native.feedback([path], %{path => {:ok, baseline}})

      assert feedback =~ "Edit applied."
      assert feedback =~ "no new diagnostics"
      refute feedback =~ "undefined variable"
    end

    test "a missing baseline reports nothing rather than the file's whole history", %{
      workspace: workspace
    } do
      path = fake_file(workspace)
      {:ok, _version} = CodeIntel.touch(path, :open)
      _ = await(fn -> settled(path) end)

      feedback = Native.feedback([path], %{})

      assert feedback =~ Native.no_data_line()
      refute feedback =~ "undefined variable"
    end

    @tag server_args: ["--publish-on-change", "--publish-version", "1"]
    test "a diagnostic that describes an older version of the file is never served", %{
      workspace: workspace
    } do
      # The fake publishes with a fixed version 1 while the pool moves the document on,
      # so the freshness gate never matches — which is exactly the stale-push Claude Code
      # fixed in v2.1.107, and here it becomes "no LSP data" instead of a wrong report.
      path = fake_file(workspace)
      {:ok, _version} = CodeIntel.touch(path, :open)
      File.write!(path, "changed\n")
      {:ok, _version} = CodeIntel.touch(path, :changed)

      feedback = Native.feedback([path], %{path => {:ok, %{items: []}}}, wait_ms: 300)

      assert feedback =~ Native.no_data_line()
      refute feedback =~ "undefined variable"
    end

    @tag server_args: ["--slow", "textDocument/didOpen"]
    test "a server that never answers becomes `no LSP data` within the budget", %{
      workspace: workspace
    } do
      path = fake_file(workspace)

      started = System.monotonic_time(:millisecond)
      feedback = Native.feedback([path], %{path => {:ok, %{items: []}}}, wait_ms: 400)
      elapsed = System.monotonic_time(:millisecond) - started

      assert feedback =~ Native.no_data_line()
      assert elapsed < 20_000
    end

    test "a file with no registered server says nothing at all", %{workspace: workspace} do
      path = Path.join(workspace, "notes.unknownext")
      File.write!(path, "text\n")

      assert Native.feedback([path], %{}) == ""
    end

    test "nothing was written means nothing is said", %{workspace: workspace} do
      assert Native.feedback([], %{}) == ""
      assert Native.baseline([]) == %{}
      _ = workspace
    end

    test "code intelligence switched off is silent, not `no LSP data`", %{workspace: workspace} do
      path = fake_file(workspace)
      previous = Application.get_env(:ouroboros, :code_intel, [])
      Application.put_env(:ouroboros, :code_intel, Keyword.put(previous, :enabled, false))
      on_exit(fn -> Application.put_env(:ouroboros, :code_intel, previous) end)

      assert Native.feedback([path], %{path => {:ok, %{items: []}}}) == ""
      assert Native.baseline([path]) == %{}
    end
  end

  # ================================================================ the tool

  describe "the `code_intel` tool" do
    test "answers the navigation operations from the pool", %{
      workspace: workspace,
      context: context
    } do
      path = fake_file(workspace)
      relative = Path.relative_to(path, workspace)

      for operation <- ~w(definition references hover document_symbols workspace_symbols
                          implementation prepare_call_hierarchy incoming_calls outgoing_calls) do
        result =
          Tools.execute(
            Tool,
            %{"operation" => operation, "path" => relative, "line" => 1, "character" => 2},
            context,
            30_000
          )

        refute result.is_error, "#{operation} answered with an error: #{result.output}"
        assert result.output =~ operation
      end
    end

    test "`diagnostics` reports what the server currently says", %{
      workspace: workspace,
      context: context
    } do
      path = fake_file(workspace)
      relative = Path.relative_to(path, workspace)

      result =
        await(fn ->
          answer =
            Tools.execute(
              Tool,
              %{"operation" => "diagnostics", "path" => relative},
              context,
              30_000
            )

          if answer.output =~ "undefined variable", do: answer
        end)

      refute result.is_error
      assert result.output =~ "1 errors"
    end

    test "an unknown operation names the ones that exist", %{
      workspace: workspace,
      context: context
    } do
      path = fake_file(workspace)

      result =
        Tools.execute(
          Tool,
          %{"operation" => "teleport", "path" => Path.relative_to(path, workspace)},
          context,
          10_000
        )

      assert result.is_error
      assert result.output =~ "`teleport` is not an operation"
      assert result.output =~ "definition"
      assert result.output =~ "rename_apply"
    end

    test "a path outside the workspace is refused before any server is asked", %{
      context: context
    } do
      result =
        Tools.execute(
          Tool,
          %{"operation" => "definition", "path" => "/etc/passwd"},
          context,
          10_000
        )

      assert result.is_error
      assert result.output =~ "outside this session's workspace"
    end

    test "a language with no server is an in-band error, never a crash", %{
      workspace: workspace,
      context: context
    } do
      File.write!(Path.join(workspace, "x.unknownext"), "y")

      result =
        Tools.execute(
          Tool,
          %{"operation" => "definition", "path" => "x.unknownext"},
          context,
          10_000
        )

      assert result.is_error
      assert result.output =~ "no language server is registered"
    end

    test "`rename` with no server support answers rather than raising", %{
      workspace: workspace,
      context: context
    } do
      path = fake_file(workspace)

      result =
        Tools.execute(
          Tool,
          %{
            "operation" => "rename",
            "path" => Path.relative_to(path, workspace),
            "line" => 0,
            "character" => 0,
            "new_name" => "renamed"
          },
          context,
          30_000
        )

      # The fake server does not implement rename, so this is the error path — the point
      # is that it is an error *result*, in band, and the turn continues.
      assert is_binary(result.output)
      assert result.output =~ "code_intel"
    end
  end

  describe "classification" do
    test "navigation reads; rename_apply writes and is gated like one", %{scope: scope} do
      read =
        Tools.classify("code_intel", %{"operation" => "references", "path" => "a.fake"}, scope)

      assert read.mode == :read
      assert read.write_paths == []

      assert Tool.writing?("rename_apply")
      refute Tool.writing?("rename")
      refute Tool.writing?("references")

      write =
        Tools.classify(
          "code_intel",
          %{"operation" => "rename_apply", "path" => "a.fake", "new_name" => "b"},
          scope
        )

      assert write.mode == :write
    end

    test "every operation the tool advertises is one it understands" do
      advertised = Tool.operations()

      assert "diagnostics" in advertised
      assert "rename" in advertised
      assert "rename_apply" in advertised

      for operation <- CodeIntel.operations() do
        assert Atom.to_string(operation) in advertised
      end
    end
  end

  # ================================================================ the loop

  describe "through the loop" do
    test "a successful write carries the report, after `Edit applied.`", %{
      workspace: workspace,
      scope: scope
    } do
      script = [
        [
          {:tool_call,
           %{id: "c1", name: "write", input: %{"path" => "written.fake", "content" => "x\n"}}}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      result = await(fn -> loop_result(scope, workspace, script, "Edit applied.") end)

      refute result["is_error"]
      assert result["output"] =~ "Wrote written.fake"
      # Order is the whole point: the success line precedes anything a server said.
      applied = :binary.match(result["output"], "Edit applied.") |> elem(0)
      finding = :binary.match(result["output"], "undefined variable") |> elem(0)
      assert applied < finding
    end

    test "a failed edit carries no diagnostics at all", %{workspace: workspace, scope: scope} do
      script = [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "edit",
             input: %{
               "path" => "never-read.fake",
               "old_string" => "a",
               "new_string" => "b"
             }
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      File.write!(Path.join(workspace, "never-read.fake"), "a\n")
      [result] = run_loop(scope, workspace, script)

      assert result["is_error"]
      refute result["output"] =~ "Edit applied."
      refute result["output"] =~ "undefined variable"
    end

    test "a write to a file with no server appends nothing", %{
      workspace: workspace,
      scope: scope
    } do
      script = [
        [
          {:tool_call,
           %{id: "c1", name: "write", input: %{"path" => "plain.txt", "content" => "x\n"}}}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      [result] = run_loop(scope, workspace, script)

      refute result["is_error"]
      assert result["output"] =~ "Wrote plain.txt"
      refute result["output"] =~ "Edit applied."
      refute result["output"] =~ Native.no_data_line()
    end
  end

  # ---------------------------------------------------------------- helpers

  defp loop_result(scope, workspace, script, marker) do
    case run_loop(scope, workspace, script) do
      [result] -> if result["output"] =~ marker and result["output"] =~ "undefined", do: result
      _none -> nil
    end
  end

  defp run_loop(scope, workspace, script) do
    {model_spec, _agent} = Ouroboros.Test.NativeModelScript.start(script)
    test = self()

    loop =
      struct!(%Ouroboros.Provider.Native.Loop{
        emit: fn event -> send(test, {:ci_event, event}) end,
        model_module: Ouroboros.Test.NativeModelScript,
        model_spec: model_spec,
        system: "system",
        scope: scope,
        session_dir: Path.join(workspace, ".session"),
        session_id: "sess-ci",
        provider_session_id: "native-x-y",
        turn_id: "turn-#{System.unique_integer([:positive])}",
        approval_mode: :auto_approve,
        approval_timeout_ms: 2_000
      })

    File.mkdir_p!(Path.join(workspace, ".session"))
    spawn_link(fn -> Ouroboros.Provider.Native.Loop.run_turn(loop, "go") end)
    drain_loop([])
  end

  defp drain_loop(acc) do
    receive do
      {:ci_event, %{type: type}}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse(acc)

      {:ci_event, %{type: :tool_result, payload: payload}} ->
        drain_loop([payload | acc])

      {:ci_event, _other} ->
        drain_loop(acc)
    after
      25_000 -> flunk("the loop never finished")
    end
  end

  defp present(""), do: nil
  defp present(feedback), do: if(feedback =~ "undefined variable", do: feedback)

  defp settled(path) do
    case CodeIntel.diagnostics(path, wait_ms: 500) do
      {:ok, %{items: [_first | _rest]} = answer} -> answer
      _not_yet -> nil
    end
  end
end
