defmodule Ouroboros.Provider.Native.ToolsTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools

  setup do
    root = Path.join(System.tmp_dir!(), "native-tools-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "outside"))
    File.write!(Path.join(root, "outside/secret.txt"), "keep out\n")
    on_exit(fn -> File.rm_rf(root) end)

    workspace = Path.join(root, "workspace")
    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)
    {:ok, read_only} = Paths.scope(workspace, [], :read_only)
    session_dir = Path.join(root, "session")
    File.mkdir_p!(session_dir)

    %{
      root: root,
      workspace: scope.root,
      scope: scope,
      read_only: read_only,
      session_dir: session_dir,
      context: %{scope: scope, session_dir: session_dir, reads: %{}}
    }
  end

  defp run(module, input, context, timeout \\ 30_000),
    do: Tools.execute(module, input, context, timeout)

  defp write_file(workspace, relative, content) do
    path = Path.join(workspace, relative)
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, content)
    path
  end

  describe "the tool set" do
    test "is D2's full set plus G3's two, and every one has a JSON Schema the model can read" do
      names = Enum.map(Tools.specs(nil, nil), & &1.name)

      assert names == [
               "read",
               "write",
               "edit",
               "apply_patch",
               "bash",
               "grep",
               "glob",
               "ls",
               "web_fetch",
               "code_intel",
               "ask_user",
               "agent",
               "agent_result",
               "skill",
               "plan"
             ]

      for spec <- Tools.specs(nil, nil) do
        assert is_binary(spec.description) and spec.description != ""
        assert %{"type" => "object", "properties" => properties} = spec.parameters
        assert is_map(properties)

        required = spec.parameters["required"] || []
        assert Enum.all?(required, &Map.has_key?(properties, &1))
      end
    end

    test "validates every advertised static tool before permission or execution" do
      specs = Tools.specs(nil, nil)

      for spec <- specs, (spec.parameters["required"] || []) != [] do
        assert {:error, message} = Tools.validate_call(spec.name, %{}, specs)
        assert message =~ "Invalid arguments for `#{spec.name}`"
        assert message =~ "Required arguments:"
        assert message =~ "Argument schema:"
        assert message =~ "do not repeat the unchanged call"
        refute message =~ "evaluationPath"

        for required <- spec.parameters["required"] do
          assert message =~ required
        end
      end

      assert {:ok, %{}} = Tools.validate_call("ls", %{}, specs)

      assert {:error, message} =
               Tools.validate_call("ls", %{"depth" => "deep"}, specs)

      assert message =~ "depth"
      assert message =~ "depth: integer (optional)"
    end

    test "validates exact and open MCP schemas by the contract shown to the model" do
      exact = %{
        name: "mcp__test__exact",
        description: "exact",
        parameters: %{
          "type" => "object",
          "properties" => %{"query" => %{"type" => "string"}},
          "required" => ["query"],
          "additionalProperties" => false
        }
      }

      open = %{
        name: "mcp__test__open",
        description: "open",
        parameters: %{"type" => "object", "additionalProperties" => true}
      }

      assert {:error, message} = Tools.validate_call(exact.name, %{}, [exact, open])
      assert message =~ "query"

      assert {:ok, %{"anything" => 1}} =
               Tools.validate_call(open.name, %{"anything" => 1}, [exact, open])
    end

    test "allowed_tools narrows the set and disallowed_tools always wins" do
      assert Enum.map(Tools.specs(["read", "bash"], nil), & &1.name) == ["read", "bash"]
      assert Enum.map(Tools.specs(["read", "bash"], ["bash"]), & &1.name) == ["read"]

      assert Enum.map(Tools.specs(nil, ["bash", "write", "edit"]), & &1.name) == [
               "read",
               "apply_patch",
               "grep",
               "glob",
               "ls",
               "web_fetch",
               "code_intel",
               "ask_user",
               "agent",
               "agent_result",
               "skill",
               "plan"
             ]
    end

    test "a filtered tool is unknown, exactly like one that does not exist" do
      assert {:error, :unknown_tool} = Tools.lookup("bash", ["read"], nil)
      assert {:error, :unknown_tool} = Tools.lookup("bash", nil, ["bash"])
      assert {:error, :unknown_tool} = Tools.lookup("Grep", nil, nil)
      assert {:error, :unknown_tool} = Tools.lookup("websearch", nil, nil)
      assert {:ok, Ouroboros.Provider.Native.Tools.Bash} = Tools.lookup("bash", nil, nil)
      assert {:ok, Ouroboros.Provider.Native.Tools.Grep} = Tools.lookup("grep", nil, nil)
    end

    test "`todo` is an alias of `plan`, is not a second schema, and honours the filters" do
      refute "todo" in Enum.map(Tools.specs(nil, nil), & &1.name)

      assert {:ok, Ouroboros.Provider.Native.Tools.Plan} = Tools.lookup("todo", nil, nil)
      assert {:ok, Ouroboros.Provider.Native.Tools.Plan} = Tools.lookup("todowrite", nil, nil)
      assert Tools.canonical("todo") == "plan"
      assert Tools.canonical("bash") == "bash"

      # A filter that an alias walks around is not a filter.
      assert {:error, :unknown_tool} = Tools.lookup("todo", nil, ["plan"])
      assert {:error, :unknown_tool} = Tools.lookup("todo", nil, ["todo"])
      assert {:ok, Ouroboros.Provider.Native.Tools.Plan} = Tools.lookup("todo", ["plan"], nil)
    end

    test "the desktop tools are unknown and unlisted while Computer Use is off (D9)" do
      original = Application.get_env(:ouroboros, :computer_use)

      Application.put_env(:ouroboros, :computer_use, helper_path: "/nope/missing")

      on_exit(fn ->
        if original == nil,
          do: Application.delete_env(:ouroboros, :computer_use),
          else: Application.put_env(:ouroboros, :computer_use, original)
      end)

      assert {:error, :unknown_tool} = Tools.lookup("desktop_state", nil, nil)
      assert {:error, :unknown_tool} = Tools.lookup("desktop_act", nil, nil)

      names = Enum.map(Tools.specs(nil, nil, workspace: "/tmp"), & &1.name)
      refute "desktop_state" in names
      refute "desktop_act" in names
    end
  end

  describe "classify/3" do
    test "names the mode, the canonical paths, and the command", %{
      scope: scope,
      workspace: workspace
    } do
      write_file(workspace, "lib/a.ex", "x")

      assert %{tool: "read", mode: :read, paths: [path], command: nil} =
               Tools.classify("read", %{"path" => "lib/a.ex"}, scope)

      assert path == Path.join(workspace, "lib/a.ex")

      assert %{mode: :write} = Tools.classify("edit", %{"path" => "lib/a.ex"}, scope)
      assert %{mode: :write} = Tools.classify("write", %{"path" => "lib/b.ex"}, scope)

      assert %{mode: :execute, command: "mix test", paths: []} =
               Tools.classify("bash", %{"command" => "mix test"}, scope)
    end

    test "reports an unresolvable path as given rather than dropping it", %{scope: scope} do
      assert %{paths: ["../escape"]} = Tools.classify("read", %{"path" => "../escape"}, scope)
    end

    test "classifies the desktop tools by mode and puts app identity in context", %{scope: scope} do
      # desktop_state observes: :read, no workspace paths, action tag "state".
      assert %{tool: "desktop_state", mode: :read, paths: [], context: state_context} =
               Tools.classify("desktop_state", %{"app" => "Safari"}, scope)

      assert state_context == %{app: "com.apple.Safari", desktop_action: "state"}

      # desktop_act operates: :execute, the claimed action carried through.
      assert %{tool: "desktop_act", mode: :execute, context: act_context} =
               Tools.classify(
                 "desktop_act",
                 %{"app" => "com.apple.Calculator", "action" => "click"},
                 scope
               )

      assert act_context == %{app: "com.apple.Calculator", desktop_action: "click"}

      # No claimed app or action is nil, not an invented value (Phase 0: the claim only).
      assert %{context: %{app: nil, desktop_action: nil}} =
               Tools.classify("desktop_act", %{}, scope)
    end
  end

  describe "read" do
    test "returns line-numbered text and records a fingerprint", %{
      context: context,
      workspace: workspace
    } do
      path = write_file(workspace, "lib/a.ex", "defmodule A do\n  def x, do: 1\nend\n")

      result = run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "lib/a.ex"}, context)

      refute result.is_error
      assert result.output =~ "     1\tdefmodule A do"
      assert result.output =~ "     2\t  def x, do: 1"
      assert %{^path => %{hash: hash, size: size, mtime: _}} = result.reads
      assert is_binary(hash) and size > 0
    end

    test "honours offset and limit and says how much is left", %{
      context: context,
      workspace: workspace
    } do
      write_file(workspace, "big.txt", Enum.map_join(1..100, "", &"line #{&1}\n"))

      result =
        run(
          Ouroboros.Provider.Native.Tools.Read,
          %{"path" => "big.txt", "offset" => 10, "limit" => 5},
          context
        )

      assert result.output =~ "    11\tline 11"
      assert result.output =~ "    15\tline 15"
      refute result.output =~ "line 16\n"
      assert result.output =~ "more lines"
    end

    test "refuses a path outside the workspace", %{context: context, root: root} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Read,
          %{"path" => Path.join(root, "outside/secret.txt")},
          context
        )

      assert result.is_error
      assert result.output =~ "outside this session's workspace"
      refute result.output =~ "keep out"
    end

    test "refuses a `..` traversal", %{context: context} do
      result =
        run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "../outside/secret.txt"}, context)

      assert result.is_error
      assert result.output =~ "`..`"
    end

    test "is bounded at 64 KiB per call", %{context: context, workspace: workspace} do
      write_file(
        workspace,
        "huge.txt",
        Enum.map_join(1..40_000, "", &"#{&1} #{String.duplicate("x", 60)}\n")
      )

      result = run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "huge.txt"}, context)

      assert byte_size(result.output) < 80 * 1024
      assert result.output =~ "truncated at"
    end

    test "describes a binary file instead of dumping it", %{
      context: context,
      workspace: workspace
    } do
      write_file(workspace, "blob.bin", <<0, 159, 146, 150, 0>>)
      result = run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "blob.bin"}, context)
      assert result.output =~ "binary file"
    end
  end

  describe "write" do
    test "creates a file and emits a real diff", %{context: context, workspace: workspace} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Write,
          %{"path" => "lib/new.ex", "content" => "hello\n"},
          context
        )

      refute result.is_error
      assert File.read!(Path.join(workspace, "lib/new.ex")) == "hello\n"
      assert [change] = result.changes
      assert change["kind"] == "add"
      assert change["diff"] =~ "+hello"
      assert change["relative_path"] == "lib/new.ex"
    end

    test "creates missing parent directories inside the workspace", %{
      context: context,
      workspace: workspace
    } do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Write,
          %{"path" => "a/b/c/d.txt", "content" => "x"},
          context
        )

      refute result.is_error
      assert File.read!(Path.join(workspace, "a/b/c/d.txt")) == "x"
    end

    test "is refused under read_only, by name", %{read_only: read_only, session_dir: session_dir} do
      context = %{scope: read_only, session_dir: session_dir, reads: %{}}

      result =
        run(
          Ouroboros.Provider.Native.Tools.Write,
          %{"path" => "lib/new.ex", "content" => "x"},
          context
        )

      assert result.is_error
      assert result.output =~ "read_only"
    end

    test "refuses a write outside the workspace", %{context: context, root: root} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Write,
          %{"path" => Path.join(root, "outside/planted.txt"), "content" => "x"},
          context
        )

      assert result.is_error
      refute File.exists?(Path.join(root, "outside/planted.txt"))
    end
  end

  test "refuses a leaf that became a symlink between resolution and the write", %{
    context: context,
    workspace: workspace,
    root: root
  } do
    # The race SafeWrite exists for: resolve proved the path, then the leaf was swapped
    # for a link pointing outside. The write is refused, and the link's target is never
    # touched — the planted secret keeps its bytes.
    File.ln_s!(Path.join(root, "outside/secret.txt"), Path.join(workspace, "swapped"))

    result =
      run(
        Ouroboros.Provider.Native.Tools.Write,
        %{"path" => Path.join(workspace, "swapped"), "content" => "exfiltrated"},
        context
      )

    # Paths.resolve canonicalizes the leaf to the outside target and refuses there; the
    # containment gate is the one named either way.
    assert result.is_error
    assert File.read!(Path.join(root, "outside/secret.txt")) == "keep out\n"

    # The same refusal holds when the tool receives an already-resolved path carrying a
    # symlink leaf — the shape the race would produce mid-flight.
    assert {:error, {:unwritable, _path, :symlinked_leaf}} =
             Ouroboros.Provider.Native.Tools.SafeWrite.write(
               Path.join(workspace, "swapped"),
               "exfiltrated",
               context.scope
             )

    assert File.read!(Path.join(root, "outside/secret.txt")) == "keep out\n"
  end

  test "refuses a write whose parent directory became a symlink", %{
    context: context,
    workspace: workspace,
    root: root
  } do
    File.ln_s!(Path.join(root, "outside"), Path.join(workspace, "parent"))

    assert {:error, {:unwritable, _path, :symlinked_parent}} =
             Ouroboros.Provider.Native.Tools.SafeWrite.write(
               Path.join([workspace, "parent", "planted.txt"]),
               "x",
               context.scope
             )

    refute File.exists?(Path.join(root, "outside/planted.txt"))
  end

  test "refuses a nested write through a symlinked ancestor without mkdir outside", %{
    context: context,
    workspace: workspace,
    root: root
  } do
    File.ln_s!(Path.join(root, "outside"), Path.join(workspace, "link"))

    assert {:error, {:unwritable, _path, :symlinked_parent}} =
             Ouroboros.Provider.Native.Tools.SafeWrite.write(
               Path.join([workspace, "link", "nested", "planted.txt"]),
               "x",
               context.scope
             )

    refute File.exists?(Path.join(root, "outside/nested"))
    refute File.exists?(Path.join(root, "outside/nested/planted.txt"))
  end

  test "refuses to delete a leaf that became a symlink", %{
    context: context,
    workspace: workspace,
    root: root
  } do
    File.ln_s!(Path.join(root, "outside/secret.txt"), Path.join(workspace, "swapped-del"))

    assert {:error, {:undeletable, _path, :symlinked_leaf}} =
             Ouroboros.Provider.Native.Tools.SafeWrite.delete(
               Path.join(workspace, "swapped-del"),
               context.scope
             )

    assert File.read!(Path.join(root, "outside/secret.txt")) == "keep out\n"
  end

  test "a delete never recreates a parent that vanished after resolution", %{
    context: context,
    workspace: workspace
  } do
    parent = Path.join(workspace, "vanished")
    path = Path.join(parent, "old.txt")
    File.mkdir_p!(parent)
    File.write!(path, "old")
    File.rm_rf!(parent)

    assert {:error, {:undeletable, _path, _reason}} =
             Ouroboros.Provider.Native.Tools.SafeWrite.delete(path, context.scope)

    refute File.exists?(parent)
  end

  test "writes to an admitted add_dirs root", %{context: context, root: root} do
    extra = Path.join(root, "extra")
    File.mkdir_p!(extra)

    {:ok, scope} =
      Ouroboros.Provider.Native.Paths.scope(context.scope.root, [extra], :workspace_write)

    context = %{context | scope: scope}

    result =
      run(
        Ouroboros.Provider.Native.Tools.Write,
        %{"path" => Path.join(extra, "nested/added.txt"), "content" => "admitted"},
        context
      )

    refute result.is_error
    assert File.read!(Path.join(extra, "nested/added.txt")) == "admitted"
  end

  test "editing an executable preserves its execute bits", %{
    context: context,
    workspace: workspace
  } do
    path = Path.join(workspace, "run.sh")
    File.write!(path, "#!/bin/sh\necho before\n")
    File.chmod!(path, 0o751)

    result =
      run(
        Ouroboros.Provider.Native.Tools.Write,
        %{"path" => path, "content" => "#!/bin/sh\necho after\n"},
        context
      )

    refute result.is_error
    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o751
  end

  describe "edit" do
    setup %{context: context, workspace: workspace} do
      path = write_file(workspace, "lib/a.ex", "defmodule A do\n  def x, do: 1\nend\n")
      read = run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "lib/a.ex"}, context)
      %{path: path, context: %{context | reads: read.reads}}
    end

    test "replaces an exact unique string", %{context: context, path: path} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{"path" => "lib/a.ex", "old_string" => "def x, do: 1", "new_string" => "def x, do: 2"},
          context
        )

      refute result.is_error
      assert File.read!(path) =~ "def x, do: 2"
      assert [change] = result.changes
      assert change["diff"] =~ "-  def x, do: 1"
      assert change["diff"] =~ "+  def x, do: 2"
    end

    test "refuses a file this session has not read", %{context: context, workspace: workspace} do
      write_file(workspace, "lib/b.ex", "one\n")

      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{"path" => "lib/b.ex", "old_string" => "one", "new_string" => "two"},
          context
        )

      assert result.is_error
      assert result.output =~ "has not been read"
    end

    test "refuses a file modified since the read", %{context: context, path: path} do
      File.write!(path, "defmodule A do\n  def x, do: 99\nend\n")

      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{"path" => "lib/a.ex", "old_string" => "defmodule A", "new_string" => "defmodule B"},
          context
        )

      assert result.is_error
      assert result.output =~ "changed since it was read"
    end

    test "refuses an ambiguous match and names the count", %{
      context: context,
      workspace: workspace
    } do
      write_file(workspace, "lib/c.ex", "same\nsame\nsame\n")
      read = run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "lib/c.ex"}, context)
      context = %{context | reads: read.reads}

      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{"path" => "lib/c.ex", "old_string" => "same", "new_string" => "other"},
          context
        )

      assert result.is_error
      assert result.output =~ "appears 3 times"
      assert result.output =~ "replace_all"
    end

    test "replace_all replaces every occurrence", %{context: context, workspace: workspace} do
      path = write_file(workspace, "lib/c.ex", "same\nsame\nsame\n")
      read = run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "lib/c.ex"}, context)
      context = %{context | reads: read.reads}

      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{
            "path" => "lib/c.ex",
            "old_string" => "same",
            "new_string" => "other",
            "replace_all" => true
          },
          context
        )

      refute result.is_error
      assert File.read!(path) == "other\nother\nother\n"
    end

    test "ladder tier 2 recovers a trailing-whitespace difference and says so", %{
      context: context,
      workspace: workspace
    } do
      # The file picked up trailing whitespace an editor left behind; the model quotes
      # the two lines as it read them. An exact search fails on the invisible bytes.
      path = write_file(workspace, "lib/d.ex", "alpha   \nbeta\ngamma\n")
      read = run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "lib/d.ex"}, context)
      context = %{context | reads: read.reads}

      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{"path" => "lib/d.ex", "old_string" => "alpha\nbeta", "new_string" => "ALPHA\nBETA"},
          context
        )

      refute result.is_error
      assert result.output =~ "trailing whitespace"
      assert result.output =~ "not byte-for-byte"
      assert File.read!(path) == "ALPHA\nBETA\ngamma\n"
    end

    test "ladder tier 3 recovers an indentation difference and re-indents the replacement", %{
      context: context,
      workspace: workspace
    } do
      # The file is indented six spaces; the model quotes it at two. Neither an exact
      # search nor a trailing-whitespace one can match across the newline.
      path =
        write_file(
          workspace,
          "lib/e.ex",
          "defmodule E do\n      def x, do: 1\n      def y, do: 2\nend\n"
        )

      read = run(Ouroboros.Provider.Native.Tools.Read, %{"path" => "lib/e.ex"}, context)
      context = %{context | reads: read.reads}

      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{
            "path" => "lib/e.ex",
            "old_string" => "  def x, do: 1\n  def y, do: 2",
            "new_string" => "  def x, do: 10\n  def y, do: 20"
          },
          context
        )

      refute result.is_error
      assert result.output =~ "indentation"

      assert File.read!(path) ==
               "defmodule E do\n      def x, do: 10\n      def y, do: 20\nend\n"
    end

    test "a no-match failure names the closest lines with their numbers", %{context: context} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{"path" => "lib/a.ex", "old_string" => "def y, do: 1", "new_string" => "def y, do: 2"},
          context
        )

      assert result.is_error
      assert result.output =~ "was not found"
      assert result.output =~ "Closest lines in the file:"
      assert result.output =~ "2: "
      assert result.output =~ "def x, do: 1"
    end

    test "is refused under read_only", %{context: context, read_only: read_only} do
      context = %{context | scope: read_only}

      result =
        run(
          Ouroboros.Provider.Native.Tools.Edit,
          %{"path" => "lib/a.ex", "old_string" => "def x", "new_string" => "def y"},
          context
        )

      assert result.is_error
      assert result.output =~ "read_only"
    end
  end

  describe "bash" do
    test "runs in the workspace and returns output", %{context: context} do
      result =
        run(Ouroboros.Provider.Native.Tools.Bash, %{"command" => "pwd && echo hi"}, context)

      refute result.is_error
      assert result.output =~ "hi"
      assert result.output =~ context.scope.root
    end

    test "reports a non-zero exit as an error result", %{context: context} do
      result = run(Ouroboros.Provider.Native.Tools.Bash, %{"command" => "exit 3"}, context)
      assert result.is_error
      assert result.output =~ "exited 3"
    end

    test "applies umask 022 like every other provider child", %{
      context: context,
      workspace: workspace
    } do
      result =
        run(Ouroboros.Provider.Native.Tools.Bash, %{"command" => "touch umasked.txt"}, context)

      refute result.is_error
      {:ok, %File.Stat{mode: mode}} = File.stat(Path.join(workspace, "umasked.txt"))
      assert Bitwise.band(mode, 0o777) == 0o644
    end

    test "kills a command that overruns its timeout", %{context: context} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Bash,
          %{"command" => "sleep 30", "timeout_ms" => 300},
          context,
          30_000
        )

      assert result.is_error
      assert result.output =~ "timed out after 300 ms"
    end

    test "a timeout reaps ordinary background descendants", %{context: context} do
      pid_file = Path.join(context.scope.root, "background.pid")
      command = "sleep 30 & child=$!; echo \"$child\" > background.pid; wait"

      result =
        run(
          Ouroboros.Provider.Native.Tools.Bash,
          %{"command" => command, "timeout_ms" => 300},
          context,
          30_000
        )

      assert result.is_error
      {pid, ""} = pid_file |> File.read!() |> String.trim() |> Integer.parse()
      {_output, status} = System.cmd("/bin/kill", ["-0", Integer.to_string(pid)])
      assert status != 0, "background descendant #{pid} survived the command deadline"
    end

    test "spills a large output to a private file and returns its path", %{context: context} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Bash,
          %{
            "command" =>
              ~s|awk 'BEGIN { for (i = 0; i < 60000; i++) print i " padding padding padding" }'|
          },
          context
        )

      refute result.is_error
      assert byte_size(result.output) < 40 * 1024
      assert result.output =~ "bytes elided"
      assert [_, spill_path] = Regex.run(~r{full output, \d+ bytes: (\S+) }, result.output)
      assert File.exists?(spill_path)
      assert byte_size(File.read!(spill_path)) > 30 * 1024
      {:ok, %File.Stat{mode: mode}} = File.stat(spill_path)
      assert Bitwise.band(mode, 0o777) == 0o600
    end

    # C5: read_only runs inside the OS sandbox where the node has one, and keeps the old
    # refusal where it does not. Both halves are asserted, on whichever node this runs.
    # The escapes themselves live in `Ouroboros.Provider.Native.SandboxTest`.
    test "runs under read_only only inside an OS sandbox, and is refused where there is none",
         %{read_only: read_only, session_dir: session_dir} do
      context = %{scope: read_only, session_dir: session_dir, reads: %{}}
      result = run(Ouroboros.Provider.Native.Tools.Bash, %{"command" => "echo hi"}, context)

      case Ouroboros.Provider.Native.Sandbox.detect().backend do
        :none ->
          assert result.is_error
          assert result.output =~ "read_only"
          assert result.output =~ "no OS sandbox backend"

        _present ->
          refute result.is_error
          assert result.output =~ "hi"
      end
    end

    test "clamps a timeout above the documented maximum", %{context: context} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Bash,
          %{"command" => "echo ok", "timeout_ms" => 99_999_999},
          context
        )

      refute result.is_error
      assert result.output =~ "ok"
    end
  end

  describe "plan" do
    test "normalizes steps and returns a plan payload", %{context: context} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Plan,
          %{
            "steps" => [
              %{"step" => "read the file", "status" => "completed"},
              %{"step" => "edit it", "status" => "in_progress"},
              %{"step" => "run tests"}
            ],
            "explanation" => "three steps"
          },
          context
        )

      refute result.is_error
      assert %{"plan" => steps, "explanation" => "three steps"} = result.plan
      assert Enum.map(steps, & &1["status"]) == ["completed", "in_progress", "pending"]
      assert result.output =~ "✓ read the file"
    end

    test "coerces an unknown status rather than trusting it", %{context: context} do
      result =
        run(
          Ouroboros.Provider.Native.Tools.Plan,
          %{"steps" => [%{"step" => "x", "status" => "exploded"}]},
          context
        )

      assert [%{"status" => "pending"}] = result.plan["plan"]
    end
  end

  describe "execute/4" do
    test "every static action with required arguments fails in band when they are absent", %{
      context: context
    } do
      for module <- Tools.modules(),
          Enum.any?(module.schema(), fn {_key, opts} -> opts[:required] == true end) do
        result = Tools.execute(module, %{}, context, 5_000)

        assert result.is_error,
               "#{module.name()} unexpectedly executed without required arguments"

        assert result.output =~ "required"
      end
    end

    test "executor validation rejects wrong types and applies declared defaults", %{
      context: context,
      workspace: workspace
    } do
      invalid = run(Ouroboros.Provider.Native.Tools.Ls, %{"depth" => "deep"}, context)
      assert invalid.is_error
      assert invalid.output =~ "depth"

      write_file(workspace, "lib/defaults.ex", "ok\n")

      valid =
        run(
          Ouroboros.Provider.Native.Tools.Read,
          %{"path" => "lib/defaults.ex"},
          context
        )

      refute valid.is_error
      assert valid.output =~ "     1\tok"
    end

    test "a tool that raises becomes an error result, not a crash", %{context: context} do
      defmodule Exploding do
        use Jido.Action, name: "exploding", description: "raises", schema: []

        @impl true
        def run(_params, _context), do: raise("boom")
      end

      result = Tools.execute(Exploding, %{}, context, 5_000)
      assert result.is_error
      assert result.output =~ "boom"
    end

    test "a tool that hangs is killed at the timeout", %{context: context} do
      defmodule Hanging do
        use Jido.Action, name: "hanging", description: "hangs", schema: []

        @impl true
        def run(_params, _context) do
          Process.sleep(30_000)
          {:ok, %{output: "never", is_error: false}}
        end
      end

      result = Tools.execute(Hanging, %{}, context, 200)
      assert result.is_error
      assert result.output =~ "timed out after 200 ms"
    end

    test "a hallucinated argument is dropped and never becomes an atom on this node", %{
      context: context,
      workspace: workspace
    } do
      write_file(workspace, "lib/a.ex", "x\n")
      invented = "hallucinated_#{System.unique_integer([:positive])}"

      result =
        Tools.execute(
          Ouroboros.Provider.Native.Tools.Read,
          %{"path" => "lib/a.ex", invented => "value"},
          context,
          5_000
        )

      refute result.is_error
      assert result.output =~ "     1\tx"
      assert_raise ArgumentError, fn -> String.to_existing_atom(invented) end
    end
  end
end
