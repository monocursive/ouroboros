defmodule Ouroboros.Provider.Native.SearchToolsTest do
  @moduledoc """
  `grep`, `glob` and `ls`: what they find, what they refuse, and where they stop.

  `grep` is tested twice over where it matters — once through whichever engine this host
  has, and once through the built-in walker regardless — because the whole point of
  having two engines behind one schema is that a repository does not behave differently
  depending on whether an operator installed ripgrep.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Glob
  alias Ouroboros.Provider.Native.Tools.Grep
  alias Ouroboros.Provider.Native.Tools.Ls

  setup do
    root = Path.join(System.tmp_dir!(), "native-search-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib/nested"))
    File.mkdir_p!(Path.join(workspace, "test"))
    File.mkdir_p!(Path.join(workspace, "_build/junk"))
    File.mkdir_p!(Path.join(root, "outside"))

    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def needle, do: 1\nend\n")
    File.write!(Path.join(workspace, "lib/nested/b.ex"), "defmodule B do\n  # NEEDLE here\nend\n")
    File.write!(Path.join(workspace, "test/a_test.exs"), "defmodule ATest do\nend\n")
    File.write!(Path.join(workspace, "_build/junk/c.ex"), "needle in the junk\n")
    File.write!(Path.join(root, "outside/secret.txt"), "needle outside\n")

    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)

    %{
      root: root,
      workspace: scope.root,
      scope: scope,
      context: %{scope: scope, session_dir: Path.join(root, "session"), reads: %{}}
    }
  end

  defp run(module, input, context), do: Tools.execute(module, input, context, 30_000)

  describe "grep" do
    test "finds a literal with its path and line number", %{context: context} do
      result = run(Grep, %{"pattern" => "def needle"}, context)

      refute result.is_error
      assert result.output =~ "lib/a.ex:2:"
      assert result.output =~ "def needle"
    end

    test "-i is case insensitive and off by default", %{context: context} do
      sensitive = run(Grep, %{"pattern" => "NEEDLE"}, context)
      assert sensitive.output =~ "nested/b.ex"
      refute sensitive.output =~ "lib/a.ex:2"

      insensitive = run(Grep, %{"pattern" => "NEEDLE", "case_insensitive" => true}, context)
      assert insensitive.output =~ "nested/b.ex"
      assert insensitive.output =~ "lib/a.ex"
    end

    test "-n off drops the line numbers", %{context: context} do
      result = run(Grep, %{"pattern" => "def needle", "line_numbers" => false}, context)
      assert result.output =~ "lib/a.ex: "
      refute result.output =~ "lib/a.ex:2:"
    end

    test "a glob narrows the files searched", %{context: context} do
      assert run(Grep, %{"pattern" => "defmodule", "glob" => "*_test.exs"}, context).output =~
               "a_test.exs"

      refute run(Grep, %{"pattern" => "defmodule", "glob" => "*_test.exs"}, context).output =~
               "lib/a.ex"
    end

    test "a path outside the workspace is refused, not searched", %{
      context: context,
      root: root
    } do
      result = run(Grep, %{"pattern" => "needle", "path" => Path.join(root, "outside")}, context)

      assert result.is_error
      assert result.output =~ "outside this session's workspace"
      refute result.output =~ "secret"
    end

    test "`..` in the path is refused before anything is resolved", %{context: context} do
      result = run(Grep, %{"pattern" => "needle", "path" => "../outside"}, context)

      assert result.is_error
      assert result.output =~ "contains a `..` segment"
    end

    test "an unusable regular expression is named rather than run", %{context: context} do
      result = run(Grep, %{"pattern" => "([unclosed"}, context)

      assert result.is_error
      assert result.output =~ "not a usable regular expression"
    end

    test "no matches is an answer, not an error", %{context: context} do
      result = run(Grep, %{"pattern" => "zzz-not-here-zzz"}, context)

      refute result.is_error
      assert result.output =~ "No matches"
    end

    test "a line longer than the per-line cap is clipped", %{
      workspace: workspace,
      context: context
    } do
      File.write!(Path.join(workspace, "lib/long.ex"), "needle " <> String.duplicate("x", 5_000))
      result = run(Grep, %{"pattern" => "needle x"}, context)

      refute result.is_error
      assert Enum.all?(String.split(result.output, "\n"), &(byte_size(&1) < 1_000))
    end
  end

  describe "glob" do
    test "matches by pattern, relative to the workspace", %{context: context} do
      result = run(Glob, %{"pattern" => "lib/**/*.ex"}, context)

      refute result.is_error
      assert result.output =~ "lib/a.ex"
      assert result.output =~ "lib/nested/b.ex"
      refute result.output =~ "a_test.exs"
    end

    test "sorts newest first", %{workspace: workspace, context: context} do
      newest = Path.join(workspace, "lib/zzz_newest.ex")
      File.write!(newest, "x\n")
      future = System.os_time(:second) + 120
      File.touch!(newest, future)

      result = run(Glob, %{"pattern" => "lib/**/*.ex"}, context)
      [first | _rest] = result.output |> String.split("\n") |> Enum.drop(1)

      assert first == "lib/zzz_newest.ex"
    end

    test "an absolute pattern is refused", %{context: context} do
      result = run(Glob, %{"pattern" => "/etc/*"}, context)

      assert result.is_error
      assert result.output =~ "is absolute"
    end

    test "a `..` pattern is refused rather than resolved", %{context: context} do
      result = run(Glob, %{"pattern" => "../outside/*"}, context)

      assert result.is_error
      assert result.output =~ "`..` segment"
    end

    test "a pattern that expands outside the workspace yields nothing", %{
      root: root,
      workspace: workspace,
      context: context
    } do
      # A symlink is the one way a relative pattern can leave the tree, and it is the
      # case the containment filter exists for.
      File.ln_s(Path.join(root, "outside"), Path.join(workspace, "link"))
      result = run(Glob, %{"pattern" => "link/*.txt"}, context)

      refute result.output =~ "secret.txt"
    end

    test "no match is an answer, not an error", %{context: context} do
      result = run(Glob, %{"pattern" => "**/*.zzz"}, context)

      refute result.is_error
      assert result.output =~ "No files matched"
    end
  end

  describe "ls" do
    test "lists one level by default and marks directories", %{context: context} do
      result = run(Ls, %{}, context)

      refute result.is_error
      assert result.output =~ "lib/"
      assert result.output =~ "test/"
      refute result.output =~ "a.ex"
    end

    test "depth descends and is capped at three", %{context: context} do
      two = run(Ls, %{"depth" => 2}, context)
      assert two.output =~ "a.ex"
      refute two.output =~ "b.ex"

      deep = run(Ls, %{"depth" => 99}, context)
      assert deep.output =~ "(depth 3)"
      assert deep.output =~ "b.ex"
    end

    test "the noise directories are named but not descended into", %{context: context} do
      result = run(Ls, %{"depth" => 3}, context)

      assert result.output =~ "_build"
      assert result.output =~ "not descended into"
      refute result.output =~ "c.ex"
    end

    test "a file is not a directory and says so", %{context: context} do
      result = run(Ls, %{"path" => "lib/a.ex"}, context)

      assert result.is_error
      assert result.output =~ "is not a directory"
    end

    test "outside the workspace is refused", %{context: context, root: root} do
      result = run(Ls, %{"path" => Path.join(root, "outside")}, context)

      assert result.is_error
      assert result.output =~ "outside this session's workspace"
    end

    test "an empty directory says so rather than printing nothing", %{
      workspace: workspace,
      context: context
    } do
      File.mkdir_p!(Path.join(workspace, "empty"))
      result = run(Ls, %{"path" => "empty"}, context)

      refute result.is_error
      assert result.output =~ "is empty"
    end
  end

  describe "classification" do
    test "the search tools read, and their path is what the engine is asked about", %{
      scope: scope,
      workspace: workspace
    } do
      for tool <- ["grep", "glob", "ls"] do
        classified = Tools.classify(tool, %{"path" => "lib"}, scope)
        assert classified.mode == :read
        assert classified.write_paths == []
        assert classified.paths == [Path.join(workspace, "lib")]
      end
    end
  end
end

defmodule Ouroboros.Provider.Native.GrepFallbackTest do
  @moduledoc """
  The same questions, put to the built-in walker.

  Two engines behind one schema is only worth having if a repository does not behave
  differently depending on whether an operator installed ripgrep, so the walker is forced
  on and asked the same things. Not `async` because forcing it is node configuration.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Grep

  setup do
    previous = Application.get_env(:ouroboros, :native_grep_engine)
    Application.put_env(:ouroboros, :native_grep_engine, :fallback)

    root = Path.join(System.tmp_dir!(), "native-grep-fb-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib/nested"))
    File.mkdir_p!(Path.join(workspace, "_build/junk"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def needle, do: 1\nend\n")
    File.write!(Path.join(workspace, "lib/nested/b.ex"), "defmodule B do\n  # NEEDLE\nend\n")
    File.write!(Path.join(workspace, "_build/junk/c.ex"), "needle in the junk\n")

    on_exit(fn ->
      File.rm_rf(root)

      if previous,
        do: Application.put_env(:ouroboros, :native_grep_engine, previous),
        else: Application.delete_env(:ouroboros, :native_grep_engine)
    end)

    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)
    %{workspace: scope.root, context: %{scope: scope, session_dir: root, reads: %{}}}
  end

  defp run(input, context), do: Tools.execute(Grep, input, context, 30_000)

  test "answers with the walker and says which engine answered", %{context: context} do
    assert Grep.engine() == :fallback
    result = run(%{"pattern" => "def needle"}, context)

    refute result.is_error
    assert result.output =~ "built-in walker"
    assert result.output =~ "lib/a.ex:2:"
  end

  test "honours -i and the glob exactly as ripgrep does", %{context: context} do
    assert run(%{"pattern" => "NEEDLE"}, context).output =~ "nested/b.ex"
    assert run(%{"pattern" => "needle", "case_insensitive" => true}, context).output =~ "b.ex"
    refute run(%{"pattern" => "needle", "glob" => "b.ex"}, context).output =~ "lib/a.ex"
  end

  test "skips the directories every repository fills with noise", %{context: context} do
    refute run(%{"pattern" => "needle"}, context).output =~ "junk"
  end

  test "stops at the match cap and says so", %{workspace: workspace, context: context} do
    for index <- 1..40 do
      File.write!(
        Path.join(workspace, "lib/bulk#{index}.ex"),
        Enum.map_join(1..20, "\n", fn line -> "needle #{index} #{line}" end)
      )
    end

    result = run(%{"pattern" => "needle"}, context)

    refute result.is_error
    assert result.output =~ "stopped at 200 matches"
    assert length(String.split(result.output, "\n")) <= 202
  end

  test "no matches is an answer, not an error", %{context: context} do
    result = run(%{"pattern" => "zzz-absent-zzz"}, context)

    refute result.is_error
    assert result.output =~ "No matches"
  end
end
