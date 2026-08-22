defmodule Ouroboros.Provider.Native.ApplyPatchTest do
  @moduledoc """
  The V4A corpus: what parses, what applies, and what is refused.

  Split in two. `Patch` is pure — no filesystem, no clock, no process — so its half of
  the corpus is a specification of the format. `ApplyPatch` adds the guards, the atomic
  commit and the per-file `file_change`, and its half is about effects.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.ApplyPatch
  alias Ouroboros.Provider.Native.Tools.Patch
  alias Ouroboros.Provider.Native.Tools.Read

  setup do
    root = Path.join(System.tmp_dir!(), "native-patch-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)
    {:ok, read_only} = Paths.scope(workspace, [], :read_only)

    %{
      root: root,
      workspace: scope.root,
      scope: scope,
      read_only: read_only,
      session_dir: root
    }
  end

  defp write(workspace, relative, content) do
    path = Path.join(workspace, relative)
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, content)
    path
  end

  # A context whose `reads` already knows every file the patch will touch, which is what
  # a session looks like after the model has read them.
  defp context(scope, session_dir, paths) do
    reads =
      Map.new(paths, fn path ->
        {:ok, fingerprint} = Read.fingerprint(path)
        {path, fingerprint}
      end)

    %{scope: scope, session_dir: session_dir, reads: reads}
  end

  defp run(patch, context), do: Tools.execute(ApplyPatch, %{"patch" => patch}, context, 30_000)

  defp envelope(body), do: "*** Begin Patch\n" <> body <> "*** End Patch\n"

  # ================================================================ parsing

  describe "Patch.parse/1" do
    test "reads an Add File section as whole content" do
      assert {:ok, [file]} =
               Patch.parse(envelope("*** Add File: lib/new.ex\n+defmodule New do\n+end\n"))

      assert file.kind == :add
      assert file.path == "lib/new.ex"
      assert file.content == "defmodule New do\nend"
    end

    test "reads a Delete File section as a path and nothing else" do
      assert {:ok, [file]} = Patch.parse(envelope("*** Delete File: lib/gone.ex\n"))
      assert file.kind == :delete
      assert file.path == "lib/gone.ex"
      assert file.hunks == []
    end

    test "reads an Update File section's hunk into context, removals and additions" do
      patch =
        envelope("""
        *** Update File: lib/a.ex
        @@ defmodule A do
           def keep, do: 1
        -  def old, do: 2
        +  def new, do: 3
        """)

      assert {:ok, [file]} = Patch.parse(patch)
      assert file.kind == :update
      assert [hunk] = file.hunks
      assert hunk.markers == ["defmodule A do"]

      assert hunk.lines == [
               {:context, "  def keep, do: 1"},
               {:remove, "  def old, do: 2"},
               {:add, "  def new, do: 3"}
             ]
    end

    test "stacked `@@` lines with no body between them are one hunk's scope markers" do
      patch =
        envelope("""
        *** Update File: lib/a.ex
        @@ class Outer:
        @@     def inner(self):
         body
        -old
        +new
        """)

      assert {:ok, [%{hunks: [hunk]}]} = Patch.parse(patch)
      # Stored trimmed: a marker is matched against the trimmed file line, so the
      # patch's own indentation would only make a correct marker fail.
      assert hunk.markers == ["class Outer:", "def inner(self):"]
    end

    test "`*** Move to:` is read as the section's rename target" do
      patch =
        envelope("""
        *** Update File: lib/a.ex
        *** Move to: lib/renamed.ex
        @@
         keep
        -old
        +new
        """)

      assert {:ok, [file]} = Patch.parse(patch)
      assert file.move_to == "lib/renamed.ex"
    end

    test "`*** End of File` marks the hunk that runs to the end" do
      patch =
        envelope("""
        *** Update File: lib/a.ex
        @@
         keep
        +appended
        *** End of File
        """)

      assert {:ok, [%{hunks: [hunk]}]} = Patch.parse(patch)
      assert hunk.eof?
    end

    test "several sections parse in order and `paths/1` names every file" do
      patch =
        envelope("""
        *** Add File: lib/new.ex
        +x
        *** Update File: lib/a.ex
        *** Move to: lib/b.ex
        @@
         keep
        -old
        +new
        *** Delete File: lib/gone.ex
        """)

      assert {:ok, files} = Patch.parse(patch)
      assert Enum.map(files, & &1.kind) == [:add, :update, :delete]
      assert Patch.paths(files) == ["lib/new.ex", "lib/a.ex", "lib/b.ex", "lib/gone.ex"]
    end

    test "a blank line inside a hunk is a blank context line, not a refusal" do
      patch = envelope("*** Update File: lib/a.ex\n@@\n keep\n\n-old\n+new\n")

      assert {:ok, [%{hunks: [hunk]}]} = Patch.parse(patch)
      assert {:context, ""} in hunk.lines
    end

    test "refuses a patch with no envelope" do
      assert {:error, {:missing_begin, _marker}} = Patch.parse("*** Add File: x\n+y\n")
      assert {:error, {:missing_end, _marker}} = Patch.parse("*** Begin Patch\n*** Add File: x\n")
    end

    test "refuses an unknown directive rather than skipping it" do
      assert {:error, {:unknown_directive, _line, "*** Rename File: a"}} =
               Patch.parse(envelope("*** Rename File: a\n"))
    end

    test "refuses a body line with no prefix" do
      assert {:error, {:body_line_without_prefix, _line, "no prefix"}} =
               Patch.parse(envelope("*** Update File: a\n@@\nno prefix\n"))
    end

    test "refuses content in an Add File section that does not start with `+`" do
      assert {:error, {:add_line_without_plus, _line, "bare"}} =
               Patch.parse(envelope("*** Add File: a\nbare\n"))
    end

    test "refuses an Update section with no hunk, and a hunk with no body" do
      assert {:error, {:update_without_hunks, "a"}} =
               Patch.parse(envelope("*** Update File: a\n"))

      assert {:error, {:empty_hunk, "a"}} = Patch.parse(envelope("*** Update File: a\n@@\n"))
    end

    test "refuses the same path in two sections" do
      assert {:error, {:duplicate_file, "a"}} =
               Patch.parse(envelope("*** Add File: a\n+x\n*** Delete File: a\n"))
    end

    test "refuses content before any file section, and a second Move to" do
      assert {:error, {:content_before_any_file, _l, _t}} = Patch.parse(envelope("+orphan\n"))

      assert {:error, {:duplicate_move_to, _line, _text}} =
               Patch.parse(
                 envelope("*** Update File: a\n*** Move to: b\n*** Move to: c\n@@\n k\n-o\n+n\n")
               )
    end

    test "every refusal describes itself in words a model can act on" do
      for patch <- [
            "*** Add File: x\n+y\n",
            envelope("*** Rename File: a\n"),
            envelope("*** Update File: a\n@@\nno prefix\n"),
            envelope("*** Update File: a\n")
          ] do
        assert {:error, reason} = Patch.parse(patch)
        described = Patch.describe(reason)
        assert is_binary(described) and described != inspect(reason)
      end
    end
  end

  # ================================================================ applying

  describe "hunk location" do
    test "applies a hunk with no line numbers, by its context" do
      original = "defmodule A do\n  def keep, do: 1\n  def old, do: 2\nend\n"

      patch =
        envelope(
          "*** Update File: a\n@@\n   def keep, do: 1\n-  def old, do: 2\n+  def new, do: 3\n"
        )

      {:ok, [file]} = Patch.parse(patch)
      assert {:ok, updated, :exact} = Patch.apply_hunks(original, file)
      assert updated == "defmodule A do\n  def keep, do: 1\n  def new, do: 3\nend\n"
    end

    test "two hunks apply in order, each after the last" do
      original = Enum.map_join(1..8, "\n", &"line #{&1}") <> "\n"

      patch =
        envelope("""
        *** Update File: a
        @@
         line 2
        -line 3
        +LINE 3
        @@
         line 6
        -line 7
        +LINE 7
        """)

      {:ok, [file]} = Patch.parse(patch)
      assert {:ok, updated, :exact} = Patch.apply_hunks(original, file)
      assert updated =~ "LINE 3"
      assert updated =~ "LINE 7"
      refute updated =~ "line 3\n"
    end

    test "two identical bodies resolve to the two places they appear, not twice to the first" do
      original = "a\nmark\nb\nmark\nc\n"

      patch =
        envelope("*** Update File: a\n@@\n-mark\n+first\n@@\n-mark\n+second\n")

      {:ok, [file]} = Patch.parse(patch)
      assert {:ok, updated, :exact} = Patch.apply_hunks(original, file)
      assert updated == "a\nfirst\nb\nsecond\nc\n"
    end

    test "trailing whitespace in the file is tolerated and the tier is reported" do
      original = "defmodule A do   \n  def old, do: 2\t\nend\n"
      patch = envelope("*** Update File: a\n@@\n-  def old, do: 2\n+  def new, do: 3\n")

      {:ok, [file]} = Patch.parse(patch)
      assert {:ok, updated, :trailing_whitespace} = Patch.apply_hunks(original, file)
      assert updated =~ "def new, do: 3"
    end

    test "indentation is tolerated and the replacement is re-hung on the file's own" do
      original = "defmodule A do\n\t\tdef old, do: 2\nend\n"
      patch = envelope("*** Update File: a\n@@\n-  def old, do: 2\n+  def new, do: 3\n")

      {:ok, [file]} = Patch.parse(patch)
      assert {:ok, updated, :indentation} = Patch.apply_hunks(original, file)
      assert updated == "defmodule A do\n\t\tdef new, do: 3\nend\n"
    end

    test "an `@@` marker that matches nothing does not refuse a good hunk" do
      original = "a\nold\nb\n"
      patch = envelope("*** Update File: a\n@@ nothing named this\n-old\n+new\n")

      {:ok, [file]} = Patch.parse(patch)
      assert {:ok, "a\nnew\nb\n", :exact} = Patch.apply_hunks(original, file)
    end

    test "an `@@` marker disambiguates two identical bodies" do
      original = "def one\n  value = 1\nend\ndef two\n  value = 1\nend\n"
      patch = envelope("*** Update File: a\n@@ def two\n-  value = 1\n+  value = 2\n")

      {:ok, [file]} = Patch.parse(patch)
      assert {:ok, updated, :exact} = Patch.apply_hunks(original, file)
      assert updated == "def one\n  value = 1\nend\ndef two\n  value = 2\nend\n"
    end

    test "an addition-only hunk marked End of File appends" do
      original = "a\nb\n"
      patch = envelope("*** Update File: a\n@@\n+appended\n*** End of File\n")

      {:ok, [file]} = Patch.parse(patch)
      assert {:ok, updated, :exact} = Patch.apply_hunks(original, file)
      assert String.ends_with?(updated, "appended")
    end

    test "context that is nowhere in the file fails with the hunk that failed" do
      patch = envelope("*** Update File: a\n@@\n-absent line\n+new\n")
      {:ok, [file]} = Patch.parse(patch)

      assert {:error, {:hunk_not_found, _hunk, ["absent line"]}} =
               Patch.apply_hunks("a\nb\n", file)
    end
  end

  # ================================================================ the tool

  describe "apply_patch" do
    test "adds, updates, moves and deletes in one call, one file_change each", %{
      workspace: workspace,
      scope: scope,
      session_dir: session_dir
    } do
      update = write(workspace, "lib/a.ex", "defmodule A do\n  def old, do: 1\nend\n")
      move = write(workspace, "lib/move_me.ex", "defmodule M do\nend\n")
      delete = write(workspace, "lib/gone.ex", "defmodule G do\nend\n")

      patch =
        envelope("""
        *** Add File: lib/new.ex
        +defmodule New do
        +end
        *** Update File: lib/a.ex
        @@
        -  def old, do: 1
        +  def new, do: 2
        *** Update File: lib/move_me.ex
        *** Move to: lib/moved.ex
        @@
        -defmodule M do
        +defmodule Moved do
        *** Delete File: lib/gone.ex
        """)

      result = run(patch, context(scope, session_dir, [update, move, delete]))

      refute result.is_error
      assert result.output =~ "added"
      assert result.output =~ "updated"
      assert result.output =~ "deleted"

      assert File.read!(Path.join(workspace, "lib/new.ex")) == "defmodule New do\nend"
      assert File.read!(update) =~ "def new, do: 2"
      assert File.read!(Path.join(workspace, "lib/moved.ex")) =~ "defmodule Moved do"
      refute File.exists?(move)
      refute File.exists?(delete)

      # One entry per file, each with its own diff — a client renders four diffs, and the
      # checkpoint records four restorable paths.
      paths = Enum.map(result.changes, & &1["relative_path"]) |> Enum.sort()
      assert paths == ["lib/a.ex", "lib/gone.ex", "lib/move_me.ex", "lib/moved.ex", "lib/new.ex"]
      assert Enum.all?(result.changes, &is_binary(&1["diff"]))
    end

    test "refuses to update a file that was never read", %{
      workspace: workspace,
      scope: scope,
      session_dir: session_dir
    } do
      write(workspace, "lib/a.ex", "old\n")
      patch = envelope("*** Update File: lib/a.ex\n@@\n-old\n+new\n")

      result = run(patch, %{scope: scope, session_dir: session_dir, reads: %{}})

      assert result.is_error
      assert result.output =~ "has not been read in this session"
      assert File.read!(Path.join(workspace, "lib/a.ex")) == "old\n"
    end

    test "refuses a file changed since it was read", %{
      workspace: workspace,
      scope: scope,
      session_dir: session_dir
    } do
      path = write(workspace, "lib/a.ex", "old\n")
      context = context(scope, session_dir, [path])
      File.write!(path, "changed by someone else\n")

      result = run(envelope("*** Update File: lib/a.ex\n@@\n-old\n+new\n"), context)

      assert result.is_error
      assert result.output =~ "changed since it was read"
      assert File.read!(path) == "changed by someone else\n"
    end

    test "nothing is written when a later section fails", %{
      workspace: workspace,
      scope: scope,
      session_dir: session_dir
    } do
      path = write(workspace, "lib/a.ex", "keep\nold\n")

      patch =
        envelope("""
        *** Add File: lib/first.ex
        +created
        *** Update File: lib/a.ex
        @@
        -absent line
        +new
        """)

      result = run(patch, context(scope, session_dir, [path]))

      assert result.is_error
      refute File.exists?(Path.join(workspace, "lib/first.ex"))
      assert File.read!(path) == "keep\nold\n"
    end

    test "a context mismatch names the closest lines in the file", %{
      workspace: workspace,
      scope: scope,
      session_dir: session_dir
    } do
      path = write(workspace, "lib/a.ex", "defmodule A do\n  def value, do: 41\nend\n")

      patch =
        envelope("*** Update File: lib/a.ex\n@@\n-  def value, do: 42\n+  def value, do: 43\n")

      result = run(patch, context(scope, session_dir, [path]))

      assert result.is_error
      assert result.output =~ "Closest lines in the file"
      assert result.output =~ "def value, do: 41"
    end

    test "`*** Add File:` refuses to overwrite", %{
      workspace: workspace,
      scope: scope,
      session_dir: session_dir
    } do
      write(workspace, "lib/a.ex", "existing\n")

      result =
        run(envelope("*** Add File: lib/a.ex\n+replacement\n"), context(scope, session_dir, []))

      assert result.is_error
      assert result.output =~ "already exists"
      assert File.read!(Path.join(workspace, "lib/a.ex")) == "existing\n"
    end

    test "a path outside the workspace is refused", %{
      root: root,
      scope: scope,
      session_dir: session_dir
    } do
      File.mkdir_p!(Path.join(root, "outside"))

      result =
        run(
          envelope("*** Add File: #{Path.join(root, "outside/x.ex")}\n+pwned\n"),
          context(scope, session_dir, [])
        )

      assert result.is_error
      assert result.output =~ "outside this session's workspace"
      refute File.exists?(Path.join(root, "outside/x.ex"))
    end

    test "read_only refuses the whole patch", %{read_only: read_only, session_dir: session_dir} do
      result =
        run(envelope("*** Add File: lib/x.ex\n+y\n"), %{
          scope: read_only,
          session_dir: session_dir,
          reads: %{}
        })

      assert result.is_error
      assert result.output =~ "read_only"
    end

    test "an unparseable patch is refused before anything is touched", %{
      scope: scope,
      session_dir: session_dir
    } do
      result = run("this is not a patch", context(scope, session_dir, []))

      assert result.is_error
      assert result.output =~ "does not start with"
    end
  end

  describe "classification" do
    test "apply_patch writes, and its write paths are every file in the patch", %{
      scope: scope,
      workspace: workspace
    } do
      patch =
        envelope("*** Add File: lib/new.ex\n+x\n*** Update File: lib/a.ex\n@@\n-o\n+n\n")

      classified = Tools.classify("apply_patch", %{"patch" => patch}, scope)

      assert classified.mode == :write

      assert Enum.sort(classified.write_paths) ==
               Enum.sort([Path.join(workspace, "lib/new.ex"), Path.join(workspace, "lib/a.ex")])
    end

    test "a patch that will not parse reports no paths and still classifies as a write", %{
      scope: scope
    } do
      classified = Tools.classify("apply_patch", %{"patch" => "garbage"}, scope)

      assert classified.mode == :write
      assert classified.write_paths == []
      assert ApplyPatch.paths(%{"patch" => "garbage"}, scope) == []
    end
  end
end
