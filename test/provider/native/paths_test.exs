defmodule Ouroboros.Provider.Native.PathsTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Paths

  setup do
    root = Path.join(System.tmp_dir!(), "native-paths-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "outside"))
    File.write!(Path.join(root, "workspace/lib/a.ex"), "defmodule A do\nend\n")
    File.write!(Path.join(root, "outside/secret.txt"), "keep out\n")
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)
    %{root: root, scope: scope, workspace: scope.root}
  end

  describe "scope/3" do
    test "canonicalizes the workspace and every declared extra root", %{root: root} do
      {:ok, scope} =
        Paths.scope(Path.join(root, "workspace"), [Path.join(root, "outside")], :workspace_write)

      assert length(scope.roots) == 2
      assert scope.root in scope.roots
    end

    test "drops an add_dir that cannot be canonicalized rather than trusting it", %{root: root} do
      {:ok, scope} =
        Paths.scope(Path.join(root, "workspace"), [Path.join(root, "nope")], :workspace_write)

      assert scope.roots == [scope.root]
    end

    test "refuses a workspace that does not exist", %{root: root} do
      assert {:error, {:workspace_unavailable, _reason}} =
               Paths.scope(Path.join(root, "missing"), [], :workspace_write)
    end
  end

  describe "resolve/2" do
    test "accepts an existing file inside the workspace", %{scope: scope, workspace: workspace} do
      assert {:ok, resolved} = Paths.resolve("lib/a.ex", scope)
      assert resolved == Path.join(workspace, "lib/a.ex")
    end

    test "accepts a file that does not exist yet under an existing parent", %{scope: scope} do
      assert {:ok, resolved} = Paths.resolve("lib/new.ex", scope)
      assert String.ends_with?(resolved, "/lib/new.ex")
    end

    test "accepts a path whose parent directories do not exist yet", %{scope: scope} do
      assert {:ok, resolved} = Paths.resolve("lib/deep/deeper/new.ex", scope)
      assert String.ends_with?(resolved, "/lib/deep/deeper/new.ex")
    end

    test "refuses a `..` segment outright", %{scope: scope} do
      assert {:error, {:path_traversal, _path}} =
               Paths.resolve("lib/../../outside/secret.txt", scope)

      assert {:error, {:path_traversal, _path}} = Paths.resolve("../outside/secret.txt", scope)
    end

    test "refuses an absolute path outside the workspace", %{scope: scope, root: root} do
      assert {:error, {:path_escapes_workspace, _path, _roots}} =
               Paths.resolve(Path.join(root, "outside/secret.txt"), scope)
    end

    test "refuses a symlink that points outside the workspace", %{
      scope: scope,
      root: root,
      workspace: workspace
    } do
      File.ln_s!(Path.join(root, "outside"), Path.join(workspace, "escape"))

      assert {:error, {:path_escapes_workspace, resolved, _roots}} =
               Paths.resolve("escape/secret.txt", scope)

      refute String.starts_with?(resolved, workspace <> "/escape")
    end

    test "refuses a write through a symlinked parent that leaves the workspace", %{
      scope: scope,
      root: root,
      workspace: workspace
    } do
      File.ln_s!(Path.join(root, "outside"), Path.join(workspace, "escape"))

      assert {:error, {:path_escapes_workspace, _path, _roots}} =
               Paths.resolve("escape/planted.txt", scope)
    end

    test "accepts a path under a declared add_dir", %{root: root} do
      {:ok, scope} =
        Paths.scope(Path.join(root, "workspace"), [Path.join(root, "outside")], :workspace_write)

      assert {:ok, _resolved} = Paths.resolve(Path.join(root, "outside/secret.txt"), scope)
    end

    test "refuses a non-binary or empty path", %{scope: scope} do
      assert {:error, {:invalid_path, _}} = Paths.resolve("", scope)
      assert {:error, {:invalid_path, _}} = Paths.resolve(nil, scope)
    end
  end

  describe "session ids" do
    test "a fresh id embeds this node and round-trips validation" do
      id = Paths.new_session_id()
      assert :ok = Paths.validate_session_id(id)
      assert String.starts_with?(id, "native-")

      # Same node, same tag; a second node would produce a different middle segment.
      assert id |> String.split("-") |> Enum.at(1) ==
               Paths.new_session_id() |> String.split("-") |> Enum.at(1)
    end

    test "refuses an id that could become a path" do
      assert {:error, _} = Paths.validate_session_id("../../etc/passwd")
      assert {:error, _} = Paths.validate_session_id("native-a/b-c")
      assert {:error, _} = Paths.validate_session_id(nil)
    end
  end

  describe "session_dir/1" do
    test "creates a private directory and reports whether it is durable" do
      id = Paths.new_session_id()
      assert {:ok, dir, durable?} = Paths.session_dir(id)
      assert File.dir?(dir)
      assert is_boolean(durable?)

      {:ok, %File.Stat{mode: mode}} = File.stat(dir)
      assert Bitwise.band(mode, 0o777) == 0o700

      File.rm_rf(dir)
    end
  end
end
