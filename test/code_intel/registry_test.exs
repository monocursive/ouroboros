defmodule Ouroboros.CodeIntel.RegistryTest do
  use ExUnit.Case, async: false

  alias Ouroboros.CodeIntel.Registry
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @moduletag :capture_log

  setup do
    base =
      Path.join(System.tmp_dir!(), "ouroboros-code-intel-#{System.unique_integer([:positive])}")

    File.mkdir_p!(base)
    # /tmp is a symlink on macOS; every assertion below compares against canonical paths.
    {:ok, workspace} = WorkspacePath.canonicalize(base)

    previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots, [])
    previous_servers = Application.get_env(:ouroboros, :code_intel, [])
    Application.put_env(:ouroboros, :workspace_allowed_roots, [workspace])

    on_exit(fn ->
      Application.put_env(:ouroboros, :workspace_allowed_roots, previous_roots)
      Application.put_env(:ouroboros, :code_intel, previous_servers)
      File.rm_rf(base)
    end)

    {:ok, workspace: workspace}
  end

  defp write(workspace, relative, contents \\ "") do
    path = Path.join(workspace, relative)
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, contents)
    path
  end

  defp put_servers(servers) do
    existing = Application.get_env(:ouroboros, :code_intel, [])
    Application.put_env(:ouroboros, :code_intel, Keyword.put(existing, :servers, servers))
  end

  ## ancestors/3 — the walk itself

  test "the walk includes the boundary directory rather than stopping one short of it" do
    assert Registry.ancestors("/a/b/c", "/a") == ["/a/b/c", "/a/b", "/a"]
  end

  test "the walk terminates at the filesystem root and includes it" do
    # `Path.dirname("/") == "/"`: the bug this asserts against is either an endless walk
    # or a list that silently omits "/".
    assert Registry.ancestors("/a", "/") == ["/a", "/"]
    assert Registry.ancestors("/", "/") == ["/"]
    assert List.last(Registry.ancestors("/a/b/c", "/")) == "/"
  end

  test "a directory the boundary does not contain yields no walk at all" do
    assert Registry.ancestors("/other/place", "/a") == []
    assert Registry.ancestors("/a-sibling", "/a") == []
  end

  test "the walk is depth-bounded" do
    deep = "/" <> Enum.map_join(1..40, "/", &"level#{&1}")
    assert length(Registry.ancestors(deep, "/", 5)) == 5
  end

  ## nearest_root/3

  test "the nearest marker above the file wins over one further up", context do
    write(context.workspace, "mix.exs")
    write(context.workspace, "apps/inner/mix.exs")
    file = write(context.workspace, "apps/inner/lib/thing.ex")

    assert {:ok, root} = Registry.nearest_root(file, context.workspace, ["mix.exs"])
    assert root == Path.join(context.workspace, "apps/inner")
  end

  test "a marker sitting in the workspace root itself is found", context do
    write(context.workspace, "mix.exs")
    file = write(context.workspace, "lib/deep/nested/thing.ex")

    assert {:ok, root} = Registry.nearest_root(file, context.workspace, ["mix.exs"])
    assert root == context.workspace
  end

  test "a marker above the workspace root is never reached", context do
    file = write(context.workspace, "sub/thing.ex")
    inner = Path.join(context.workspace, "sub")

    # The marker exists in the workspace root, but the walk is bounded at `sub`.
    write(context.workspace, "mix.exs")
    assert :error = Registry.nearest_root(file, inner, ["mix.exs"])
  end

  test "no marker anywhere is an honest :error, not the workspace root", context do
    file = write(context.workspace, "lib/thing.ex")
    assert :error = Registry.nearest_root(file, context.workspace, ["mix.exs"])
  end

  ## resolve/2

  test "an unsupported extension names the extension", context do
    file = write(context.workspace, "notes.unknownext")
    assert {:error, {:unsupported_language, ".unknownext"}} = Registry.resolve(file)
  end

  test "a file outside every admitted workspace root is refused", context do
    outside =
      Path.join(System.tmp_dir!(), "ouroboros-outside-#{System.unique_integer([:positive])}.ex")

    File.write!(outside, "")
    on_exit(fn -> File.rm(outside) end)

    assert {:error, {:outside_workspace, _path}} = Registry.resolve(outside)
    # Even naming the workspace root explicitly does not admit a file outside it.
    assert {:error, {:outside_workspace, _path}} =
             Registry.resolve(outside, workspace_root: context.workspace)
  end

  test "a forced root outside the workspace is refused", context do
    write(context.workspace, "mix.exs")
    file = write(context.workspace, "lib/thing.ex")

    assert {:error, {:root_outside_workspace, _root, _workspace}} =
             Registry.resolve(file, root: System.tmp_dir!())
  end

  test "a file with no project marker gets no server", context do
    file = write(context.workspace, "lib/thing.ex")
    assert {:error, {:no_project_root, :elixir, ["mix.exs"]}} = Registry.resolve(file)
  end

  test "an absent server resolves to its install hint, and installs nothing", context do
    write(context.workspace, "Cargo.toml")
    file = write(context.workspace, "src/main.rs")

    case Registry.resolve(file) do
      {:error, {:server_unavailable, "rust-analyzer", hint}} ->
        assert hint =~ "rustup"

      {:ok, spec} ->
        # rust-analyzer really is installed on this machine; the shape is still asserted.
        assert spec.server_id == "rust-analyzer"
        assert spec.root == context.workspace
    end
  end

  test "a project-local binary is preferred over one on PATH", context do
    write(context.workspace, "package.json", "{}")
    file = write(context.workspace, "src/app.ts")

    local = Path.join(context.workspace, "node_modules/.bin/typescript-language-server")
    File.mkdir_p!(Path.dirname(local))
    File.write!(local, "#!/bin/sh\nexit 0\n")
    File.chmod!(local, 0o755)

    assert {:ok, spec} = Registry.resolve(file)
    assert spec.executable == local
    assert spec.server_id == "typescript-language-server"
    assert spec.args == ["--stdio"]
    assert spec.language == :typescript
    assert spec.language_id == "typescript"
    assert spec.root == context.workspace
  end

  test "a hoisted binary above the project root is found in a monorepo layout", context do
    write(context.workspace, "package.json", "{}")
    write(context.workspace, "packages/web/package.json", "{}")
    file = write(context.workspace, "packages/web/src/app.tsx")

    hoisted = Path.join(context.workspace, "node_modules/.bin/typescript-language-server")
    File.mkdir_p!(Path.dirname(hoisted))
    File.write!(hoisted, "#!/bin/sh\nexit 0\n")
    File.chmod!(hoisted, 0o755)

    assert {:ok, spec} = Registry.resolve(file)
    assert spec.executable == hoisted
    assert spec.root == Path.join(context.workspace, "packages/web")
    assert spec.language_id == "typescriptreact"
  end

  test "a non-executable file at a local bin path is not mistaken for a server", context do
    write(context.workspace, "package.json", "{}")
    file = write(context.workspace, "src/app.ts")
    write(context.workspace, "node_modules/.bin/typescript-language-server", "not executable")

    case Registry.resolve(file) do
      {:error, {:server_unavailable, "typescript-language-server", hint}} ->
        assert hint =~ "npm install"

      {:ok, spec} ->
        # A real one is on PATH; what matters is that the unexecutable file lost.
        refute spec.executable =~ "node_modules"
    end
  end

  ## Operator configuration

  test "an operator can add a language the built-in registry does not know", context do
    server = write(context.workspace, "fake-server", "#!/bin/sh\nexit 0\n")
    File.chmod!(server, 0o755)
    write(context.workspace, "widget.toml")
    file = write(context.workspace, "thing.widget")

    put_servers([
      %{
        language: :widget,
        extensions: [".widget"],
        root_markers: ["widget.toml"],
        candidates: [
          %{server_id: "widget-ls", command: "widget-ls", local_bins: ["fake-server"]}
        ]
      }
    ])

    assert {:ok, spec} = Registry.resolve(file)
    assert spec.server_id == "widget-ls"
    assert spec.executable == server
    assert spec.language_id == "widget"
  end

  test "an operator override merges over a built-in definition", context do
    put_servers([%{language: :elixir, extensions: [".ex"], root_markers: ["custom.marker"]}])

    write(context.workspace, "custom.marker")
    file = write(context.workspace, "lib/thing.ex")

    # mix.exs no longer roots the project; the operator's marker does.
    assert {:ok, definition, "elixir"} = Registry.for_path(file)
    assert definition.root_markers == ["custom.marker"]
    assert {:ok, root} = Registry.nearest_root(file, context.workspace, definition.root_markers)
    assert root == context.workspace

    # The built-in candidate list survived the merge.
    assert [%{server_id: "expert"} | _rest] = definition.candidates
  end

  test "a malformed operator entry is dropped rather than taking the boot with it" do
    put_servers([%{extensions: [".zz"]}, "not a definition", %{language: :zz}])

    assert Enum.all?(Registry.definitions(), &is_atom(&1.language))
    refute Enum.any?(Registry.definitions(), &(&1.language == :zz))
  end

  test "every built-in definition is well formed" do
    for definition <- Registry.definitions() do
      assert is_atom(definition.language)
      assert map_size(definition.extensions) > 0
      assert definition.root_markers != []
      assert definition.candidates != []

      for candidate <- definition.candidates do
        assert is_binary(candidate.server_id)
        assert is_binary(candidate.command)
        assert is_binary(candidate.hint)
        assert is_list(candidate.args)
      end
    end
  end

  test "the nine languages the slice promises all resolve to a definition" do
    languages = Enum.map(Registry.definitions(), & &1.language)

    for language <- [:typescript, :python, :go, :rust, :c, :java, :elixir, :ruby, :swift] do
      assert language in languages
    end
  end

  test "elixir prefers expert and falls back to elixir-ls" do
    assert {:ok, definition, "elixir"} = Registry.for_path("/x/y.ex")

    assert Enum.map(definition.candidates, & &1.server_id) == [
             "expert",
             "elixir-ls",
             "elixir-ls"
           ]

    assert Enum.map(definition.candidates, & &1.command) == [
             "expert",
             "elixir-ls",
             "language_server.sh"
           ]
  end
end
