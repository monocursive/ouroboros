defmodule Ouroboros.Gateway.WorkspaceBrowseTest do
  use ExUnit.Case, async: false

  @moduledoc """
  `workspace.browse` (D11, docs/WEB.md §7), driven through `Methods.invoke/2` against
  directories this test makes.

  Nothing here is stubbed. The method's whole reason for existing is that a client picking
  a workspace never reaches the disk itself, so what has to be true is a property of a real
  filesystem: that `..` and a symlink out of a root are the same refusal, that a root which
  is itself a symlink still works, that a cut list says so, and — the one that is easy to
  get wrong and impossible to notice — that a refusal outside the roots says *only* that.

  `async: false`, because two of these tests move `HOME`, which is the process-wide
  environment rather than an application key.
  """

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @invalid_params Methods.code(:invalid_params)
  @not_found Methods.code(:not_found)
  @unavailable Methods.code(:unavailable)

  setup do
    base =
      Path.join(System.tmp_dir!(), "ouroboros-browse-#{System.unique_integer([:positive])}")

    File.mkdir_p!(base)
    {:ok, base} = WorkspacePath.canonicalize(base)

    home = Path.join(base, "home")
    work = Path.join(base, "work")
    outside = Path.join(base, "outside")

    Enum.each([home, work, outside], &File.mkdir_p!/1)

    previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots)
    previous_home = System.get_env("HOME")

    Application.put_env(:ouroboros, :workspace_allowed_roots, [work])
    System.put_env("HOME", home)

    on_exit(fn ->
      if previous_home, do: System.put_env("HOME", previous_home), else: System.delete_env("HOME")

      if previous_roots,
        do: Application.put_env(:ouroboros, :workspace_allowed_roots, previous_roots),
        else: Application.delete_env(:ouroboros, :workspace_allowed_roots)

      File.rm_rf(base)
    end)

    {:ok, base: base, home: home, work: work, outside: outside}
  end

  defp browse(params), do: Methods.invoke("workspace.browse", params)
  defp browse_at(path), do: browse(%{"path" => path})
  defp names(listing), do: Enum.map(listing["entries"], & &1["name"])

  # ---------------------------------------------------------------------------
  # The table entry
  # ---------------------------------------------------------------------------

  test "the method is advertised, costs operate scope, and takes one optional path" do
    assert "workspace.browse" in Methods.names()
    assert {:ok, %{scope: :operate, timeout: 15_000}} = Methods.fetch("workspace.browse")

    # `operate` even though it writes nothing: this exists to start sessions, and a
    # listener held at `read` scope is one that was not trusted to.
    refute Methods.permits?(:read, %{scope: :operate, timeout: 15_000})

    assert {:ok, %{envelope: :closed, params: [%{name: "path", requirement: :optional}]}} =
             Methods.params("workspace.browse")
  end

  test "an unknown key is refused by name rather than ignored", context do
    assert {:error, @invalid_params, message} = browse(%{"path" => context.work, "depth" => 2})
    assert message =~ "depth"
  end

  test "a path that is not a nonempty string is a parameter error" do
    assert {:error, @invalid_params, message} = browse(%{"path" => ""})
    assert message =~ "params.path"

    assert {:error, @invalid_params, _message} = browse(%{"path" => 7})
  end

  # ---------------------------------------------------------------------------
  # The listing
  # ---------------------------------------------------------------------------

  test "the answer is directories only, name-sorted, with dotfiles left out", context do
    Enum.each(~w(zebra alpha .hidden middle), &File.mkdir_p!(Path.join(context.work, &1)))
    File.write!(Path.join(context.work, "notes.md"), "")
    File.write!(Path.join(context.work, ".env"), "")

    assert {:ok, listing} = browse_at(context.work)

    assert names(listing) == ~w(alpha middle zebra)
    assert Enum.all?(listing["entries"], &(&1["dir"] == true))
    assert Enum.all?(listing["entries"], &(map_size(&1) == 2))
    refute listing["truncated"]
  end

  test "the path it answers with is canonical, so a client knows where it really is",
       context do
    real = Path.join(context.work, "real")
    File.mkdir_p!(real)
    File.ln_s!(real, Path.join(context.work, "alias"))

    assert {:ok, listing} = browse_at(Path.join(context.work, "alias"))
    assert listing["path"] == real
  end

  test "roots are $HOME then the configured roots, canonical, and the default is the first",
       context do
    assert {:ok, listing} = browse_at(context.work)
    assert listing["roots"] == [context.home, context.work]

    # No `path` means the browse root, which is the head of that same list.
    assert {:ok, default} = browse(%{})
    assert default["path"] == context.home
  end

  test "a root that does not resolve to a directory is dropped rather than advertised",
       context do
    Application.put_env(:ouroboros, :workspace_allowed_roots, [
      context.work,
      Path.join(context.base, "never-created")
    ])

    assert {:ok, listing} = browse_at(context.work)
    assert listing["roots"] == [context.home, context.work]
  end

  test "parent is null at a root boundary and the directory above everywhere else",
       context do
    nested = Path.join([context.work, "apps", "web"])
    File.mkdir_p!(nested)

    assert {:ok, at_root} = browse_at(context.work)
    assert at_root["parent"] == nil

    assert {:ok, below} = browse_at(nested)
    assert below["parent"] == Path.join(context.work, "apps")

    assert {:ok, one_up} = browse_at(Path.join(context.work, "apps"))
    assert one_up["parent"] == context.work
  end

  # ---------------------------------------------------------------------------
  # Containment
  # ---------------------------------------------------------------------------

  test "a `..` that climbs out of a root is refused, and says only that", context do
    for path <- [
          Path.join(context.work, ".."),
          Path.join(context.work, "../outside"),
          Path.join([context.work, "..", "..", "etc"])
        ] do
      assert {:error, @invalid_params, message, data} = browse_at(path)
      assert data["reason"] == "outside_roots"
      assert data["roots"] == [context.home, context.work]
      assert message =~ "outside every directory this node browses"
      refute message =~ path
    end
  end

  test "an absolute path outside every root is refused whether or not it exists",
       context do
    existing = browse_at(context.outside)
    missing = browse_at(Path.join(context.base, "no-such-place"))

    # Byte-identical answers. The whole point: a directory picker that answered these two
    # differently would be a filesystem probe with a friendly name.
    assert {:error, @invalid_params, _message, %{"reason" => "outside_roots"}} = existing
    assert existing == missing
  end

  test "a symlink inside a root that points outside it is refused, and never listed",
       context do
    escape = Path.join(context.work, "escape")
    File.ln_s!(context.outside, escape)

    assert {:error, @invalid_params, _message, data} = browse_at(escape)
    assert data["reason"] == "outside_roots"

    # And the row that would have offered it is absent, because an entry the very next
    # call refuses is a lie a picker tells.
    assert {:ok, listing} = browse_at(context.work)
    refute "escape" in names(listing)
  end

  test "a name under an escaping symlink cannot be used to probe for existence",
       context do
    File.ln_s!(context.outside, Path.join(context.work, "escape"))
    File.mkdir_p!(Path.join(context.outside, "secret"))

    present = browse_at(Path.join([context.work, "escape", "secret"]))
    absent = browse_at(Path.join([context.work, "escape", "no-such-secret"]))

    assert {:error, @invalid_params, _message, %{"reason" => "outside_roots"}} = present
    assert present == absent
  end

  test "a dangling symlink is not offered as a directory", context do
    File.ln_s!(Path.join(context.work, "gone"), Path.join(context.work, "dangling"))
    File.mkdir_p!(Path.join(context.work, "real"))

    assert {:ok, listing} = browse_at(context.work)
    assert names(listing) == ["real"]
  end

  test "a symlink to a directory inside the roots is listed and resolves to the real one",
       context do
    File.mkdir_p!(Path.join(context.work, "real"))
    File.ln_s!(Path.join(context.work, "real"), Path.join(context.work, "shortcut"))

    assert {:ok, listing} = browse_at(context.work)
    assert names(listing) == ~w(real shortcut)

    assert {:ok, followed} = browse_at(Path.join(context.work, "shortcut"))
    assert followed["path"] == Path.join(context.work, "real")
  end

  test "a root that is itself a symlink browses its target rather than refusing itself",
       context do
    real = Path.join(context.base, "real-root")
    link = Path.join(context.base, "link-root")
    File.mkdir_p!(Path.join(real, "inside"))
    File.ln_s!(real, link)

    Application.put_env(:ouroboros, :workspace_allowed_roots, [link])

    assert {:ok, listing} = browse_at(link)
    assert listing["roots"] == [context.home, real]
    assert listing["path"] == real
    assert listing["parent"] == nil
    assert names(listing) == ["inside"]

    assert {:ok, below} = browse_at(Path.join(link, "inside"))
    assert below["path"] == Path.join(real, "inside")
    assert below["parent"] == real
  end

  test "a relative path is refused rather than resolved against the daemon's cwd" do
    assert {:error, @invalid_params, message, data} = browse_at("work")
    assert data["reason"] == "relative_path"
    assert message =~ "absolute"

    assert {:error, @invalid_params, _message, %{"reason" => "relative_path"}} = browse_at("..")
  end

  test "inside a root, a missing directory and a file get their own refusals", context do
    File.write!(Path.join(context.work, "notes.md"), "")

    assert {:error, @not_found, _message, %{"reason" => "no_such_directory"}} =
             browse_at(Path.join(context.work, "nope"))

    assert {:error, @invalid_params, _message, %{"reason" => "not_a_directory"}} =
             browse_at(Path.join(context.work, "notes.md"))
  end

  # ---------------------------------------------------------------------------
  # The bound
  # ---------------------------------------------------------------------------

  test "the list is cut at 500 and says so, and an uncut list says that too", context do
    dir = Path.join(context.work, "many")

    for index <- 0..500 do
      File.mkdir_p!(Path.join(dir, "dir-" <> String.pad_leading("#{index}", 3, "0")))
    end

    assert {:ok, cut} = browse_at(dir)
    assert length(cut["entries"]) == 500
    assert cut["truncated"] == true

    # The first five hundred by name, not an arbitrary five hundred: a client that pages
    # by name has to be able to say where the window it was given ends.
    assert List.first(names(cut)) == "dir-000"
    assert List.last(names(cut)) == "dir-499"

    File.rm_rf!(Path.join(dir, "dir-500"))

    assert {:ok, whole} = browse_at(dir)
    assert length(whole["entries"]) == 500
    assert whole["truncated"] == false
  end

  # ---------------------------------------------------------------------------
  # Roots that are not there
  # ---------------------------------------------------------------------------

  test "with HOME unset the configured roots still answer, and become the default",
       context do
    System.delete_env("HOME")

    assert {:ok, listing} = browse(%{})
    assert listing["roots"] == [context.work]
    assert listing["path"] == context.work
  end

  test "with HOME unset and no root configured, it refuses and says which two to set" do
    System.delete_env("HOME")
    Application.put_env(:ouroboros, :workspace_allowed_roots, [])

    assert {:error, @unavailable, message, %{"reason" => "no_browse_roots"}} = browse(%{})
    assert message =~ "$HOME"
    assert message =~ "workspace_allowed_roots"
  end

  test "a HOME that is not a directory is dropped rather than refused", context do
    file = Path.join(context.base, "not-a-home")
    File.write!(file, "")
    System.put_env("HOME", file)

    assert {:ok, listing} = browse(%{})
    assert listing["roots"] == [context.work]
  end

  # ---------------------------------------------------------------------------
  # The pinned frame
  # ---------------------------------------------------------------------------

  test "the pinned fixture has the shape the handler answers with", context do
    File.mkdir_p!(Path.join([context.work, "apps", "web"]))

    assert {:ok, live} = browse_at(Path.join(context.work, "apps"))

    pinned =
      "workspace_browse_result"
      |> Golden.path()
      |> File.read!()
      |> JSON.decode!()
      |> Map.fetch!("result")

    assert Enum.sort(Map.keys(live)) == Enum.sort(Map.keys(pinned))

    assert Enum.sort(Map.keys(hd(live["entries"]))) ==
             Enum.sort(Map.keys(hd(pinned["entries"])))
  end
end
