defmodule Ouroboros.Build.ErlexecPatchTest do
  use ExUnit.Case, async: true
  alias Ouroboros.Build.ErlexecPatch

  @patch Path.expand("../patches/erlexec-2.3.4-macos-setpgid.patch", __DIR__)

  setup do
    root =
      Path.join(System.tmp_dir!(), "ouro-erlexec-patch-#{System.unique_integer([:positive])}")

    dependency = Path.join(root, "erlexec")
    source = Path.join(dependency, "c_src/exec_impl.cpp")
    File.mkdir_p!(Path.dirname(source))
    File.cp!(Path.join(Mix.Project.deps_path(), "erlexec/c_src/exec_impl.cpp"), source)
    # The build hook has already patched the actual dependency. Reconstruct the exact
    # pristine file in scratch space, without copying or editing shared dependency state.
    assert {_output, 0} =
             System.cmd("git", ["apply", "--unidiff-zero", "--reverse", @patch], cd: dependency)

    on_exit(fn -> File.rm_rf!(root) end)
    %{root: root, source: source}
  end

  test "reproduces the reviewed patch and leaves an already patched source untouched", c do
    original = File.read!(c.source)
    assert :patched = ErlexecPatch.apply!(c.root)
    patched = File.read!(c.source)
    refute patched == original
    before = File.stat!(c.source)
    assert :unchanged = ErlexecPatch.apply!(c.root)
    assert File.stat!(c.source) == before
    assert File.read!(c.source) == patched
  end

  test "refuses unexpected dependency changes without overwriting them", c do
    File.write!(c.source, "\n// another dependency revision\n", [:append])
    changed = File.read!(c.source)

    assert_raise Mix.Error, ~r/refused unfamiliar source/, fn ->
      ErlexecPatch.apply!(c.root)
    end

    assert File.read!(c.source) == changed
  end

  test "missing dependency tells the operator how to fetch it", c do
    File.rm!(c.source)
    assert_raise Mix.Error, ~r/run mix deps.get/, fn -> ErlexecPatch.apply!(c.root) end
  end
end
