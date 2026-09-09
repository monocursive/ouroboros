defmodule Ouroboros.Runtime.CapabilitiesTest do
  @moduledoc """
  The operator surface around a workspace proposal: what it lists, what it refuses to
  read, and what the gateway verbs in front of it accept.

  What a *successful* preview and admit do — the C9 validation, the sandboxed build, the
  signature and the rollout — belongs to `test/wasm/forge_test.exs`, which has a real
  Cargo project and a helper to do it with. This file is about the reading.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Runtime.Capabilities

  @name "workspace-echo"

  setup do
    suffix = System.unique_integer([:positive])
    workspace = Path.join(System.tmp_dir!(), "ouroboros-capabilities-#{suffix}")
    proposal = Path.join(workspace, ".ouroboros/capabilities/Echo")
    File.mkdir_p!(proposal)
    File.write!(Path.join(proposal, "manifest.json"), manifest())
    File.write!(Path.join(proposal, "Cargo.toml"), cargo_manifest())

    on_exit(fn -> File.rm_rf!(workspace) end)

    %{workspace: workspace, path: ".ouroboros/capabilities/Echo"}
  end

  test "lists readable proposals and reports unreadable ones", %{workspace: workspace} do
    broken = Path.join(workspace, ".ouroboros/capabilities/Broken")
    File.mkdir_p!(broken)
    File.write!(Path.join(broken, "manifest.json"), "{}")
    File.write!(Path.join(broken, "Cargo.toml"), cargo_manifest())

    assert {:ok, [broken_summary, echo]} = Capabilities.list(workspace)
    assert echo.path == ".ouroboros/capabilities/Echo"
    assert echo.lane == :wasm
    assert echo.module == "wasm/" <> @name
    assert echo.readable?
    refute broken_summary.readable?
  end

  # The `Cargo.toml` is what makes a directory a proposal. A directory without one is
  # refused rather than read as something else: there is one lane and one project shape.
  test "a proposal with no Cargo manifest is refused rather than guessed at", context do
    File.rm!(Path.join([context.workspace, context.path, "Cargo.toml"]))

    assert {:error, {:missing_proposal_file, "Cargo.toml"}} =
             Capabilities.preview(context.workspace, context.path)

    assert {:error, {:missing_proposal_file, "Cargo.toml"}} =
             Capabilities.admit(context.workspace, context.path)
  end

  test "contained-path refusals do not read outside the workspace", %{workspace: workspace} do
    assert {:error, {:source_outside_workspace, _}} =
             Capabilities.preview(workspace, "../outside")

    assert {:error, {:source_outside_workspace, _}} =
             Capabilities.preview(workspace, "/etc")

    assert {:error, {:source_outside_workspace, _}} =
             Capabilities.admit(workspace, "..")
  end

  test "gateway methods are operate-scoped and refuse extra keys", context do
    table = Methods.table()
    assert table["capabilities.list"].scope == :operate
    assert table["capabilities.preview"].scope == :operate
    assert table["capabilities.admit"].scope == :operate

    assert {:error, -32602, message} = Methods.invoke("capabilities.list", %{})
    assert message =~ "workspace"

    assert {:error, -32602, extra} =
             Methods.invoke("capabilities.preview", %{
               "workspace" => context.workspace,
               "path" => context.path,
               "sign" => true
             })

    assert extra =~ "unsupported fields"

    assert {:error, -32602, admit_extra} =
             Methods.invoke("capabilities.admit", %{
               "workspace" => context.workspace,
               "path" => context.path,
               "sign" => true
             })

    assert admit_extra =~ "unsupported fields"

    assert {:error, -32006, "the runtime refused the call", data} =
             Methods.invoke("capabilities.preview", %{
               "workspace" => context.workspace,
               "path" => "../outside"
             })

    assert inspect(data) =~ "source_outside_workspace"

    assert {:ok, listed} =
             Methods.invoke("capabilities.list", %{"workspace" => context.workspace})

    assert Enum.any?(listed, &(&1.path == context.path))
  end

  defp manifest do
    JSON.encode!(%{
      "name" => @name,
      "description" => "An echo capability authored in a workspace proposal"
    })
  end

  # Never read by this module — `Ouroboros.Wasm.Forge` owns C9 — but its presence is what
  # says "this directory is a proposal".
  defp cargo_manifest do
    """
    [package]
    name = "#{@name}"
    version = "0.1.0"
    edition = "2021"
    """
  end
end
