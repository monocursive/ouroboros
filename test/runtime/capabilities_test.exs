defmodule Ouroboros.Runtime.CapabilitiesTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Runtime.Capabilities
  alias Ouroboros.Upgrade.Forge.Signer

  @module Ouroboros.Capability.WorkspaceEcho
  @moduletag timeout: 300_000

  setup do
    suffix = System.unique_integer([:positive])
    workspace = Path.join(System.tmp_dir!(), "ouroboros-capabilities-#{suffix}")
    proposal = Path.join(workspace, ".ouroboros/capabilities/Echo")
    File.mkdir_p!(proposal)
    File.write!(Path.join(proposal, "manifest.json"), manifest())
    File.write!(Path.join(proposal, "source.ex"), capability_source())
    File.write!(Path.join(proposal, "test.exs"), capability_test_source())

    on_exit(fn ->
      File.rm_rf!(workspace)
      unload(@module)
    end)

    %{workspace: workspace, path: ".ouroboros/capabilities/Echo"}
  end

  test "lists readable proposals and reports unreadable ones", %{workspace: workspace} do
    broken = Path.join(workspace, ".ouroboros/capabilities/Broken")
    File.mkdir_p!(broken)
    File.write!(Path.join(broken, "manifest.json"), "{}")

    assert {:ok, [broken_summary, echo]} = Capabilities.list(workspace)
    assert echo.path == ".ouroboros/capabilities/Echo"
    assert echo.module == inspect(@module)
    assert echo.readable?
    refute broken_summary.readable?
  end

  test "preview compiles in the peer and does not load the module", context do
    assert {:ok, result} = Capabilities.preview(context.workspace, context.path)
    assert result.module == inspect(@module)
    assert result.loaded? == false
    assert result.test_report.failures == 0
    assert result.test_report.total == 1
    assert :code.which(@module) == :non_existing
  end

  test "contained-path refusals do not read outside the workspace", %{workspace: workspace} do
    assert {:error, {:source_outside_workspace, _}} =
             Capabilities.preview(workspace, "../outside")

    assert {:error, {:source_outside_workspace, _}} =
             Capabilities.preview(workspace, "/etc")

    assert {:error, {:source_outside_workspace, _}} =
             Capabilities.admit(workspace, "..")
  end

  test "admit with the shipped Deny signer fails and loads nothing", context do
    assert {Signer.Deny, _} = Signer.configured()

    assert {:error, {:signing_failed, reason}} =
             Capabilities.admit(context.workspace, context.path, author: "session:test")

    # Deny without a configured `forge_signer_id` stops at `:signer_id_required`;
    # Deny with an id returns `:signing_denied`. Both leave the module unloaded.
    assert reason in [:signing_denied, :signer_id_required]

    assert :code.which(@module) == :non_existing
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
      "module" => inspect(@module),
      "description" => "An echo capability authored in a workspace proposal"
    })
  end

  defp capability_source do
    """
    defmodule #{inspect(@module)} do
      @vsn 1

      use Jido.Agent,
        name: "workspace_echo",
        description: "A capability authored as a workspace proposal",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          messages_received: [type: :non_neg_integer, default: 0]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]
    end
    """
  end

  defp capability_test_source do
    """
    defmodule Ouroboros.Capability.WorkspaceEchoTest do
      use ExUnit.Case, async: false

      test "the capability compiled" do
        assert to_string(Ouroboros.Capability.WorkspaceEcho) =~ "WorkspaceEcho"
      end
    end
    """
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end
end
