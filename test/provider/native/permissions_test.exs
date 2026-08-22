defmodule Ouroboros.Provider.Native.PermissionsTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Permissions

  @request %{
    principal: %{session_id: "s1", provider: :native, node: :nonode@nohost},
    tool: "bash",
    command: "mix test",
    paths: [],
    mode: :execute,
    domains: [],
    context: %{}
  }

  test "with no engine loaded every request asks, never allows" do
    refute Permissions.engine?()
    assert {:ask, :no_engine} = Permissions.evaluate(@request)
  end

  test "recording without an engine reports it rather than pretending to have logged" do
    assert {:error, :no_engine} = Permissions.record("d1", %{decision: :approve, scope: :once})
  end

  test "suggests a rule keyed on the tool and the command's first word" do
    assert Permissions.suggested_rule("bash", "mix test --stale", []) == %{
             "tool" => "bash",
             "command_prefix" => "mix"
           }

    assert Permissions.suggested_rule("edit", nil, ["/w/lib/a.ex"]) == %{
             "tool" => "edit",
             "paths" => ["/w/lib/a.ex"]
           }

    assert Permissions.suggested_rule("read", nil, []) == %{"tool" => "read"}
  end

  test "a denial names the rule it came from" do
    assert Permissions.deny_message("bash", "no-network") =~ "no-network"
    assert Permissions.deny_message("bash", nil) =~ "(unnamed)"
  end
end
