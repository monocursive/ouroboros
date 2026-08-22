defmodule Ouroboros.Provider.Native.PermissionsTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Permissions

  # The durable engine is loaded in this application; "no engine" is a node that names
  # a module which does not exist, which is also what an older or partial node looks like.
  defp without_engine(fun) do
    previous = Application.get_env(:ouroboros, :permissions_engine)
    Application.put_env(:ouroboros, :permissions_engine, Ouroboros.Test.NoSuchEngine)

    try do
      fun.()
    after
      if previous,
        do: Application.put_env(:ouroboros, :permissions_engine, previous),
        else: Application.delete_env(:ouroboros, :permissions_engine)
    end
  end

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
    without_engine(fn ->
      refute Permissions.engine?()
      assert {:ask, :no_engine} = Permissions.evaluate(@request)
    end)
  end

  test "recording without an engine reports it rather than pretending to have logged" do
    without_engine(fn ->
      assert {:error, :no_engine} =
               Permissions.record("d1", %{decision: :approve, scope: :once})
    end)
  end

  test "with the durable engine loaded, a request with no rule asks in the engine's words" do
    assert Permissions.engine?()
    assert {:ask, :no_rule} = Permissions.evaluate(@request)
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
