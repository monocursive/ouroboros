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

  # The rule the card's remember row would save. It has to be a pattern the engine's own
  # grammar accepts, because `permissions.add` validates it with `Control.Permissions
  # .Pattern` "and by nothing else" — the map this used to build was a shape no client
  # could render and `Rule.new/1` refused outright.
  test "suggests the engine's own pattern, in the grammar permissions.add validates" do
    assert Permissions.suggested_rule(%{@request | command: "mix test --stale"}) ==
             "Bash(mix test *)"

    assert Permissions.suggested_rule(%{
             @request
             | tool: "edit",
               command: nil,
               mode: :write,
               paths: ["/w/lib/a.ex"]
           }) == "Edit(/w/lib/**)"

    assert Permissions.suggested_rule(%{
             @request
             | tool: "desktop_act",
               command: nil,
               mode: :execute,
               context: %{app: "com.apple.calculator"}
           }) == "ComputerUse(app:com.apple.calculator)"
  end

  test "every suggestion it offers is one permissions.add would accept" do
    for command <- ["mix test --stale", "git push --force origin main", "cargo build"] do
      rule = Permissions.suggested_rule(%{@request | command: command})

      assert {:ok, _pattern} = Ouroboros.Control.Permissions.Pattern.parse(rule),
             "#{inspect(rule)} is not a pattern the rule store would take"
    end
  end

  test "a request the engine has nothing honest to say about carries no rule" do
    assert Permissions.suggested_rule(%{
             @request
             | tool: "unknown",
               command: nil,
               mode: :read,
               paths: []
           }) == nil
  end

  # The loop never writes the rule language itself, so a node with no engine offers no
  # rule rather than a made-up one.
  test "with no engine loaded there is no rule to suggest" do
    without_engine(fn ->
      assert Permissions.suggested_rule(@request) == nil
    end)
  end

  test "a denial names the rule it came from" do
    assert Permissions.deny_message("bash", "no-network") =~ "no-network"
    assert Permissions.deny_message("bash", nil) =~ "(unnamed)"
  end
end
