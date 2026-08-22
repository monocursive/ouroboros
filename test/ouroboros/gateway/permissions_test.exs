defmodule Ouroboros.Gateway.PermissionsTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Control.Permissions
  alias Ouroboros.Gateway.Methods

  setup do
    on_exit(fn ->
      {:ok, rules} = Permissions.list()

      Enum.each(rules, fn rule ->
        if rule.scope != :node, do: Permissions.remove(rule.scope, rule.id)
      end)

      Application.delete_env(:ouroboros, :permissions)
    end)

    :ok
  end

  test "the three methods are in the table with the scopes their effects deserve" do
    assert "permissions.list" in Methods.names()
    assert "permissions.add" in Methods.names()
    assert "permissions.remove" in Methods.names()

    assert {:ok, %{scope: :read}} = Methods.fetch("permissions.list")
    assert {:ok, %{scope: :operate}} = Methods.fetch("permissions.add")
    assert {:ok, %{scope: :operate}} = Methods.fetch("permissions.remove")
  end

  test "a rule can be added, listed, and removed over the wire shape" do
    assert {:ok, rule} =
             Methods.invoke("permissions.add", %{
               "scope" => "user",
               "decision" => "allow",
               "pattern" => "Bash(git status *)"
             })

    assert rule.scope == :user
    assert rule.decision == :allow
    assert rule.pattern == "Bash(git status *)"
    assert rule.fragile == false

    assert {:ok, listed} = Methods.invoke("permissions.list", %{"scope" => "user"})
    assert Enum.map(listed, & &1.id) == [rule.id]

    # `"ok"` on the wire, the same shape `interactive.delete` answers with.
    assert {:ok, :ok} =
             Methods.invoke("permissions.remove", %{"scope" => "user", "id" => rule.id})

    assert {:ok, []} = Methods.invoke("permissions.list", %{"scope" => "user"})
  end

  test "list shows the operator's own rules beside the stored ones" do
    Application.put_env(:ouroboros, :permissions, [{"Bash(rm *)", :deny}])

    assert {:ok, rules} = Methods.invoke("permissions.list", %{})
    assert Enum.any?(rules, &(&1.scope == :node and &1.pattern == "Bash(rm *)"))
  end

  test "a fragile pattern is accepted and says so, rather than being refused or hidden" do
    assert {:ok, rule} =
             Methods.invoke("permissions.add", %{
               "scope" => "user",
               "decision" => "deny",
               "pattern" => "Bash(curl http://github.com/ *)"
             })

    assert rule.fragile == true
  end

  test "node scope is operator configuration and cannot be written over the wire" do
    assert {:error, -32602, message} =
             Methods.invoke("permissions.add", %{
               "scope" => "node",
               "decision" => "allow",
               "pattern" => "Bash(ls *)"
             })

    assert message =~ "user, workspace"
  end

  test "a pattern the language does not contain is refused by the engine, not guessed at" do
    assert {:error, _code, _message, _data} =
             Methods.invoke("permissions.add", %{
               "scope" => "user",
               "decision" => "allow",
               "pattern" => "Bash(command:rm *)"
             })

    assert {:error, _code, _message, _data} =
             Methods.invoke("permissions.add", %{
               "scope" => "user",
               "decision" => "allow",
               "pattern" => "Tool(bash:shell=zsh)"
             })
  end

  test "the parameter surface is closed" do
    assert {:error, -32602, message} =
             Methods.invoke("permissions.list", %{"limit" => 5})

    assert message =~ "unsupported fields"

    assert {:error, -32602, _message} =
             Methods.invoke("permissions.add", %{
               "scope" => "user",
               "decision" => "maybe",
               "pattern" => "Bash(ls *)"
             })

    assert {:error, -32602, _message} = Methods.invoke("permissions.remove", %{"scope" => "user"})
    assert {:error, -32602, _message} = Methods.invoke("permissions.list", %{"scope" => "global"})
  end

  test "removing a rule that is not there is a not-found, not a silent success" do
    assert {:error, -32007, message} =
             Methods.invoke("permissions.remove", %{"scope" => "user", "id" => "rule-nope"})

    assert message =~ "rule-nope"
  end

  test "a workspace rule needs its workspace named" do
    assert {:error, _code, _message, _data} =
             Methods.invoke("permissions.add", %{
               "scope" => "workspace",
               "decision" => "allow",
               "pattern" => "Bash(make *)"
             })

    assert {:ok, rule} =
             Methods.invoke("permissions.add", %{
               "scope" => "workspace",
               "decision" => "allow",
               "pattern" => "Bash(make *)",
               "workspace" => "/tmp/some-workspace"
             })

    # Stored under the canonical root, which is what the scopes table promises and what a
    # request's own root is resolved to before the two are compared. On a host where
    # `/tmp` is a symlink these are two strings for one directory, and a rule written
    # under the unresolved one would never apply to anything.
    {:ok, canonical} = Ouroboros.Control.Permissions.Paths.canonicalize("/tmp/some-workspace")
    assert rule.workspace == canonical

    # The filter resolves the same way, so an operator naming the directory as they typed
    # it finds the rule they just wrote.
    assert {:ok, [^rule]} =
             Methods.invoke("permissions.list", %{"workspace" => "/tmp/some-workspace"})

    assert {:ok, [^rule]} = Methods.invoke("permissions.list", %{"workspace" => canonical})
  end
end
